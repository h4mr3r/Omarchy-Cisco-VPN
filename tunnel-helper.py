#!/usr/bin/python3 -I
"""Omarchy Cisco VPN tunnel helper: runs openconnect with vpnc-script as root.

Installed (root-owned) as /usr/local/libexec/omarchy-cisco-vpn-tunnel and run
by the widget through pkexec; a polkit rule lets only the installing user do
that without a password. The widget authenticates as the user and passes the
resulting session cookie here; this helper never sees the password.

  up      read a JSON request on stdin and start openconnect in the background
  down    disconnect (openconnect logs off and vpnc-script restores routes/DNS)
  script  vpnc-script wrapper used by openconnect: replaces the gateway's split
          routes with the user's networks, then runs the stock vpnc-script

Routes and DNS are handled entirely by /etc/vpnc/vpnc-script, exactly like
`openconnect ... gw.example.com` from a terminal. With networks configured,
only those go through the VPN (CISCO_SPLIT_INC); DNS is set on the tunnel
device in systemd-resolved by vpnc-script itself.
"""

import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time

OPENCONNECT = "/usr/bin/openconnect"
VPNC_SCRIPT = "/etc/vpnc/vpnc-script"
SELF = "/usr/local/libexec/omarchy-cisco-vpn-tunnel"
RUN_DIR = "/run/omarchy-cisco-vpn"
PID_FILE = RUN_DIR + "/openconnect.pid"
ROUTES_FILE = RUN_DIR + "/routes.json"
INFO_FILE = RUN_DIR + "/info.json"
LOG_FILE = RUN_DIR + "/openconnect.log"
MAX_ROUTES = 64
MAX_REQUEST = 64 * 1024

HOST = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])"
URL = re.compile(r"^https://" + HOST + r"(?::\d{1,5})?(?:/[A-Za-z0-9._~%!$&()*+,;=:@/-]*)?$")
PROXY = re.compile(r"^(?:http|socks|socks5)://" + HOST + r":\d{1,5}$")
FINGERPRINT = re.compile(r"^(?:pin-sha256:[A-Za-z0-9+/]{43}=|sha256:[0-9a-fA-F]{64}|sha1:[0-9a-fA-F]{40})$")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
LOCAL_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
REPORTED_OS = ("linux", "linux-64", "win", "mac-intel", "android", "apple-ios")
RESOLVE_HOST = re.compile(r"^" + HOST + r"$")


class HelperError(Exception):
    pass


def running_pid():
    """PID of our openconnect, or 0."""
    try:
        with open(PID_FILE) as handle:
            pid = int(handle.read().strip())
        with open(f"/proc/{pid}/comm") as handle:
            if handle.read().strip() == "openconnect":
                return pid
    except (OSError, ValueError):
        pass
    return 0


def field(request, name, pattern=None, required=False):
    value = request.get(name, "")
    if not isinstance(value, str) or any(c in value for c in "\r\n\0"):
        raise HelperError(f"Invalid {name}")
    if not value:
        if required:
            raise HelperError(f"Missing {name}")
        return ""
    if pattern is not None and not pattern.fullmatch(value):
        raise HelperError(f"Invalid {name}")
    return value


def parse_routes(values):
    if not isinstance(values, list) or len(values) > MAX_ROUTES:
        raise HelperError("Invalid routes")
    routes = []
    for value in values:
        try:
            network = ipaddress.IPv4Network(str(value), strict=False)
        except ValueError as error:
            raise HelperError("Invalid routes") from error
        if network.prefixlen == 0:
            raise HelperError("Invalid routes")
        routes.append([str(network.network_address), str(network.netmask), network.prefixlen])
    return routes


def parse_resolve(value):
    if not value:
        return ""
    host, _, address = value.partition(":")  # host:ip (openconnect's --resolve)
    if not RESOLVE_HOST.fullmatch(host):
        raise HelperError("Invalid resolve")
    try:
        ipaddress.ip_address(address)
    except ValueError as error:
        raise HelperError("Invalid resolve") from error
    return value


def failure_message(log):
    text = log.lower()
    if "cookie" in text and any(t in text for t in ("rejected", "invalid", "401", "403")):
        return "The VPN gateway rejected the session; connect again"
    if "certificate" in text or "servercert" in text:
        return "The VPN gateway's certificate did not match the pinned one"
    if any(t in text for t in ("resolve", "getaddrinfo", "name or service not known")):
        return "VPN server name could not be resolved"
    if any(t in text for t in ("failed to connect", "connection refused", "network is unreachable")):
        return "Could not reach the VPN server"
    if "vpnc-script" in text or "script" in text and "failed" in text:
        return "The VPN connected but setting up routes/DNS failed (vpnc-script)"
    return "OpenConnect could not start the tunnel"


def up():
    raw = sys.stdin.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        raise HelperError("Request too large")
    try:
        request = json.loads(raw)
    except ValueError as error:
        raise HelperError("Invalid request") from error
    if not isinstance(request, dict):
        raise HelperError("Invalid request")
    if running_pid():
        raise HelperError("The VPN is already connected")

    url = field(request, "url", URL, required=True)
    cookie = field(request, "cookie", required=True)
    if len(cookie) > 8192 or not cookie.isprintable():
        raise HelperError("Invalid cookie")
    fingerprint = field(request, "fingerprint", FINGERPRINT, required=True)
    resolve = parse_resolve(field(request, "resolve"))
    proxy = field(request, "proxy", PROXY)
    version = field(request, "version", VERSION)
    hostname = field(request, "hostname", LOCAL_HOSTNAME)
    if hostname and ".." in hostname:
        raise HelperError("Invalid hostname")
    reported_os = field(request, "os")
    if reported_os and reported_os not in REPORTED_OS:
        raise HelperError("Invalid os")
    routes = parse_routes(request.get("routes", []))

    os.makedirs(RUN_DIR, mode=0o755, exist_ok=True)
    os.chmod(RUN_DIR, 0o755)
    for path in (PID_FILE, INFO_FILE):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    # Read back by the vpnc-script wrapper (parse_routes) at connect and disconnect.
    with open(ROUTES_FILE, "w") as handle:
        json.dump([f"{address}/{length}" for address, _mask, length in routes], handle)

    args = [OPENCONNECT, "--protocol=anyconnect", "--cookie-on-stdin",
            "--servercert", fingerprint, "--script", SELF + " script",
            "--background", "--pid-file", PID_FILE, "--disable-ipv6"]
    args += ["--proxy", proxy] if proxy else ["--no-proxy"]
    if resolve:
        args.append(f"--resolve={resolve}")
    if version:
        args.append(f"--version-string={version}")
    if hostname:
        args.append(f"--local-hostname={hostname}")
    if reported_os:
        args.append(f"--os={reported_os}")
    args.append(url)

    # The backgrounded openconnect keeps its output streams, so they go to a
    # root-only log file instead of the widget's pipes.
    descriptor = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as log:
        try:
            result = subprocess.run(args, input=cookie + "\n", stdout=log, stderr=log,
                                    text=True, timeout=60, start_new_session=True)
        except subprocess.TimeoutExpired as error:
            stop(running_pid())
            raise HelperError("OpenConnect timed out starting the tunnel") from error
    if result.returncode:
        with open(LOG_FILE, errors="replace") as handle:
            raise HelperError(failure_message(handle.read(256 * 1024)))
    for _ in range(50):
        if running_pid():
            return {"ok": True, "pid": running_pid()}
        time.sleep(0.1)
    raise HelperError("OpenConnect exited right after connecting")


def stop(pid, timeout=15):
    if not pid:
        return
    # SIGINT: openconnect logs off the session and runs vpnc-script disconnect.
    os.kill(pid, signal.SIGINT)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not os.path.exists(f"/proc/{pid}"):
            return
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)


def down():
    stop(running_pid())
    for path in (PID_FILE, INFO_FILE, ROUTES_FILE):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    return {"ok": True}


def split_environment(environ, routes):
    """vpnc-script environment with the gateway's IPv4 split includes replaced."""
    env = dict(environ)
    if not routes:
        return env  # no networks configured: the gateway's routes (full tunnel)
    for key in list(env):
        if key == "CISCO_SPLIT_INC" or key.startswith("CISCO_SPLIT_INC_"):
            del env[key]
    env["CISCO_SPLIT_INC"] = str(len(routes))
    for index, (address, mask, length) in enumerate(routes):
        prefix = f"CISCO_SPLIT_INC_{index}_"
        env.update({prefix + "ADDR": address, prefix + "MASK": mask,
                    prefix + "MASKLEN": str(length), prefix + "PROTOCOL": "0",
                    prefix + "SPORT": "0", prefix + "DPORT": "0"})
    return env


def script():
    try:
        with open(ROUTES_FILE) as handle:
            routes = parse_routes(json.load(handle))
    except (OSError, ValueError, HelperError):
        routes = []
    env = split_environment(os.environ, routes)
    reason = env.get("reason", "")
    if reason == "connect":
        info = {"device": env.get("TUNDEV", ""), "domain": env.get("CISCO_DEF_DOMAIN", ""),
                "dns": env.get("INTERNAL_IP4_DNS", "").split(), "address": env.get("INTERNAL_IP4_ADDRESS", "")}
        temporary = INFO_FILE + ".tmp"
        with open(temporary, "w") as handle:
            json.dump(info, handle)
        os.chmod(temporary, 0o644)
        os.replace(temporary, INFO_FILE)
    elif reason == "disconnect":
        try:
            os.remove(INFO_FILE)
        except FileNotFoundError:
            pass
    os.execve(VPNC_SCRIPT, [VPNC_SCRIPT], env)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("up", "down", "script"):
        print("usage: omarchy-cisco-vpn-tunnel up|down|script", file=sys.stderr)
        return 2
    if sys.argv[1] == "script":
        script()
        return 1  # execve failed
    if os.geteuid() != 0:
        print(json.dumps({"ok": False, "error": "The tunnel helper must run as root"}))
        return 1
    try:
        print(json.dumps(up() if sys.argv[1] == "up" else down()))
        return 0
    except (HelperError, OSError) as error:
        message = str(error) if isinstance(error, HelperError) else "Tunnel helper failed"
        print(json.dumps({"ok": False, "error": message}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
