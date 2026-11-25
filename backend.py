#!/usr/bin/env python3
"""Local Cisco VPN bridge: OpenConnect login as the user, tunnel via a root helper.

The login (openconnect --authenticate) runs as the user. The tunnel itself is
started by the root-owned tunnel helper (tunnel-helper.py, run through pkexec):
openconnect with the stock vpnc-script, so routes and DNS behave exactly like
running openconnect in a terminal.
"""

import collections
import ipaddress
import json
import os
import re
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit


PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
# Root-owned copy of tunnel-helper.py, installed once by install-helper.sh.
TUNNEL_HELPER = "/usr/local/libexec/omarchy-cisco-vpn-tunnel"
TUNNEL_HELPER_SOURCE = os.path.join(PLUGIN_DIR, "tunnel-helper.py")
TUNNEL_RUN_DIR = "/run/omarchy-cisco-vpn"
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_PAC_BYTES = 1024 * 1024
# Empty answers sent to extra prompts after the password (some gateways show a
# form that only needs Enter). EOF after these makes openconnect give up.
BLANK_RESPONSES = 3
PROXY_SCHEMES = ("http", "socks", "socks5")
HOST_PORT = re.compile(r"^\[?[A-Za-z0-9.:\-]+\]?:\d{1,5}$")
FORWARDER_URL = "http://127.0.0.1:3128"
PROXY_ENV_NAMES = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")
NO_PROXY_VALUE = "localhost,127.0.0.1,::1"
SETTINGS_DEFAULTS = {"corporateProxy": "", "proxyLogin": "", "useVpnPassword": True,
                     "appsProxy": False, "trustedCertificates": {}, "ignoreCertificates": [],
                     "versionString": "", "localHostname": "", "noXmlPost": False,
                     "splitRoutes": "", "reportedOs": "", "server": "", "username": "",
                     "gatewayProxy": ""}
# openconnect --os values; "" keeps openconnect's default (linux-64).
REPORTED_OS = ("", "linux", "linux-64", "win", "mac-intel", "android", "apple-ios")
# Split tunnel: at most this many networks (vpn-slice style "only these subnets").
MAX_SPLIT_ROUTES = 64
VERSION_STRING = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
LOCAL_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
FINGERPRINT = re.compile(r"^(?:pin-sha256:[A-Za-z0-9+/]{43}=|sha256:[0-9a-fA-F]{64}|sha1:[0-9a-fA-F]{40})$")
# Printed by openconnect for an untrusted certificate ("--servercert pin-sha256:...")
# and for a pinned one that no longer matches ("...match server's certificate: pin-sha256:...").
SERVERCERT_HINT = re.compile(r"(?:--servercert[ =]+|match server's certificate:\s*)"
                             r"((?:pin-sha256|sha256|sha1):[A-Za-z0-9+/=]+)")


class VpnError(Exception):
    pass


class VpnCancelled(VpnError):
    pass


class MoreInputRequired(VpnError):
    """The gateway showed another form after the password (non-interactive mode stopped)."""


class CertificateUntrusted(VpnError):
    """The gateway's certificate failed verification; carries what the UI may pin."""

    def __init__(self, message, host, fingerprint, reason, changed):
        super().__init__(message)
        self.details = {"host": host, "fingerprint": fingerprint, "reason": reason,
                        "changed": changed}


active_child = None
active_cancellable = False
cancel_requested = False


def cancel(_signal, _frame):
    """Record the cancel and stop a cancellable child; never raise here.

    Raising from a signal handler could interrupt cleanup code (bringing the
    tunnel down, clearing secrets). run() and check_cancelled() raise instead.
    """
    global cancel_requested
    cancel_requested = True
    child = active_child
    if child is not None and active_cancellable and child.poll() is None:
        child.terminate()


signal.signal(signal.SIGTERM, cancel)


def check_cancelled():
    if cancel_requested:
        raise VpnCancelled("Connection cancelled")


def run(args, *, input=None, timeout=100, cancellable=True):
    global active_child, active_cancellable
    try:
        with subprocess.Popen(
            args, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as child:
            active_child = child
            active_cancellable = cancellable
            try:
                if cancellable and cancel_requested:
                    child.terminate()
                output = {child.stdout: [], child.stderr: []}
                total = 0
                deadline = time.monotonic() + timeout
                kill_at = None
                pending = memoryview(input.encode() if input is not None else b"")
                with selectors.DefaultSelector() as selector:
                    for stream in output:
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ)
                    if input is not None:
                        os.set_blocking(child.stdin.fileno(), False)
                        if pending:
                            selector.register(child.stdin, selectors.EVENT_WRITE)
                        else:
                            child.stdin.close()
                    while selector.get_map():
                        if cancellable and cancel_requested and kill_at is None:
                            kill_at = time.monotonic() + 2
                        now = time.monotonic()
                        if kill_at is not None and now >= kill_at:
                            child.kill()
                            child.wait()
                            raise VpnCancelled("Connection cancelled")
                        remaining = min(deadline, kill_at or deadline) - now
                        if remaining <= 0:
                            child.kill()
                            child.wait()
                            raise VpnError(f"{args[0]} timed out")
                        for key, _ in selector.select(min(remaining, 0.25)):
                            stream = key.fileobj
                            if stream is child.stdin:
                                try:
                                    count = os.write(stream.fileno(), pending[:65536])
                                except BrokenPipeError:
                                    count = len(pending)
                                pending = pending[count:]
                                if not pending:
                                    selector.unregister(stream)
                                    stream.close()
                            else:
                                chunk = os.read(stream.fileno(), 65536)
                                if not chunk:
                                    selector.unregister(stream)
                                else:
                                    total += len(chunk)
                                    if total > MAX_OUTPUT_BYTES:
                                        child.kill()
                                        child.wait()
                                        raise VpnError(f"{args[0]} produced too much output")
                                    output[stream].append(chunk)
                try:
                    child.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    child.kill()
                    child.wait()
                    raise VpnError(f"{args[0]} timed out") from error
                if cancellable and cancel_requested:
                    raise VpnCancelled("Connection cancelled")
                return subprocess.CompletedProcess(
                    args, child.returncode,
                    b"".join(output[child.stdout]).decode(errors="replace"),
                    b"".join(output[child.stderr]).decode(errors="replace"),
                )
            finally:
                active_child = None
                active_cancellable = False
    except OSError as error:
        raise VpnError(f"Could not start {args[0]}: {error.strerror}") from error


def tunnel_pid():
    """PID of the tunnel's openconnect (started by the helper), or 0."""
    try:
        with open(os.path.join(TUNNEL_RUN_DIR, "openconnect.pid")) as handle:
            pid = int(handle.read().strip())
        with open(f"/proc/{pid}/comm") as handle:
            return pid if handle.read().strip() == "openconnect" else 0
    except (OSError, ValueError):
        return 0


def tunnel_info():
    """Tunnel device, VPN domain and DNS recorded by the helper's vpnc-script wrapper."""
    try:
        with open(os.path.join(TUNNEL_RUN_DIR, "info.json")) as handle:
            info = json.load(handle)
    except (OSError, ValueError):
        return {}
    return info if isinstance(info, dict) else {}


def helper_state():
    """missing / outdated / installed: the root-owned helper against this plugin's copy."""
    try:
        with open(TUNNEL_HELPER, "rb") as installed:
            current = installed.read()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "outdated"
    try:
        with open(TUNNEL_HELPER_SOURCE, "rb") as source:
            return "installed" if source.read() == current else "outdated"
    except OSError:
        return "installed"


def state():
    settings = load_settings()
    connected = bool(tunnel_pid())
    info = tunnel_info() if connected else {}
    return {
        "settings": settings,
        "connected": connected,
        "server": settings["server"],
        "username": settings["username"],
        "proxy": settings["gatewayProxy"],
        "certificatePinned": pinned_for(settings["server"]),
        "certificateIgnored": ignored_for(settings["server"]),
        "tunnelHelper": helper_state(),
        "vpnDevice": str(info.get("device", "")),
        "vpnAddress": str(info.get("address", "")),
    }


def ignored_for(address):
    try:
        return bool(address) and ignores_certificate(address)
    except VpnError:
        return False


def pinned_for(address):
    try:
        return bool(address) and bool(trusted_certificate(address))
    except VpnError:
        return False


def server_url(value):
    value = value.strip()
    if not value or any(char.isspace() for char in value):
        raise VpnError("Enter a VPN server address without spaces")
    address = value if "://" in value else "https://" + value
    parsed = urlsplit(address)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise VpnError("Enter a valid HTTPS VPN server address")
    try:
        parsed.port
    except ValueError as error:
        raise VpnError("Invalid VPN server port") from error
    return address


def proxy_url(value):
    """Validate a proxy for reaching the VPN gateway; return scheme://host:port."""
    value = value.strip()
    if not value or any(char.isspace() for char in value) or "," in value:
        raise VpnError("Enter a proxy address like http://proxy.example.com:8080")
    address = value if "://" in value else "http://" + value
    parsed = urlsplit(address)
    if parsed.username or parsed.password:
        raise VpnError("Proxy logins are not supported for reaching the VPN server: "
                       "NetworkManager would store them where other local users can read them")
    if parsed.scheme not in PROXY_SCHEMES:
        raise VpnError("Proxy must start with http://, socks:// or socks5://")
    try:
        port = parsed.port
    except ValueError as error:
        raise VpnError("Invalid proxy port") from error
    if not parsed.hostname or not port or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise VpnError("Enter a proxy address with a host and port, like http://proxy.example.com:8080")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}:{port}"


def environment_proxy(environ=None):
    environ = os.environ if environ is None else environ
    for name in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY"):
        value = environ.get(name, "").strip()
        # Skip this widget's own loopback forwarder: NetworkManager's tunnel
        # runs as another user and the forwarder only serves this user.
        if value and value.rstrip("/") != FORWARDER_URL:
            return proxy_url(value)
    raise VpnError("No proxy is set in the environment (https_proxy or http_proxy)")


def resolve_proxy(mode, url):
    if mode in ("", "off"):
        return ""
    if mode == "manual":
        return proxy_url(url)
    if mode == "env":
        return environment_proxy()
    raise VpnError("Unknown proxy mode")


def settings_path():
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "omarchy", "settings", "cisco-vpn.json")


def env_file_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "environment.d", "90-omarchy-cisco-vpn-proxy.conf")


def corporate_proxy(value):
    value = value.strip().removeprefix("http://").rstrip("/")
    if value and not HOST_PORT.fullmatch(value):
        raise VpnError("Enter the corporate proxy as host:port")
    return value


def load_settings():
    settings = dict(SETTINGS_DEFAULTS)
    try:
        with open(settings_path()) as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        return settings
    if isinstance(stored, dict):
        for key, default in SETTINGS_DEFAULTS.items():
            if isinstance(stored.get(key), type(default)):
                settings[key] = stored[key]
    settings["trustedCertificates"] = {
        host: pin for host, pin in settings["trustedCertificates"].items()
        if isinstance(host, str) and isinstance(pin, str) and FINGERPRINT.fullmatch(pin)
    }
    settings["ignoreCertificates"] = [
        host for host in settings["ignoreCertificates"] if isinstance(host, str)]
    return settings


def write_private(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
    os.replace(temporary, path)


def version_string(value):
    value = str(value).strip()
    if value and not VERSION_STRING.fullmatch(value):
        raise VpnError("Client version may contain only letters, digits, '.', '_' and '-', "
                       "for example 5.1.15.287")
    return value


def local_hostname(value):
    value = str(value).strip()
    if value and (not LOCAL_HOSTNAME.fullmatch(value) or ".." in value):
        raise VpnError("Hostname may contain only letters, digits, '.' and '-'")
    return value


def split_routes(value):
    """Parse "10.0.0.0/8, 172.16.0.0/16" into networks; empty means full tunnel."""
    networks = []
    for part in re.split(r"[\s,;]+", str(value).strip()):
        if not part:
            continue
        try:
            network = ipaddress.IPv4Network(part, strict=False)
        except ValueError as error:
            raise VpnError(f"Invalid network '{part[:50]}'; use IPv4 CIDR like 10.0.0.0/8") from error
        if network.prefixlen == 0:
            raise VpnError("0.0.0.0/0 sends all traffic; leave the field empty for a full tunnel")
        if network not in networks:
            networks.append(network)
    if len(networks) > MAX_SPLIT_ROUTES:
        raise VpnError(f"Enter at most {MAX_SPLIT_ROUTES} networks")
    return networks


def save_settings(changes):
    settings = load_settings()
    if "server" in changes:
        settings["server"] = server_url(str(changes["server"])) if changes["server"] else ""
    if "username" in changes:
        username = str(changes["username"]).strip()
        if any(char in username for char in "\r\n"):
            raise VpnError("Enter a valid username")
        settings["username"] = username
    if "gatewayProxy" in changes:
        settings["gatewayProxy"] = proxy_url(changes["gatewayProxy"]) if changes["gatewayProxy"] else ""
    if "reportedOs" in changes:
        if changes["reportedOs"] not in REPORTED_OS:
            raise VpnError("Unknown operating system to report")
        settings["reportedOs"] = changes["reportedOs"]
    if "noXmlPost" in changes:
        settings["noXmlPost"] = changes["noXmlPost"] is True
    if "splitRoutes" in changes:
        settings["splitRoutes"] = ", ".join(str(n) for n in split_routes(changes["splitRoutes"]))
    if "versionString" in changes:
        settings["versionString"] = version_string(changes["versionString"])
    if "localHostname" in changes:
        settings["localHostname"] = local_hostname(changes["localHostname"])
    if "corporateProxy" in changes:
        settings["corporateProxy"] = corporate_proxy(str(changes["corporateProxy"]))
    if "proxyLogin" in changes:
        login = str(changes["proxyLogin"]).strip()
        if any(char in login for char in "\r\n:"):
            raise VpnError("The proxy login cannot contain ':' or line breaks")
        settings["proxyLogin"] = login
    if "useVpnPassword" in changes:
        settings["useVpnPassword"] = changes["useVpnPassword"] is True
    if "appsProxy" in changes:
        settings["appsProxy"] = changes["appsProxy"] is True
    if "trustedCertificates" in changes:
        settings["trustedCertificates"] = changes["trustedCertificates"]
    if "ignoreCertificates" in changes:
        settings["ignoreCertificates"] = changes["ignoreCertificates"]
    write_private(settings_path(), json.dumps(settings, indent=2) + "\n")
    return settings


def set_apps_proxy(enable):
    """Point new apps at the loopback forwarder (no credentials in the environment)."""
    path = env_file_path()
    values = {name: FORWARDER_URL for name in PROXY_ENV_NAMES}
    values.update(no_proxy=NO_PROXY_VALUE, NO_PROXY=NO_PROXY_VALUE)
    if enable:
        write_private(path, "# Written by the Omarchy Cisco VPN widget; remove it in the widget.\n"
                      + "".join(f"{name}={value}\n" for name, value in values.items()))
        command = ["systemctl", "--user", "set-environment",
                   *(f"{name}={value}" for name, value in values.items())]
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        command = ["systemctl", "--user", "unset-environment", *values]
    result = run(command, timeout=10, cancellable=False)
    settings = save_settings({"appsProxy": enable})
    if result.returncode:
        raise VpnError("Saved, but the running session was not updated; log out and back in")
    return settings


def certificate_host(address):
    """Key for a pinned certificate: lowercase host and port of the gateway."""
    parsed = urlsplit(server_url(address))
    return f"{parsed.hostname.lower()}:{parsed.port or 443}"


def trusted_certificate(address):
    return load_settings().get("trustedCertificates", {}).get(certificate_host(address), "")


def trust_certificate(request):
    host = certificate_host(str(request.get("server", "")))
    fingerprint = str(request.get("fingerprint", ""))
    if not FINGERPRINT.fullmatch(fingerprint):
        raise VpnError("Invalid certificate fingerprint")
    pins = dict(load_settings()["trustedCertificates"])
    pins[host] = fingerprint
    return save_settings({"trustedCertificates": pins})


def ignores_certificate(address):
    return certificate_host(address) in load_settings().get("ignoreCertificates", [])


def ignore_certificate(request):
    """Accept any certificate from this one server (no impersonation protection)."""
    host = certificate_host(str(request.get("server", "")))
    hosts = [h for h in load_settings()["ignoreCertificates"] if h != host] + [host]
    return save_settings({"ignoreCertificates": hosts})


def forget_certificate(request):
    host = certificate_host(str(request.get("server", "")))
    settings = load_settings()
    pins = dict(settings["trustedCertificates"])
    pins.pop(host, None)
    hosts = [h for h in settings["ignoreCertificates"] if h != host]
    return save_settings({"trustedCertificates": pins, "ignoreCertificates": hosts})


def authenticate_server(address, username, password, proxy):
    """Authenticate with the saved certificate policy and client identity."""
    settings = load_settings()
    identity = {"version": settings.get("versionString", ""),
                "hostname": settings.get("localHostname", ""),
                "no_xmlpost": settings.get("noXmlPost", False),
                "reported_os": settings.get("reportedOs", "")}

    def attempt(servercert):
        try:
            return authenticate(address, username, password, proxy, servercert, **identity)
        except MoreInputRequired:
            # The certificate already passed in the first attempt, so answering
            # prompts is safe now: only form fields can read the blank lines.
            check_cancelled()
            return authenticate(address, username, password, proxy, servercert,
                                blank_responses=BLANK_RESPONSES, **identity)

    if ignores_certificate(address):
        try:
            return attempt("")
        except CertificateUntrusted as untrusted:
            # Ignore mode: accept whatever certificate the server presented.
            return attempt(untrusted.details["fingerprint"])
    return attempt(trusted_certificate(address))


def certificate_failure(stderr, address):
    """Return CertificateUntrusted when stderr shows a pinnable verification failure."""
    match = SERVERCERT_HINT.search(stderr)
    if not match or not FINGERPRINT.fullmatch(match.group(1)):
        return None
    reason = ""
    reason_match = re.search(r"^Reason:\s*(.{1,200})$", stderr, re.MULTILINE)
    if reason_match:
        reason = re.sub(r"[^\w .,:;()'/-]", "", reason_match.group(1)).strip()
    changed = "none of the" in stderr.lower() and "--servercert" in stderr.lower()
    if changed:
        message = ("WARNING: the VPN server's certificate CHANGED since you trusted it. "
                   "This can mean someone is intercepting the connection; ask your IT team "
                   "before trusting the new one")
    else:
        message = "The VPN server's certificate is not trusted by this computer"
        if reason:
            message += f" ({reason})"
    return CertificateUntrusted(message, certificate_host(address), match.group(1), reason, changed)


def authentication_error(stderr):
    details = stderr.lower()
    if "proxy" in details:
        if any(term in details for term in ("parse proxy", "unknown proxy type")):
            return "The proxy address is invalid"
        if any(term in details for term in ("407", "authentication", "basic")):
            return "The proxy requires a login, which is not supported for reaching the VPN server"
        return "Could not connect through the proxy; check the proxy address"
    # With a pinned certificate openconnect still logs "Server certificate verify
    # failed" before accepting the pin, so only blame the certificate when the
    # TLS connection never came up.
    tls_up = "connected to https" in details
    if not tls_up and any(term in details for term in ("certificate", "servercert", "issuer", "trust anchor")):
        return "VPN server certificate could not be verified; check with your IT team"
    if any(term in details for term in ("resolve", "getaddrinfo", "name or service not known")):
        return "VPN server name could not be resolved"
    if any(term in details for term in ("failed to connect", "connection refused", "network is unreachable")):
        return "Could not reach the VPN server; check the address and network"
    if any(term in details for term in ("authgroup", "non-interactive", "form entry", "token", "challenge")):
        return ("VPN asked for more sign-in input. If your gateway requires a specific client "
                "version or hostname, fill in Client version / Hostname; otherwise it needs a "
                "group or token step this widget does not support")
    if any(term in details for term in ("login failed", "authentication failed", "invalid credentials", "incorrect password")):
        return "VPN rejected the credentials; check your username and password"
    return "OpenConnect authentication failed; the gateway may require another login step"


def authenticate(address, username, password, proxy="", servercert="", version="", hostname="",
                 blank_responses=0, no_xmlpost=False, reported_os=""):
    proxy_args = ["--proxy", proxy] if proxy else ["--no-proxy"]
    # --servercert accepts only this exact certificate (it implies --no-system-trust).
    cert_args = ["--servercert", servercert] if servercert else []
    # Some gateways only accept known AnyConnect client versions / hostnames.
    identity_args = []
    if version:
        identity_args.append(f"--version-string={version_string(version)}")
    if hostname:
        identity_args.append(f"--local-hostname={local_hostname(hostname)}")
    # Some gateways only finish the login with the older (non-XML) form POST.
    if no_xmlpost:
        identity_args.append("--no-xmlpost")
    # Gateways may apply a different policy (or refuse) depending on the OS.
    if reported_os:
        if reported_os not in REPORTED_OS:
            raise VpnError("Unknown operating system to report")
        identity_args.append(f"--os={reported_os}")
    # Normally --non-inter: any unexpected prompt (including a certificate
    # question) fails instead of reading stdin. With blank_responses, extra
    # form prompts after the password are answered with an empty line.
    mode_args = [] if blank_responses else ["--non-inter"]
    result = run(
        ["openconnect", "--protocol=anyconnect", "--authenticate", *proxy_args, *cert_args,
         *identity_args, *mode_args, "--passwd-on-stdin", "--user", username, address],
        input=password + "\n" + "\n" * blank_responses, timeout=90,
    )
    if result.returncode:
        untrusted = certificate_failure(result.stderr, address)
        if untrusted is not None:
            raise untrusted
        if not blank_responses and "user input required in non-interactive mode" in result.stderr.lower():
            raise MoreInputRequired(authentication_error(result.stderr))
        raise VpnError(authentication_error(result.stderr))

    values = {}
    for line in result.stdout.splitlines():
        key, separator, raw = line.partition("=")
        if not separator or key not in ("COOKIE", "CONNECT_URL", "FINGERPRINT", "RESOLVE"):
            continue
        try:
            parts = shlex.split(raw)
        except ValueError as error:
            raise VpnError("OpenConnect returned malformed authentication data") from error
        if len(parts) != 1 or "\n" in parts[0] or "\r" in parts[0]:
            raise VpnError("OpenConnect returned malformed authentication data")
        values[key] = parts[0]
    if not all(values.get(key) for key in ("COOKIE", "CONNECT_URL", "FINGERPRINT")):
        raise VpnError("OpenConnect did not return the gateway, cookie, and certificate fingerprint")
    if proxy:
        # Through a proxy the gateway name is resolved by the proxy; pinning a
        # locally resolved address for the tunnel stage would bypass that.
        values.pop("RESOLVE", None)
    return values


# --- Tunnel (root helper: openconnect + vpnc-script) -------------------------

def run_helper(action, request=None, timeout=90):
    """Run the tunnel helper through pkexec and return its JSON reply."""
    if helper_state() == "missing":
        raise VpnError("Install the VPN helper first (one-time administrator step)")
    # Not cancellable: killing pkexec mid-way could leave a half-started tunnel;
    # a cancel during "up" is handled by bringing the tunnel down afterwards.
    result = run(["pkexec", TUNNEL_HELPER, action],
                 input=json.dumps(request) if request is not None else None,
                 timeout=timeout, cancellable=False)
    if result.returncode in (126, 127) and not result.stdout.strip():
        raise VpnError("Administrator authorization for the VPN helper was refused; "
                       "reinstall the VPN helper")
    try:
        reply = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as error:
        raise VpnError("The VPN helper returned an invalid response") from error
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        message = reply.get("error") if isinstance(reply, dict) else ""
        raise VpnError(str(message or "The VPN helper failed"))
    return reply


def tunnel_up(values, settings, networks, proxy):
    request = {
        "url": values["CONNECT_URL"],
        "cookie": values["COOKIE"],
        "fingerprint": values["FINGERPRINT"],
        "resolve": values.get("RESOLVE", ""),
        "proxy": proxy,
        "version": settings.get("versionString", ""),
        "hostname": settings.get("localHostname", ""),
        "os": settings.get("reportedOs", ""),
        "routes": [str(network) for network in networks],
    }
    run_helper("up", request)
    if cancel_requested:
        run_helper("down")
        raise VpnCancelled("Connection cancelled")


def tunnel_down():
    run_helper("down", timeout=30)


# --- Corporate proxy inside the tunnel -------------------------------------

def vpn_domains():
    domains = []
    for part in str(tunnel_info().get("domain", "")).split():
        domain = part.strip().strip(".").lower()
        if domain and re.fullmatch(r"[a-z0-9.\-]+", domain) and domain not in domains:
            domains.append(domain)
    return domains


def wpad_candidates(domains):
    hosts = []
    for domain in domains:
        labels = domain.split(".")
        for start in range(len(labels) - 1):
            host = "wpad." + ".".join(labels[start:])
            if host not in hosts:
                hosts.append(host)
    return hosts


def pac_proxy(script):
    """Pick the most used PROXY host:port from a PAC script."""
    found = re.findall(r"PROXY\s+([A-Za-z0-9.\-]+:\d{1,5})", script)
    return collections.Counter(found).most_common(1)[0][0] if found else ""


def fetch_pac(url, timeout=3):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as response:
        body = response.read(MAX_PAC_BYTES + 1)
    if len(body) > MAX_PAC_BYTES:
        raise VpnError("PAC file is too large")
    return body.decode(errors="replace")


def discover_proxy():
    for host in wpad_candidates(vpn_domains()):
        try:
            proxy = pac_proxy(fetch_pac(f"http://{host}/wpad.dat"))
        except (OSError, VpnError, ValueError):
            continue
        if proxy:
            return proxy, host
    return "", ""


def probe_proxy(proxy, target="www.example.com:443", timeout=5):
    """Send one unauthenticated CONNECT and report what the proxy asks for."""
    host, _, port = proxy.rpartition(":")
    host = host.strip("[]")
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    lines = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace").split("\r\n")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if not match:
        raise VpnError("The corporate proxy returned an unexpected response")
    schemes = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "proxy-authenticate":
            scheme = value.strip().split(" ", 1)[0]
            if scheme and scheme not in schemes:
                schemes.append(scheme)
    return {"status": int(match.group(1)), "schemes": schemes}


def proxy_check(request):
    if not tunnel_pid():
        raise VpnError("Connect the VPN before checking the corporate proxy")
    proxy = corporate_proxy(str(request.get("proxy", "")))
    source = "manual"
    if not proxy:
        proxy, source = discover_proxy()
        if not proxy:
            raise VpnError("No corporate proxy found automatically; enter it as host:port")
    try:
        result = probe_proxy(proxy)
    except OSError as error:
        raise VpnError(f"Could not reach the corporate proxy {proxy}") from error
    return {"proxy": proxy, "source": source, **result}


def read_request():
    request = json.loads(sys.stdin.readline())
    if not isinstance(request, dict):
        raise VpnError("Invalid request")
    return request


def main():
    actions = ("status", "connect", "disconnect", "proxy-check", "save-settings",
               "apps-proxy-on", "apps-proxy-off", "trust-certificate", "ignore-certificate",
               "forget-certificate")
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        raise VpnError("Expected one of: " + ", ".join(actions))
    action = sys.argv[1]
    if action == "save-settings":
        request = read_request()
        request.pop("trustedCertificates", None)  # only via the certificate actions
        request.pop("ignoreCertificates", None)
        return {"settings": save_settings(request)}
    if action == "trust-certificate":
        return {"settings": trust_certificate(read_request())}
    if action == "ignore-certificate":
        return {"settings": ignore_certificate(read_request())}
    if action == "forget-certificate":
        return {"settings": forget_certificate(read_request())}
    if action in ("apps-proxy-on", "apps-proxy-off"):
        return {"settings": set_apps_proxy(action == "apps-proxy-on")}
    if action == "proxy-check":
        return {"proxyCheck": proxy_check(read_request())}
    if action == "connect":
        request = read_request()
        address = server_url(request.get("server", ""))
        username = request.get("username", "").strip()
        password = request.get("password", "")
        if (not username or not password
                or any(char in value for value in (username, password) for char in "\r\n")):
            raise VpnError("Enter a username and password")
        proxy = resolve_proxy(request.get("proxyMode", "off"), request.get("proxyUrl", ""))
        options = {key: request[key] for key in
                   ("versionString", "localHostname", "noXmlPost", "splitRoutes", "reportedOs")
                   if key in request}
        if tunnel_pid():
            raise VpnError("The VPN is already connected")
        if helper_state() == "missing":
            raise VpnError("Install the VPN helper first (one-time administrator step)")
        # Validated and remembered for the next connect.
        settings = save_settings({**options, "server": address, "username": username,
                                  "gatewayProxy": proxy})
        networks = split_routes(settings["splitRoutes"])
        check_cancelled()
        values = authenticate_server(address, username, password, proxy)
        check_cancelled()
        tunnel_up(values, settings, networks, proxy)
    elif action == "disconnect":
        if not tunnel_pid():
            raise VpnError("The VPN is not connected")
        tunnel_down()
    return state()


if __name__ == "__main__":
    try:
        print(json.dumps({"ok": True, **main()}))
    except CertificateUntrusted as error:
        print(json.dumps({"ok": False, "error": str(error), "certificate": error.details}))
        sys.exit(1)
    except (VpnError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        sys.exit(1)
