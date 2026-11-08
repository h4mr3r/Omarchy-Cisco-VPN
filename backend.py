#!/usr/bin/env python3
"""Local Cisco VPN bridge: OpenConnect authentication, NetworkManager tunnel."""

import collections
import json
import os
import pwd
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

import gi

gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM


PROFILE = "Omarchy Cisco VPN"
SERVICE = "org.freedesktop.NetworkManager.openconnect"
UUID = re.compile(r"^[0-9a-fA-F-]{36}$")
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_PAC_BYTES = 1024 * 1024
PROXY_SCHEMES = ("http", "socks", "socks5")
HOST_PORT = re.compile(r"^\[?[A-Za-z0-9.:\-]+\]?:\d{1,5}$")
FORWARDER_URL = "http://127.0.0.1:3128"
PROXY_ENV_NAMES = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")
NO_PROXY_VALUE = "localhost,127.0.0.1,::1"
SETTINGS_DEFAULTS = {"corporateProxy": "", "proxyLogin": "", "useVpnPassword": True,
                     "appsProxy": False, "trustedCertificates": {}, "ignoreCertificates": []}
FINGERPRINT = re.compile(r"^(?:pin-sha256:[A-Za-z0-9+/]{43}=|sha256:[0-9a-fA-F]{64}|sha1:[0-9a-fA-F]{40})$")
# Printed by openconnect for an untrusted certificate ("--servercert pin-sha256:...")
# and for a pinned one that no longer matches ("...match server's certificate: pin-sha256:...").
SERVERCERT_HINT = re.compile(r"(?:--servercert[ =]+|match server's certificate:\s*)"
                             r"((?:pin-sha256|sha256|sha1):[A-Za-z0-9+/=]+)")
NM_BUS = "org.freedesktop.NetworkManager"
NM_SETTINGS = "/org/freedesktop/NetworkManager/Settings"


class VpnError(Exception):
    pass


class VpnCancelled(VpnError):
    pass


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


def nmcli(*args, cancellable=True):
    result = run(["nmcli", *args], cancellable=cancellable)
    if result.returncode:
        raise VpnError(f"NetworkManager command failed: {result.stderr.strip()}")
    return result.stdout.strip()


def system_bus():
    return Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


def profile_settings(uuid):
    """Read a profile's non-secret settings over D-Bus without loading NM.Client."""
    bus = system_bus()
    path = bus.call_sync(
        NM_BUS, NM_SETTINGS, "org.freedesktop.NetworkManager.Settings",
        "GetConnectionByUuid", GLib.Variant("(s)", (uuid,)), GLib.VariantType("(o)"),
        Gio.DBusCallFlags.NONE, 10000, None,
    ).unpack()[0]
    return bus.call_sync(
        NM_BUS, path, "org.freedesktop.NetworkManager.Settings.Connection",
        "GetSettings", None, GLib.VariantType("(a{sa{sv}})"),
        Gio.DBusCallFlags.NONE, 10000, None,
    ).unpack()[0]


def profile_uuid():
    profiles = nmcli("-t", "--escape", "no", "-f", "UUID,TYPE,NAME", "connection", "show")
    matches = []
    for line in profiles.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[2] == PROFILE:
            matches.append((parts[0], parts[1]))
    if not matches:
        return ""
    if len(matches) != 1 or matches[0][1] != "vpn" or not UUID.fullmatch(matches[0][0]):
        raise VpnError(f"Conflicting NetworkManager profile named {PROFILE}")
    uuid = matches[0][0]
    if profile_settings(uuid).get("vpn", {}).get("service-type") != SERVICE:
        raise VpnError(f"Conflicting NetworkManager profile named {PROFILE}")
    return uuid


def is_active(uuid):
    return uuid in nmcli("-t", "-f", "UUID", "connection", "show", "--active",
                         cancellable=False).splitlines()


def state():
    uuid = profile_uuid()
    if not uuid:
        return {"connected": False, "server": "", "username": "", "proxy": "",
                "certificatePinned": False, "certificateIgnored": False,
                "settings": load_settings()}
    vpn = profile_settings(uuid).get("vpn")
    if vpn is None:
        raise VpnError("NetworkManager could not read the VPN profile")
    data = vpn.get("data", {})
    return {
        "settings": load_settings(),
        "connected": is_active(uuid),
        "server": data.get("gateway", ""),
        "username": vpn.get("user-name", ""),
        "proxy": data.get("proxy", ""),
        "certificatePinned": pinned_for(data.get("gateway", "")),
        "certificateIgnored": ignored_for(data.get("gateway", "")),
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


def save_settings(changes):
    settings = load_settings()
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


def current_user():
    return pwd.getpwuid(os.getuid()).pw_name


def ensure_profile(address, username, proxy):
    uuid = profile_uuid()
    if not uuid:
        nmcli("connection", "add", "type", "vpn", "vpn-type", "openconnect",
              "ifname", "*", "con-name", PROFILE, "autoconnect", "no",
              "--", "connection.permissions", f"user:{current_user()}",
              "vpn.data", "protocol=anyconnect")
        uuid = profile_uuid()
        if not uuid:
            raise VpnError("NetworkManager did not create the VPN profile")
    # Keep the client referenced: a RemoteConnection stops working once its
    # NM.Client is garbage-collected ("Object is no longer in the client cache").
    client = NM.Client.new(None)
    connection = client.get_connection_by_uuid(uuid)
    if connection is None or connection.get_setting_vpn() is None:
        raise VpnError("NetworkManager could not read the VPN profile")
    # Merge only the keys this widget owns; keep anything set elsewhere
    # (for example cacert or useragent from nm-connection-editor).
    vpn = connection.get_setting_vpn()
    vpn.add_data_item("gateway", address)
    vpn.add_data_item("protocol", "anyconnect")
    if proxy:
        vpn.add_data_item("proxy", proxy)
    else:
        vpn.remove_data_item("proxy")
    vpn.set_property("user-name", username)
    setting = connection.get_setting_connection()
    setting.set_property("autoconnect", False)
    if setting.get_num_permissions() == 0:
        setting.add_permission("user", current_user(), None)
    if not connection.commit_changes(True, None):
        raise VpnError("NetworkManager did not save the VPN profile")
    return uuid


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
    """Authenticate with the saved certificate policy for this server."""
    if ignores_certificate(address):
        try:
            return authenticate(address, username, password, proxy)
        except CertificateUntrusted as untrusted:
            # Ignore mode: accept whatever certificate the server presented.
            return authenticate(address, username, password, proxy,
                                untrusted.details["fingerprint"])
    return authenticate(address, username, password, proxy, trusted_certificate(address))


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
        return "VPN requires an additional sign-in step (group or token) not supported by this widget"
    if any(term in details for term in ("login failed", "authentication failed", "invalid credentials", "incorrect password")):
        return "VPN rejected the credentials; check your username and password"
    return "OpenConnect authentication failed; the gateway may require another login step"


def authenticate(address, username, password, proxy="", servercert=""):
    proxy_args = ["--proxy", proxy] if proxy else ["--no-proxy"]
    # --servercert accepts only this exact certificate (it implies --no-system-trust).
    cert_args = ["--servercert", servercert] if servercert else []
    result = run(
        ["openconnect", "--protocol=anyconnect", "--authenticate", *proxy_args, *cert_args,
         "--non-inter", "--passwd-on-stdin", "--user", username, address],
        input=password + "\n", timeout=90,
    )
    if result.returncode:
        untrusted = certificate_failure(result.stderr, address)
        if untrusted is not None:
            raise untrusted
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


def clear_secrets(connection):
    try:
        system_bus().call_sync(
            NM_BUS, connection.get_path(),
            "org.freedesktop.NetworkManager.Settings.Connection", "ClearSecrets",
            None, None, Gio.DBusCallFlags.NONE, 10000, None,
        )
    except GLib.Error as error:
        print(f"Could not clear VPN secrets: {error.message}", file=sys.stderr)


def activate(uuid, values):
    secrets = {
        "cookie": values["COOKIE"],
        "gateway": values["CONNECT_URL"],
        "gwcert": values["FINGERPRINT"],
    }
    if values.get("RESOLVE"):
        secrets["resolve"] = values["RESOLVE"]
    client = NM.Client.new(None)
    connection = client.get_connection_by_uuid(uuid)
    if connection is None:
        raise VpnError("NetworkManager could not find the VPN profile")
    vpn = connection.get_setting_vpn()
    if vpn is None:
        raise VpnError("NetworkManager VPN profile is invalid")
    for key, value in secrets.items():
        vpn.add_secret(key, value)
    try:
        if not connection.commit_changes(False, None):
            raise VpnError("Could not pass VPN credentials to NetworkManager")
        check_cancelled()
        result = run(["nmcli", "--wait", "90", "connection", "up", "uuid", uuid])
        if result.returncode:
            raise VpnError(f"VPN activation failed (NetworkManager exit code {result.returncode})")
    except VpnCancelled:
        if is_active(uuid):
            nmcli("connection", "down", "uuid", uuid, cancellable=False)
        raise
    finally:
        clear_secrets(connection)


# --- Corporate proxy inside the tunnel -------------------------------------

def vpn_domains(uuid):
    text = nmcli("-g", "IP4.DOMAIN,IP6.DOMAIN", "connection", "show", "uuid", uuid)
    domains = []
    for part in re.split(r"[\n|]", text):
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


def discover_proxy(uuid):
    for host in wpad_candidates(vpn_domains(uuid)):
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
    uuid = profile_uuid()
    if not uuid or not is_active(uuid):
        raise VpnError("Connect the VPN before checking the corporate proxy")
    proxy = corporate_proxy(str(request.get("proxy", "")))
    source = "manual"
    if not proxy:
        proxy, source = discover_proxy(uuid)
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
        uuid = ensure_profile(address, username, proxy)
        check_cancelled()
        activate(uuid, authenticate_server(address, username, password, proxy))
    elif action == "disconnect":
        uuid = profile_uuid()
        if not uuid:
            raise VpnError("No Cisco VPN profile exists")
        nmcli("connection", "down", "uuid", uuid)
    return state()


if __name__ == "__main__":
    try:
        print(json.dumps({"ok": True, **main()}))
    except GLib.Error as error:
        # NetworkManager's message names the failing step; it carries no secrets.
        print(json.dumps({"ok": False,
                          "error": f"NetworkManager rejected the VPN operation: {error.message}"}))
        sys.exit(1)
    except CertificateUntrusted as error:
        print(json.dumps({"ok": False, "error": str(error), "certificate": error.details}))
        sys.exit(1)
    except (VpnError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        sys.exit(1)
