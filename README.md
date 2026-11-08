# Omarchy Cisco VPN

A bar widget for connecting to Cisco AnyConnect-compatible VPNs on
[Omarchy](https://omarchy.org/). OpenConnect authenticates to the gateway,
NetworkManager manages the tunnel, and a Quickshell popup shows the status and
connect/disconnect controls.

## Install

Install the widget from this repository:

```sh
omarchy plugin add https://github.com/h4mr3r/Omarchy-CISCO-VPN-Plugin.git --enable
```

Click the VPN icon in the right-hand bar section. On first use, if
`networkmanager-openconnect` or `python-gobject` is missing, the widget offers
an **Install packages** button. Click it to authorize the installation through
Omarchy's graphical administrator prompt. The `omarchy plugin add` command
does not install packages itself. If graphical authorization is unavailable,
install the dependencies in a terminal instead:

```sh
omarchy pkg add networkmanager-openconnect python-gobject
```

Then open the widget again. Enter the HTTPS VPN server,
username, and password, then choose **Connect**. While connecting, use
**Cancel** to stop the attempt. When connected, the button becomes
**Disconnect**. The server can be entered as a hostname or an HTTPS URL.

## Proxies

There are two different proxies to think about:

**Proxy to reach the VPN server.** Only needed when your network can't reach the
gateway directly. Open **Proxy to VPN server** in the popup and choose
**Manual** (`http://host:port`, `socks5://host:port`) or **From environment**
(uses `https_proxy`/`http_proxy` from the shell's environment). The same proxy is
used for the login step and is saved in the NetworkManager profile (`vpn.data`
key `proxy`) for the tunnel. DTLS is not used through a proxy, so the tunnel runs
over TLS only. Proxy logins are rejected here. NetworkManager runs the tunnel as
the `nm-openconnect` system user and can only store the proxy as plain profile
data, which other local users can read.

**Corporate proxy inside the VPN.** Many gateways push a proxy (PAC) that
NetworkManager receives but Omarchy apps don't use automatically. When
connected, **Check corporate proxy** finds it through WPAD on the VPN's DNS
domains (or uses the `host:port` you enter). It then reports whether it needs a
login and which method: Basic, NTLM or Negotiate/Kerberos. No credentials are
sent during the check.

If it needs a Basic login (the kind you would otherwise put in
`http_proxy=http://login:password@proxy:80`), enter the proxy login and password
and choose **Sign in to corporate proxy**. A small helper
(`proxy_forwarder.py`) then listens on `127.0.0.1:3128`, adds your login to
requests sent to the corporate proxy, and connects directly while the VPN is
off. The password stays in that process's memory. It is not written to disk, to
NetworkManager, or to the environment. With **Sign in with the VPN password**
on, the next connect signs in to the proxy automatically using the password you
just typed. The helper only serves connections from your own user account.

**Use the corporate proxy in apps** sets `http_proxy`, `https_proxy`,
`HTTP_PROXY`, `HTTPS_PROXY` (to `http://127.0.0.1:3128`) and `no_proxy`/`NO_PROXY`
in the systemd user environment and in
`~/.config/environment.d/90-omarchy-cisco-vpn-proxy.conf`. Apps started after
that (Chromium, terminals, curl, git) use the proxy without a password.
Terminals that are already open keep their old environment. Turn the toggle off
to undo it. NTLM- and Kerberos-only proxies are not supported yet. As with the
`http_proxy` URL, a Basic login reaches the corporate proxy unencrypted, so it
is protected only by the VPN tunnel.


## Remove

Disconnect in the widget first if the VPN is active, then remove the plugin:

```sh
omarchy plugin remove h4mr3r.cisco-vpn
```

If you turned on **Use the corporate proxy in apps**, turn it off before
removing the plugin. Otherwise new apps will keep trying to use
`127.0.0.1:3128`. To clean up by hand, delete
`~/.config/environment.d/90-omarchy-cisco-vpn-proxy.conf` and log out and back in.

Removing the plugin does not disconnect an active VPN, uninstall system
packages, or delete the `Omarchy Cisco VPN` NetworkManager profile. The
profile may also be used by an earlier local version of this widget.

## Credentials and limitations

The server, username and optional gateway proxy are stored in the
NetworkManager profile. Autoconnect is disabled and the profile is restricted
to the user who created it. Other keys in the profile (for example a CA
certificate set in nm-connection-editor) are kept. The password is sent over stdin to OpenConnect for one
authentication attempt and is not saved in the profile or passed as a command
argument. A short-lived session cookie is passed through NetworkManager's
in-memory profile and cleared after the attempt. The popup does not print raw
OpenConnect errors because those may contain sensitive details. The helper
stops a subprocess if its combined output exceeds 1 MiB. Never commit
your VPN server details, credentials, NetworkManager profile, or logs to this
repository.

This initial release supports a single Cisco AnyConnect username/password
flow. VPN groups, OTP/MFA prompts, browser SSO, client certificates, and
custom certificate trust are not supported. Certificate validation is never
disabled. A successful login depends on your gateway's authentication policy.

## Development

Run the backend tests on Arch with `python-gobject` and NetworkManager
installed:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
omarchy plugin validate .
```

The shell loads `Panel.qml` directly from this repository when installed.
Changes to files in an installed plugin trigger an Omarchy shell reload.
For a QML edit that does not take effect after hot-reload, run
`omarchy restart shell`.

Licensed under [MIT](LICENSE).
