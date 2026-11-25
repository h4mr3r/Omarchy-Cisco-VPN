# Omarchy Cisco VPN

A bar widget for connecting to Cisco AnyConnect-compatible VPNs on
[Omarchy](https://omarchy.org/). OpenConnect signs in to the gateway as you,
then a small root helper runs the tunnel with `openconnect` and the stock
`vpnc-script`, exactly as `sudo openconnect …` would in a terminal. A Quickshell
popup shows the status and connect/disconnect controls.

## Install

Install the widget from this repository:

```sh
omarchy plugin add https://github.com/h4mr3r/Omarchy-CISCO-VPN-Plugin.git --enable
```

Click the VPN icon in the right-hand bar section. On first use, if
`openconnect` or `vpnc` (which provides `/etc/vpnc/vpnc-script`) is missing, the widget offers
an **Install packages** button. Click it to authorize the installation through
Omarchy's graphical administrator prompt. The `omarchy plugin add` command
does not install packages itself. If graphical authorization is unavailable,
install the dependencies in a terminal instead:

```sh
omarchy pkg add openconnect vpnc
```

Then open the widget again. The button now reads **Install VPN helper**, a
one-time administrator step (see [The tunnel helper](#the-tunnel-helper)).
After that, enter the HTTPS VPN server, username, and password, then choose
**Connect**. While connecting, use
**Cancel** to stop the attempt. When connected, the button becomes
**Disconnect**. The server can be entered as a hostname or an HTTPS URL.

## Proxies

There are two different proxies to think about:

**Proxy to reach the VPN server.** Only needed when your network can't reach the
gateway directly. Open **Proxy to VPN server** in the popup and choose
**Manual** (`http://host:port`, `socks5://host:port`) or **From environment**
(uses `https_proxy`/`http_proxy` from the shell's environment). The same proxy is
used for the login step and for the tunnel. DTLS is not used through a proxy, so
the tunnel runs over TLS only. Proxy logins are not supported here.

**Corporate proxy inside the VPN.** Many gateways have a proxy (PAC) that
Omarchy apps don't use automatically. When
connected, **Check corporate proxy** finds it through WPAD on the VPN's DNS
domains (or uses the `host:port` you enter). It then reports whether it needs a
login and which method: Basic, NTLM or Negotiate/Kerberos. No credentials are
sent during the check.

If it needs a Basic login (the kind you would otherwise put in
`http_proxy=http://login:password@proxy:80`), enter the proxy login and password
and choose **Sign in to corporate proxy**. A small helper
(`proxy_forwarder.py`) then listens on `127.0.0.1:3128`, adds your login to
requests sent to the corporate proxy, and connects directly while the VPN is
off. The password stays in that process's memory. It is not written to disk or
to the environment. With **Sign in with the VPN password**
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

## Legacy login (`--no-xmlpost`)

Some gateways only complete the sign-in with OpenConnect's older form POST. If
the login fails but `openconnect --no-xmlpost …` works in a terminal, turn on
**Use legacy login (--no-xmlpost)**. It is saved on the next connect and only
affects the login step.

## Split tunnel (only some networks through the VPN)

By default all traffic goes through the VPN, using whatever routes the gateway
pushes. To send only internal networks through it, list them in **Route only
these networks**, separated by commas or spaces, for example
`10.0.0.0/8, 172.16.0.0/16` (IPv4 only, since the tunnel runs with
`--disable-ipv6`). Leave the field empty for a full tunnel again.

The helper does this the way vpnc-script expects split tunnels. Its `--script`
is a small wrapper that replaces the gateway's `CISCO_SPLIT_INC_*` networks with
yours, then runs `/etc/vpnc/vpnc-script` unchanged. vpnc-script then adds a route
for each network and no default route. Your normal internet connection keeps
everything else.

**DNS needs no setup.** vpnc-script sets the VPN's DNS servers and domain on the
tunnel device in systemd-resolved, as it does in a terminal. Internal names
resolve through the corporate DNS, including short names like `host` (expanded
with the VPN's domain) and any other internal domain. You don't list domains.
Make sure the VPN's DNS server is inside one of your networks. The popup shows
the tunnel device and address when connected.

## The tunnel helper

Creating a tunnel device and changing routes and DNS needs root.
**Install VPN helper** runs `install-helper.sh` once through `pkexec`
(administrator authentication). It installs:

- `/usr/local/libexec/omarchy-cisco-vpn-tunnel`: a root-owned copy of
  `tunnel-helper.py`. It accepts only a session cookie, the gateway URL, the
  certificate pin, an optional proxy, the client identity and your networks. It
  validates each one, then starts `openconnect --cookie-on-stdin --background`.
  It never sees your password.
- `/etc/polkit-1/rules.d/49-omarchy-cisco-vpn.rules`: lets your user, and only
  yours, in an active local session, run that helper through `pkexec` without a
  password. Connect and disconnect then don't ask for your password.

The tunnel keeps running if the shell restarts. **Disconnect** sends openconnect
SIGINT, so it logs off the session and vpnc-script restores routes and DNS.
Runtime state (PID, the routes in use, the tunnel device) is kept in
`/run/omarchy-cisco-vpn/`. When the plugin's copy of the helper changes, the
button reads **Update VPN helper**. The installer also removes the
NetworkManager DNS hook used by earlier versions of this widget.

## Remove

Disconnect in the widget first if the VPN is active, then remove the plugin:

```sh
omarchy plugin remove h4mr3r.cisco-vpn
```

If you turned on **Use the corporate proxy in apps**, turn it off before
removing the plugin. Otherwise new apps will keep trying to use
`127.0.0.1:3128`. To clean up by hand, delete
`~/.config/environment.d/90-omarchy-cisco-vpn-proxy.conf` and log out and back in.

Remove the tunnel helper too:

```sh
sudo rm /usr/local/libexec/omarchy-cisco-vpn-tunnel /etc/polkit-1/rules.d/49-omarchy-cisco-vpn.rules
```

Removing the plugin does not disconnect an active VPN or uninstall system
packages. Earlier versions of this widget created a NetworkManager profile named
`Omarchy Cisco VPN`. It is no longer used, and you can delete it with
`nmcli connection delete "Omarchy Cisco VPN"`.

## Credentials and limitations

The server, username, gateway proxy and options are stored in
`~/.local/state/omarchy/settings/cisco-vpn.json` (mode 0600). The password is
sent over stdin to OpenConnect for one authentication attempt, running as you.
It is never saved or passed as a command argument, and the root helper never
receives it. The short-lived session cookie goes over stdin from the widget to
the helper and from the helper to openconnect. It is not written to disk. The
popup does not print raw OpenConnect errors because those may contain sensitive
details. The helper keeps openconnect's log in the root-only file
`/run/omarchy-cisco-vpn/openconnect.log`, which is cleared on reboot. The backend
stops a subprocess if its combined output exceeds 1 MiB. Never commit your VPN
server details, credentials or logs to this repository.

This initial release supports a single Cisco AnyConnect username/password
flow. VPN groups, OTP/MFA prompts, browser SSO and client certificates are not
supported. A successful login depends on your gateway's authentication policy.

## Untrusted server certificates

Certificate validation is never switched off. If the gateway's certificate
isn't trusted by this computer (for example, it is signed by a company CA that
isn't installed), the popup shows the reason and the certificate's
`pin-sha256:` fingerprint, with two choices.

**Ignore certificate errors for this server and connect** accepts whatever
certificate that server (host and port) presents from then on. The widget can
then no longer tell an impostor from your real gateway. Someone who intercepts
your network could pose as the VPN and receive your password. Use it only on
networks you trust. **Stop ignoring** under the form turns it off.

**Trust only this certificate** is the safer choice. Trusting
pins that exact certificate for that server and port only (OpenConnect
`--servercert`). The pin is saved in `~/.local/state/omarchy/settings/cisco-vpn.json`.
Any other certificate, including one an attacker presents, is still refused.
Only trust a fingerprint your IT team confirms. If the server's certificate
later changes, the connection is refused with a warning. You can trust the new
one after checking it. **Forget** under the form removes the pin.

## Development

Run the tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
omarchy plugin validate .
```

The shell loads `Panel.qml` directly from the plugin folder. If the plugin is a
symlink to this repository, the shell's file watcher doesn't see edits, so run
`omarchy restart shell` after changing QML. Backend changes take effect on the
next action. After changing `tunnel-helper.py`, use **Update VPN helper** (or
run `pkexec /bin/sh install-helper.sh`) so the root-owned copy matches.

Licensed under [MIT](LICENSE).
