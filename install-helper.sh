#!/bin/sh
# Omarchy Cisco VPN: one-time install of the root-owned tunnel helper.
#
# Run by the widget as `pkexec /bin/sh install-helper.sh` (administrator
# authentication). It installs:
#   /usr/local/libexec/omarchy-cisco-vpn-tunnel   copy of tunnel-helper.py
#   /etc/polkit-1/rules.d/49-omarchy-cisco-vpn.rules
#     lets the user who ran this (and only them, in an active local session)
#     run that helper through pkexec without a password
# and removes the NetworkManager DNS hook used by earlier versions.
set -eu

HELPER=/usr/local/libexec/omarchy-cisco-vpn-tunnel
RULE=/etc/polkit-1/rules.d/49-omarchy-cisco-vpn.rules
OLD_DNS_HOOK=/etc/NetworkManager/dispatcher.d/90-omarchy-cisco-vpn-dns

[ "$(id -u)" -eq 0 ] || { echo "run through pkexec" >&2; exit 1; }
uid=${PKEXEC_UID:-}
case "$uid" in '' | *[!0-9]*) echo "PKEXEC_UID missing" >&2; exit 1 ;; esac
[ "$uid" -ne 0 ] || { echo "run as your own user through pkexec" >&2; exit 1; }
user=$(id -nu "$uid")
case "$user" in '' | -* | *[!A-Za-z0-9._-]*) echo "unsupported user name" >&2; exit 1 ;; esac

source_dir=$(dirname "$(readlink -f "$0")")
install -D -m 0755 -o root -g root "$source_dir/tunnel-helper.py" "$HELPER"

umask 022
temporary=$(mktemp "$RULE.XXXXXX")
cat >"$temporary" <<EOF
// Installed by the Omarchy Cisco VPN widget. Lets $user start and stop the
// VPN tunnel helper without a password. Remove this file to revoke it.
polkit.addRule(function (action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        action.lookup("program") == "$HELPER" &&
        subject.user == "$user" && subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
EOF
chmod 0644 "$temporary"
mv -f "$temporary" "$RULE"

rm -f "$OLD_DNS_HOOK"
echo "installed"
