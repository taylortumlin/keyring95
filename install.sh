#!/bin/sh
# Install or upgrade KeyRing 95 on a Proxmox VE host. Run as root from a checkout:
#   git clone https://github.com/taylortumlin/keyring95 && cd keyring95 && ./install.sh
# Upgrades never touch your config (/etc/keyring95) or state (/var/lib/keyring95).
set -e
[ "$(id -u)" = 0 ] || { echo "Run as root."; exit 1; }
command -v pct >/dev/null || echo "warning: 'pct' not found. KeyRing 95 currently needs a Proxmox VE host."
command -v python3 >/dev/null || { echo "python3 is required."; exit 1; }
cd "$(dirname "$0")"
install -d -m 755 /opt/keyring95
install -m 644 keyring95.py ui.html /opt/keyring95/
install -d -m 700 /etc/keyring95 /var/lib/keyring95
[ -f /etc/keyring95/config.json ] || { install -m 600 config.example.json /etc/keyring95/config.json; NEW=1; }
install -m 644 keyring95.service /etc/systemd/system/keyring95.service
systemctl daemon-reload
if [ ! -f /var/lib/keyring95/passwd ]; then
  echo "Choose a login password:"
  KEYRING_STATE=/var/lib/keyring95 python3 /opt/keyring95/keyring95.py passwd
fi
systemctl enable keyring95 >/dev/null 2>&1
systemctl restart keyring95
echo
[ -n "$NEW" ] && echo "Edit /etc/keyring95/config.json to list your apps, then: systemctl restart keyring95"
echo "KeyRing 95 is running on http://$(hostname -I | awk '{print $1}'):8099"
