#!/bin/sh
# Install integrity-watch as an hourly systemd timer. Run as root.
set -eu

PREFIX=/opt/integrity-watch
CONF=/etc/integrity-watch
STATE=/var/lib/integrity-watch
SRC="$(cd "$(dirname "$0")/.." && pwd)"

install -d -m 0755 "$PREFIX" && cp -r "$SRC/integrity_watch" "$PREFIX/"
install -d -m 0700 "$CONF" "$STATE"
[ -f "$CONF/policy.json" ] || install -m 0600 "$SRC/deploy/policy.example.json" "$CONF/policy.json"
[ -f "$CONF/hmac.key" ] || (cd "$PREFIX" && python3 -m integrity_watch keygen --key "$CONF/hmac.key")

(cd "$PREFIX" && python3 -m integrity_watch init --config "$CONF/policy.json" \
    --key "$CONF/hmac.key" --baseline "$STATE/baseline.json")

install -m 0644 "$SRC/deploy/integrity-watch.service" "$SRC/deploy/integrity-watch.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now integrity-watch.timer
echo "Installed. Back up $CONF/hmac.key off-host, then check: journalctl -t integrity-watch"
