#!/usr/bin/env bash
# watch_failed_auth.sh
# client-connect only fires on SUCCESSFUL auth, so brute-force detection
# needs failed attempts from somewhere else: the main OpenVPN server log.
# This tails that log and appends a login_failed event for lines that look
# like an auth failure. Pattern-matching failed auth is inherently a bit
# heuristic — the exact log wording depends on your auth method
# (certs vs username/password) — so treat this as best-effort, and check
# the patterns below against a few real failed attempts on your own server
# before trusting it fully.
#
# USAGE:
#   sudo ./watch_failed_auth.sh /var/log/openvpn/openvpn.log &
#   (or point it at whatever your server.conf's "log" directive is,
#    or `journalctl -u openvpn-server@server -f` if you log via systemd)

SRC_LOG="${1:-/var/log/openvpn/openvpn.log}"
OUT_LOG="/var/log/openvpn/events.log"
mkdir -p "$(dirname "$OUT_LOG")"

tail -Fn0 "$SRC_LOG" | while read -r line; do
  if echo "$line" | grep -qiE "auth.?fail|verify error|tls.?error|authentication failed"; then
    ip=$(echo "$line" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n1)
    user=$(echo "$line" | grep -oP "(?<=CN=)[^,\s]+|(?<=client ')[^']+" | head -n1)
    [ -z "$user" ] && user="unknown"
    [ -z "$ip" ] && ip="unknown"
    echo "login_failed|$(date +%s)|${user}|${ip}||" >> "$OUT_LOG"
  fi
done
