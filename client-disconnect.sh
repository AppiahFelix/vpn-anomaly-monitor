#!/bin/bash
# client-disconnect.sh
# OpenVPN calls this on every disconnect and additionally provides
# time_duration (seconds the session lasted) and byte counters.
#
# INSTALL: same as client-connect.sh, but add this line to server.conf:
#        client-disconnect /etc/openvpn/client-disconnect.sh

LOGFILE="/etc/openvpn/events.log"
mkdir -p "$(dirname "$LOGFILE")"

# Fields: event|epoch_seconds|common_name|trusted_ip|assigned_vpn_ip|duration_seconds
echo "logout|$(date +%s)|${common_name}|${trusted_ip}|${ifconfig_pool_remote_ip}|${time_duration}" >> "$LOGFILE"

exit 0
