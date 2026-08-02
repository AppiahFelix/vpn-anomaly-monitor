#!/bin/bash
# client-connect.sh
# OpenVPN calls this automatically for every successful connection and
# passes connection details as environment variables. We just append a
# clean, structured line to a log file — no parsing of noisy syslog needed.
#
# INSTALL:
#   1. Copy this file to /etc/openvpn/client-connect.sh on the server
#   2. chmod +x /etc/openvpn/client-connect.sh
#   3. In /etc/openvpn/server.conf add:
#        script-security 2
#        client-connect /etc/openvpn/client-connect.sh
#   4. sudo systemctl restart openvpn-server@server   (or your unit name)

LOGFILE="/etc/openvpn/events.log"
mkdir -p "$(dirname "$LOGFILE")"

# Fields: event|epoch_seconds|common_name(username)|trusted_ip|assigned_vpn_ip
echo "login_success|$(date +%s)|${common_name}|${trusted_ip}|${ifconfig_pool_remote_ip}" >> "$LOGFILE"

exit 0
