#!/bin/bash
CURRENT_IP=$(ipconfig getifaddr en0)
echo "Current Mac IP: $CURRENT_IP"
cd ~/Documents/access_logs
for f in *.ovpn; do
  sed -i '' "s/^remote .*/remote $CURRENT_IP 1194 udp/" "$f"
  echo "Updated $f"
done
