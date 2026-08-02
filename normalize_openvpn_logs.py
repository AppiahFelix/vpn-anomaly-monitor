"""
normalize_openvpn_logs.py
Reads the raw pipe-delimited event log written by client-connect.sh /
client-disconnect.sh / watch_failed_auth.sh, enriches each event with
geolocation for the source IP, and writes vpn_logs.csv in the exact schema
analyze_logs.py already expects:

    timestamp, username, event, source_ip, country, city, lat, lon,
    vpn_gateway, session_duration_min

This is the ONLY new step required to go from real OpenVPN traffic to your
existing detectors and dashboard — analyze_logs.py and dashboard.html don't
change at all.

GEOLOCATION:
Uses MaxMind's free GeoLite2 City database if present locally (recommended:
no rate limits, no per-lookup network call, keeps user IPs off a third-party
API). Sign up free at https://www.maxmind.com/en/geolite2/signup-sponsored,
download GeoLite2-City.mmdb, and put it next to this script.

If no GeoLite2-City.mmdb is found, falls back to the free ip-api.com API
(45 requests/min limit — fine for a class project, not for production) so
the pipeline still runs end-to-end without any signup.

Usage:
    python3 normalize_openvpn_logs.py [path/to/events.log] [output.csv]
    (defaults: events.log -> vpn_logs.csv)
"""

import csv
import sys
import time
import json
import urllib.request
from datetime import datetime

IN_LOG = sys.argv[1] if len(sys.argv) > 1 else "events.log"
OUT_CSV = sys.argv[2] if len(sys.argv) > 2 else "vpn_logs.csv"
GEOIP_DB = "GeoLite2-City.mmdb"
VPN_GATEWAY_NAME = "openvpn-server-01"  # rename to match your deployment

_geo_cache = {}
_geoip_reader = None

try:
    import geoip2.database
    _geoip_reader = geoip2.database.Reader(GEOIP_DB)
    print(f"Using local GeoLite2 database: {GEOIP_DB}")
except Exception:
    print("No local GeoLite2-City.mmdb found (or geoip2 not installed) — "
          "falling back to ip-api.com for lookups. "
          "pip install geoip2 --break-system-packages for offline lookups.")


def is_private_ip(ip):
    if not ip or ip in ("unknown", ""):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    a, b = int(parts[0]), int(parts[1])
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127


def geolocate(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    if is_private_ip(ip):
        result = ("Local/VPN-assigned", "", "", "")
        _geo_cache[ip] = result
        return result

    if _geoip_reader:
        try:
            r = _geoip_reader.city(ip)
            result = (r.country.name or "Unknown", r.city.name or "",
                      r.location.latitude or "", r.location.longitude or "")
        except Exception:
            result = ("Unknown", "", "", "")
    else:
        try:
            with urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=3) as resp:
                d = json.loads(resp.read())
            if d.get("status") == "success":
                result = (d.get("country", "Unknown"), d.get("city", ""),
                          d.get("lat", ""), d.get("lon", ""))
            else:
                result = ("Unknown", "", "", "")
            time.sleep(1.4)  # stay under ip-api.com's 45 req/min free limit
        except Exception:
            result = ("Unknown", "", "", "")

    _geo_cache[ip] = result
    return result


def main():
    rows_out = []
    with open(IN_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) < 5:
                continue
            event, epoch, user, ip, vpn_ip = parts[:5]
            duration = parts[5] if len(parts) > 5 and parts[5] else ""

            ts = datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
            country, city, lat, lon = geolocate(ip)
            duration_min = str(round(float(duration) / 60, 1)) if duration else ""

            rows_out.append({
                "timestamp": ts,
                "username": user,
                "event": event,
                "source_ip": ip,
                "country": country,
                "city": city,
                "lat": lat,
                "lon": lon,
                "vpn_gateway": VPN_GATEWAY_NAME,
                "session_duration_min": duration_min,
            })

    rows_out.sort(key=lambda r: r["timestamp"])

    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "username", "event", "source_ip", "country",
            "city", "lat", "lon", "vpn_gateway", "session_duration_min"])
        writer.writeheader()
        writer.writerows(rows_out)

    print(f"Wrote {len(rows_out)} normalized events to {OUT_CSV}")
    print(f"Now run: python3 analyze_logs.py {OUT_CSV}")


if __name__ == "__main__":
    main()
