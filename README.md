# VPN Anomaly Monitor

**CY376: Network Monitoring, Security and Auditing — End-of-Semester Project (Blue Team)**

**Name:** Appiah Felix
**Index Number:** FCM.41.018.066.23

## Summary

A working, rule-based monitoring pipeline for OpenVPN. Connect/disconnect hooks on
the server log every session to a structured event file; a normalisation script
enriches each event with geolocation and writes it to a common CSV schema; a
detection engine applies five explainable rules (brute force, impossible travel,
off-hours access, unusual country, long session); and a static HTML dashboard
renders the findings with no server of its own.

Full write-up, methodology, and analysis are in `docs/VPN_Anomaly_Monitoring_Report.docx`.

## Tools used

- **OpenVPN** (via the `kylemanna/openvpn` Docker image) — VPN gateway and Easy-RSA PKI
- **Docker Desktop** — containerised lab environment
- **Tunnelblick** — OpenVPN client (macOS)
- **Python 3** — normalisation and detection engine
- **MaxMind GeoLite2 City** (`geoip2` Python package) — offline IP geolocation, with
  `ip-api.com` as a fallback when no local database is present
- **HTML / CSS / JavaScript** — the dashboard (`dashboard.html`, `dashboard_data.js`)

## Repository structure

```
.
├── client-connect.sh          # OpenVPN hook: logs every successful connection
├── client-disconnect.sh       # OpenVPN hook: logs every disconnect + duration
├── watch_failed_auth.sh       # Tails server log, appends login_failed events
├── update_ip.sh               # Rewrites every .ovpn file to the current gateway IP
├── normalize_openvpn_logs.py  # Raw events.log -> normalised vpn_logs.csv (+ GeoIP)
├── analyze_logs.py            # Detection engine -> anomalies.json + dashboard_data.js
├── dashboard.html             # Analyst-facing dashboard (reads dashboard_data.js)
├── GeoLite2-City.mmdb         # Local MaxMind database used for offline geolocation
├── evidence/                  # Screenshots referenced in the report (1.png - 7.png)
├── docs/
│   └── VPN_Anomaly_Monitoring_Report.docx
└── README.md
```

## How to run it

1. **Start the OpenVPN server** (Docker):
   ```bash
   docker run -v ~/openvpn-data:/etc/openvpn --rm kylemanna/openvpn ovpn_genconfig -u udp://<gateway-ip>
   docker run -v ~/openvpn-data:/etc/openvpn --rm -it kylemanna/openvpn ovpn_initpki
   docker run -v ~/openvpn-data:/etc/openvpn -d -p 1194:1194/udp --cap-add=NET_ADMIN --name openvpn-server kylemanna/openvpn
   ```

2. **Issue a client certificate and export its config**:
   ```bash
   docker run -v ~/openvpn-data:/etc/openvpn --rm -it kylemanna/openvpn easyrsa build-client-full user1 nopass
   docker run -v ~/openvpn-data:/etc/openvpn --rm kylemanna/openvpn ovpn_getclient user1 > user1.ovpn
   ./update_ip.sh   # keeps every .ovpn file pointed at the gateway's current address
   ```

3. **Install the logging hooks** on the server (inside `/etc/openvpn/server.conf`):
   ```
   script-security 2
   client-connect /etc/openvpn/client-connect.sh
   client-disconnect /etc/openvpn/client-disconnect.sh
   ```
   Restart the service, then run `watch_failed_auth.sh <path-to-openvpn-log> &` in the
   background to capture failed logins as well.

4. **Let clients connect** for a while so `events.log` accumulates real sessions.

5. **Normalise and analyse the log**:
   ```bash
   pip install geoip2 --break-system-packages   # for offline GeoIP lookups
   python3 normalize_openvpn_logs.py events.log vpn_logs.csv
   python3 analyze_logs.py vpn_logs.csv
   ```

6. **Open the dashboard**:
   ```bash
   open dashboard.html
   ```
   It loads `dashboard_data.js` directly, so it just needs to be regenerated
   (step 5) and reopened after each run — no server required.

## Detectors

| Detector | Rule | Severity |
|---|---|---|
| Brute force | ≥5 failed logins, same user + IP, within 15 minutes | High |
| Impossible travel | Two logins >300 km apart implying >900 km/h | High |
| Off-hours access | Successful login outside 07:00–19:00 | Medium |
| Unusual country | First-ever login from a country not seen before for that user | High |
| Long session | Session >8h and ≥3x that user's median session length | Low |

## Known limitation

Running the server behind Docker Desktop's NAT means every client's visible
source IP collapses to the same local gateway address, which limits the
impossible-travel and unusual-country detectors in this lab setup specifically.
See Section 6 of the report for the full discussion and the fix (deploy on a
routable host instead of behind a local container NAT).

## Screenshots

See `evidence/1.png` through `evidence/7.png`, referenced as Figures 2–8 in
`docs/VPN_Anomaly_Monitoring_Report.docx`.
