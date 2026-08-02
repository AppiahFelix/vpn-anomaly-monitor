# Monitoring VPN Access Logs for Anomalous Remote Connections

A working prototype: sample log generator + rule-based anomaly detection script
+ a browser dashboard. Works against **any** VPN vendor's logs as long as they're
normalized into the schema below — that's the point of the project (most orgs
run a mix of OpenVPN, AnyConnect, FortiGate, etc., and a SOC needs one pipeline
that works across all of them).

## How to run it

```bash
python3 generate_logs.py   # creates sample_vpn_logs.csv (synthetic, 14 days, 8 users)
python3 analyze_logs.py    # reads the CSV, writes anomalies.json + dashboard_data.js
```

Then just open `dashboard.html` in a browser (no server needed — it reads
`dashboard_data.js`, which is generated fresh each time you run `analyze_logs.py`).

## Log schema (the normalization layer)

```
timestamp, username, event, source_ip, country, city, lat, lon, vpn_gateway, session_duration_min
```
`event` is one of `login_success`, `login_failed`, `logout`. Any vendor's raw
log can be mapped into this shape — that mapping step is what you'd point to
in a real deployment (e.g. a small parser per vendor, or a SIEM's normalization
pipeline) if you extend this beyond the prototype.

## Detectors implemented (analyze_logs.py)

1. **Brute force** — ≥5 failed logins from the same IP against the same user
   within 15 minutes.
2. **Impossible travel** — same user logs in from two locations too far apart
   to reach in the time between logins (great-circle distance ÷ time > 900 km/h).
3. **Off-hours access** — successful login outside 07:00–19:00.
4. **Unusual country** — first-ever login from a country not in that user's
   history.
5. **Long session** — session length is both >8 hours and ≥3x that user's
   typical session length.

Each is a simple, explainable rule — deliberately, since a big part of "why
these five" is that analysts can audit and tune a rule-based detector, unlike
a black-box ML model, which matters for a first monitoring pass.

## Files

- `generate_logs.py` — synthetic log generator (14 days, 8 users, 6 injected anomalies)
- `analyze_logs.py` — the detection engine
- `sample_vpn_logs.csv` — generated sample data
- `anomalies.json` — detection output
- `dashboard.html` + `dashboard_data.js` — the monitoring dashboard

## Using real logs instead of the sample data

`openvpn_hooks/` has everything needed to wire this up to a real, free
OpenVPN server instead of synthetic data — logging hooks, a failed-login
watcher, and a normalizer that converts raw OpenVPN events (+ GeoIP) into
the exact CSV schema `analyze_logs.py` already expects. See
`openvpn_hooks/SETUP.md` for the full walkthrough. Once you have
`vpn_logs.csv`, everything downstream (detectors, dashboard) works
unchanged: `python3 analyze_logs.py vpn_logs.csv`.

## Further extensions

- Add a baseline-per-user store (e.g. SQLite) so "unusual country" and "long
  session" compare against real history instead of only what's in the current file.
- Wire alerting (email/Slack/SMS) off high-severity findings instead of just
  writing to `anomalies.json`.
