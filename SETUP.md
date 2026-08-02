# Using real OpenVPN logs instead of sample data

Your detectors (`analyze_logs.py`) and dashboard don't need to change at all —
they just need input in the same CSV schema the sample data used. This
folder's job is turning real OpenVPN activity into that schema.

## 1. Get a free OpenVPN server

- Any free-tier cloud VM (Oracle Cloud's always-free tier works well) or a
  spare Linux machine/Raspberry Pi.
- Install with the standard community installer:
  ```
  curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
  sudo bash openvpn-install.sh
  ```
- Generate 2-3 client certs so you have more than one "user" in your data.

## 2. Install the logging hooks

Copy `client-connect.sh` and `client-disconnect.sh` to `/etc/openvpn/`,
make them executable, and add to `/etc/openvpn/server.conf`:

```
script-security 2
client-connect /etc/openvpn/client-connect.sh
client-disconnect /etc/openvpn/client-disconnect.sh
```

Restart the service: `sudo systemctl restart openvpn-server@server`
(unit name may differ — check `systemctl list-units | grep openvpn`).

Every connect/disconnect now appends a clean line to
`/var/log/openvpn/events.log`.

**Failed logins** (needed for brute-force detection) don't go through
`client-connect`, since that only fires on success. Run
`watch_failed_auth.sh` in the background (or as a systemd service) pointed
at your OpenVPN server log — it's pattern-matching based, so check it
against a few real failed attempts on your setup before trusting it fully.

## 3. Let it collect real traffic

Give it at least a day or two, ideally with a few different users/devices/
locations connecting, so the detectors (especially "unusual country" and
"impossible travel") have a real baseline to compare against.

## 4. Pull the log and normalize it

Copy `/var/log/openvpn/events.log` off the server (`scp` works fine), then:

```bash
python3 normalize_openvpn_logs.py events.log vpn_logs.csv
python3 analyze_logs.py vpn_logs.csv
```

That's it — `dashboard_data.js` gets regenerated from real data, and
`dashboard.html` picks it up exactly like before.

## GeoIP note

`normalize_openvpn_logs.py` needs to turn IPs into countries/cities. It'll
work out of the box using the free ip-api.com API (rate-limited, fine for a
class project), but for anything more serious — or if you don't want VPN
users' IPs sent to a third party — sign up free at MaxMind
(https://www.maxmind.com/en/geolite2/signup-sponsored), download
`GeoLite2-City.mmdb`, and drop it next to the script. It'll be picked up
automatically and looked up entirely offline.

## Files in this folder

- `client-connect.sh` / `client-disconnect.sh` — OpenVPN hooks, log successful sessions
- `watch_failed_auth.sh` — best-effort tailer for failed-login events
- `normalize_openvpn_logs.py` — converts the raw event log + GeoIP into `vpn_logs.csv`
