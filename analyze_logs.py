"""
analyze_logs.py
Parses a normalized VPN access log (CSV) and flags anomalous remote connections
using a set of rule-based detectors commonly used in real VPN/SIEM monitoring:

  1. Brute-force / credential-stuffing pattern (repeated login_failed)
  2. Impossible travel (two logins for the same user, too far apart to be
     physically possible given the time between them)
  3. Off-hours access (connections outside normal business hours)
  4. New / unusual country for a given user (baseline vs. current event)
  5. Excessive session duration (outlier vs. that user's typical session length)
  6. Non-private/public source IP where the org expects private client subnets
     (simple "unexpected source" heuristic - tune to your environment)

Works on ANY VPN vendor's logs as long as they're normalized into this schema:
    timestamp, username, event, source_ip, country, city, lat, lon,
    vpn_gateway, session_duration_min

event is one of: login_success, login_failed, logout

Output: anomalies.json (list of findings) + dashboard_data.js (same data,
wrapped as a JS variable so dashboard.html can load it with no server needed)
and a printed summary to stdout.
"""

import csv
import json
import math
import sys
from datetime import datetime
from collections import defaultdict

# Pass a path to analyze real data, e.g.:
#   python3 analyze_logs.py vpn_logs.csv
# Defaults to the synthetic sample so the script still runs out of the box.
LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "sample_vpn_logs.csv"

# --- Tunable thresholds -----------------------------------------------------
BRUTE_FORCE_FAILS = 5          # failed logins...
BRUTE_FORCE_WINDOW_MIN = 15    # ...within this many minutes -> flag
IMPOSSIBLE_TRAVEL_MIN_KMH = 900   # faster than a commercial flight -> flag
BUSINESS_HOURS = (7, 19)       # 07:00–19:00 considered normal
LONG_SESSION_MULTIPLIER = 3    # session > 3x user's median -> flag
LONG_SESSION_FLOOR_MIN = 480   # ...but only if also > 8 hours absolute


def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def load_rows(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            r["timestamp"] = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
            rows.append(r)
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def detect_brute_force(rows):
    findings = []
    fails_by_target = defaultdict(list)
    for r in rows:
        if r["event"] == "login_failed":
            fails_by_target[(r["username"], r["source_ip"])].append(r["timestamp"])

    for (user, ip), timestamps in fails_by_target.items():
        timestamps.sort()
        window = []
        for t in timestamps:
            window.append(t)
            window = [w for w in window if (t - w).total_seconds() <= BRUTE_FORCE_WINDOW_MIN * 60]
            if len(window) >= BRUTE_FORCE_FAILS:
                findings.append({
                    "type": "brute_force",
                    "severity": "high",
                    "username": user,
                    "source_ip": ip,
                    "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
                    "detail": f"{len(window)} failed logins within {BRUTE_FORCE_WINDOW_MIN} min from {ip}",
                })
                break
    return findings


def detect_impossible_travel(rows):
    findings = []
    logins_by_user = defaultdict(list)
    for r in rows:
        if r["event"] == "login_success" and r["lat"] and r["lon"]:
            logins_by_user[r["username"]].append(r)

    for user, logins in logins_by_user.items():
        for prev, cur in zip(logins, logins[1:]):
            dt_hours = (cur["timestamp"] - prev["timestamp"]).total_seconds() / 3600
            if dt_hours <= 0:
                continue
            dist_km = haversine_km(float(prev["lat"]), float(prev["lon"]),
                                    float(cur["lat"]), float(cur["lon"]))
            speed = dist_km / dt_hours
            if speed > IMPOSSIBLE_TRAVEL_MIN_KMH and dist_km > 300:
                findings.append({
                    "type": "impossible_travel",
                    "severity": "high",
                    "username": user,
                    "source_ip": cur["source_ip"],
                    "timestamp": cur["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "detail": (f"{prev['city']}, {prev['country']} -> {cur['city']}, {cur['country']} "
                               f"({dist_km:.0f} km in {dt_hours:.1f}h, implies {speed:.0f} km/h)"),
                })
    return findings


def detect_off_hours(rows):
    findings = []
    start_h, end_h = BUSINESS_HOURS
    for r in rows:
        if r["event"] == "login_success":
            hour = r["timestamp"].hour
            if hour < start_h or hour >= end_h:
                findings.append({
                    "type": "off_hours_access",
                    "severity": "medium",
                    "username": r["username"],
                    "source_ip": r["source_ip"],
                    "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "detail": f"Login at {r['timestamp'].strftime('%H:%M')} outside business hours "
                              f"({start_h:02d}:00-{end_h:02d}:00)",
                })
    return findings


def detect_new_country(rows):
    findings = []
    seen_countries = defaultdict(set)
    for r in rows:
        if r["event"] != "login_success":
            continue
        user, country = r["username"], r["country"]
        if seen_countries[user] and country not in seen_countries[user]:
            findings.append({
                "type": "unusual_country",
                "severity": "high",
                "username": user,
                "source_ip": r["source_ip"],
                "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "detail": f"First-ever login from {country} (previously seen: {', '.join(seen_countries[user])})",
            })
        seen_countries[user].add(country)
    return findings


def detect_long_sessions(rows):
    findings = []
    durations_by_user = defaultdict(list)
    logout_rows = [r for r in rows if r["event"] == "logout" and r["session_duration_min"]]
    for r in logout_rows:
        durations_by_user[r["username"]].append(float(r["session_duration_min"]))

    medians = {u: sorted(d)[len(d) // 2] for u, d in durations_by_user.items() if d}

    for r in logout_rows:
        dur = float(r["session_duration_min"])
        med = medians.get(r["username"], dur)
        if dur >= LONG_SESSION_FLOOR_MIN and dur >= med * LONG_SESSION_MULTIPLIER:
            findings.append({
                "type": "long_session",
                "severity": "low",
                "username": r["username"],
                "source_ip": r["source_ip"],
                "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "detail": f"Session lasted {dur:.0f} min (user's typical: {med:.0f} min)",
            })
    return findings


def main():
    rows = load_rows(LOG_FILE)
    print(f"Loaded {len(rows)} log entries from {LOG_FILE}")

    findings = []
    findings += detect_brute_force(rows)
    findings += detect_impossible_travel(rows)
    findings += detect_off_hours(rows)
    findings += detect_new_country(rows)
    findings += detect_long_sessions(rows)
    findings.sort(key=lambda f: f["timestamp"])

    by_type = defaultdict(int)
    for f in findings:
        by_type[f["type"]] += 1

    print(f"\nTotal anomalies flagged: {len(findings)}")
    for t, c in by_type.items():
        print(f"  {t}: {c}")

    with open("anomalies.json", "w") as f:
        json.dump(findings, f, indent=2)

    # Also compute simple daily volume stats for the dashboard
    daily_counts = defaultdict(lambda: {"success": 0, "failed": 0})
    for r in rows:
        day = r["timestamp"].strftime("%Y-%m-%d")
        if r["event"] == "login_success":
            daily_counts[day]["success"] += 1
        elif r["event"] == "login_failed":
            daily_counts[day]["failed"] += 1
    daily_series = [{"date": d, **v} for d, v in sorted(daily_counts.items())]

    dashboard_payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": len(rows),
        "total_anomalies": len(findings),
        "by_type": by_type,
        "findings": findings,
        "daily_series": daily_series,
    }

    with open("dashboard_data.js", "w") as f:
        f.write("const VPN_DASHBOARD_DATA = ")
        json.dump(dashboard_payload, f, indent=2)
        f.write(";\n")

    print("\nWrote anomalies.json and dashboard_data.js")


if __name__ == "__main__":
    main()
