const VPN_DASHBOARD_DATA = {
  "generated_at": "2026-08-01 23:07:12",
  "total_events": 32,
  "total_anomalies": 8,
  "by_type": {
    "unusual_country": 1,
    "off_hours_access": 7
  },
  "findings": [
    {
      "type": "unusual_country",
      "severity": "high",
      "username": "joe",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-07-13 08:46:47",
      "detail": "First-ever login from Local/VPN-assigned (previously seen: Nigeria)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "joe-laptop2",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 21:43:00",
      "detail": "Login at 21:43 outside business hours (07:00-19:00)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "user1",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 22:47:39",
      "detail": "Login at 22:47 outside business hours (07:00-19:00)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "user1",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 22:57:39",
      "detail": "Login at 22:57 outside business hours (07:00-19:00)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "user1",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 22:59:46",
      "detail": "Login at 22:59 outside business hours (07:00-19:00)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "user1",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 23:00:03",
      "detail": "Login at 23:00 outside business hours (07:00-19:00)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "user1",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 23:06:28",
      "detail": "Login at 23:06 outside business hours (07:00-19:00)"
    },
    {
      "type": "off_hours_access",
      "severity": "medium",
      "username": "user1",
      "source_ip": "192.168.65.1",
      "timestamp": "2026-08-01 23:06:37",
      "detail": "Login at 23:06 outside business hours (07:00-19:00)"
    }
  ],
  "daily_series": [
    {
      "date": "2026-07-13",
      "success": 6,
      "failed": 0
    },
    {
      "date": "2026-07-19",
      "success": 1,
      "failed": 0
    },
    {
      "date": "2026-07-21",
      "success": 5,
      "failed": 0
    },
    {
      "date": "2026-08-01",
      "success": 7,
      "failed": 0
    }
  ]
};
