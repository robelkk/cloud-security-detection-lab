"""Detect repeated failed authentication attempts in JSONL security logs."""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

LOG_PATH = Path("logs/auth_events.jsonl")
ALERT_PATH = Path("alerts/brute_force_alerts.jsonl")
THRESHOLD = 5
WINDOW = timedelta(minutes=10)


def load_events(path):
    with path.open(encoding="utf-8") as log_file:
        return [json.loads(line) for line in log_file if line.strip()]


def detect_brute_force(events):
    failures = defaultdict(list)
    alerts = []

    for event in events:
        if event.get("event_type") != "authentication" or event.get("outcome") != "failure":
            continue

        key = (event["source_ip"], event["username"])
        timestamp = datetime.fromisoformat(event["timestamp"])
        failures[key].append(timestamp)

    for (source_ip, username), timestamps in failures.items():
        timestamps.sort()
        for start_index, start_time in enumerate(timestamps):
            window_events = [
                ts for ts in timestamps[start_index:]
                if ts - start_time <= WINDOW
            ]
            if len(window_events) >= THRESHOLD:
                alerts.append({
                    "alert_type": "possible_brute_force",
                    "severity": "high",
                    "username": username,
                    "source_ip": source_ip,
                    "failed_attempts": len(window_events),
                    "window_minutes": int(WINDOW.total_seconds() / 60),
                    "first_seen": window_events[0].isoformat(),
                    "last_seen": window_events[-1].isoformat(),
                })
                break

    return alerts


def main():
    if not LOG_PATH.exists():
        raise SystemExit(
            f"Log file not found: {LOG_PATH}. Run the authentication event generator first."
        )

    events = load_events(LOG_PATH)
    alerts = detect_brute_force(events)

    ALERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_PATH.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Analyzed {len(events)} authentication events")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print("\n🚨 POSSIBLE BRUTE FORCE DETECTED")
        print(f"User: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Window: {alert['window_minutes']} minutes")
        print(f"Severity: {alert['severity'].upper()}")

    print(f"\nAlert file: {ALERT_PATH}")


if __name__ == "__main__":
    main()
