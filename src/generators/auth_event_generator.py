"""Generate synthetic authentication events for the security detection lab.

This script creates benign login activity plus a controlled burst of failed
logins. It is intentionally a simulator: it does not attempt authentication
against any real system.
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT_PATH = Path("logs/auth_events.jsonl")
RANDOM_SEED = 42


def make_event(timestamp, username, source_ip, outcome):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "authentication",
        "username": username,
        "source_ip": source_ip,
        "outcome": outcome,
    }


def generate_events():
    random.seed(RANDOM_SEED)
    start = datetime.now(timezone.utc).replace(microsecond=0)
    events = []

    # Normal authentication activity.
    users = ["alice", "bob", "carol"]
    normal_ips = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
    for minute in range(10):
        events.append(
            make_event(
                start + timedelta(minutes=minute),
                random.choice(users),
                random.choice(normal_ips),
                "success",
            )
        )

    # Controlled suspicious pattern for our detector to find later.
    # 203.0.113.50 is TEST-NET-3, reserved for documentation/examples.
    for seconds in (0, 45, 90, 135, 180, 225):
        events.append(
            make_event(
                start + timedelta(minutes=12, seconds=seconds),
                "admin",
                "203.0.113.50",
                "failure",
            )
        )

    events.sort(key=lambda event: event["timestamp"])
    return events


def main():
    events = generate_events()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as log_file:
        for event in events:
            log_file.write(json.dumps(event) + "\n")

    successes = sum(event["outcome"] == "success" for event in events)
    failures = sum(event["outcome"] == "failure" for event in events)

    print(f"Generated {len(events)} authentication events")
    print(f"Successful logins: {successes}")
    print(f"Failed logins: {failures}")
    print(f"Log file: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
