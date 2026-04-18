#!/usr/bin/env python3
"""
retr0pot Dashboard — Real-time attack visualization
by retr0
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, date
from collections import defaultdict
from flask import Flask, render_template, jsonify

# ─── Setup ────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
LOG_DIR = ROOT / "logs"
CONFIG_PATH = ROOT / "config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

app = Flask(__name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static")
)


# ─── Helpers ──────────────────────────────────────────────────
def load_events():
    """Load all events from log files."""
    events = []
    if not LOG_DIR.exists():
        return events
    for log_file in sorted(LOG_DIR.glob("events_*.json")):
        try:
            with open(log_file) as f:
                events.extend(json.load(f))
        except (json.JSONDecodeError, FileNotFoundError):
            continue
    return events


# ─── Routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    events = load_events()
    return jsonify(events[-200:])  # Last 200 events


@app.route("/api/stats")
def api_stats():
    events = load_events()

    stats = {
        "total_events": len(events),
        "total_unique_ips": len(set(e.get("src_ip", "") for e in events)),
        "by_service": defaultdict(int),
        "by_type": defaultdict(int),
        "top_ips": defaultdict(int),
        "credentials": [],
        "commands": [],
        "timeline": defaultdict(int),
    }

    for e in events:
        stats["by_service"][e.get("service", "unknown")] += 1
        stats["by_type"][e.get("type", "unknown")] += 1
        stats["top_ips"][e.get("src_ip", "unknown")] += 1

        # Timeline (hourly buckets)
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            stats["timeline"][hour_key] += 1
        except (KeyError, ValueError):
            pass

        if e.get("type") == "auth_attempt":
            cred = {
                "ip": e.get("src_ip"),
                "service": e.get("service"),
                "time": e.get("timestamp"),
            }
            data = e.get("data", {})
            if "username" in data:
                cred["username"] = data["username"]
            if "password" in data:
                cred["password"] = data["password"]
            if "post_body" in data:
                cred["post_body"] = data["post_body"][:200]
            stats["credentials"].append(cred)

        if e.get("type") == "command":
            stats["commands"].append({
                "ip": e.get("src_ip"),
                "command": e.get("data", {}).get("command", ""),
                "time": e.get("timestamp"),
                "service": e.get("service"),
            })

    stats["by_service"] = dict(stats["by_service"])
    stats["by_type"] = dict(stats["by_type"])
    stats["top_ips"] = dict(
        sorted(stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:15]
    )
    stats["timeline"] = dict(sorted(stats["timeline"].items())[-48:])
    stats["credentials"] = stats["credentials"][-50:]
    stats["commands"] = stats["commands"][-50:]

    return jsonify(stats)


@app.route("/api/live")
def api_live():
    """Get only the most recent events for live polling."""
    events = load_events()
    return jsonify(events[-20:])


if __name__ == "__main__":
    host = CONFIG.get("dashboard", {}).get("host", "127.0.0.1")
    port = CONFIG.get("dashboard", {}).get("port", 5000)
    print(f"\n\033[38;5;208m[retr0pot dashboard]\033[0m Running on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
