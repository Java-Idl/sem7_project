#!/usr/bin/env python3
"""
PeripheralShield - Native Messaging Companion Host (Python)
Ingests security telemetry, blocks, and device write events from the browser extension.
Logs events in standardized SIEM JSON format and can forward alerts to syslog / event log.
"""

import sys
import json
import struct
import os
import datetime
from pathlib import Path

LOG_DIR = Path.home() / ".peripheralshield"
LOG_FILE = LOG_DIR / "security_alerts.jsonl"

def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def append_audit_log(entry):
    setup_logging()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def read_message():
    """Reads a message from standard input with 4-byte length prefix."""
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        return None
    message_length = struct.unpack("@I", raw_length)[0]
    raw_data = sys.stdin.buffer.read(message_length)
    if len(raw_data) < message_length:
        return None
    return json.loads(raw_data.decode("utf-8"))

def send_message(message):
    """Sends a message to standard output with 4-byte length prefix."""
    encoded = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("@I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()

def main():
    setup_logging()
    append_audit_log({
        "event_type": "HOST_STARTED",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pid": os.getpid()
    })

    while True:
        try:
            msg = read_message()
            if msg is None:
                break

            action = msg.get("action")
            if action == "LOG_SECURITY_ALERT":
                alert_entry = {
                    "event_type": "PERIPHERAL_EXPLOIT_BLOCKED",
                    "host_received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "payload": msg.get("event", {})
                }
                append_audit_log(alert_entry)
                send_message({
                    "status": "LOGGED",
                    "log_path": str(LOG_FILE)
                })
            elif action == "PING":
                send_message({
                    "status": "PONG",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                })
            else:
                send_message({
                    "status": "ACK",
                    "received_action": action
                })
        except Exception as e:
            append_audit_log({
                "event_type": "HOST_ERROR",
                "error": str(e),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
            send_message({"status": "ERROR", "error": str(e)})

if __name__ == "__main__":
    main()
