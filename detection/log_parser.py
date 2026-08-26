"""
detection/log_parser.py
Converts raw uploaded .log / .txt files into structured records.

PRD section 6 ("Log Parser") requires extraction of:
    Timestamp, IP Address, Username, Event Type, Host Name, Log Message
and conversion of all logs into structured JSON.

Supported input styles (auto-detected line by line, most SIEM demo
datasets are Linux-style auth/syslog lines):
    1. Linux syslog / SSH auth log, e.g.:
       "Jul 10 14:32:01 webserver sshd[1341]: Failed password for
        invalid user admin from 192.168.1.15 port 51000 ssh2"
    2. Generic "key=value" style, e.g.:
       "timestamp=2026-07-10T14:32:01 host=web01 user=admin
        ip=192.168.1.15 event=LOGIN_FAILED msg=\"invalid credentials\""
    3. Anything else: stored as-is with only the raw message captured,
       so no line is ever silently dropped.
"""

import json
import re
from datetime import datetime

CURRENT_YEAR = datetime.now().year

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# "Jul 10 14:32:01 webserver sshd[1341]: Failed password for invalid user admin from 192.168.1.15 port 51000 ssh2"
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+?)(?:\[\d+\])?:\s*"
    r"(?P<msg>.*)$"
)

KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

EVENT_PATTERNS = [
    (re.compile(r"failed password", re.I), "AUTH_FAILED"),
    (re.compile(r"invalid user", re.I), "INVALID_USER"),
    (re.compile(r"authentication failure", re.I), "AUTH_FAILED"),
    (re.compile(r"accepted password|accepted publickey", re.I), "LOGIN_SUCCESS"),
    (re.compile(r"unauthorized", re.I), "UNAUTHORIZED_ACCESS"),
    (re.compile(r"session opened", re.I), "SESSION_OPENED"),
    (re.compile(r"session closed", re.I), "SESSION_CLOSED"),
    (re.compile(r"connection closed", re.I), "CONNECTION_CLOSED"),
    (re.compile(r"permission denied", re.I), "PERMISSION_DENIED"),
    (re.compile(r"root login", re.I), "ROOT_LOGIN_ATTEMPT"),
]

USER_RE = re.compile(r"(?:for(?: invalid user)?|user)\s+([A-Za-z0-9_\-.]+)\s+from", re.I)
USER_FALLBACK_RE = re.compile(r"user\s+([A-Za-z0-9_\-.]+)", re.I)


def _classify_event(message):
    for pattern, label in EVENT_PATTERNS:
        if pattern.search(message):
            return label
    return "OTHER"


def _normalize_syslog_timestamp(ts_raw):
    # "Jul 10 14:32:01" has no year in classic syslog; assume current year.
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {ts_raw}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts_raw


def _parse_syslog_line(line):
    m = SYSLOG_RE.match(line)
    if not m:
        return None

    msg = m.group("msg")
    ip_match = IP_RE.search(msg)
    user_match = USER_RE.search(msg) or USER_FALLBACK_RE.search(msg)

    return {
        "timestamp": _normalize_syslog_timestamp(m.group("ts")),
        "host_name": m.group("host"),
        "ip_address": ip_match.group(0) if ip_match else None,
        "username": user_match.group(1) if user_match else None,
        "event_type": _classify_event(msg),
        "message": msg.strip(),
        "raw_line": line,
    }


def _parse_kv_line(line):
    pairs = dict(KV_RE.findall(line))
    if not pairs:
        return None

    def clean(v):
        return v.strip('"') if v else v

    ip_val = clean(pairs.get("ip") or pairs.get("ip_address") or pairs.get("src_ip"))
    if not ip_val:
        ip_match = IP_RE.search(line)
        ip_val = ip_match.group(0) if ip_match else None

    message = clean(pairs.get("msg") or pairs.get("message") or line)
    event_type = clean(pairs.get("event") or pairs.get("event_type")) or _classify_event(message)

    return {
        "timestamp": clean(pairs.get("timestamp") or pairs.get("time") or pairs.get("ts")),
        "host_name": clean(pairs.get("host") or pairs.get("hostname")),
        "ip_address": ip_val,
        "username": clean(pairs.get("user") or pairs.get("username")),
        "event_type": event_type,
        "message": message,
        "raw_line": line,
    }


def _parse_fallback_line(line):
    ip_match = IP_RE.search(line)
    user_match = USER_RE.search(line) or USER_FALLBACK_RE.search(line)
    return {
        "timestamp": None,
        "host_name": None,
        "ip_address": ip_match.group(0) if ip_match else None,
        "username": user_match.group(1) if user_match else None,
        "event_type": _classify_event(line),
        "message": line.strip(),
        "raw_line": line,
    }


def parse_line(line):
    line = line.rstrip("\n")
    if not line.strip():
        return None

    for parser in (_parse_syslog_line, _parse_kv_line, _parse_fallback_line):
        result = parser(line)
        if result:
            result["is_suspicious"] = 0  # rule engine decides this later
            return result
    return None


def parse_log_file(file_path):
    """Reads a .log/.txt file and returns a list of structured dict records."""
    parsed = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            record = parse_line(raw_line)
            if record:
                parsed.append(record)
    return parsed


def to_json(parsed_logs):
    """Converts parsed log records into a structured JSON string
    (PRD requirement: 'Convert all logs into structured JSON.')"""
    return json.dumps(parsed_logs, indent=2, default=str)
