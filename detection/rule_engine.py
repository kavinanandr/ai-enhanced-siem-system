"""
detection/rule_engine.py
Rule-based threat detection (PRD section 6, "Rule Engine").

Detects:
    - Brute-force attacks / repeated failed logins
    - Unauthorized login attempts
    - Suspicious IP activity (one IP hitting many different usernames)
    - Authentication failures

Only logs that trip a rule are marked is_suspicious and are the ones
forwarded to the AI Engine, per the PRD ("Only suspicious logs are
forwarded to AI").

Each finding is grouped by IP address so that, e.g., 12 failed-login
lines from the same IP become ONE incident instead of 12 duplicates,
which is how a real SIEM/analyst would triage it.
"""

from collections import defaultdict
from datetime import datetime, timedelta

from config import Config

FAILED_EVENTS = {"AUTH_FAILED", "INVALID_USER"}
UNAUTHORIZED_EVENTS = {"UNAUTHORIZED_ACCESS", "PERMISSION_DENIED", "ROOT_LOGIN_ATTEMPT"}


def _safe_parse_ts(ts_value):
    if not ts_value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_value, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _group_by_ip(logs):
    groups = defaultdict(list)
    for log in logs:
        ip = log.get("ip_address") or "unknown"
        groups[ip].append(log)
    return groups


def _within_window(events, window_minutes):
    """Given a list of logs (dicts with a 'timestamp'), return True if the
    volume qualifies inside the configured time window. Falls back to
    treating all events as in-window if timestamps can't be parsed
    (common with heterogeneous demo log files)."""
    timestamps = [t for t in (_safe_parse_ts(e.get("timestamp")) for e in events) if t]
    if len(timestamps) < 2:
        return True  # not enough info to rule it out -> don't miss a real attack
    timestamps.sort()
    return (timestamps[-1] - timestamps[0]) <= timedelta(minutes=window_minutes)


def apply_rules(logs):
    """
    Takes the full list of parsed log dicts for one uploaded file and:
      1. Marks each log's is_suspicious flag in place.
      2. Returns a list of "findings" -- one per detected attack pattern
         per source IP -- ready to be handed to the AI engine.

    A finding dict looks like:
        {
            "rule": "BRUTE_FORCE",
            "ip_address": "192.168.1.15",
            "usernames": ["admin", "root"],
            "event_count": 8,
            "logs": [ ...matching log dicts... ],
        }
    """
    findings = []
    grouped = _group_by_ip(logs)

    for ip, ip_logs in grouped.items():
        if ip == "unknown":
            continue

        failed_logins = [l for l in ip_logs if l.get("event_type") in FAILED_EVENTS]
        unauthorized = [l for l in ip_logs if l.get("event_type") in UNAUTHORIZED_EVENTS]
        distinct_users = {l.get("username") for l in ip_logs if l.get("username")}

        # --- Rule 1: Brute-force / repeated failed logins -----------------
        if (
            len(failed_logins) >= Config.BRUTE_FORCE_FAILED_ATTEMPTS
            and _within_window(failed_logins, Config.BRUTE_FORCE_WINDOW_MINUTES)
        ):
            for l in failed_logins:
                l["is_suspicious"] = 1
            findings.append({
                "rule": "BRUTE_FORCE",
                "ip_address": ip,
                "usernames": sorted(u for u in distinct_users if u),
                "event_count": len(failed_logins),
                "logs": failed_logins,
            })

        # --- Rule 2: Unauthorized login attempts ---------------------------
        elif unauthorized:
            for l in unauthorized:
                l["is_suspicious"] = 1
            findings.append({
                "rule": "UNAUTHORIZED_ACCESS",
                "ip_address": ip,
                "usernames": sorted(u for u in distinct_users if u),
                "event_count": len(unauthorized),
                "logs": unauthorized,
            })

        # --- Rule 3: Suspicious IP activity (credential stuffing pattern) --
        elif (
            len(distinct_users) >= Config.SUSPICIOUS_IP_DISTINCT_USERS
            and _within_window(ip_logs, Config.SUSPICIOUS_IP_WINDOW_MINUTES)
        ):
            for l in ip_logs:
                l["is_suspicious"] = 1
            findings.append({
                "rule": "SUSPICIOUS_IP_ACTIVITY",
                "ip_address": ip,
                "usernames": sorted(u for u in distinct_users if u),
                "event_count": len(ip_logs),
                "logs": ip_logs,
            })

        # --- Rule 4: Plain authentication failures (below brute-force
        #             threshold, still worth flagging + summarizing) -------
        elif failed_logins:
            for l in failed_logins:
                l["is_suspicious"] = 1
            findings.append({
                "rule": "AUTH_FAILURE",
                "ip_address": ip,
                "usernames": sorted(u for u in distinct_users if u),
                "event_count": len(failed_logins),
                "logs": failed_logins,
            })

    return findings
