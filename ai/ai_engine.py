"""
ai/ai_engine.py
AI Engine (PRD section 6 "AI Engine" + section 13 "AI Prompt").

Given a rule-engine "finding" (a group of suspicious logs from one IP),
this module asks an LLM to act as an experienced cybersecurity analyst
and return structured JSON with:
    Attack Type, Severity, Reason, Summary, Recommended Mitigation

Three interchangeable backends (PRD section 8 lists "OpenAI API or
Ollama" as the tech stack):

    SIEM_AI_PROVIDER=openai    -> OpenAI Chat Completions API
    SIEM_AI_PROVIDER=ollama    -> local Ollama server (Llama 3 / Mistral)
    SIEM_AI_PROVIDER=simulated -> offline, rule-grounded analyst (default)

The "simulated" backend exists so the project is fully runnable for
grading/demo purposes with zero setup (no API key, no GPU, no internet).
Switching to a real model is a one-line config/env change -- no code
changes needed -- because all three backends implement the exact same
function signature and return shape.
"""

import json
import re

import requests

from config import Config

# Exact prompt structure from PRD section 13 ("AI Prompt")
SYSTEM_PROMPT = "You are an experienced cybersecurity analyst working inside a SIEM system."

PROMPT_TEMPLATE = """Analyze the following security logs.

Identify:
- Attack Type
- Severity
- Reason
- Summary
- Recommended Mitigation

Return the response as structured JSON with exactly these keys:
"attack_type", "severity", "reason", "summary", "recommendation" (recommendation should be a list of short action strings).

Severity must be exactly one of: "Low", "Medium", "High", "Critical".

Security logs:
{logs}
"""

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


def _logs_to_prompt_text(finding):
    lines = []
    for log in finding["logs"][:50]:  # cap prompt size for very large findings
        lines.append(
            f"[{log.get('timestamp') or 'unknown time'}] "
            f"host={log.get('host_name') or 'unknown'} "
            f"ip={log.get('ip_address') or 'unknown'} "
            f"user={log.get('username') or 'unknown'} "
            f"event={log.get('event_type')} "
            f"msg=\"{log.get('message', '')}\""
        )
    return "\n".join(lines)


def _extract_json(text):
    """LLMs sometimes wrap JSON in prose or code fences; pull the object out."""
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence_match:
        text = fence_match.group(1)
    else:
        brace_match = re.search(r"\{.*\}", text, re.S)
        if brace_match:
            text = brace_match.group(0)
    return json.loads(text)


def _normalize_result(data, finding):
    severity = str(data.get("severity", "Medium")).strip().capitalize()
    if severity not in VALID_SEVERITIES:
        severity = "Medium"

    recommendation = data.get("recommendation", [])
    if isinstance(recommendation, str):
        recommendation = [r.strip("- ").strip() for r in recommendation.split("\n") if r.strip()]

    return {
        "attack_type": data.get("attack_type") or finding["rule"].replace("_", " ").title(),
        "severity": severity,
        "reason": data.get("reason", ""),
        "summary": data.get("summary", ""),
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Backend: OpenAI
# ---------------------------------------------------------------------------

def _call_openai(prompt_text):
    if not Config.OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY is not set")

    response = requests.post(
        Config.OPENAI_API_URL,
        headers={
            "Authorization": f"Bearer {Config.OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": Config.OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt_text},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        },
        timeout=Config.AI_REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    return _extract_json(content)


# ---------------------------------------------------------------------------
# Backend: Ollama
# ---------------------------------------------------------------------------

def _call_ollama(prompt_text):
    response = requests.post(
        f"{Config.OLLAMA_HOST}/api/chat",
        json={
            "model": Config.OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt_text},
            ],
            "stream": False,
            "format": "json",
        },
        timeout=Config.AI_REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    content = response.json()["message"]["content"]
    return _extract_json(content)


# ---------------------------------------------------------------------------
# Backend: Simulated (offline, deterministic, rule-grounded)
# ---------------------------------------------------------------------------

RULE_KNOWLEDGE = {
    "BRUTE_FORCE": {
        "attack_type": "Brute Force Attack",
        "base_severity": "High",
        "reason_tpl": (
            "{count} failed login attempts against {users} were observed from a single "
            "IP address ({ip}) within a short time window, consistent with an automated "
            "password-guessing (brute-force) attack."
        ),
        "summary_tpl": (
            "Repeated failed login attempts from {ip} targeting {users} indicate a "
            "likely brute-force attack against the authentication system."
        ),
        "recommendation": [
            "Block the IP address at the firewall/perimeter.",
            "Enable Multi-Factor Authentication (MFA) on the targeted account(s).",
            "Investigate the affected account(s) for any successful login following the attempts.",
            "Enforce account lockout / rate limiting on repeated authentication failures.",
        ],
    },
    "UNAUTHORIZED_ACCESS": {
        "attack_type": "Unauthorized Access Attempt",
        "base_severity": "High",
        "reason_tpl": (
            "{count} unauthorized or permission-denied events were logged from IP "
            "address {ip} involving {users}, suggesting an attempt to access resources "
            "without valid privileges."
        ),
        "summary_tpl": (
            "IP address {ip} attempted to access restricted resources or accounts "
            "({users}) without authorization."
        ),
        "recommendation": [
            "Review access control lists and account permissions for the targeted resource.",
            "Block or throttle the source IP address pending investigation.",
            "Audit recent privilege changes on the affected account(s).",
            "Enable alerting for future unauthorized access attempts from this source.",
        ],
    },
    "SUSPICIOUS_IP_ACTIVITY": {
        "attack_type": "Suspicious IP Activity (Credential Stuffing Pattern)",
        "base_severity": "Medium",
        "reason_tpl": (
            "IP address {ip} generated {count} authentication-related events across "
            "{user_count} distinct usernames ({users}) in a short window, a pattern "
            "typical of credential-stuffing or account-enumeration activity."
        ),
        "summary_tpl": (
            "IP address {ip} interacted with an unusually high number of distinct "
            "user accounts ({users}), which is atypical for normal user behavior."
        ),
        "recommendation": [
            "Rate-limit or CAPTCHA-gate the login endpoint for this source IP.",
            "Cross-check the targeted usernames against known breached-credential lists.",
            "Enable Multi-Factor Authentication (MFA) account-wide.",
            "Monitor the IP address for continued activity across other services.",
        ],
    },
    "AUTH_FAILURE": {
        "attack_type": "Authentication Failure",
        "base_severity": "Low",
        "reason_tpl": (
            "{count} authentication failure(s) were recorded from IP address {ip} "
            "involving {users}. Volume is below the brute-force threshold but still "
            "warrants review."
        ),
        "summary_tpl": (
            "One or more login failures from {ip} were logged for {users}."
        ),
        "recommendation": [
            "Monitor the IP address for escalation into repeated attempts.",
            "Confirm with the user(s) whether the login attempt was legitimate.",
            "Ensure password policies and MFA are enforced on the account(s).",
        ],
    },
}


def _severity_from_volume(base_severity, count):
    """Nudges severity up when volume is very high, so 40 failed logins
    doesn't get the same label as 5."""
    order = ["Low", "Medium", "High", "Critical"]
    idx = order.index(base_severity)
    if count >= 30:
        idx = min(idx + 2, len(order) - 1)
    elif count >= 15:
        idx = min(idx + 1, len(order) - 1)
    return order[idx]


def _call_simulated(finding):
    knowledge = RULE_KNOWLEDGE.get(finding["rule"], RULE_KNOWLEDGE["AUTH_FAILURE"])
    users = ", ".join(finding["usernames"]) if finding["usernames"] else "unknown user(s)"
    count = finding["event_count"]
    severity = _severity_from_volume(knowledge["base_severity"], count)

    return {
        "attack_type": knowledge["attack_type"],
        "severity": severity,
        "reason": knowledge["reason_tpl"].format(
            count=count, users=users, ip=finding["ip_address"], user_count=len(finding["usernames"]) or 1
        ),
        "summary": knowledge["summary_tpl"].format(
            count=count, users=users, ip=finding["ip_address"]
        ),
        "recommendation": knowledge["recommendation"],
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_finding(finding):
    """
    Takes one rule-engine finding and returns:
        {
            "attack_type": str,
            "severity": "Low"|"Medium"|"High"|"Critical",
            "reason": str,
            "summary": str,
            "recommendation": [str, ...],
            "ai_provider": "openai"|"ollama"|"simulated",
        }

    Always falls back to the simulated analyst on any error (missing key,
    network issue, malformed response) so a flaky/unset AI backend never
    breaks log analysis -- the incident still gets created with a
    clearly-labeled provider so the UI can be transparent about it.
    """
    provider = Config.AI_PROVIDER.lower()
    prompt_text = PROMPT_TEMPLATE.format(logs=_logs_to_prompt_text(finding))

    if provider == "openai":
        try:
            raw = _call_openai(prompt_text)
            result = _normalize_result(raw, finding)
            result["ai_provider"] = "openai"
            return result
        except Exception:
            pass  # fall through to simulated

    elif provider == "ollama":
        try:
            raw = _call_ollama(prompt_text)
            result = _normalize_result(raw, finding)
            result["ai_provider"] = "ollama"
            return result
        except Exception:
            pass  # fall through to simulated

    result = _call_simulated(finding)
    result["ai_provider"] = "simulated"
    return result
