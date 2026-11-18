# SentinelAI &mdash; AI-Enhanced SIEM System

A web-based Security Information and Event Management (SIEM) tool that collects,
parses, and analyzes security logs, then uses AI to explain and prioritize threats.
Built as a B.Tech Computer Science mini project, following the attached PRD spec.

## What it does

1. **Upload** `.log` / `.txt` security log files (SSH/auth logs, or simple
   `key=value` application logs).
2. **Parse** every line into structured fields: timestamp, IP address, username,
   event type, host name, message &mdash; stored as structured JSON/SQLite rows.
3. **Detect** suspicious activity with a rule engine: brute-force / repeated
   failed logins, unauthorized access attempts, suspicious IP activity
   (credential-stuffing pattern), and generic authentication failures. Only
   flagged logs are forwarded to the AI engine.
4. **Analyze** each flagged group with an AI engine acting as a cybersecurity
   analyst: attack type, severity, reason, plain-language summary, and
   recommended mitigation steps &mdash; returned as structured JSON.
5. **Visualize** everything on a live dashboard: alert counts by severity,
   severity distribution, attack-type distribution, a 14-day trend, recent
   incidents, an AI threat summary panel, and an attack timeline.
6. **Manage** incidents: search, filter by severity/attack type, sort, delete.
7. **Report**: export the incident history as PDF or CSV.

## Tech stack (matches the PRD)

| Layer      | Choice                                   |
|------------|-------------------------------------------|
| Backend    | Python, Flask                              |
| Frontend   | HTML, CSS, JavaScript, Bootstrap 5         |
| Charts     | Chart.js                                   |
| Database   | SQLite                                     |
| AI         | OpenAI API **or** Ollama (Llama 3 / Mistral) |

## Quick start

```bash
cd AI-Enhanced-SIEM
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**, then go to **Upload Logs** and try one of the
files in `sample_logs/` (`sample_auth.log` or `sample_app_events.txt`) to see
the full pipeline end to end &mdash; upload &rarr; parse &rarr; Analyze &rarr;
Dashboard.

The SQLite database is created automatically on first run at
`data/siem.db`. Uploaded files are stored in `logs/`.

## Connecting a real AI model

Out of the box, `SIEM_AI_PROVIDER=simulated` (the default) uses a built-in,
deterministic analyst that needs no API key or internet access, so the whole
pipeline works immediately for a demo or for grading. It uses the same rule
findings a real model would receive and writes genuinely different summaries
per attack type/IP/volume, but it is **not** a language model.

To use a real LLM instead, set environment variables before running `app.py`
&mdash; no code changes required:

**OpenAI**
```bash
export SIEM_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4o-mini      # optional, this is the default
python app.py
```

**Ollama** (run `ollama serve` and `ollama pull llama3` first)
```bash
export SIEM_AI_PROVIDER=ollama
export OLLAMA_HOST=http://localhost:11434   # optional, this is the default
export OLLAMA_MODEL=llama3                  # optional, this is the default
python app.py
```

If the configured provider errors out for any reason (bad key, network down,
model not pulled), analysis automatically falls back to the simulated
analyst for that incident rather than failing the whole request, and the
incident is labeled with which provider actually produced it (visible in the
Incident History "Details" modal).

## Project structure

```
AI-Enhanced-SIEM/
  app.py                 Flask routes / application entry point
  config.py               All configuration (env-var driven)
  requirements.txt
  logs/                    Uploaded raw log files land here
  data/                    siem.db (SQLite) lives here
  ai/
    ai_engine.py           AI analysis: OpenAI / Ollama / simulated
  detection/
    log_parse1. It endlessly loads or spins forever
If clicking the "Sync" or "Push" button results in an infinite loading loop, it usually means Git is trying to ask for your credentials in the background but the prompt is blocked. ￼
￼
Reddit
The Fix: Open your terminal and type git push. This will force the authentication prompt to appear. You will likely see a browser window pop up asking you to authorize VS Code with your GitHub account. ￼
2. "Permission Denied" or account mismatchr.py          Raw line -> structured record
    rule_engine.py          Structured records -> suspicious findings
  database/
    db.py                   Connection + schema
    models.py                Data access layer
  reports/
    report_generator.py      PDF (reportlab) + CSV export
  static/
    css/style.css
    js/dashboard.js, upload.js, incidents.js
  templates/
    index.html, upload.html, view_logs.html, dashboard.html,
    incidents.html, reports.html, base.html
  sample_logs/              Demo log files for testing
```

## Database schema

**files** &mdash; id, filename, stored_path, upload_time, log_count, status

**logs** &mdash; id, file_id, timestamp, ip_address, username, event_type,
host_name, message, raw_line, is_suspicious, created_at

**incidents** &mdash; id, file_id, log_id, attack_type, severity, reason,
ai_summary, recommendation, source_ip, username, ai_provider, created_at

## Rule engine thresholds

Configurable in `config.py`:
- Brute force: &ge;5 failed logins from one IP within 10 minutes
- Suspicious IP activity: &ge;4 distinct usernames from one IP within 15 minutes

## Scope notes (per PRD section 4)

This is an educational mini-project. It intentionally does **not** include
enterprise-scale log ingestion, real-time distributed collection, multi-user
authentication, active firewall management/automatic blocking, or commercial
SIEM integrations.

## Not included / future enhancements

Real-time log monitoring, email notifications, live system log collection,
cloud deployment, ML-based anomaly detection, user authentication, threat
intelligence feeds, and real-time dashboards are noted in the PRD as future
enhancements and are not implemented here.
