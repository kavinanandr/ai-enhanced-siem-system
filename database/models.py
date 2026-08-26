"""
database/models.py
Small data-access layer. Keeps every SQL statement in one place so
app.py and the detection/AI modules stay readable (Non-Functional
Requirement: modular architecture / maintainable code).
"""

from database.db import get_connection


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def create_file(filename, stored_path):
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO files (filename, stored_path) VALUES (?, ?)",
            (filename, stored_path),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def set_file_log_count(file_id, count):
    conn = get_connection()
    try:
        conn.execute("UPDATE files SET log_count = ? WHERE id = ?", (count, file_id))
        conn.commit()
    finally:
        conn.close()


def set_file_status(file_id, status):
    conn = get_connection()
    try:
        conn.execute("UPDATE files SET status = ? WHERE id = ?", (status, file_id))
        conn.commit()
    finally:
        conn.close()


def get_files():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM files ORDER BY upload_time DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_file(file_id):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_file(file_id):
    conn = get_connection()
    try:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def insert_logs(file_id, parsed_logs):
    """parsed_logs: list of dicts with keys timestamp, ip_address, username,
    event_type, host_name, message, raw_line, is_suspicious"""
    conn = get_connection()
    try:
        conn.executemany(
            """INSERT INTO logs
               (file_id, timestamp, ip_address, username, event_type,
                host_name, message, raw_line, is_suspicious)
               VALUES (:file_id, :timestamp, :ip_address, :username, :event_type,
                       :host_name, :message, :raw_line, :is_suspicious)""",
            [{**log, "file_id": file_id} for log in parsed_logs],
        )
        conn.commit()
        rows = conn.execute(
            "SELECT * FROM logs WHERE file_id = ? ORDER BY id", (file_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_logs_for_file(file_id):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM logs WHERE file_id = ? ORDER BY id", (file_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_suspicious_logs(file_id):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM logs WHERE file_id = ? AND is_suspicious = 1 ORDER BY id",
            (file_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def count_logs():
    conn = get_connection()
    try:
        return conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def create_incident(incident):
    """incident: dict with file_id, log_id, attack_type, severity, reason,
    ai_summary, recommendation, source_ip, username, ai_provider"""
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO incidents
               (file_id, log_id, attack_type, severity, reason, ai_summary,
                recommendation, source_ip, username, ai_provider)
               VALUES (:file_id, :log_id, :attack_type, :severity, :reason,
                       :ai_summary, :recommendation, :source_ip, :username, :ai_provider)""",
            incident,
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_incidents(search=None, severity=None, attack_type=None, sort="created_at_desc"):
    conn = get_connection()
    try:
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []

        if search:
            query += """ AND (attack_type LIKE ? OR ai_summary LIKE ?
                         OR source_ip LIKE ? OR username LIKE ?)"""
            like = f"%{search}%"
            params += [like, like, like, like]

        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity)

        if attack_type and attack_type != "All":
            query += " AND attack_type = ?"
            params.append(attack_type)

        sort_map = {
            "created_at_desc": "created_at DESC",
            "created_at_asc": "created_at ASC",
            "severity_desc": (
                "CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 "
                "WHEN 'Medium' THEN 2 ELSE 1 END DESC"
            ),
            "severity_asc": (
                "CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 "
                "WHEN 'Medium' THEN 2 ELSE 1 END ASC"
            ),
        }
        query += " ORDER BY " + sort_map.get(sort, "created_at DESC")

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_incident(incident_id):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_incident(incident_id):
    conn = get_connection()
    try:
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
    finally:
        conn.close()


def get_distinct_attack_types():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT DISTINCT attack_type FROM incidents ORDER BY attack_type").fetchall()
        return [r["attack_type"] for r in rows]
    finally:
        conn.close()


def get_severity_counts():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT severity, COUNT(*) c FROM incidents GROUP BY severity"
        ).fetchall()
        counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for r in rows:
            counts[r["severity"]] = r["c"]
        return counts
    finally:
        conn.close()


def get_attack_type_counts():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT attack_type, COUNT(*) c FROM incidents GROUP BY attack_type ORDER BY c DESC"
        ).fetchall()
        return {r["attack_type"]: r["c"] for r in rows}
    finally:
        conn.close()


def get_daily_incident_counts(days=14):
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT date(created_at) d, COUNT(*) c
               FROM incidents
               WHERE created_at >= datetime('now', ?)
               GROUP BY date(created_at)
               ORDER BY d""",
            (f"-{days} days",),
        ).fetchall()
        return {r["d"]: r["c"] for r in rows}
    finally:
        conn.close()


def get_recent_incidents(limit=10):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_attack_timeline(limit=25):
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, attack_type, severity, source_ip, created_at
               FROM incidents ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
