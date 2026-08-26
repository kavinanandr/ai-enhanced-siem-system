"""
app.py
AI-Enhanced SIEM System -- Flask application entry point.

Wires together:
    Log Upload -> Log Parser -> Rule Engine -> AI Engine -> SQLite
    -> Dashboard / Incident History / Reports

Run with:
    python app.py
Then open http://127.0.0.1:5000
"""

import os
import uuid
from datetime import datetime

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from ai.ai_engine import analyze_finding
from config import Config
from database import models
from database.db import init_db
from detection.log_parser import parse_log_file
from detection.rule_engine import apply_rules
from reports.report_generator import generate_csv, generate_pdf

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)
init_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS
    )


def severity_badge_class(severity):
    return {
        "Critical": "badge-critical",
        "High": "badge-high",
        "Medium": "badge-medium",
        "Low": "badge-low",
    }.get(severity, "badge-medium")


app.jinja_env.filters["severity_badge"] = severity_badge_class


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    stats = {
        "total_logs": models.count_logs(),
        "severity_counts": models.get_severity_counts(),
        "total_files": len(models.get_files()),
    }
    return render_template("index.html", stats=stats)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if "logfile" not in request.files:
            flash("No file part in the request.", "danger")
            return redirect(url_for("upload"))

        file = request.files["logfile"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("Only .log and .txt files are allowed.", "danger")
            return redirect(url_for("upload"))

        original_name = secure_filename(file.filename)
        stored_name = f"{uuid.uuid4().hex}_{original_name}"
        stored_path = os.path.join(Config.UPLOAD_FOLDER, stored_name)
        file.save(stored_path)

        file_id = models.create_file(original_name, stored_path)

        parsed = parse_log_file(stored_path)
        if parsed:
            models.insert_logs(file_id, parsed)
        models.set_file_log_count(file_id, len(parsed))

        flash(
            f"Uploaded '{original_name}' - {len(parsed)} log lines parsed. "
            f"Click Analyze to run threat detection.",
            "success",
        )
        return redirect(url_for("upload"))

    files = models.get_files()
    return render_template("upload.html", files=files)


@app.route("/files/<int:file_id>/view")
def view_file(file_id):
    file = models.get_file(file_id)
    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("upload"))
    logs = models.get_logs_for_file(file_id)
    return render_template("view_logs.html", file=file, logs=logs)


@app.route("/files/<int:file_id>/delete", methods=["POST"])
def delete_file(file_id):
    models.delete_file(file_id)
    flash("File and its logs were deleted.", "success")
    return redirect(url_for("upload"))


@app.route("/analyze/<int:file_id>", methods=["POST"])
def analyze_file(file_id):
    file = models.get_file(file_id)
    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("upload"))

    logs = models.get_logs_for_file(file_id)
    findings = apply_rules(logs)

    created = 0
    for finding in findings:
        ai_result = analyze_finding(finding)
        primary_log = finding["logs"][0] if finding["logs"] else {}
        models.create_incident({
            "file_id": file_id,
            "log_id": primary_log.get("id"),
            "attack_type": ai_result["attack_type"],
            "severity": ai_result["severity"],
            "reason": ai_result["reason"],
            "ai_summary": ai_result["summary"],
            "recommendation": "; ".join(ai_result["recommendation"]),
            "source_ip": finding["ip_address"],
            "username": ", ".join(finding["usernames"]) if finding["usernames"] else None,
            "ai_provider": ai_result["ai_provider"],
        })
        created += 1

    models.set_file_status(file_id, "analyzed")

    if created:
        flash(
            f"Analysis complete: {created} incident(s) detected out of "
            f"{len(logs)} log lines.",
            "warning",
        )
    else:
        flash(f"Analysis complete: no suspicious activity found in {len(logs)} log lines.", "success")

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/dashboard-data")
def api_dashboard_data():
    severity_counts = models.get_severity_counts()
    return jsonify({
        "total_logs": models.count_logs(),
        "threats_detected": sum(severity_counts.values()),
        "severity_counts": severity_counts,
        "attack_type_counts": models.get_attack_type_counts(),
        "daily_counts": models.get_daily_incident_counts(),
        "recent_incidents": models.get_recent_incidents(8),
        "attack_timeline": models.get_attack_timeline(20),
    })


@app.route("/incidents")
def incidents():
    search = request.args.get("q", "").strip()
    severity = request.args.get("severity", "All")
    attack_type = request.args.get("attack_type", "All")
    sort = request.args.get("sort", "created_at_desc")

    results = models.get_incidents(
        search=search or None, severity=severity, attack_type=attack_type, sort=sort
    )
    attack_types = models.get_distinct_attack_types()

    return render_template(
        "incidents.html",
        incidents=results,
        attack_types=attack_types,
        filters={"q": search, "severity": severity, "attack_type": attack_type, "sort": sort},
    )


@app.route("/incidents/<int:incident_id>/delete", methods=["POST"])
def delete_incident(incident_id):
    models.delete_incident(incident_id)
    flash("Incident deleted.", "success")
    return redirect(request.referrer or url_for("incidents"))


@app.route("/reports")
def reports():
    all_incidents = models.get_incidents()
    attack_types = models.get_distinct_attack_types()
    return render_template("reports.html", incidents=all_incidents, attack_types=attack_types)


@app.route("/reports/export/<fmt>")
def export_report(fmt):
    search = request.args.get("q", "").strip()
    severity = request.args.get("severity", "All")
    attack_type = request.args.get("attack_type", "All")

    incidents_list = models.get_incidents(
        search=search or None, severity=severity, attack_type=attack_type
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        out_path = os.path.join(Config.REPORTS_FOLDER, f"siem_report_{timestamp}.csv")
        generate_csv(incidents_list, out_path)
        return send_file(out_path, as_attachment=True, download_name=f"siem_report_{timestamp}.csv")

    if fmt == "pdf":
        out_path = os.path.join(Config.REPORTS_FOLDER, f"siem_report_{timestamp}.pdf")
        generate_pdf(incidents_list, out_path)
        return send_file(out_path, as_attachment=True, download_name=f"siem_report_{timestamp}.pdf")

    flash("Unknown export format.", "danger")
    return redirect(url_for("reports"))


if __name__ == "__main__":
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=5000)
