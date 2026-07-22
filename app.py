"""
=================================================================
Password Policy Compliance Checker -- Flask Web Application
=================================================================
This file is the ONLY new "backend" file in the project. It is a
thin web layer that sits on top of the original, unmodified
password_checker.py engine.

Every password rule, every score calculation, every CSV/report
read-write operation is still done by the functions inside
password_checker.py (load_policy, validate_password,
password_strength, check_compliance, save_report, save_summary,
find_reused, load_common_passwords). This file never re-implements
that logic -- it only calls it and turns the results into HTML
pages, JSON for charts, and file downloads.

Routes:
    GET  /                      -> Home dashboard (upload + analyze)
    POST /upload                -> Save an uploaded CSV as the active password file
    POST /analyze                -> Run check_compliance() and cache the results
    GET  /dashboard              -> Results dashboard (charts + table)
    GET  /settings                -> Policy settings form
    POST /settings                -> Save updated policy.json
    GET  /reports                -> Reports page (download links)
    GET  /reports/download/csv    -> Download output/compliance_report.csv
    GET  /reports/download/summary -> Download output/summary.txt
"""

import os
import json
import time

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
)
from werkzeug.utils import secure_filename

# Import the ORIGINAL engine. Nothing in this module is rewritten --
# app.py only calls into it.
import password_checker as pc

app = Flask(__name__)
app.secret_key = "password-compliance-checker-dev-key"  # only used for flash messages

# Where the CSV currently being analyzed lives (same path the
# original CLI project used).
ACTIVE_CSV_PATH = os.path.join("input", "passwords.csv")

# Where we cache the results of the most recent scan so the
# Dashboard/Reports/Home pages can all read the same data without
# re-running the analysis on every page load.
LAST_SCAN_PATH = os.path.join("output", "last_scan.json")


# -----------------------------------------------------------------
# Helpers (web-layer only -- no password-checking logic lives here)
# -----------------------------------------------------------------
def load_last_scan():
    """Load the cached results of the most recent scan, if any exist."""
    if os.path.exists(LAST_SCAN_PATH):
        with open(LAST_SCAN_PATH, "r") as f:
            return json.load(f)
    return None


def cache_scan(report, passed, failed):
    """
    Take the output of the ORIGINAL check_compliance() function,
    compute the extra dashboard stats via get_extra_stats() (also
    reused, not reimplemented), and persist everything as JSON so
    every page can render instantly.
    """
    total = len(report)
    stats = pc.get_extra_stats(report)

    data = {
        "report": report,
        "total": total,
        "passed": passed,
        "failed": failed,
        "compliance_pct": round((passed / total) * 100, 1) if total else 0,
        "stats": stats,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    os.makedirs("output", exist_ok=True)
    with open(LAST_SCAN_PATH, "w") as f:
        json.dump(data, f, indent=2)

    return data


# -----------------------------------------------------------------
# Home Dashboard
# -----------------------------------------------------------------
@app.route("/")
def index():
    last_scan = load_last_scan()
    csv_name = os.path.basename(ACTIVE_CSV_PATH)
    active_csv_exists = os.path.exists(ACTIVE_CSV_PATH)
    return render_template(
        "index.html",
        last_scan=last_scan,
        csv_name=csv_name,
        active_csv_exists=active_csv_exists,
    )


# -----------------------------------------------------------------
# Upload a CSV of usernames/passwords to analyze
# -----------------------------------------------------------------
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("csv_file")

    if not file or file.filename == "":
        flash("Please choose a CSV file before uploading.", "danger")
        return redirect(url_for("index"))

    if not file.filename.lower().endswith(".csv"):
        flash("Only .csv files are accepted.", "danger")
        return redirect(url_for("index"))

    os.makedirs("input", exist_ok=True)
    # Always land the upload at input/passwords.csv, the exact path
    # the original load_passwords() function already expects.
    filename = secure_filename(file.filename)
    file.save(ACTIVE_CSV_PATH)

    flash(f"'{filename}' uploaded successfully. Click Analyze to scan it.", "success")
    return redirect(url_for("index"))


# -----------------------------------------------------------------
# Run the compliance scan (reuses check_compliance() unchanged)
# -----------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    if not os.path.exists(ACTIVE_CSV_PATH):
        flash("No password CSV found. Please upload one first.", "danger")
        return redirect(url_for("index"))

    try:
        # ---- Original engine call, untouched ----
        report, passed, failed = pc.check_compliance()
        pc.save_report(report)
        pc.save_summary(len(report), passed, failed)
        # ------------------------------------------
    except ZeroDivisionError:
        flash("The uploaded CSV has no rows to analyze.", "danger")
        return redirect(url_for("index"))
    except Exception as exc:  # surfaces malformed CSV, bad policy, etc.
        flash(f"Analysis failed: {exc}", "danger")
        return redirect(url_for("index"))

    cache_scan(report, passed, failed)
    flash("Scan complete. Reports generated.", "success")
    return redirect(url_for("dashboard"))


# -----------------------------------------------------------------
# Results Dashboard
# -----------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    scan = load_last_scan()
    if not scan:
        flash("Run an analysis first to see results.", "warning")
        return redirect(url_for("index"))
    return render_template("dashboard.html", scan=scan)


# -----------------------------------------------------------------
# Policy Settings
# -----------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        try:
            min_length = int(request.form.get("min_length", 8))
        except ValueError:
            flash("Minimum length must be a whole number.", "danger")
            return redirect(url_for("settings"))

        policy = {
            "min_length": min_length,
            "require_uppercase": "require_uppercase" in request.form,
            "require_lowercase": "require_lowercase" in request.form,
            "require_digit": "require_digit" in request.form,
            "require_special": "require_special" in request.form,
            "prevent_reuse": "prevent_reuse" in request.form,
        }

        # ---- Original-style write, via the new save_policy() helper ----
        pc.save_policy(policy)
        # ------------------------------------------------------------

        flash("Policy updated. Re-run Analyze to apply it to the current data.", "success")
        return redirect(url_for("settings"))

    policy = pc.load_policy()  # original, unmodified function
    return render_template("settings.html", policy=policy)


# -----------------------------------------------------------------
# Reports Page
# -----------------------------------------------------------------
@app.route("/reports")
def reports():
    scan = load_last_scan()
    csv_exists = os.path.exists("output/compliance_report.csv")
    summary_exists = os.path.exists("output/summary.txt")
    return render_template(
        "reports.html",
        scan=scan,
        csv_exists=csv_exists,
        summary_exists=summary_exists,
    )


@app.route("/reports/download/csv")
def download_csv():
    path = "output/compliance_report.csv"
    if not os.path.exists(path):
        flash("No CSV report yet. Run an analysis first.", "warning")
        return redirect(url_for("reports"))
    return send_file(path, as_attachment=True, download_name="compliance_report.csv")


@app.route("/reports/download/summary")
def download_summary():
    path = "output/summary.txt"
    if not os.path.exists(path):
        flash("No summary report yet. Run an analysis first.", "warning")
        return redirect(url_for("reports"))
    return send_file(path, as_attachment=True, download_name="summary.txt")


if __name__ == "__main__":
    # Render (and most PaaS hosts) inject the port to bind via the PORT
    # env var. Locally this falls back to 5000 with debug mode on.
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
