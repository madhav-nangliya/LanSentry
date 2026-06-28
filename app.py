# =============================================================================
# app.py — LanSentry Flask Application
# =============================================================================
#
# ARCHITECTURE: API-First / Static HTML
# ──────────────────────────────────────
# Flask does two jobs:
#   1. PAGE ROUTES — serve plain static HTML files from the templates/ folder
#   2. API ROUTES  — return JSON that JavaScript fetches client-side
#
# No Jinja2 rendering anywhere. HTML files are served as raw bytes.
# All dynamic data flows through /api/* endpoints → fetch() in the browser.
# =============================================================================

from flask import Flask, send_from_directory, jsonify, request
import logging
import os
from datetime import datetime

import database as db
from scanner import (
    start_background_scanner,
    trigger_manual_scan,
    get_scan_status,
)

# =============================================================================
# PATH SETUP — must come before Flask() init
# =============================================================================
# __file__ is always the absolute path to THIS script (app.py).
# os.path.dirname() strips the filename → gives us the folder.
# os.path.abspath() resolves any relative parts (e.g. "." or "..").
#
# Why not use "." or os.getcwd()?
#   "." means "wherever Python was launched from" — if you cd to a different
#   folder before running python app.py, "." points the wrong place.
#   __file__ ALWAYS points to the app.py directory, regardless of cwd.

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")   # where HTML files live
STATIC_DIR   = os.path.join(BASE_DIR, "static")      # where CSS/JS/images live

# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers = [
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(BASE_DIR, "lansentry.log"), mode="a"),
    ]
)
logger = logging.getLogger("app")

# =============================================================================
# FLASK INIT
# =============================================================================
# static_folder  → tells Flask WHERE static files (CSS, JS, images) live on disk
# static_url_path → tells Flask WHAT URL prefix to use when serving them
#
# With static_folder=STATIC_DIR and static_url_path="/static":
#   C:\Projects\Lansentry\static\style.css  →  http://localhost:5000/static/style.css
#
# Our HTML files reference:  <link rel="stylesheet" href="/static/style.css" />
# Flask serves:              C:\Projects\Lansentry\static\style.css
# These two MUST match.

app = Flask(
    __name__,
    static_folder   = STATIC_DIR,
    static_url_path = "/static"
)

app.secret_key = os.environ.get("LANSENTRY_SECRET", "change-me-before-deploying!")

# =============================================================================
# SECURITY HEADERS
# =============================================================================
@app.after_request
def add_security_headers(response):
    """
    Added to EVERY response automatically via @after_request decorator.

    Interview answers:
      X-Content-Type-Options: nosniff
          Browser won't guess MIME type — prevents treating a .txt as JS.
      X-Frame-Options: DENY
          Page can't be embedded in an iframe — stops clickjacking.
      X-XSS-Protection: 1; mode=block
          Old-browser XSS filter fallback.
      Referrer-Policy: strict-origin-when-cross-origin
          Stops internal URLs leaking to third-party sites via the Referer header.
      Content-Security-Policy:
          Whitelist of allowed content sources. Strongest XSS defence.
    """
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        # Chart.js loaded from CDN (jsdelivr) — required for dashboard charts
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# =============================================================================
# STARTUP
# =============================================================================
def startup():
    logger.info("=" * 60)
    logger.info("LanSentry starting")
    logger.info("BASE_DIR     : %s", BASE_DIR)
    logger.info("TEMPLATE_DIR : %s", TEMPLATE_DIR)
    logger.info("STATIC_DIR   : %s", STATIC_DIR)
    logger.info("=" * 60)

    if db.init_db():
        logger.info("Database ready")
    else:
        logger.error("Database init failed — running in cache-only mode")

    start_background_scanner()
    logger.info("LanSentry fully started")


startup()


# =============================================================================
# SECTION 1 — PAGE ROUTES
# =============================================================================
# send_from_directory(directory, filename):
#   Safely sends a file from `directory`.
#   "Safely" means it prevents directory traversal — a request for
#   "../../etc/passwd" gets a 404, not the file.

@app.route("/")
def home():
    return send_from_directory(TEMPLATE_DIR, "home.html")


@app.route("/devices")
def devices_page():
    return send_from_directory(TEMPLATE_DIR, "devices.html")


@app.route("/alerts")
def alerts_page():
    return send_from_directory(TEMPLATE_DIR, "alerts.html")


@app.route("/history")
def history_page():
    return send_from_directory(TEMPLATE_DIR, "history.html")


# =============================================================================
# SECTION 2 — DEVICE API
# =============================================================================

@app.route("/api/devices")
def api_devices():
    """
    GET /api/devices
    Returns all devices as JSON. Called by devices.html on load + every 30s.

    Datetime → ISO string conversion:
        MySQL gives us Python datetime objects.
        JSON has no datetime type — we must convert to strings.
        ISO 8601 format ("2025-01-15T14:30:00") is the standard; JavaScript's
        new Date("2025-01-15T14:30:00") parses it natively.
    """
    devices = db.get_all_devices()
    for d in devices:
        if isinstance(d.get("first_seen"), datetime):
            d["first_seen"] = d["first_seen"].isoformat()
        if isinstance(d.get("last_seen"), datetime):
            d["last_seen"] = d["last_seen"].isoformat()
    return jsonify({"success": True, "devices": devices, "count": len(devices)})


# =============================================================================
# SECTION 3 — SCANNER API
# =============================================================================

@app.route("/api/scan-status")
def api_scan_status():
    """GET /api/scan-status — scanner health, polled every 15s by dashboard."""
    return jsonify({"success": True, **get_scan_status()})


@app.route("/api/scan/trigger", methods=["POST"])
def api_trigger_scan():
    """
    POST /api/scan/trigger — start an immediate scan.
    Returns 409 Conflict if scan already running.
    """
    started = trigger_manual_scan()
    if started:
        return jsonify({"success": True, "message": "Scan started"})
    return jsonify({"success": False, "message": "Scan already running"}), 409


# =============================================================================
# SECTION 4 — CHART API
# =============================================================================

@app.route("/api/chart/scan-history")
def api_chart_scan_history():
    """GET /api/chart/scan-history?hours=24 — line chart data."""
    hours = max(1, min(request.args.get("hours", 24, type=int), 168))
    rows  = db.get_scan_history_for_chart(hours=hours)
    return jsonify({
        "success":       True,
        "hours":         hours,
        "labels":        [r["label"]         for r in rows],
        "devices_found": [r["devices_found"] for r in rows],
        "new_devices":   [r["new_devices"]   for r in rows],
    })


@app.route("/api/chart/device-status")
def api_chart_device_status():
    """GET /api/chart/device-status — doughnut chart data."""
    s = db.get_device_stats()
    return jsonify({
        "success": True,
        "labels":  ["Online", "Offline", "High Risk"],
        "data":    [s["online"], s["offline"], s["high_risk"]],
        "total":   s["total"],
    })


@app.route("/api/chart/alerts")
def api_chart_alerts():
    """GET /api/chart/alerts?days=7 — stacked bar chart data."""
    days = max(1, min(request.args.get("days", 7, type=int), 30))
    rows = db.get_alerts_for_chart(days=days)
    return jsonify({
        "success":         True,
        "days":            days,
        "labels":          [str(r["day"])                   for r in rows],
        "new_device":      [int(r["new_device"]      or 0) for r in rows],
        "device_offline":  [int(r["device_offline"]  or 0) for r in rows],
        "high_risk":       [int(r["high_risk"]        or 0) for r in rows],
    })


@app.route("/api/chart/risk-breakdown")
def api_chart_risk_breakdown():
    """GET /api/chart/risk-breakdown — risk doughnut data."""
    devices     = db.get_all_devices()
    risk_counts = {"low": 0, "medium": 0, "high": 0}
    for d in devices:
        lvl = d.get("risk_level", "low")
        if lvl in risk_counts:
            risk_counts[lvl] += 1
    return jsonify({
        "success": True,
        "labels":  ["Low Risk", "Medium Risk", "High Risk"],
        "data":    [risk_counts["low"], risk_counts["medium"], risk_counts["high"]],
    })


# =============================================================================
# SECTION 5 — ALERTS API
# =============================================================================

@app.route("/api/alerts")
def api_alerts():
    """GET /api/alerts?limit=50&unread_only=false"""
    limit       = request.args.get("limit", 50, type=int)
    unread_only = request.args.get("unread_only", "false").lower() == "true"
    alerts      = db.get_alerts(limit=limit, unread_only=unread_only)
    for a in alerts:
        if isinstance(a.get("alert_time"), datetime):
            a["alert_time"] = a["alert_time"].isoformat()
    return jsonify({"success": True, "alerts": alerts, "count": len(alerts)})


@app.route("/api/alerts/unread-count")
def api_unread_count():
    """GET /api/alerts/unread-count — polled every 30s for nav badge."""
    return jsonify({"success": True, "count": db.get_unread_alert_count()})


@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
def api_mark_alert_read(alert_id):
    """POST /api/alerts/<id>/read — dismiss one alert."""
    return jsonify({"success": db.mark_alert_read(alert_id)})


@app.route("/api/alerts/read-all", methods=["POST"])
def api_mark_all_read():
    """POST /api/alerts/read-all — dismiss all unread alerts."""
    return jsonify({"success": True, "cleared": db.mark_all_alerts_read()})


# =============================================================================
# SECTION 6 — SCAN HISTORY API
# =============================================================================

@app.route("/api/scan-history")
def api_scan_history():
    """
    GET /api/scan-history?limit=50
    Returns paginated scan history records for the history page table.
    """
    limit   = max(1, min(request.args.get("limit", 50, type=int), 200))
    records = db.get_scan_history(limit=limit)
    for r in records:
        if isinstance(r.get("scan_time"), datetime):
            r["scan_time"] = r["scan_time"].isoformat()
    return jsonify({"success": True, "records": records, "count": len(records)})


# =============================================================================
# SECTION 7 — HEALTH CHECK
# =============================================================================

@app.route("/api/status")
def api_status():
    """GET /api/status — full system health. Good for uptime monitors."""
    return jsonify({
        "success":  True,
        "scanner":  get_scan_status(),
        "database": db.get_db_status(),
        "version":  "2.0.0",
        "paths": {
            "base":      BASE_DIR,
            "templates": TEMPLATE_DIR,
            "static":    STATIC_DIR,
        }
    })


# =============================================================================
# SECTION 8 — ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Endpoint not found"}), 404
    return send_from_directory(TEMPLATE_DIR, "home.html"), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("Unhandled 500: %s", e, exc_info=True)
    return jsonify({"success": False, "error": "Internal server error"}), 500


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
