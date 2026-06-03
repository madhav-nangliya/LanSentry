# =============================================================================
# app.py — LanSentry Flask Application
# =============================================================================
# Entry point for the web server. Wires together:
#   • database.py  — all MySQL operations
#   • scanner.py   — background nmap scanner
#   • templates/   — Jinja2 HTML files
#
# INTERVIEW: What is Flask?
# A "micro-framework" — it gives you routing, templating (Jinja2), and a dev
# server. "Micro" means it doesn't include an ORM, auth, or admin out of the
# box (unlike Django). You add what you need. Good for learning because there's
# less magic happening behind the scenes.
# =============================================================================

from flask import Flask, render_template, jsonify, request
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
# LOGGING
# =============================================================================
# basicConfig configures the ROOT logger. All child loggers (scanner,
# database, app) inherit this format and level.
# INTERVIEW: Why log to both console AND file?
# → Console is convenient during development; file persists across restarts
#   and can be shipped to a log aggregator (Datadog, ELK) in production.
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers = [
        logging.StreamHandler(),
        logging.FileHandler("lansentry.log", mode="a"),
    ]
)
logger = logging.getLogger("app")

# =============================================================================
# APP INIT
# =============================================================================
# template_folder default is 'templates/', but our templates are in the same
# directory (common for small projects). Explicitly set it to the project root.
# static_folder tells Flask where to serve /static/* files from.
app = Flask(
    __name__,
    template_folder = ".",        # Look for .html files in the current directory
    static_folder   = ".",        # /static/style.css → ./style.css
    static_url_path = "/static",  # URL prefix for static files
)

# Secret key: required for session cookies and CSRF tokens (Week 5: Flask-Login).
# os.environ.get() falls back to the dev value if env var isn't set.
# NEVER hardcode a real secret in source code — use .env + python-dotenv.
app.secret_key = os.environ.get("LANSENTRY_SECRET", "change-me-in-production")

# =============================================================================
# STARTUP
# =============================================================================

def startup():
    """Called once when app.py is imported. Initialises DB + scanner thread."""
    logger.info("=" * 60)
    logger.info("LanSentry starting up")
    logger.info("=" * 60)

    if db.init_db():
        logger.info("Database ready")
    else:
        logger.error("Database init failed — running without persistence")

    start_background_scanner()
    logger.info("LanSentry fully started")

startup()


# =============================================================================
# SECTION 1 — PAGE ROUTES (return rendered HTML)
# =============================================================================
# These routes serve the HTML shell. JavaScript on the page then fetches
# data from the /api/* endpoints below.
#
# INTERVIEW: Why not just render data in Jinja2 and skip the API calls?
# → SSR (server-side rendering) gives you the initial data but the page goes
#   stale immediately. With an API-first approach:
#   1. Pages are always fresh (JS re-fetches on load + timer)
#   2. The same API endpoints can be used by a mobile app or third-party tool
#   3. Frontend and backend can evolve independently

@app.route("/")
def home():
    """
    Dashboard. Passes initial stats to the template for the stat cards.
    Charts are loaded by JavaScript after the page renders.
    """
    stats         = db.get_device_stats()
    unread_alerts = db.get_unread_alert_count()
    return render_template("home.html", stats=stats, unread_alerts=unread_alerts, page="home")


@app.route("/devices")
def devices_page():
    """
    Device management page. Table rows are loaded by JavaScript.
    """
    unread_alerts = db.get_unread_alert_count()
    return render_template("devices.html", unread_alerts=unread_alerts, page="devices")


@app.route("/alerts")
def alerts_page():
    """
    Alert log page. Alerts are loaded by JavaScript via /api/alerts.
    """
    unread_alerts = db.get_unread_alert_count()
    return render_template("alerts.html", unread_alerts=unread_alerts, page="alerts")


@app.route("/history")
def history_page():
    """
    Scan history page — was a 404. Now fixed.
    Data loaded by JS from /api/scan-history.
    """
    unread_alerts = db.get_unread_alert_count()
    return render_template("history.html", unread_alerts=unread_alerts, page="history")


# =============================================================================
# SECTION 2 — DEVICE API
# =============================================================================

@app.route("/api/devices")
def api_devices():
    """
    GET /api/devices
    Returns all devices from the DB as JSON.
    Called by devices.html on load and every 30 seconds.
    """
    devices = db.get_all_devices()

    # Convert datetime objects → ISO strings for JSON serialisation
    # INTERVIEW: Python's json module doesn't know how to serialise datetime.
    # We have to do it manually, or use a library like Flask-Marshmallow.
    for d in devices:
        for field in ("first_seen", "last_seen"):
            if isinstance(d.get(field), datetime):
                d[field] = d[field].isoformat()

    return jsonify({"success": True, "devices": devices, "count": len(devices)})


@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_block_device(mac):
    """
    POST /api/devices/<mac>/block
    Body: {"blocked": true|false}

    WHY POST and not GET /api/block/<ip>?
    → GET must be safe (no side effects). Blocking a device changes DB state
      and should trigger an alert — definitely a side effect.
      Using POST also prevents CSRF via <img> or link prefetching.
    WHY MAC not IP?
    → IPs change (DHCP). MAC addresses are tied to the hardware NIC and are
      the stable identifier used in our devices table.
    """
    data    = request.get_json(silent=True) or {}   # silent=True: return None on bad JSON
    blocked = bool(data.get("blocked", True))

    # Normalise MAC to uppercase (our DB stores them in AA:BB:CC format)
    mac_upper = mac.upper()
    success   = db.set_device_blocked(mac=mac_upper, blocked=blocked)

    if success:
        action = "blocked" if blocked else "unblocked"
        device = db.get_device_by_mac(mac_upper)
        if device:
            db.create_alert(
                alert_type  = "blocked_attempt" if blocked else "new_device",
                device_mac  = mac_upper,
                device_ip   = device.get("ip", ""),
                device_name = device.get("hostname", "Unknown"),
                message     = f"Admin manually {action} device: {device.get('vendor','Unknown')} ({device.get('ip','')})",
                severity    = "warning" if blocked else "info"
            )
        return jsonify({"success": True, "message": f"Device {action}", "mac": mac_upper})

    return jsonify({"success": False, "message": "Device not found or DB error"}), 404


# =============================================================================
# SECTION 3 — SCANNER API
# =============================================================================

@app.route("/api/scan-status")
def api_scan_status():
    """
    GET /api/scan-status
    Returns scanner state: running, last_scan time, total scans, etc.
    Polled by the navbar pill and dashboard "Last scan" text.
    """
    status = get_scan_status()
    return jsonify({"success": True, **status})


@app.route("/api/scan/trigger", methods=["POST"])
def api_trigger_scan():
    """
    POST /api/scan/trigger
    Starts an immediate on-demand scan in a background thread.
    Returns immediately; JS polls /api/scan-status to know when it finishes.
    Returns 409 Conflict if a scan is already running.
    """
    started = trigger_manual_scan()
    if started:
        return jsonify({"success": True, "message": "Manual scan started"})
    return jsonify({"success": False, "message": "Scan already running"}), 409


@app.route("/api/scan-history")
def api_scan_history():
    """
    GET /api/scan-history?limit=50
    Returns recent scan records for the History page table.
    """
    limit   = request.args.get("limit", 50, type=int)
    limit   = max(1, min(limit, 500))   # Clamp 1–500
    records = db.get_scan_history(limit=limit)

    # Serialise datetimes
    for r in records:
        if isinstance(r.get("scan_time"), datetime):
            r["scan_time"] = r["scan_time"].isoformat()

    return jsonify({"success": True, "records": records, "count": len(records)})


# =============================================================================
# SECTION 4 — CHART API
# =============================================================================

@app.route("/api/chart/scan-history")
def api_chart_scan_history():
    """
    GET /api/chart/scan-history?hours=24
    Returns time-series for the line chart.
    """
    hours = request.args.get("hours", 24, type=int)
    hours = max(1, min(hours, 168))   # 1 hour → 7 days

    rows          = db.get_scan_history_for_chart(hours=hours)
    labels        = [row["label"]         for row in rows]
    devices_found = [row["devices_found"] for row in rows]
    new_devices   = [row["new_devices"]   for row in rows]

    return jsonify({
        "success":       True,
        "hours":         hours,
        "labels":        labels,
        "devices_found": devices_found,
        "new_devices":   new_devices,
    })


@app.route("/api/chart/device-status")
def api_chart_device_status():
    """
    GET /api/chart/device-status
    Returns [online, offline, blocked] counts for the doughnut chart.
    """
    stats = db.get_device_stats()
    return jsonify({
        "success": True,
        "labels":  ["Online", "Offline", "Blocked"],
        "data":    [stats["online"], stats["offline"], stats["blocked"]],
    })


@app.route("/api/chart/alerts")
def api_chart_alerts():
    """
    GET /api/chart/alerts?days=7
    Returns daily alert counts by type for the stacked bar chart.
    """
    days = request.args.get("days", 7, type=int)
    days = max(1, min(days, 30))

    rows            = db.get_alerts_for_chart(days=days)
    labels          = [str(row["day"])                       for row in rows]
    new_device      = [int(row["new_device"]      or 0)     for row in rows]
    blocked_attempt = [int(row["blocked_attempt"] or 0)     for row in rows]
    device_offline  = [int(row["device_offline"]  or 0)     for row in rows]
    high_risk       = [int(row["high_risk"]        or 0)    for row in rows]

    return jsonify({
        "success":         True,
        "days":            days,
        "labels":          labels,
        "new_device":      new_device,
        "blocked_attempt": blocked_attempt,
        "device_offline":  device_offline,
        "high_risk":       high_risk,
    })


@app.route("/api/chart/risk-breakdown")
def api_chart_risk_breakdown():
    """
    GET /api/chart/risk-breakdown
    Returns device counts by risk level for the risk doughnut chart.
    """
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
# SECTION 5 — ALERT API
# =============================================================================

@app.route("/api/alerts")
def api_alerts():
    """
    GET /api/alerts?limit=50&unread_only=false
    Returns alert objects as JSON.
    Called by alerts.html and the dashboard.
    """
    limit       = request.args.get("limit", 50,  type=int)
    unread_only = request.args.get("unread_only", "false").lower() == "true"
    alerts      = db.get_alerts(limit=limit, unread_only=unread_only)

    # Serialise datetimes
    for a in alerts:
        if isinstance(a.get("alert_time"), datetime):
            a["alert_time"] = a["alert_time"].isoformat()

    return jsonify({"success": True, "alerts": alerts, "count": len(alerts)})


@app.route("/api/alerts/unread-count")
def api_unread_count():
    """
    GET /api/alerts/unread-count
    Returns {"count": N} — tiny payload for the navbar badge.
    Separate endpoint so we don't download full alert objects just to
    update a badge number.
    """
    return jsonify({"success": True, "count": db.get_unread_alert_count()})


@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
def api_mark_alert_read(alert_id):
    """
    POST /api/alerts/<id>/read
    Marks one alert as read (is_read = 1).
    """
    success = db.mark_alert_read(alert_id)
    return jsonify({"success": success})


@app.route("/api/alerts/read-all", methods=["POST"])
def api_mark_all_read():
    """
    POST /api/alerts/read-all
    Marks all unread alerts as read.
    Returns how many were updated.
    """
    count = db.mark_all_alerts_read()
    return jsonify({"success": True, "cleared": count})


# =============================================================================
# SECTION 6 — STATUS / HEALTH
# =============================================================================

@app.route("/api/status")
def api_status():
    """
    GET /api/status
    Combined system health: scanner + DB + version.
    Useful for uptime monitoring / health-check endpoints in production.
    INTERVIEW: In production you'd add this to your load balancer health check
    so it can route traffic away from unhealthy instances.
    """
    return jsonify({
        "success":  True,
        "scanner":  get_scan_status(),
        "database": db.get_db_status(),
        "version":  "1.5.0",
    })


# =============================================================================
# SECTION 7 — ERROR HANDLERS
# =============================================================================
# Flask catches unhandled exceptions and calls these.
# Without custom handlers, Flask would serve its own HTML error pages —
# which look ugly and may leak stack traces in production.

@app.errorhandler(404)
def not_found(e):
    """404: page or API route doesn't exist."""
    # If it's an API request (Accept: application/json), return JSON error
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Endpoint not found", "code": 404}), 404
    return render_template("base.html", error="404 — Page not found", page="error"), 404


@app.errorhandler(500)
def server_error(e):
    """500: unhandled exception in a route."""
    logger.error("Unhandled 500: %s", e, exc_info=True)
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Internal server error", "code": 500}), 500
    return render_template("base.html", error="500 — Internal server error", page="error"), 500


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    # host="0.0.0.0" = listen on all network interfaces (not just 127.0.0.1)
    # This makes the app accessible from other devices on the same LAN.
    # INTERVIEW: What's the difference between 0.0.0.0 and 127.0.0.1?
    # → 127.0.0.1 (localhost) only accepts connections from the same machine.
    #   0.0.0.0 binds to all interfaces so other machines on the network can reach it.
    #   In production you'd put Nginx or a reverse proxy in front and have Flask
    #   listen only on localhost.
    #
    # debug=True: enables auto-reload + interactive debugger.
    # NEVER use debug=True in production — it exposes a Python REPL to anyone
    # who can trigger a 500 error. The Debugger PIN in the logs is NOT enough protection.
    app.run(
        host  = "0.0.0.0",
        port  = 5000,
        debug = True    # ← Set to False (or read from ENV) before deploying!
    )
