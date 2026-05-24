# ============================================================
# app.py — Flask web server for LanSentry
#
# This file is the 'Controller' of our app:
# - Receives requests from the browser
# - Calls scanner.py or database.py to get data
# - Returns HTML pages or JSON data
# ============================================================

from flask import Flask, render_template, jsonify

# Import scanner functions
from scanner import (
    scan_network,             # Returns cached device list (instant)
    get_alerts,               # Returns alert log
    check_for_alerts,         # Checks for new unknown devices
    block_device,             # Blocks a device via Windows Firewall
    unblock_device,           # Unblocks a device
    get_blocked_devices,      # Returns list of blocked IPs
    start_background_scanner  # Starts the background scan thread
)

# Import database functions
from database import (
    create_tables,      # Creates MySQL tables on startup
    get_scan_history,   # Returns list of past scans
    get_scan_devices,   # Returns devices for a specific scan
    get_chart_data,     # Returns data for Chart.js graphs
    get_total_stats     # Returns overall stats (total scans etc)
)

# Create the Flask web application
# __name__ tells Flask the location of this file
app = Flask(__name__)


# ============================================================
# PAGE ROUTES — return HTML pages
# Each @app.route() listens for a specific URL
# ============================================================

@app.route('/')
def home():
    """
    Home page — shows overview dashboard with stats and charts.
    
    Data passed to template:
    - devices: current connected devices (from cache)
    - device_count: how many devices are online
    - chart_data: 7 days of scan data for Chart.js
    - stats: total scans, unique devices etc
    """
    # Get current devices from cache (instant ⚡)
    devices = scan_network()
    
    # Get chart data for the last 7 days
    # This is used by Chart.js to draw the line graph
    chart_data = get_chart_data(days=7)
    
    # Get overall statistics for the stat cards
    stats = get_total_stats()
    
    return render_template(
        'home.html',
        devices=devices,
        device_count=len(devices),
        chart_data=chart_data,      # Passed to Jinja2 template
        stats=stats
    )


@app.route('/devices')
def devices():
    """
    Devices page — shows full table of all connected devices.
    Reads from cache so loads instantly.
    """
    device_list = scan_network()
    return render_template('devices.html', devices=device_list)


@app.route('/alerts')
def alerts():
    """
    Alerts page — shows log of unknown devices detected.
    """
    alert_list = get_alerts()
    return render_template('alerts.html', alerts=alert_list)


@app.route('/history')
def history():
    """
    History page — shows list of all past scans from database.
    User can click any scan to see which devices were online.
    """
    # Get 20 most recent scans from database
    scan_list = get_scan_history(limit=20)
    return render_template('history.html', scans=scan_list)


@app.route('/history/<int:scan_id>')
def history_detail(scan_id):
    """
    History detail page — shows devices found in ONE specific scan.
    
    <int:scan_id> in the URL is a variable:
    - /history/1 → scan_id = 1
    - /history/42 → scan_id = 42
    - 'int:' means Flask will only accept integer values here
    """
    # Get all devices found in this specific scan
    device_list = get_scan_devices(scan_id)
    return render_template(
        'history_detail.html',
        devices=device_list,
        scan_id=scan_id
    )


# ============================================================
# API ROUTES — return JSON data
# Called by JavaScript running in the browser
# ============================================================

@app.route('/api/devices')
def api_devices():
    """
    Returns current device list as JSON.
    Called by JavaScript every 30 seconds to auto-refresh table.
    
    Returns:
        JSON array of device objects
    """
    device_list = scan_network()   # From cache (instant ⚡)
    return jsonify(device_list)    # Convert Python list → JSON


@app.route('/api/alerts')
def api_alerts():
    """
    Returns alert list as JSON.
    Called by JavaScript to update the alert badge in navbar.
    """
    return jsonify(get_alerts())


@app.route('/api/block/<ip>')
def api_block(ip):
    """
    Blocks a device by its IP address.
    Called when user clicks the Block button.
    
    URL example: /api/block/192.168.1.9
    → ip = '192.168.1.9'
    
    Returns:
        JSON: {'success': True, 'message': '...'}
    """
    result = block_device(ip)
    return jsonify(result)


@app.route('/api/unblock/<ip>')
def api_unblock(ip):
    """
    Unblocks a device by its IP address.
    Called when user clicks the Unblock button.
    """
    result = unblock_device(ip)
    return jsonify(result)


@app.route('/api/blocked')
def api_blocked():
    """Returns list of all currently blocked IPs."""
    return jsonify(get_blocked_devices())


@app.route('/api/chart')
def api_chart():
    """
    Returns 7 days of chart data as JSON.
    Called by Chart.js in the browser to draw graphs.
    
    Returns JSON like:
    {
        "labels": ["Jan 10", "Jan 11", ...],
        "counts": [3, 4, 3, ...]
    }
    """
    chart_data = get_chart_data(days=7)
    return jsonify(chart_data)


@app.route('/api/stats')
def api_stats():
    """
    Returns overall statistics as JSON.
    Used to update stat cards on home page.
    """
    stats = get_total_stats()
    return jsonify(stats)


# ============================================================
# START THE APPLICATION
# This block only runs when you type: python app.py
# It does NOT run if app.py is imported by another file
# ============================================================

if __name__ == "__main__":
    
    # ── Step 1: Create database tables ──
    # Creates 'scans' and 'devices' tables if they don't exist yet
    # Safe to run every startup — won't duplicate tables
    print("🗄️ Setting up database...")
    create_tables()
    
    # ── Step 2: Start background scanner ──
    # Begins scanning network in background thread
    # Must start BEFORE Flask so first scan runs during startup
    print("📡 Starting background scanner...")
    start_background_scanner()
    
    # ── Step 3: Start Flask web server ──
    # debug=True → show detailed error messages during development
    # use_reloader=False → IMPORTANT! Without this, Flask starts
    #   TWO background threads instead of one (causes double scanning)
    print("🌐 Starting web server...")
    app.run(debug=True, use_reloader=False)