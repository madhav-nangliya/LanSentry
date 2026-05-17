from flask import Flask, render_template, jsonify

# Import all the functions we need from scanner.py
from scanner import (
    scan_network,           # Returns cached device list instantly
    get_alerts,             # Returns alert log
    check_for_alerts,       # Checks for new unknown devices
    block_device,           # Blocks a device via Windows Firewall
    unblock_device,         # Unblocks a device
    get_blocked_devices,    # Returns list of blocked IPs
    start_background_scanner # Starts the background scanning thread
)

# Create the Flask web app
# __name__ tells Flask where this file is located
app = Flask(__name__)


# ══════════════════════════════════════════════════════
# PAGE ROUTES
# Each route is a URL that shows an HTML page
# ══════════════════════════════════════════════════════

@app.route('/')
def home():
    """
    Home page — shows overview stats and quick device list.
    Reads from cache so it loads instantly.
    """
    devices = scan_network()  # Gets cached results (instant!)
    return render_template('home.html', devices=devices, device_count=len(devices))


@app.route('/devices')
def devices():
    """
    Devices page — shows full table of all connected devices.
    Reads from cache so it loads instantly.
    """
    device_list = scan_network()  # Gets cached results (instant!)
    return render_template('devices.html', devices=device_list)


@app.route('/alerts')
def alerts():
    """
    Alerts page — shows log of unknown devices detected.
    """
    alert_list = get_alerts()
    return render_template('alerts.html', alerts=alert_list)


# ══════════════════════════════════════════════════════
# API ROUTES
# These return JSON data (used by JavaScript on the frontend)
# ══════════════════════════════════════════════════════

@app.route('/api/devices')
def api_devices():
    """
    Returns all devices as JSON.
    Called by JavaScript every 30 seconds to auto-refresh the table.
    """
    device_list = scan_network()  # Gets cached results (instant!)
    return jsonify(device_list)   # Convert Python list to JSON


@app.route('/api/alerts')
def api_alerts():
    """
    Returns all alerts as JSON.
    Called by JavaScript to update the alert badge in the navbar.
    """
    return jsonify(get_alerts())


@app.route('/api/block/<ip>')
def api_block(ip):
    """
    Blocks a device by its IP address.
    Called by JavaScript when user clicks the Block button.
    <ip> in the URL gets passed as a variable to the function.
    Example: /api/block/192.168.43.5 → ip = '192.168.43.5'
    """
    result = block_device(ip)
    return jsonify(result)  # Returns {success: True/False, message: '...'}


@app.route('/api/unblock/<ip>')
def api_unblock(ip):
    """
    Unblocks a device by its IP address.
    Called by JavaScript when user clicks the Unblock button.
    """
    result = unblock_device(ip)
    return jsonify(result)


@app.route('/api/blocked')
def api_blocked():
    """
    Returns list of all currently blocked IPs.
    """
    return jsonify(get_blocked_devices())


# ══════════════════════════════════════════════════════
# START THE APP
# ══════════════════════════════════════════════════════

if __name__ == "__main__":

    # Start the background scanner BEFORE the web server starts
    # This means by the time you open the browser, the first scan
    # is already running (or finished) in the background
    start_background_scanner()

    # Start the Flask web server
    # debug=True → shows helpful error messages during development
    # use_reloader=False → IMPORTANT! Without this, Flask starts TWO
    #   background threads instead of one, causing double scanning
    app.run(debug=True, use_reloader=False)