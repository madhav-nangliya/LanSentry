from flask import Flask, render_template, jsonify
from scanner import (scan_network, get_alerts, check_for_alerts,
                     block_device, unblock_device, get_blocked_devices)

app = Flask(__name__)

@app.route('/')
def home():
    devices = scan_network()
    check_for_alerts(devices)
    return render_template('home.html', devices=devices, device_count=len(devices))

@app.route('/devices')
def devices():
    device_list = scan_network()
    check_for_alerts(device_list)
    return render_template('devices.html', devices=device_list)

@app.route('/alerts')
def alerts():
    alert_list = get_alerts()
    return render_template('alerts.html', alerts=alert_list)

@app.route('/api/devices')
def api_devices():
    device_list = scan_network()
    check_for_alerts(device_list)
    return jsonify(device_list)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_alerts())

# Block a device ──
@app.route('/api/block/<ip>')
def api_block(ip):
    result = block_device(ip)
    return jsonify(result)

# Unblock a device ──
@app.route('/api/unblock/<ip>')
def api_unblock(ip):
    result = unblock_device(ip)
    return jsonify(result)

# Get all blocked devices ──
@app.route('/api/blocked')
def api_blocked():
    return jsonify(get_blocked_devices())

if __name__ == "__main__":
    app.run(debug=True)