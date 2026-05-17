import nmap          # Lets us scan the network to find devices
import socket         # Lets us get our own IP address and device names
import subprocess     # Lets us run Windows system commands (like ipconfig, netsh)
import threading      # Lets us run the scanner in the background while the app runs
import time           # Lets us add delays (like waiting 30 seconds between scans)


# ══════════════════════════════════════════════════════
# SHARED DATA — these variables are used across the app
# ══════════════════════════════════════════════════════

# Stores IPs we've seen before — so we don't alert on them again
known_devices = set()

# Stores list of alert dictionaries when unknown devices are found
alert_log = []

# Stores IPs that have been blocked by the user
blocked_devices = set()

# Stores the most recent scan results so pages load instantly
# Instead of scanning every time, we just read this list
cached_devices = []

# Stores the timestamp of when the last scan finished
last_scan_time = 0

# A lock prevents two scans from writing to cached_devices at the same time
# Think of it like a "do not disturb" sign — only one scan writes at a time
scan_lock = threading.Lock()


# ══════════════════════════════════════════════════════
# HELPER FUNCTIONS — small utilities used by the scanner
# ══════════════════════════════════════════════════════

def get_local_ip():
    """
    Gets YOUR computer's IP address on the network.
    Example: 192.168.43.105
    """
    hostname = socket.gethostname()           # Gets your computer's name (e.g. MADHAV-PC)
    local_ip = socket.gethostbyname(hostname) # Converts name to IP address
    return local_ip


def get_network_range():
    """
    Builds the range of IPs to scan.
    Example: if your IP is 192.168.43.105
    This returns 192.168.43.0/24
    Which means: scan ALL 255 addresses on this network
    """
    local_ip = get_local_ip()

    # rsplit splits from the RIGHT at the dot, only once
    # '192.168.43.105'.rsplit('.', 1) → ['192.168.43', '105']
    # [0] takes the first part → '192.168.43'
    # + '.0/24' adds the range → '192.168.43.0/24'
    network_range = local_ip.rsplit('.', 1)[0] + '.0/24'
    return network_range


def get_hostname(ip):
    """
    Tries to find the name of a device from its IP address.
    Example: 192.168.43.1 → 'router.local'
    If it can't find a name, returns 'Unknown'
    """
    try:
        # gethostbyaddr does a reverse lookup — IP → name
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        # If lookup fails (most devices don't share their name), return Unknown
        return "Unknown"


def get_gateway_ip():
    """
    Finds your hotspot/router's IP address (called the gateway).
    The gateway is the device that connects you to the internet.
    We never want to block this device!

    We run 'ipconfig' (a Windows command) and read its output to find it.
    """
    try:
        # Run the 'ipconfig' command — same as typing it in CMD
        # capture_output=True means save the output so we can read it
        # text=True means give us the output as readable text (not bytes)
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True,
            text=True
        )

        # Split the output into individual lines so we can read them one by one
        lines = result.stdout.split('\n')

        # Go through each line with its index number
        for i, line in enumerate(lines):
            line_stripped = line.strip()  # Remove spaces from start and end

            # Look for the line that mentions "Default Gateway"
            if 'Default Gateway' in line_stripped:

                # Sometimes the IPv4 address is on the SAME line
                # Example: "Default Gateway . . . : 10.220.174.185"
                parts = line_stripped.split(':')
                if len(parts) >= 2:
                    gateway = parts[-1].strip()  # Take everything after the last colon
                    # Check it looks like an IPv4 address (starts with a number and has dots)
                    if gateway and gateway[0].isdigit() and '.' in gateway:
                        print(f"✅ Gateway detected (same line): {gateway}")
                        return gateway

                # Sometimes IPv6 is on the SAME line and IPv4 is on the NEXT line
                # Example:
                # "Default Gateway . . . : fe80::a046%17"   ← IPv6 (we skip this)
                # "                        10.220.174.185"  ← IPv4 (we want this)
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    # Check next line looks like IPv4
                    if next_line and next_line[0].isdigit() and '.' in next_line:
                        print(f"✅ Gateway detected (next line): {next_line}")
                        return next_line

        # If we couldn't find it, return None
        print("⚠️ Could not auto-detect gateway")
        return None

    except Exception as e:
        print(f"Gateway detection error: {e}")
        return None


# ══════════════════════════════════════════════════════
# CORE SCAN FUNCTION
# This does the actual network scanning work
# It runs in the background every 30 seconds
# ══════════════════════════════════════════════════════

def run_scan():
    """
    Scans the network and saves results to cached_devices.
    This is called by the background thread automatically.
    Pages read from cached_devices instead of scanning themselves.
    """

    # We use 'global' because we're modifying these variables
    # that were defined outside this function
    global cached_devices, last_scan_time

    # Get network info before scanning
    network_range = get_network_range()
    local_ip = get_local_ip()
    gateway_ip = get_gateway_ip()

    print(f"\n🔍 Background scan starting...")
    print(f"   Your IP : {local_ip}")
    print(f"   Gateway : {gateway_ip or 'Not detected'}")
    print(f"   Range   : {network_range}\n")

    try:
        # Create the Nmap scanner object
        nm = nmap.PortScanner()

        # Run the scan
        # -sn        → ping scan only, don't scan ports (much faster)
        # --host-timeout 10s → skip any device that doesn't respond in 10 seconds
        nm.scan(hosts=network_range, arguments='-sn --host-timeout 10s')

        # Empty list to store devices we find
        devices = []

        # Loop through every IP address that responded to our scan
        for host in nm.all_hosts():

            # Try to get MAC address — only works on Ethernet, not WiFi usually
            mac = nm[host]['addresses'].get('mac', 'N/A')

            # Try to get hostname from Nmap first
            hostname = nm[host].hostname()

            # If Nmap couldn't find it, try Python's own method
            if not hostname:
                hostname = get_hostname(host)

            # Give special labels to important devices
            if host == local_ip:
                # This is YOUR computer
                hostname = socket.gethostname() + " (You)"

            elif gateway_ip and host == gateway_ip:
                # This is your hotspot/router
                hostname = "My Hotspot/Router (Gateway)"

            # Build a dictionary for this device with all its info
            device = {
                'ip'        : host,
                'status'    : nm[host].state(),  # 'up' or 'down'
                'hostname'  : hostname,
                'mac'       : mac,
                'blocked'   : host in blocked_devices,  # True if user blocked it
                'is_gateway': gateway_ip is not None and host == gateway_ip,
                'is_me'     : host == local_ip
            }

            # Add this device to our list
            devices.append(device)

        # Save results to cache
        # 'with scan_lock' means: lock the cache while we write to it
        # so no other thread can read half-written data
        with scan_lock:
            cached_devices = devices
            last_scan_time = time.time()  # Record when this scan finished

        print(f"✅ Scan complete — {len(devices)} devices found\n")

        # Check if any new unknown devices appeared
        check_for_alerts(devices)

    except Exception as e:
        print(f"❌ Scan error: {e}")


# ══════════════════════════════════════════════════════
# PUBLIC FUNCTION — called by Flask routes to get devices
# ══════════════════════════════════════════════════════

def scan_network():
    """
    Returns the list of devices from the cache instantly.
    If cache is empty (very first run), waits for one scan to finish.

    This is what Flask calls when a page needs device data.
    Instead of scanning right then, it just reads the cached results.
    """

    # Check if we have cached results
    with scan_lock:
        if cached_devices:
            # Cache has data — return it instantly! ⚡
            return cached_devices

    # Cache is empty — this only happens on the very first startup
    # Wait for one scan to finish before returning
    print("⏳ First scan in progress, please wait...")
    run_scan()
    return cached_devices


# ══════════════════════════════════════════════════════
# BACKGROUND THREAD FUNCTIONS
# These run the scanner automatically in the background
# ══════════════════════════════════════════════════════

def background_scanner():
    """
    Runs forever in the background:
    1. Scans immediately when app starts
    2. Waits 30 seconds
    3. Scans again
    4. Repeat forever
    """
    print("🚀 Background scanner started!")

    # First scan immediately so cache has data right away
    run_scan()

    # Then keep scanning every 30 seconds forever
    while True:
        time.sleep(30)  # Wait 30 seconds
        run_scan()      # Scan again


def start_background_scanner():
    """
    Creates and starts the background scanner thread.
    Called once when the Flask app starts.

    threading.Thread creates a new thread (like a parallel worker)
    daemon=True means the thread automatically stops when the main app stops
    """
    thread = threading.Thread(target=background_scanner, daemon=True)
    thread.start()
    print("✅ Background scanner thread started")


# ══════════════════════════════════════════════════════
# ALERT SYSTEM
# ══════════════════════════════════════════════════════

def check_for_alerts(devices):
    """
    Checks if any device in the scan is new/unknown.
    If yes, adds it to the alert log.
    Never alerts on your own device or your gateway.
    """
    global known_devices, alert_log

    my_ip = get_local_ip()
    gateway_ip = get_gateway_ip()

    for device in devices:
        ip = device['ip']

        # Skip your own device and your gateway — never flag these
        if ip == my_ip or (gateway_ip and ip == gateway_ip):
            known_devices.add(ip)  # Add to known so we don't check again
            continue

        # If we've never seen this IP before
        if ip not in known_devices:

            # Only alert if this isn't the very first scan
            # (first scan just learns what's on the network)
            if len(known_devices) > 0:
                alert = {
                    'ip'      : ip,
                    'hostname': device['hostname'],
                    'message' : f"New unknown device joined the network: {ip}"
                }
                alert_log.append(alert)
                print(f"🚨 ALERT: New device detected — {ip}")

            # Add to known devices so we don't alert on it again
            known_devices.add(ip)


def get_alerts():
    """Returns the full list of alerts."""
    return alert_log


# ══════════════════════════════════════════════════════
# BLOCK / UNBLOCK SYSTEM
# Uses Windows Firewall to block devices
# ══════════════════════════════════════════════════════

def block_device(ip):
    """
    Blocks a device by adding a Windows Firewall rule.
    The rule tells Windows to drop all traffic from that IP.
    Also updates the cache immediately so the UI shows 'Blocked' right away.
    """

    gateway_ip = get_gateway_ip()
    my_ip = get_local_ip()

    # Safety checks — never allow blocking protected devices
    if ip == my_ip:
        return {'success': False, 'message': 'Cannot block your own device!'}

    if gateway_ip and ip == gateway_ip:
        return {'success': False, 'message': 'Cannot block your gateway — you would lose internet!'}

    try:
        # Build the netsh command to add a firewall rule
        # netsh advfirewall → Windows advanced firewall tool
        # firewall add rule → add a new rule
        # name=NETWATCH_BLOCK_x.x.x.x → rule name (so we can find/delete it later)
        # dir=in → block incoming traffic from this device
        # action=block → the action is to block (not allow)
        # remoteip=x.x.x.x → the IP to block
        command = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=NETWATCH_BLOCK_{ip}',
            'dir=in',
            'action=block',
            f'remoteip={ip}'
        ]

        # Run the command
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            # Command succeeded — add to our blocked set
            blocked_devices.add(ip)

            # Update the cache immediately so UI shows 'Blocked' without waiting for next scan
            with scan_lock:
                for device in cached_devices:
                    if device['ip'] == ip:
                        device['blocked'] = True

            print(f"🚫 Blocked: {ip}")
            return {'success': True, 'message': f'{ip} has been blocked'}
        else:
            return {'success': False, 'message': f'Firewall error: {result.stderr}'}

    except Exception as e:
        return {'success': False, 'message': str(e)}


def unblock_device(ip):
    """
    Unblocks a device by removing its Windows Firewall rule.
    Also updates the cache immediately.
    """
    try:
        # Delete the firewall rule we created earlier
        command = [
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name=NETWATCH_BLOCK_{ip}'
        ]

        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            # Command succeeded — remove from our blocked set
            # discard() is like remove() but doesn't crash if IP isn't in the set
            blocked_devices.discard(ip)

            # Update the cache immediately
            with scan_lock:
                for device in cached_devices:
                    if device['ip'] == ip:
                        device['blocked'] = False

            print(f"✅ Unblocked: {ip}")
            return {'success': True, 'message': f'{ip} has been unblocked'}
        else:
            return {'success': False, 'message': f'Error: {result.stderr}'}

    except Exception as e:
        return {'success': False, 'message': str(e)}


def get_blocked_devices():
    """Returns list of all currently blocked IPs."""
    return list(blocked_devices)