# =============================================================================
# scanner.py — LanSentry Network Scanner
# =============================================================================
# Runs nmap scans in a background thread, persists results to MySQL,
# and maintains an in-memory cache for fast API responses.
#
# FLOW:
#   startup (app.py)
#     → start_background_scanner()
#       → _background_scan_loop() [daemon thread]
#         → run_scan() every SCAN_INTERVAL seconds
#           → nmap → upsert_device → mark_devices_offline
#           → create_alert (new devices, blocked attempts, offline)
#           → save_scan_result → update scan_cache
#
# INTERVIEW: What is a daemon thread?
# → A thread marked daemon=True is automatically killed when the main
#   process exits. Without daemon=True, Python would wait for the thread
#   to finish before exiting, which would make Ctrl+C not work.
# =============================================================================

import nmap
import psutil
import threading
import time
import logging
import ipaddress
from datetime import datetime

from database import (
    upsert_device,
    mark_devices_offline,
    get_all_devices,
    save_scan_result,
    create_alert,
    get_device_by_mac,
)

logger = logging.getLogger("scanner")

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
SCAN_INTERVAL   = 60      # Seconds between automatic scans
SCAN_TIMEOUT    = 30      # Max seconds nmap waits per host
NMAP_ARGUMENTS  = "-sn"   # Ping scan: discover hosts without port scanning
                           # Add "-O" for OS detection (requires root/sudo)
                           # Add "-sV -p 1-1024" for service detection (much slower)

# In-memory cache — app.py reads from here for instant responses
# without a DB query on every poll.
scan_cache = {
    "devices":      [],     # List of device dicts from the latest scan
    "last_scan":    None,   # datetime of last completed scan
    "scan_running": False,  # True while nmap is running
    "total_scans":  0,      # Lifetime scan count (since startup)
    "last_error":   None,   # Last error string or None
    "subnet":       "",     # Which subnet was last scanned
}

# Thread lock: prevents a race condition where the background thread
# writes to scan_cache at the same time app.py reads it.
# INTERVIEW: What is a race condition?
# → Two threads read and write shared data concurrently in a way that
#   produces incorrect results. Example: thread A reads scan_running=False,
#   thread B sets it to True, thread A then starts a second scan because it
#   thinks none is running. The lock prevents this by making the read-check
#   and the write atomic (one thread at a time).
cache_lock = threading.Lock()


# =============================================================================
# SECTION 1 — SUBNET DETECTION
# =============================================================================

def detect_subnet():
    """
    Finds the local network's CIDR (e.g. "192.168.1.0/24") by inspecting
    active network interfaces via psutil.
    Falls back to "192.168.1.0/24" if detection fails.

    INTERVIEW: What is a CIDR?
    → Classless Inter-Domain Routing. "192.168.1.0/24" means:
      • Network: 192.168.1.0
      • /24 = 24-bit mask = 255.255.255.0
      • Host range: 192.168.1.1 – 192.168.1.254 (254 addresses)
      nmap scans all addresses in this range.
    """
    try:
        for iface_name, addrs in psutil.net_if_addrs().items():
            if "lo" in iface_name.lower():
                continue   # Skip loopback (127.x.x.x)
            for addr in addrs:
                if addr.family == 2 and addr.address and addr.netmask:
                    if addr.address.startswith("127."):
                        continue
                    network = ipaddress.ip_network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    subnet = str(network)
                    logger.info("Detected subnet: %s (via %s)", subnet, iface_name)
                    return subnet
    except Exception as err:
        logger.warning("Subnet detection failed: %s", err)

    logger.warning("Using fallback subnet 192.168.1.0/24")
    return "192.168.1.0/24"


# =============================================================================
# SECTION 2 — RISK CALCULATOR
# =============================================================================

def calculate_risk(open_ports_str, vendor, hostname):
    """
    Assigns a risk level ('low', 'medium', 'high') based on open ports
    and device identity.

    INTERVIEW: Is this a real vulnerability scanner?
    → No. It's a heuristic (rule-based educated guess). A real scanner
      would check CVE databases (Common Vulnerabilities and Exposures),
      service versions, SSL certificate expiry, etc.
      Tools like OpenVAS or Nessus do this properly.
      Our risk score is a first approximation to show the concept.
    """
    if open_ports_str and open_ports_str.strip():
        ports = [int(p.strip()) for p in open_ports_str.split(",") if p.strip().isdigit()]
    else:
        ports = []

    HIGH_RISK_PORTS = {21, 23, 3389, 5900, 4444, 6667}
    # 21=FTP (unencrypted), 23=Telnet (unencrypted shell),
    # 3389=RDP (frequent attack target), 5900=VNC,
    # 4444=Metasploit default, 6667=IRC (botnet C2)
    if any(p in HIGH_RISK_PORTS for p in ports):
        return "high"

    MEDIUM_RISK_PORTS = {22, 80, 443, 8080, 8443, 3306, 5432, 27017}
    # SSH/web are normal; DB ports exposed externally are concerning
    if any(p in MEDIUM_RISK_PORTS for p in ports):
        return "medium"
    if len(ports) > 5:
        return "medium"   # Many open ports = larger attack surface
    if vendor.lower() in ("unknown", "", "n/a"):
        return "medium"   # Unknown vendor could be rogue device

    return "low"


# =============================================================================
# SECTION 3 — CORE SCAN
# =============================================================================

def run_scan(subnet=None):
    """
    Performs one complete network scan cycle:
      1. Run nmap ping scan
      2. Parse results → device dicts
      3. Upsert each device to DB (with risk_level)
      4. Mark missing devices offline
      5. Create alerts for new/blocked/offline devices
      6. Save scan summary to scan_history
      7. Update in-memory cache
    Returns list of device dicts (empty list on error).
    """

    with cache_lock:
        scan_cache["scan_running"] = True
        scan_cache["last_error"]   = None

    scan_start = time.time()

    if subnet is None:
        subnet = detect_subnet()

    logger.info("Starting scan of %s", subnet)

    try:
        # ── Step 1: nmap ─────────────────────────────────────────────────
        # python-nmap is a wrapper around the nmap CLI binary.
        # It invokes nmap as a subprocess, captures XML output, and parses it.
        # INTERVIEW: Why use nmap instead of raw sockets?
        # → nmap has years of refinement for host discovery, fingerprinting,
        #   and handling edge cases (firewalls, rate limiting, etc.).
        #   Reimplementing that in Python would be weeks of work.
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments=NMAP_ARGUMENTS)

        # ── Step 2: Parse results ─────────────────────────────────────────
        devices_found    = []
        active_macs      = []
        new_device_count = 0

        for ip in nm.all_hosts():
            host_data = nm[ip]
            if host_data.state() != "up":
                continue

            # Extract hostname, MAC, vendor from nmap output
            hostname = host_data.hostname() or "Unknown"
            mac      = host_data['addresses'].get('mac', '').upper()
            vendor   = host_data.get('vendor', {}).get(mac, 'Unknown') if mac else 'Unknown'

            # If nmap didn't get a MAC (happens when scanning your own host,
            # or in non-root mode on some systems), synthesise a stable fake one.
            # INTERVIEW: Why do we need a MAC at all?
            # → It's our primary key in the devices table. IPs aren't stable.
            #   The fake MAC won't match real hardware but it's consistent across scans.
            if not mac:
                # Use IP octets: scanning 192.168.1.5 → "00:00:C0:A8:01:05"
                octets = ip.split('.')
                mac = f"00:00:{int(octets[0]):02X}:{int(octets[1]):02X}:{int(octets[2]):02X}:{int(octets[3]):02X}"

            # Extract open ports (only populated if using -sV or -p, not -sn)
            open_ports = ""
            if "tcp" in host_data:
                open_ports = ",".join(str(p) for p in host_data["tcp"].keys())

            # ── Step 3: Calculate risk ────────────────────────────────────
            risk = calculate_risk(open_ports, vendor, hostname)

            device = {
                "ip":         ip,
                "mac":        mac,
                "hostname":   hostname,
                "vendor":     vendor,
                "open_ports": open_ports,
                "status":     "online",
                "risk_level": risk,
                "scan_time":  datetime.now().strftime("%H:%M:%S"),
            }
            devices_found.append(device)

            # ── Step 3: Upsert to DB ──────────────────────────────────────
            # FIX: Pass risk_level to upsert_device (was missing before,
            # so risk was calculated but never saved).
            row_id, is_new = upsert_device(
                mac        = mac,
                ip         = ip,
                hostname   = hostname,
                vendor     = vendor,
                open_ports = open_ports,
                status     = "online",
                risk_level = risk,    # ← THE FIX
            )

            active_macs.append(mac)

            # Alert for new device
            if is_new:
                new_device_count += 1
                create_alert(
                    alert_type  = "new_device",
                    device_mac  = mac,
                    device_ip   = ip,
                    device_name = hostname if hostname != "Unknown" else vendor,
                    message     = f"New device: {vendor} at {ip} — hostname: {hostname} — risk: {risk}",
                    severity    = "warning" if risk in ("medium", "high") else "info"
                )
                logger.info("New device: %s | %s | %s | risk=%s", mac, ip, vendor, risk)

                # Extra alert if the NEW device is already high-risk
                if risk == "high":
                    create_alert(
                        alert_type  = "high_risk",
                        device_mac  = mac,
                        device_ip   = ip,
                        device_name = hostname if hostname != "Unknown" else vendor,
                        message     = f"HIGH RISK new device detected: {vendor} ({ip}) — open ports: {open_ports}",
                        severity    = "critical"
                    )

            # Alert if a blocked device is seen on the network
            db_device = get_device_by_mac(mac)
            if db_device and db_device.get("is_blocked"):
                create_alert(
                    alert_type  = "blocked_attempt",
                    device_mac  = mac,
                    device_ip   = ip,
                    device_name = hostname if hostname != "Unknown" else vendor,
                    message     = f"BLOCKED device active on network: {vendor} ({ip})",
                    severity    = "critical"
                )
                logger.warning("Blocked device detected: %s (%s)", mac, ip)

        # ── Step 4: Mark missing devices offline ──────────────────────────
        mark_devices_offline(active_macs)

        # ── Step 5: Alert for devices that just went offline ──────────────
        all_db_devices = get_all_devices()
        for db_dev in all_db_devices:
            if db_dev["status"] == "offline" and db_dev["mac"] not in active_macs:
                last_seen_ts = db_dev["last_seen"]
                if isinstance(last_seen_ts, datetime):
                    seconds_ago = (datetime.now() - last_seen_ts).total_seconds()
                    # Only alert once per offline event (within 2 scan intervals)
                    if seconds_ago < SCAN_INTERVAL * 2:
                        create_alert(
                            alert_type  = "device_offline",
                            device_mac  = db_dev["mac"],
                            device_ip   = db_dev["ip"],
                            device_name = db_dev["hostname"],
                            message     = f"Device went offline: {db_dev['hostname']} ({db_dev['ip']})",
                            severity    = "info"
                        )

        # ── Step 6: Save scan summary ─────────────────────────────────────
        scan_duration = round(time.time() - scan_start, 2)
        save_scan_result(
            devices_found  = len(devices_found),
            new_devices    = new_device_count,
            scan_duration  = scan_duration,
            subnet         = subnet,
        )

        # ── Step 7: Update cache ──────────────────────────────────────────
        with cache_lock:
            scan_cache["devices"]      = devices_found
            scan_cache["last_scan"]    = datetime.now()
            scan_cache["scan_running"] = False
            scan_cache["total_scans"] += 1
            scan_cache["subnet"]       = subnet

        logger.info(
            "Scan complete — %d found, %d new | %.2fs",
            len(devices_found), new_device_count, scan_duration
        )
        return devices_found

    except Exception as err:
        # Broad catch so the background thread never silently dies.
        # exc_info=True logs the full traceback — essential for debugging.
        logger.error("Scan failed: %s", err, exc_info=True)
        with cache_lock:
            scan_cache["scan_running"] = False
            scan_cache["last_error"]   = str(err)
        return []


# =============================================================================
# SECTION 4 — BACKGROUND THREAD
# =============================================================================

def _background_scan_loop():
    """Runs forever in a daemon thread: scan → sleep → repeat."""
    logger.info("Background scanner started (interval=%ds)", SCAN_INTERVAL)
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL)


def start_background_scanner():
    """Spawns the background scan thread. Called once from app.py startup."""
    thread = threading.Thread(
        target = _background_scan_loop,
        name   = "LanSentry-Scanner",
        daemon = True,   # ← Dies automatically when Flask process exits
    )
    thread.start()
    logger.info("Scanner thread started (TID=%d)", thread.ident)
    return thread


# =============================================================================
# SECTION 5 — CACHE ACCESSORS
# =============================================================================

def get_cached_devices():
    """Thread-safe read of the latest device list from cache."""
    with cache_lock:
        return list(scan_cache["devices"])


def get_scan_status():
    """Returns a dict snapshot of the scanner state for /api/scan-status."""
    with cache_lock:
        return {
            "scan_running":  scan_cache["scan_running"],
            "last_scan":     scan_cache["last_scan"].isoformat() if scan_cache["last_scan"] else None,
            "device_count":  len(scan_cache["devices"]),
            "total_scans":   scan_cache["total_scans"],
            "last_error":    scan_cache["last_error"],
            "subnet":        scan_cache["subnet"],
            "scan_interval": SCAN_INTERVAL,
        }


def trigger_manual_scan(subnet=None):
    """
    Starts an immediate scan in a new thread.
    Returns False if a scan is already running.
    INTERVIEW: Why a new thread and not just run_scan() directly?
    → The HTTP request handler for POST /api/scan/trigger needs to return
      a response quickly. If we called run_scan() directly, the request would
      hang for 5–30 seconds while nmap runs. The new thread lets the response
      return immediately while the scan continues in the background.
    """
    with cache_lock:
        if scan_cache["scan_running"]:
            logger.warning("Manual scan requested but already running — skipped")
            return False

    thread = threading.Thread(
        target = run_scan,
        args   = (subnet,),
        name   = "LanSentry-ManualScan",
        daemon = True,
    )
    thread.start()
    logger.info("Manual scan triggered")
    return True
