# =============================================================================
# scanner.py — LanSentry Network Scanner (Week 4: DB Integration)
# =============================================================================
# This file runs the actual network scanning logic.
# Week 3: returned raw dicts held in memory.
# Week 4 additions (marked ★):
#   ★ Saves every scan result to scan_history table
#   ★ Upserts every device to devices table
#   ★ Marks vanished devices as offline
#   ★ Creates alerts for new devices, offline events, blocked attempts
#   ★ Calculates a simple risk score per device
# =============================================================================

import nmap                    # python-nmap: wraps the nmap CLI tool
import psutil                  # System/network info — used to auto-detect subnet
import threading               # Run scans in a background thread
import time                    # Timing scans + sleep between scans
import logging                 # Log scan events to file/console
import ipaddress               # Parse and validate IP/CIDR ranges
from datetime import datetime  # Timestamps

# import all database helpers we need
from database import (
    upsert_device,
    mark_devices_offline,
    get_all_devices,
    save_scan_result,
    create_alert,
    get_device_by_mac,
)

# ---------------------------------------------------------------------------
# Logger — separate name so we can filter scanner logs in the log file
# ---------------------------------------------------------------------------
logger = logging.getLogger("scanner")

# ---------------------------------------------------------------------------
# SCANNER CONFIGURATION
# ---------------------------------------------------------------------------
SCAN_INTERVAL   = 60      # Seconds between automatic background scans
SCAN_TIMEOUT    = 30      # Max seconds nmap waits per host
NMAP_ARGUMENTS  = "-sn"   # Ping scan: discover hosts without port scanning
                           # Add "-O" for OS detection (requires root)
                           # Add "-sV" for service/version detection (slower)

# This in-memory dict is the "live view" cache.
# app.py reads from here for instant responses without hitting the DB.
scan_cache = {
    "devices":      [],           # List of device dicts from the latest scan
    "last_scan":    None,         # datetime of last completed scan
    "scan_running": False,        # True while a scan is in progress
    "total_scans":  0,            # How many scans have run since startup
    "last_error":   None,         # Last error message (None = no error)
    "subnet":       "",           # Which subnet was last scanned
}

# Thread-safety lock — prevents race conditions when the background thread
# writes to scan_cache while app.py reads it simultaneously.
cache_lock = threading.Lock()   # acquire() before read/write, release() after


# =============================================================================
# SECTION 1 — SUBNET DETECTION
# =============================================================================

def detect_subnet():
    """
    Auto-detect the local network subnet by inspecting active interfaces.
    Returns a CIDR string like "192.168.1.0/24", or falls back to a default.

    Why not just scan "192.168.1.0/24" hardcoded?
    → Works on any network without manual configuration.
    """
    try:
        # psutil.net_if_addrs() returns a dict:
        # { 'eth0': [snicaddr(family, address, netmask, …), …], 'lo': […], … }
        for iface_name, iface_addresses in psutil.net_if_addrs().items():

            # Skip loopback interfaces (lo, lo0) — scanning 127.x.x.x is useless
            if "lo" in iface_name.lower():
                continue

            for addr in iface_addresses:
                # addr.family == 2 is AF_INET (IPv4).
                # We skip IPv6 (family 10/23) and link-layer (family 17/18).
                if addr.family == 2 and addr.address and addr.netmask:
                    ip   = addr.address    # e.g. "192.168.1.105"
                    mask = addr.netmask    # e.g. "255.255.255.0"

                    # Skip loopback address range even if not named "lo"
                    if ip.startswith("127."):
                        continue

                    # ipaddress.ip_network converts IP + mask → CIDR
                    # strict=False allows host bits to be set (e.g. 192.168.1.105/24)
                    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    subnet  = str(network)   # "192.168.1.0/24"

                    logger.info("🌐 Auto-detected subnet: %s (via %s)", subnet, iface_name)
                    return subnet

    except Exception as err:
        logger.warning("⚠️  Subnet detection failed: %s", err)

    # Fallback — common home/office default gateway subnet
    logger.warning("⚠️  Using fallback subnet 192.168.1.0/24")
    return "192.168.1.0/24"


# =============================================================================
# SECTION 2 — RISK CALCULATOR
# =============================================================================

def calculate_risk(open_ports_str, vendor, hostname):
    """
    Assign a simple risk level based on open ports and device identity.
    Returns 'low', 'medium', or 'high'.

    This is a heuristic — not a full vulnerability scanner.
    Extend this in Week 5 with CVE lookups or Shodan integration.

    open_ports_str — comma-separated port numbers e.g. "22,80,443,8080"
    vendor         — NIC manufacturer string
    hostname       — resolved hostname
    """

    # Parse the port string into a list of integers
    if open_ports_str and open_ports_str.strip():
        ports = [int(p.strip()) for p in open_ports_str.split(",") if p.strip().isdigit()]
    else:
        ports = []   # No open ports detected

    # --- High risk indicators ---
    HIGH_RISK_PORTS = {
        21,    # FTP — unencrypted file transfer
        23,    # Telnet — unencrypted shell
        3389,  # RDP — Remote Desktop (common attack target)
        5900,  # VNC — remote desktop
        4444,  # Metasploit default listener
        6667,  # IRC — often used by botnets
    }
    if any(p in HIGH_RISK_PORTS for p in ports):
        return "high"

    # --- Medium risk indicators ---
    MEDIUM_RISK_PORTS = {22, 80, 443, 8080, 8443, 3306, 5432, 27017}
    # SSH (22) and web servers are normal but worth noting
    # Database ports (3306=MySQL, 5432=Postgres, 27017=MongoDB) should NOT be open externally
    if any(p in MEDIUM_RISK_PORTS for p in ports):
        return "medium"

    # Devices with many open ports are higher risk regardless of which ports
    if len(ports) > 5:
        return "medium"

    # Unknown vendor = could be a rogue device
    if vendor.lower() in ("unknown", "", "n/a"):
        return "medium"

    return "low"   # Default: minimal exposure


# =============================================================================
# SECTION 3 — CORE SCAN FUNCTION
# =============================================================================

def run_scan(subnet=None):
    """
    Perform one full nmap ping scan of the given subnet.
    If subnet is None, auto-detects via detect_subnet().

    Flow:
      1. Run nmap -sn <subnet>
      2. Parse results into device dicts
      3. ★ Upsert each device into the DB
      4. ★ Mark missing devices offline
      5. ★ Create alerts for notable events
      6. ★ Save scan summary to scan_history
      7. Update the in-memory scan_cache
    """

    # ------------------------------------------------------------------
    # Step 0: Set scan_running flag so the UI can show a spinner
    # ------------------------------------------------------------------
    with cache_lock:
        scan_cache["scan_running"] = True
        scan_cache["last_error"]   = None

    scan_start = time.time()   # Record when scan began (for duration calculation)

    if subnet is None:
        subnet = detect_subnet()

    logger.info("🔍 Starting scan of %s", subnet)

    try:
        # ------------------------------------------------------------------
        # Step 1: Run nmap
        # nmap.PortScanner() is the python-nmap wrapper object.
        # .scan(hosts, arguments) runs the CLI command and parses XML output.
        # ------------------------------------------------------------------
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments=NMAP_ARGUMENTS)
        # nm.all_hosts() now returns a list of IP strings that responded

        # ------------------------------------------------------------------
        # Step 2: Parse nmap results into device dicts
        # ------------------------------------------------------------------
        devices_found   = []   # Will hold one dict per discovered device
        active_macs     = []   # ★ Track MACs for mark_devices_offline()
        new_device_count = 0   # ★ Count new devices for scan_history

        for ip in nm.all_hosts():
            host_data = nm[ip]   # nmap.PortScannerHostDict for this IP

            # Skip hosts that nmap reports as 'down' (rare in -sn but possible)
            if host_data.state() != "up":
                continue

            # Extract hostname — nmap may resolve it, default to 'Unknown'
            hostnames = host_data.hostname()    # Returns string or ''
            hostname  = hostnames if hostnames else "Unknown"

            # Extract MAC address and vendor (only available if running as root)
            # nmap stores these under host_data['addresses'] and host_data['vendor']
            mac    = host_data['addresses'].get('mac', '').upper()
            vendor = "Unknown"
            if mac and mac in host_data.get('vendor', {}):
                vendor = host_data['vendor'][mac]

            # If nmap didn't get a MAC (non-root scan or same-host), derive a
            # fake one from the IP so we still have a stable unique identifier.
            if not mac:
                mac = f"00:00:{ip.replace('.', ':')}"   # Fake MAC — NOT real hardware
                logger.debug("No MAC for %s — using synthetic ID %s", ip, mac)

            # Extract open ports (nmap -sn doesn't scan ports, but -sV/-p would)
            open_ports = ""
            if "tcp" in host_data:
                open_ports = ",".join(str(p) for p in host_data["tcp"].keys())

            # ★ Calculate risk score for this device
            risk = calculate_risk(open_ports, vendor, hostname)

            # Build the device dict for this host
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

            # ★ Step 3: Upsert into the DB
            row_id, is_new = upsert_device(
                mac=mac,
                ip=ip,
                hostname=hostname,
                vendor=vendor,
                open_ports=open_ports,
                status="online"
            )

            active_macs.append(mac)   # Track MAC as active in this scan

            # ★ Create a 'new_device' alert if this MAC has never been seen
            if is_new:
                new_device_count += 1
                create_alert(
                    alert_type  = "new_device",
                    device_mac  = mac,
                    device_ip   = ip,
                    device_name = hostname if hostname != "Unknown" else vendor,
                    message     = f"New device discovered: {vendor} ({ip}) — {hostname}",
                    severity    = "warning" if risk in ("medium", "high") else "info"
                )
                logger.info("🆕 New device: %s | %s | %s | Risk: %s", mac, ip, vendor, risk)

            # ★ Alert if a blocked device was detected on the network
            # (It shouldn't be here — maybe firewall rule failed)
            db_device = get_device_by_mac(mac)
            if db_device and db_device.get("is_blocked"):
                create_alert(
                    alert_type  = "blocked_attempt",
                    device_mac  = mac,
                    device_ip   = ip,
                    device_name = hostname if hostname != "Unknown" else vendor,
                    message     = f"⚠️ BLOCKED device detected on network: {vendor} ({ip})",
                    severity    = "critical"
                )
                logger.warning("🚫 Blocked device detected: %s (%s)", mac, ip)

        # ------------------------------------------------------------------
        # ★ Step 4: Mark devices not seen in this scan as offline
        # ------------------------------------------------------------------
        mark_devices_offline(active_macs)

        # ------------------------------------------------------------------
        # ★ Step 5: Alert for devices that went offline (were online before)
        # ------------------------------------------------------------------
        # Get the now-offline devices (status just changed)
        all_db_devices = get_all_devices()
        for db_dev in all_db_devices:
            if (db_dev["status"] == "offline"
                    and db_dev["mac"] not in active_macs
                    and db_dev.get("last_seen")):
                # Only alert once per offline event — check if last_seen was recent
                # (within the last 2 scan intervals, meaning it WAS online last scan)
                last_seen_ts = db_dev["last_seen"]
                if isinstance(last_seen_ts, datetime):
                    seconds_ago = (datetime.now() - last_seen_ts).total_seconds()
                    if seconds_ago < SCAN_INTERVAL * 2:
                        create_alert(
                            alert_type  = "device_offline",
                            device_mac  = db_dev["mac"],
                            device_ip   = db_dev["ip"],
                            device_name = db_dev["hostname"],
                            message     = f"Device went offline: {db_dev['hostname']} ({db_dev['ip']})",
                            severity    = "info"
                        )

        # ------------------------------------------------------------------
        # Calculate scan duration
        # ------------------------------------------------------------------
        scan_duration = round(time.time() - scan_start, 2)   # Seconds, 2dp

        # ------------------------------------------------------------------
        # ★ Step 6: Save scan summary to scan_history table
        # ------------------------------------------------------------------
        save_scan_result(
            devices_found  = len(devices_found),
            new_devices    = new_device_count,
            scan_duration  = scan_duration,
            subnet         = subnet
        )

        # ------------------------------------------------------------------
        # Step 7: Update the in-memory cache (thread-safe)
        # ------------------------------------------------------------------
        with cache_lock:
            scan_cache["devices"]      = devices_found
            scan_cache["last_scan"]    = datetime.now()
            scan_cache["scan_running"] = False
            scan_cache["total_scans"] += 1
            scan_cache["subnet"]       = subnet

        logger.info(
            "✅ Scan complete — %d device(s) found, %d new | Duration: %.2fs",
            len(devices_found), new_device_count, scan_duration
        )
        return devices_found

    except Exception as err:
        # Catch all errors so the background thread never silently dies
        logger.error("❌ Scan failed: %s", err, exc_info=True)   # exc_info=True logs the stack trace
        with cache_lock:
            scan_cache["scan_running"] = False
            scan_cache["last_error"]   = str(err)
        return []


# =============================================================================
# SECTION 4 — BACKGROUND SCAN THREAD
# =============================================================================

def _background_scan_loop():
    """
    Runs in a daemon thread.
    Performs an initial scan immediately, then repeats every SCAN_INTERVAL seconds.
    A daemon thread dies automatically when the main Flask process exits.
    """
    logger.info("🚀 Background scanner started (interval=%ds)", SCAN_INTERVAL)

    while True:
        run_scan()                # Run one full scan (blocks until complete)
        time.sleep(SCAN_INTERVAL) # Wait before the next scan


def start_background_scanner():
    """
    Called once from app.py at startup.
    Spawns the background scan thread.
    daemon=True means the thread won't keep the process alive after Flask exits.
    """
    thread = threading.Thread(
        target=_background_scan_loop,
        name="LanSentry-Scanner",   # Name shows in debugger / process list
        daemon=True                  # Dies with the main process
    )
    thread.start()
    logger.info("✅ Background scanner thread started (TID=%d)", thread.ident)
    return thread


# =============================================================================
# SECTION 5 — CACHE ACCESSORS
# =============================================================================
# These functions are called by app.py to read the latest scan results
# without directly touching the cache dict (keeps coupling low).

def get_cached_devices():
    """
    Thread-safe read of the latest device list from cache.
    Returns a list of device dicts (may be empty if no scan has run yet).
    """
    with cache_lock:
        return list(scan_cache["devices"])   # Return a copy, not the live list


def get_scan_status():
    """
    Returns a dict with the current scanner status.
    Used by /api/scan-status and the dashboard pulse indicator.
    """
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
    Kick off an immediate on-demand scan in a new thread.
    Called when the admin clicks "Scan Now" on the dashboard.
    Returns immediately — the scan runs in the background.
    Won't start a new scan if one is already running.
    """
    with cache_lock:
        if scan_cache["scan_running"]:
            logger.warning("⏳ Manual scan requested but scan already running — skipped")
            return False   # Scan already in progress

    # Run the scan in its own short-lived thread so the HTTP request returns
    thread = threading.Thread(
        target=run_scan,
        args=(subnet,),
        name="LanSentry-ManualScan",
        daemon=True
    )
    thread.start()
    logger.info("🔍 Manual scan triggered")
    return True