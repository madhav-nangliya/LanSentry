# =============================================================================
# scanner.py — LanSentry Network Scanner
# =============================================================================
#
# HOW SCANNING WORKS (important for interviews):
#
#   We use TWO complementary discovery methods:
#
#   Method 1 — ARP scan (via nmap -PR)
#     ARP (Address Resolution Protocol) maps IP addresses to MAC addresses
#     on a local network. Every device MUST respond to ARP requests (it's
#     how TCP/IP works at the Ethernet level), so ARP scanning is:
#       • Near-instant (milliseconds per device)
#       • 100% reliable on local subnets
#       • Works WITHOUT Administrator rights on Windows
#       • Only works on the LOCAL subnet (can't cross routers)
#
#   Method 2 — TCP ping fallback (via nmap -PS80,443 -PA80)
#     If ARP returns nothing (e.g. VPN or unusual network config), we fall
#     back to TCP-based host discovery. This tries to connect to port 80/443
#     — if the port is open OR the device sends a TCP RST (port closed),
#     nmap marks the host as "up". This doesn't require raw ICMP.
#
#   Why NOT plain "nmap -sn" (ICMP ping)?
#     Windows blocks raw ICMP socket creation for non-Administrator processes.
#     nmap silently returns 0 hosts instead of an error. This is the #1 reason
#     LAN scanners appear "broken" on Windows but work fine on Linux.
#
# =============================================================================

import nmap
import psutil
import threading
import time
import logging
import ipaddress
import subprocess
import re
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

# =============================================================================
# CONFIGURATION
# =============================================================================

SCAN_INTERVAL = 60       # Seconds between background scans
SCAN_TIMEOUT  = 120      # Hard timeout for the entire nmap run (seconds)

# Nmap arguments explained:
#   -sn          : host discovery only, no port scan
#   -PR          : ARP ping — most reliable on local LAN, no admin needed
#   -PS80,443    : TCP SYN to port 80 + 443 as fallback
#   -PA80        : TCP ACK to port 80 as another fallback
#   --host-timeout 5s : skip any single host that doesn't respond in 5 seconds
#   -T4          : aggressive timing (faster scans, fine on a LAN)
NMAP_ARGS_PRIMARY  = "-sn -PR -PS80,443 -PA80 --host-timeout 5s -T4"

# Fallback: pure TCP connect (slowest but works in every environment)
NMAP_ARGS_FALLBACK = "-sn -PS21,22,80,443,8080 -PA80,443 --host-timeout 8s -T3"

scan_cache = {
    "devices":      [],
    "last_scan":    None,
    "scan_running": False,
    "total_scans":  0,
    "last_error":   None,
    "subnet":       "",
}

cache_lock = threading.Lock()


# =============================================================================
# SECTION 1 — SUBNET DETECTION
# =============================================================================

def detect_subnet():
    """
    Find the best subnet to scan by inspecting network interfaces.

    Windows-specific pitfalls we handle:
      • 169.254.x.x (APIPA): Windows auto-assigns this when no DHCP server
        responds. The interface is technically "up" but has no real devices.
      • Multiple interfaces: A laptop often has Ethernet (unplugged) +
        WiFi (connected) + VPN adapters. We must pick the right one.
      • Large subnets: A /8 has 16 million addresses — scanning it would
        take hours. We cap at /16 (65,534 addresses).

    Scoring system:
      We score every candidate and return the best one.
      Private RFC 1918 ranges (10.x, 192.168.x, 172.16-31.x) score highest
      because they are LAN subnets. Smaller prefix length = smaller network
      = faster scan, so /24 beats /16.
    """
    try:
        candidates = []

        for iface_name, iface_addresses in psutil.net_if_addrs().items():
            # Skip loopback interfaces entirely
            if iface_name.lower() in ("lo", "loopback pseudo-interface 1"):
                continue
            if "loopback" in iface_name.lower():
                continue

            for addr in iface_addresses:
                # We only want IPv4 (family=2 = AF_INET)
                if addr.family != 2:
                    continue
                if not addr.address or not addr.netmask:
                    continue

                ip   = addr.address
                mask = addr.netmask

                # Skip loopback range
                if ip.startswith("127."):
                    continue

                # ── CRITICAL WINDOWS FIX ──
                # 169.254.x.x = APIPA (Automatic Private IP Addressing)
                # Windows assigns these to disconnected interfaces.
                # There are zero real devices behind this address.
                if ip.startswith("169.254."):
                    logger.debug("Skipping APIPA address %s on '%s'", ip, iface_name)
                    continue

                try:
                    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                except ValueError:
                    continue

                # Skip subnets too large to scan meaningfully
                if network.prefixlen < 16:
                    logger.debug("Skipping huge subnet %s on '%s'", network, iface_name)
                    continue

                # Score this candidate:
                #   is_private: 1 if RFC 1918 (real LAN), 0 if public/unusual
                #   prefixlen:  larger = smaller network = faster scan (preferred)
                is_private = network.is_private
                score = (int(is_private), network.prefixlen)

                candidates.append({
                    "score":   score,
                    "subnet":  str(network),
                    "iface":   iface_name,
                    "ip":      ip,
                })
                logger.debug("Candidate: %s via '%s' score=%s", network, iface_name, score)

        if candidates:
            # Best = highest score (private first, then smallest subnet)
            best = max(candidates, key=lambda c: c["score"])
            logger.info(
                "Selected subnet: %s  (interface: '%s',  IP: %s)",
                best["subnet"], best["iface"], best["ip"]
            )
            return best["subnet"]

    except Exception as err:
        logger.warning("Subnet detection error: %s", err)

    # Hard fallback — most common home/office subnet
    logger.warning("Could not detect subnet — falling back to 192.168.1.0/24")
    return "192.168.1.0/24"


# =============================================================================
# SECTION 2 — ARP TABLE READER (Windows bonus method)
# =============================================================================

def get_arp_table():
    """
    Read the Windows ARP cache using 'arp -a'.

    The ARP cache is a table the OS maintains mapping IP → MAC for every
    device it has recently communicated with. Reading it is:
      • Instant (no network traffic at all)
      • No privileges required
      • Gives us MACs we might miss from nmap

    We use this as a SUPPLEMENT to nmap, not a replacement:
      • ARP cache may be stale (entries expire after ~2 minutes of inactivity)
      • nmap actively probes — ARP cache is passive

    Returns: dict of {ip: mac} for all non-multicast entries.
    """
    devices = {}
    try:
        # Run 'arp -a' — available on Windows, Linux, macOS
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10
        )

        for line in result.stdout.splitlines():
            # Windows 'arp -a' output format:
            #   10.172.19.1          00-50-56-c0-00-08     dynamic
            #   10.172.19.74         <own machine>
            # We extract IP and MAC using regex
            match = re.search(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}",
                line
            )
            if match:
                ip  = match.group(0).split()[0]
                mac = match.group(0).split()[1].replace("-", ":").upper()

                # Skip multicast/broadcast MACs (not real devices)
                # Multicast MACs start with 01:00:5E or 33:33 (IPv6 multicast)
                if mac.startswith("01:") or mac.startswith("33:33") or mac == "FF:FF:FF:FF:FF:FF":
                    continue

                devices[ip] = mac

        if devices:
            logger.info("ARP table: found %d entries", len(devices))

    except Exception as err:
        logger.debug("ARP table read failed: %s", err)

    return devices


# =============================================================================
# SECTION 3 — RISK CALCULATOR
# =============================================================================

def calculate_risk(open_ports_str, vendor, hostname):
    """
    Heuristic risk score based on open ports and device identity.
    Returns 'low', 'medium', or 'high'.

    This is NOT a CVE scanner — it's a simple triage tool.
    """
    ports = []
    if open_ports_str and open_ports_str.strip():
        ports = [int(p.strip()) for p in open_ports_str.split(",") if p.strip().isdigit()]

    HIGH_RISK_PORTS   = {21, 23, 3389, 5900, 4444, 6667}
    MEDIUM_RISK_PORTS = {22, 80, 443, 8080, 8443, 3306, 5432, 27017}

    if any(p in HIGH_RISK_PORTS for p in ports):
        return "high"
    if any(p in MEDIUM_RISK_PORTS for p in ports):
        return "medium"
    if len(ports) > 5:
        return "medium"
    if not vendor or vendor.lower() in ("unknown", "", "n/a"):
        return "medium"
    return "low"


# =============================================================================
# SECTION 4 — CORE SCAN FUNCTION
# =============================================================================

def run_scan(subnet=None):
    """
    Full network scan combining nmap + ARP table.

    Flow:
      1.  Detect subnet (skip APIPA, prefer private ranges)
      2.  Read ARP cache (instant, no network traffic)
      3.  Run nmap with ARP+TCP ping arguments
      4.  If nmap finds nothing, try fallback arguments
      5.  Merge nmap results with ARP cache
      6.  Upsert every device to DB
      7.  Mark absent devices offline
      8.  Create alerts (new device, blocked, offline)
      9.  Save scan summary to scan_history
      10. Update in-memory cache
    """

    with cache_lock:
        scan_cache["scan_running"] = True
        scan_cache["last_error"]   = None

    scan_start = time.time()

    if subnet is None:
        subnet = detect_subnet()

    logger.info("Starting scan — subnet: %s", subnet)

    try:
        # ── Step 2: Read ARP cache (free extra data) ──
        arp_table = get_arp_table()

        # ── Step 3: Run nmap primary scan ──
        nm = nmap.PortScanner()
        logger.info("Running nmap: %s %s", NMAP_ARGS_PRIMARY, subnet)
        nm.scan(hosts=subnet, arguments=NMAP_ARGS_PRIMARY, timeout=SCAN_TIMEOUT)

        found_hosts = [ip for ip in nm.all_hosts() if nm[ip].state() == "up"]
        logger.info("nmap primary found %d host(s)", len(found_hosts))

        # ── Step 4: Fallback if nmap found nothing ──
        # This handles VPNs, restrictive firewalls, or environments where
        # ARP doesn't work (e.g. scanning across a router)
        if len(found_hosts) == 0 and len(arp_table) == 0:
            logger.warning("Primary scan found nothing — trying fallback arguments")
            nm2 = nmap.PortScanner()
            nm2.scan(hosts=subnet, arguments=NMAP_ARGS_FALLBACK, timeout=SCAN_TIMEOUT)
            found_hosts = [ip for ip in nm2.all_hosts() if nm2[ip].state() == "up"]
            if found_hosts:
                nm = nm2   # Use fallback results
                logger.info("Fallback scan found %d host(s)", len(found_hosts))

        # ── Step 5: Merge nmap + ARP ──
        # Build a unified set of all IPs we know about
        all_ips = set(found_hosts)

        # Add IPs from ARP table that nmap may have missed
        # Filter to only IPs in our target subnet
        target_network = ipaddress.ip_network(subnet, strict=False)
        for ip in arp_table:
            try:
                if ipaddress.ip_address(ip) in target_network:
                    all_ips.add(ip)
            except ValueError:
                pass

        logger.info("Total unique hosts (nmap + ARP): %d", len(all_ips))

        # ── Step 6: Build device list + upsert to DB ──
        devices_found    = []
        active_macs      = []
        new_device_count = 0

        for ip in sorted(all_ips):  # sorted = deterministic order
            # Try to get nmap data for this IP
            host_data  = nm[ip] if ip in nm.all_hosts() else None

            # Hostname from nmap
            hostname = "Unknown"
            if host_data:
                hn = host_data.hostname()
                if hn:
                    hostname = hn

            # MAC: prefer nmap (more reliable), fall back to ARP table
            mac = ""
            if host_data:
                mac = host_data["addresses"].get("mac", "").upper()
            if not mac and ip in arp_table:
                mac = arp_table[ip]

            # Vendor from nmap (requires admin for ARP scan to return vendor)
            vendor = "Unknown"
            if host_data and mac and mac in host_data.get("vendor", {}):
                vendor = host_data["vendor"][mac]

            # Synthetic MAC if we still have nothing
            # Format: IP octets packed into a MAC-like string for uniqueness
            if not mac:
                octets = ip.split(".")
                mac = f"00:00:{octets[0].zfill(3)[:2]}:{octets[1].zfill(3)[:2]}:{octets[2].zfill(3)[:2]}:{octets[3].zfill(3)[:2]}"
                logger.debug("Synthetic MAC for %s: %s", ip, mac)

            # Open ports (only populated if we did a port scan, not just -sn)
            open_ports = ""
            if host_data and "tcp" in host_data:
                open_ports = ",".join(str(p) for p in host_data["tcp"].keys())

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

            # Upsert to DB (INSERT if new, UPDATE if seen before)
            row_id, is_new = upsert_device(
                mac=mac, ip=ip, hostname=hostname,
                vendor=vendor, open_ports=open_ports, status="online"
            )
            active_macs.append(mac)

            # Alert: new device discovered
            if is_new:
                new_device_count += 1
                create_alert(
                    alert_type  = "new_device",
                    device_mac  = mac,
                    device_ip   = ip,
                    device_name = hostname if hostname != "Unknown" else vendor,
                    message     = f"New device: {vendor} — {ip} ({hostname})",
                    severity    = "warning" if risk in ("medium", "high") else "info"
                )
                logger.info("New device: %s | %s | %s | risk=%s", mac, ip, vendor, risk)

            # Alert: blocked device appeared on network
            db_dev = get_device_by_mac(mac)
            if db_dev and db_dev.get("is_blocked"):
                create_alert(
                    alert_type  = "blocked_attempt",
                    device_mac  = mac,
                    device_ip   = ip,
                    device_name = hostname if hostname != "Unknown" else vendor,
                    message     = f"BLOCKED device on network: {vendor} ({ip})",
                    severity    = "critical"
                )
                logger.warning("Blocked device detected: %s (%s)", mac, ip)

        # ── Step 7: Mark absent devices offline ──
        mark_devices_offline(active_macs)

        # ── Step 8: Alert for devices that just went offline ──
        for db_dev in get_all_devices():
            if db_dev["status"] == "offline" and db_dev["mac"] not in active_macs:
                last_seen = db_dev.get("last_seen")
                if isinstance(last_seen, datetime):
                    secs_ago = (datetime.now() - last_seen).total_seconds()
                    # Only alert if it was online within the last 2 scan intervals
                    # (avoids alerting on devices that have been offline for hours)
                    if secs_ago < SCAN_INTERVAL * 2:
                        create_alert(
                            alert_type  = "device_offline",
                            device_mac  = db_dev["mac"],
                            device_ip   = db_dev["ip"],
                            device_name = db_dev["hostname"],
                            message     = f"Device offline: {db_dev['hostname']} ({db_dev['ip']})",
                            severity    = "info"
                        )

        # ── Step 9: Save scan summary ──
        scan_duration = round(time.time() - scan_start, 2)
        save_scan_result(
            devices_found = len(devices_found),
            new_devices   = new_device_count,
            scan_duration = scan_duration,
            subnet        = subnet
        )

        # ── Step 10: Update cache ──
        with cache_lock:
            scan_cache["devices"]      = devices_found
            scan_cache["last_scan"]    = datetime.now()
            scan_cache["scan_running"] = False
            scan_cache["total_scans"] += 1
            scan_cache["subnet"]       = subnet

        logger.info(
            "Scan complete — %d device(s), %d new | %.2fs | subnet: %s",
            len(devices_found), new_device_count, scan_duration, subnet
        )
        return devices_found

    except Exception as err:
        logger.error("Scan failed: %s", err, exc_info=True)
        with cache_lock:
            scan_cache["scan_running"] = False
            scan_cache["last_error"]   = str(err)
        return []


# =============================================================================
# SECTION 5 — BACKGROUND THREAD
# =============================================================================

def _background_loop():
    logger.info("Background scanner started (interval=%ds)", SCAN_INTERVAL)
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL)


def start_background_scanner():
    """
    Spawns the background scan thread as a daemon.
    daemon=True: thread dies automatically when Flask exits.
    This prevents the scanner from keeping the process alive after Ctrl+C.
    """
    t = threading.Thread(target=_background_loop, name="LanSentry-Scanner", daemon=True)
    t.start()
    logger.info("Background scanner thread started (TID=%d)", t.ident)
    return t


# =============================================================================
# SECTION 6 — CACHE ACCESSORS
# =============================================================================

def get_cached_devices():
    with cache_lock:
        return list(scan_cache["devices"])


def get_scan_status():
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
    Start an immediate on-demand scan in a new thread.
    Returns False if a scan is already running (prevents pile-up).
    """
    with cache_lock:
        if scan_cache["scan_running"]:
            return False

    t = threading.Thread(
        target=run_scan, args=(subnet,),
        name="LanSentry-ManualScan", daemon=True
    )
    t.start()
    logger.info("Manual scan triggered")
    return True