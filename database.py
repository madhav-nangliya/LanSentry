# =============================================================================
# database.py — LanSentry MySQL Database Layer
# =============================================================================
# All DB operations live here. app.py and scanner.py never write SQL directly —
# they call these functions. This is the Repository pattern: a single module
# owns all data-access logic for a given data store.
#
# INTERVIEW: Why isolate DB code in its own module?
# → Separation of concerns. If we switch from MySQL to PostgreSQL, we only
#   change this file. The rest of the app is unaffected.
#   It also makes testing easier — you can mock this module in unit tests.
#
# Tables:
#   • devices        — every unique device (MAC is the primary key)
#   • scan_history   — one row per completed scan
#   • alerts         — new device, offline, blocked, high-risk events
# =============================================================================

import mysql.connector
from mysql.connector import pooling
from datetime import datetime
import logging

logger = logging.getLogger("database")

# ---------------------------------------------------------------------------
# CONNECTION CONFIGURATION
# ---------------------------------------------------------------------------
# INTERVIEW: Why not hardcode credentials in the source code?
# → Source code often ends up in version control (GitHub). Hardcoded passwords
#   in a public repo are found by bots in minutes.
#   In production, load these from environment variables or a secrets manager
#   (AWS Secrets Manager, Vault, etc.).
# os.environ.get() is how you read environment variables in Python.
import os

DB_CONFIG = {
    "host":      os.environ.get("DB_HOST",     "localhost"),
    "port":      int(os.environ.get("DB_PORT", 3306)),
    "user":      os.environ.get("DB_USER",     "lansentry_user"),
    "password":  os.environ.get("DB_PASSWORD", "StrongPass123!"),
    "database":  os.environ.get("DB_NAME",     "lansentry_db"),
    "charset":   "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
}

POOL_CONFIG = {
    "pool_name":          "lansentry_pool",
    "pool_size":          5,       # Max simultaneous DB connections
    # INTERVIEW: What happens when all 5 connections are in use?
    # → get_connection() blocks until one is returned to the pool.
    #   If the pool is too small for your traffic, requests pile up.
    #   Too large and you waste DB server resources.
    "pool_reset_session": True,    # Reset session state on reuse (safer)
}

_connection_pool = None   # Set by init_db()


# =============================================================================
# SECTION 1 — INITIALISATION
# =============================================================================

def init_db():
    """
    Called ONCE at startup from app.py.
    1. Creates the connection pool.
    2. Creates tables (IF NOT EXISTS — safe to call repeatedly).
    Returns True on success, False on any error.
    """
    global _connection_pool
    try:
        _connection_pool = pooling.MySQLConnectionPool(**POOL_CONFIG, **DB_CONFIG)
        logger.info("MySQL pool created (size=%d)", POOL_CONFIG["pool_size"])
        _create_tables()
        logger.info("Tables verified / created")
        return True
    except mysql.connector.Error as err:
        logger.error("DB init failed: %s", err)
        return False


def get_connection():
    """
    Borrow a connection from the pool.
    ALWAYS call conn.close() when done — this returns it to the pool,
    not actually disconnect from MySQL.
    INTERVIEW: Connection pools avoid the overhead of opening a new TCP
    connection + MySQL handshake on every request. A new connection can
    take 10–50ms; a pool checkout is essentially free.
    """
    if _connection_pool is None:
        raise RuntimeError("DB pool not initialised — call init_db() first")
    return _connection_pool.get_connection()


# =============================================================================
# SECTION 2 — SCHEMA
# =============================================================================

def _create_tables():
    """Creates all three tables if they don't already exist."""
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        # ── devices ──────────────────────────────────────────────────────
        # MAC is UNIQUE (not just the primary key) so that upsert_device()
        # can use INSERT ... ON DUPLICATE KEY UPDATE in one statement.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id           INT          AUTO_INCREMENT PRIMARY KEY,
                mac          VARCHAR(17)  NOT NULL UNIQUE,
                ip           VARCHAR(15)  NOT NULL,
                hostname     VARCHAR(255) DEFAULT 'Unknown',
                vendor       VARCHAR(255) DEFAULT 'Unknown',
                os_guess     VARCHAR(255) DEFAULT 'Unknown',
                open_ports   TEXT         NULL,
                status       ENUM('online','offline','blocked') DEFAULT 'online',
                is_blocked   TINYINT(1)   DEFAULT 0,
                risk_level   ENUM('low','medium','high') DEFAULT 'low',
                first_seen   DATETIME     DEFAULT CURRENT_TIMESTAMP,
                last_seen    DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        # ── scan_history ─────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id              INT         AUTO_INCREMENT PRIMARY KEY,
                scan_time       DATETIME    DEFAULT CURRENT_TIMESTAMP,
                devices_found   INT         DEFAULT 0,
                new_devices     INT         DEFAULT 0,
                scan_duration   FLOAT       DEFAULT 0.0,
                subnet          VARCHAR(50) DEFAULT '',
                INDEX idx_scan_time (scan_time)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        # ── alerts ───────────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INT          AUTO_INCREMENT PRIMARY KEY,
                alert_time   DATETIME     DEFAULT CURRENT_TIMESTAMP,
                alert_type   VARCHAR(50)  NOT NULL,
                device_mac   VARCHAR(17)  DEFAULT '',
                device_ip    VARCHAR(15)  DEFAULT '',
                device_name  VARCHAR(255) DEFAULT 'Unknown',
                message      TEXT         NOT NULL,
                severity     ENUM('info','warning','critical') DEFAULT 'info',
                is_read      TINYINT(1)   DEFAULT 0,
                INDEX idx_alert_time (alert_time),
                INDEX idx_is_read    (is_read)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        conn.commit()
    except mysql.connector.Error as err:
        logger.error("Table creation error: %s", err)
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 3 — DEVICE FUNCTIONS
# =============================================================================

def upsert_device(mac, ip, hostname="Unknown", vendor="Unknown",
                  os_guess="Unknown", open_ports="", status="online",
                  risk_level="low"):
    """
    INSERT a new device OR UPDATE an existing one (by MAC).
    Returns (row_id, is_new_device).

    INTERVIEW: What is an upsert?
    → "Update or Insert" — check if a row exists, insert if not, update if yes.
      MySQL's INSERT ... ON DUPLICATE KEY UPDATE does this atomically in one
      statement (no race condition between the check and the write).
      We use the simpler SELECT-first approach here so we can return is_new.

    WHY MAC as identifier and not IP?
    → IP addresses are assigned by DHCP and can change between scans.
      MAC addresses are burned into the NIC hardware and are stable.
      (Note: modern OSes can randomise MACs — this is a known limitation.)

    FIX: Added risk_level parameter (was missing in the original, so risk
         was calculated but never saved to the DB).
    """
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM devices WHERE mac = %s", (mac,))
        existing = cursor.fetchone()
        is_new   = existing is None

        if is_new:
            cursor.execute("""
                INSERT INTO devices
                    (mac, ip, hostname, vendor, os_guess, open_ports, status, risk_level)
                VALUES
                    (%s,  %s, %s,      %s,     %s,       %s,         %s,     %s)
            """, (mac, ip, hostname, vendor, os_guess, open_ports, status, risk_level))
            row_id = cursor.lastrowid
        else:
            row_id = existing[0]
            cursor.execute("""
                UPDATE devices
                SET ip         = %s,
                    hostname   = %s,
                    vendor     = %s,
                    os_guess   = %s,
                    open_ports = %s,
                    status     = %s,
                    risk_level = %s
                WHERE mac = %s
            """, (ip, hostname, vendor, os_guess, open_ports, status, risk_level, mac))

        conn.commit()
        return row_id, is_new

    except mysql.connector.Error as err:
        logger.error("upsert_device(%s): %s", mac, err)
        conn.rollback()
        return None, False
    finally:
        cursor.close()
        conn.close()


def get_all_devices():
    """
    Returns all devices ordered by last_seen DESC.
    Used by /api/devices and the devices page table.

    INTERVIEW: What does dictionary=True do?
    → By default, MySQL cursor returns rows as tuples: (1, 'AA:BB:...', ...).
      dictionary=True returns dicts: {'id': 1, 'mac': 'AA:BB:...', ...}.
      Much easier to work with in Python and to serialise to JSON.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, mac, ip, hostname, vendor, os_guess,
                   open_ports, status, is_blocked, risk_level,
                   first_seen, last_seen
            FROM devices
            ORDER BY last_seen DESC
        """)
        return cursor.fetchall()
    except mysql.connector.Error as err:
        logger.error("get_all_devices: %s", err)
        return []
    finally:
        cursor.close()
        conn.close()


def get_device_by_mac(mac):
    """Returns one device dict or None."""
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM devices WHERE mac = %s", (mac,))
        return cursor.fetchone()
    except mysql.connector.Error as err:
        logger.error("get_device_by_mac(%s): %s", mac, err)
        return None
    finally:
        cursor.close()
        conn.close()


def set_device_blocked(mac, blocked: bool):
    """
    Toggle is_blocked and status for a device.
    Returns True if the MAC was found and updated.

    INTERVIEW: Why do we check rowcount?
    → cursor.rowcount is the number of rows affected by the last UPDATE.
      If it's 0, the MAC wasn't found in the table. We use this to tell
      the API caller whether the operation succeeded.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    status = "blocked" if blocked else "online"
    flag   = 1         if blocked else 0
    try:
        cursor.execute("""
            UPDATE devices SET is_blocked = %s, status = %s WHERE mac = %s
        """, (flag, status, mac))
        conn.commit()
        return cursor.rowcount > 0
    except mysql.connector.Error as err:
        logger.error("set_device_blocked(%s): %s", mac, err)
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def mark_devices_offline(active_macs: list):
    """
    After a scan, mark any device NOT in active_macs as 'offline'.
    active_macs — list of MAC strings seen in the CURRENT scan.

    INTERVIEW: Why the guard for empty list?
    → If the scan returned 0 devices (maybe nmap failed silently), we don't
      want to mark ALL devices as offline. That would be data corruption.
      The guard makes the function "safe by default".
    """
    if not active_macs:
        return

    conn   = get_connection()
    cursor = conn.cursor()
    try:
        placeholders = ", ".join(["%s"] * len(active_macs))
        cursor.execute(f"""
            UPDATE devices
            SET status = 'offline'
            WHERE mac NOT IN ({placeholders})
              AND is_blocked = 0
              AND status = 'online'
        """, tuple(active_macs))
        conn.commit()
        if cursor.rowcount:
            logger.info("Marked %d device(s) offline", cursor.rowcount)
    except mysql.connector.Error as err:
        logger.error("mark_devices_offline: %s", err)
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def get_device_stats():
    """
    Returns {'total', 'online', 'offline', 'blocked', 'high_risk'}.
    Uses conditional SUM in a single query — faster than 5 COUNT queries.

    INTERVIEW: What does SUM(status = 'online') do?
    → In MySQL, a boolean expression returns 1 (true) or 0 (false).
      SUM() adds them up, giving the count of rows where the condition is true.
      It's equivalent to COUNT(*) WHERE status = 'online' but done in one pass.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                COUNT(*)                 AS total,
                SUM(status = 'online')   AS online,
                SUM(status = 'offline')  AS offline,
                SUM(status = 'blocked')  AS blocked,
                SUM(risk_level = 'high') AS high_risk
            FROM devices
        """)
        row = cursor.fetchone()
        return {k: int(v or 0) for k, v in row.items()}
    except mysql.connector.Error as err:
        logger.error("get_device_stats: %s", err)
        return {"total": 0, "online": 0, "offline": 0, "blocked": 0, "high_risk": 0}
    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 4 — SCAN HISTORY
# =============================================================================

def save_scan_result(devices_found, new_devices, scan_duration, subnet=""):
    """Appends one row to scan_history. Called by scanner.py after each scan."""
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO scan_history (devices_found, new_devices, scan_duration, subnet)
            VALUES (%s, %s, %s, %s)
        """, (devices_found, new_devices, scan_duration, subnet))
        conn.commit()
        return cursor.lastrowid
    except mysql.connector.Error as err:
        logger.error("save_scan_result: %s", err)
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()


def get_scan_history(limit=50):
    """Returns the most recent `limit` scan records, newest first."""
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, scan_time, devices_found, new_devices, scan_duration, subnet
            FROM scan_history
            ORDER BY scan_time DESC
            LIMIT %s
        """, (limit,))
        return cursor.fetchall()
    except mysql.connector.Error as err:
        logger.error("get_scan_history: %s", err)
        return []
    finally:
        cursor.close()
        conn.close()


def get_scan_history_for_chart(hours=24):
    """
    Returns scan data for the last N hours in ascending time order
    (oldest → newest) so Chart.js draws the line left to right.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                DATE_FORMAT(scan_time, '%%H:%%i') AS label,
                devices_found,
                new_devices,
                scan_time
            FROM scan_history
            WHERE scan_time >= NOW() - INTERVAL %s HOUR
            ORDER BY scan_time ASC
        """, (hours,))
        return cursor.fetchall()
    except mysql.connector.Error as err:
        logger.error("get_scan_history_for_chart: %s", err)
        return []
    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 5 — ALERTS
# =============================================================================

def create_alert(alert_type, device_mac, device_ip, device_name, message, severity="info"):
    """
    Inserts one alert row.
    severity: 'info' | 'warning' | 'critical'
    Returns the new alert ID or None on failure.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO alerts
                (alert_type, device_mac, device_ip, device_name, message, severity)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (alert_type, device_mac, device_ip, device_name, message, severity))
        conn.commit()
        logger.info("Alert: [%s] %s", severity.upper(), message)
        return cursor.lastrowid
    except mysql.connector.Error as err:
        logger.error("create_alert: %s", err)
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()


def get_alerts(limit=100, unread_only=False):
    """
    Returns recent alerts as a list of dicts.
    unread_only=True: only is_read=0 rows.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        where = "WHERE is_read = 0" if unread_only else ""
        cursor.execute(f"""
            SELECT id, alert_time, alert_type, device_mac, device_ip,
                   device_name, message, severity, is_read
            FROM alerts {where}
            ORDER BY alert_time DESC
            LIMIT %s
        """, (limit,))
        return cursor.fetchall()
    except mysql.connector.Error as err:
        logger.error("get_alerts: %s", err)
        return []
    finally:
        cursor.close()
        conn.close()


def mark_alert_read(alert_id):
    """Marks one alert as read. Returns True if the ID existed."""
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE id = %s", (alert_id,))
        conn.commit()
        return cursor.rowcount > 0
    except mysql.connector.Error as err:
        logger.error("mark_alert_read(%s): %s", alert_id, err)
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def mark_all_alerts_read():
    """Marks all unread alerts as read. Returns the count updated."""
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE alerts SET is_read = 1 WHERE is_read = 0")
        conn.commit()
        return cursor.rowcount
    except mysql.connector.Error as err:
        logger.error("mark_all_alerts_read: %s", err)
        conn.rollback()
        return 0
    finally:
        cursor.close()
        conn.close()


def get_alerts_for_chart(days=7):
    """
    Returns daily alert counts by type for the stacked bar chart.
    INTERVIEW: SUM(alert_type = 'new_device') counts rows where
    alert_type equals 'new_device' — same conditional-SUM trick as
    get_device_stats(). GROUP BY DATE(...) buckets rows by calendar day.
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                DATE(alert_time)                            AS day,
                SUM(alert_type = 'new_device')              AS new_device,
                SUM(alert_type = 'blocked_attempt')         AS blocked_attempt,
                SUM(alert_type = 'device_offline')          AS device_offline,
                SUM(alert_type = 'high_risk')               AS high_risk,
                COUNT(*)                                    AS total
            FROM alerts
            WHERE alert_time >= CURDATE() - INTERVAL %s DAY
            GROUP BY DATE(alert_time)
            ORDER BY day ASC
        """, (days,))
        return cursor.fetchall()
    except mysql.connector.Error as err:
        logger.error("get_alerts_for_chart: %s", err)
        return []
    finally:
        cursor.close()
        conn.close()


def get_unread_alert_count():
    """
    Returns the integer count of unread alerts.
    Called on every page load to update the navbar badge.
    Fast query — only reads the index on is_read.
    """
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0")
        result = cursor.fetchone()
        return result[0] if result else 0
    except mysql.connector.Error as err:
        logger.error("get_unread_alert_count: %s", err)
        return 0
    finally:
        cursor.close()
        conn.close()


# =============================================================================
# SECTION 6 — UTILITY
# =============================================================================

def purge_old_scan_history(keep_days=30):
    """Deletes scan_history rows older than keep_days. Run weekly via cron."""
    conn   = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            DELETE FROM scan_history WHERE scan_time < NOW() - INTERVAL %s DAY
        """, (keep_days,))
        conn.commit()
        deleted = cursor.rowcount
        logger.info("Purged %d old scan_history rows", deleted)
        return deleted
    except mysql.connector.Error as err:
        logger.error("purge_old_scan_history: %s", err)
        conn.rollback()
        return 0
    finally:
        cursor.close()
        conn.close()


def get_db_status():
    """
    Quick health check: tries a trivial query and reports row counts.
    Called by /api/status.
    """
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        counts = {}
        for table in ("devices", "scan_history", "alerts"):
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return {"connected": True, "row_counts": counts}
    except Exception as err:
        return {"connected": False, "error": str(err), "row_counts": {}}


# =============================================================================
# MYSQL SETUP INSTRUCTIONS (run once before starting the app)
# =============================================================================
# mysql -u root -p
# CREATE DATABASE lansentry_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
# CREATE USER 'lansentry_user'@'localhost' IDENTIFIED BY 'StrongPass123!';
# GRANT ALL PRIVILEGES ON lansentry_db.* TO 'lansentry_user'@'localhost';
# FLUSH PRIVILEGES;
# Tables are auto-created by init_db() on first run.
