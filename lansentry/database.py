# ============================================================
# database.py — Handles all database operations for LanSentry
# This file is responsible for:
#   1. Connecting to MySQL
#   2. Creating tables if they don't exist
#   3. Saving scan results
#   4. Reading scan history
# ============================================================

import mysql.connector   # Library that lets Python talk to MySQL
from datetime import datetime  # For getting current date and time


# ============================================================
# DATABASE CONFIGURATION
# Change these values to match your MySQL setup
# ============================================================

DB_CONFIG = {
    'host'    : 'localhost',   # MySQL is running on your own computer
    'user'    : 'root',        # MySQL username (default is 'root')
    'password': 'madsql',  # ← CHANGE THIS to your MySQL password
    'database': 'lansentry'    # The database we created earlier
}


# ============================================================
# CONNECT TO DATABASE
# This function creates and returns a connection to MySQL
# Think of it like opening a file before reading/writing it
# ============================================================

def get_connection():
    """
    Creates a connection to the MySQL database.
    Returns the connection object so we can use it.
    
    We create a fresh connection each time we need it,
    and close it when we're done. This is called
    'connection-per-request' pattern.
    """
    try:
        # mysql.connector.connect() opens a connection to MySQL
        # using the settings we defined above
        connection = mysql.connector.connect(**DB_CONFIG)
        # ** means "unpack the dictionary as keyword arguments"
        # So this is same as: connect(host='localhost', user='root', ...)
        return connection
    
    except mysql.connector.Error as e:
        # If connection fails, print the error and return None
        print(f"❌ Database connection failed: {e}")
        print("Make sure MySQL is running and your password is correct!")
        return None


# ============================================================
# CREATE TABLES
# This function creates our tables if they don't exist yet
# Called once when the app starts
# ============================================================

def create_tables():
    """
    Creates the 'scans' and 'devices' tables in MySQL.
    
    'IF NOT EXISTS' means: only create if table isn't already there.
    So running this multiple times is safe — it won't duplicate tables.
    """
    
    # Get a connection to MySQL
    conn = get_connection()
    
    # If connection failed, stop here
    if not conn:
        return
    
    try:
        # A cursor is like a pen — we use it to write SQL commands
        cursor = conn.cursor()
        
        # ── Create 'scans' table ──
        # This stores ONE row for each network scan that runs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id             INT AUTO_INCREMENT PRIMARY KEY,
                -- AUTO_INCREMENT means MySQL automatically gives each row a unique number
                -- PRIMARY KEY means this column uniquely identifies each row
                
                scanned_at     DATETIME NOT NULL,
                -- DATETIME stores date + time (e.g. 2024-01-15 10:30:00)
                -- NOT NULL means this field is required
                
                total_devices  INT DEFAULT 0
                -- How many devices were found in this scan
                -- DEFAULT 0 means if we don't provide a value, use 0
            )
        """)
        
        # ── Create 'devices' table ──
        # This stores ONE row for each device found in each scan
        # One scan can have multiple devices
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                
                scan_id     INT NOT NULL,
                -- Which scan this device belongs to
                -- Links to the 'id' column in the 'scans' table
                
                ip          VARCHAR(45) NOT NULL,
                -- VARCHAR(45) = text up to 45 characters long
                -- IPv6 addresses can be up to 45 chars
                
                hostname    VARCHAR(255) DEFAULT 'Unknown',
                -- Device name, up to 255 characters
                
                mac         VARCHAR(20) DEFAULT 'N/A',
                -- MAC address like AA:BB:CC:DD:EE:FF
                
                status      VARCHAR(10) DEFAULT 'up',
                -- 'up' or 'down'
                
                is_gateway  BOOLEAN DEFAULT FALSE,
                -- TRUE if this is the router/hotspot
                
                is_me       BOOLEAN DEFAULT FALSE,
                -- TRUE if this is your own device
                
                FOREIGN KEY (scan_id) REFERENCES scans(id)
                -- FOREIGN KEY means scan_id must match an id in scans table
                -- This creates a link between the two tables
            )
        """)
        
        # Save the changes to the database
        # Without commit(), changes aren't actually saved
        conn.commit()
        
        print("✅ Database tables created successfully!")
    
    except mysql.connector.Error as e:
        print(f"❌ Error creating tables: {e}")
    
    finally:
        # 'finally' block ALWAYS runs, even if there was an error
        # We always want to close the connection to free up resources
        cursor.close()   # Close the cursor (pen)
        conn.close()     # Close the connection (file)


# ============================================================
# SAVE SCAN TO DATABASE
# Called every time the background scanner finishes a scan
# ============================================================

def save_scan(devices):
    """
    Saves a complete scan result to the database.
    
    Steps:
    1. Create a new row in 'scans' table
    2. For each device, create a row in 'devices' table
    3. Link all device rows to the scan row using scan_id
    
    Parameters:
        devices (list): List of device dictionaries from scanner.py
    """
    
    conn = get_connection()
    if not conn:
        return  # Stop if no database connection
    
    try:
        cursor = conn.cursor()
        
        # ── Step 1: Insert a new scan record ──
        # datetime.now() gives us the current date and time
        # Example: 2024-01-15 10:30:00
        now = datetime.now()
        
        # INSERT INTO adds a new row to the table
        # %s are placeholders — MySQL fills them in safely
        # (prevents SQL injection attacks)
        cursor.execute("""
            INSERT INTO scans (scanned_at, total_devices)
            VALUES (%s, %s)
        """, (now, len(devices)))
        # len(devices) counts how many devices were found
        
        # Get the ID of the scan we just inserted
        # lastrowid gives us the AUTO_INCREMENT id that was assigned
        scan_id = cursor.lastrowid
        print(f"📝 Created scan record with ID: {scan_id}")
        
        # ── Step 2: Insert each device ──
        for device in devices:
            cursor.execute("""
                INSERT INTO devices 
                    (scan_id, ip, hostname, mac, status, is_gateway, is_me)
                VALUES 
                    (%s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,                    # Links to our scan
                device['ip'],               # IP address
                device['hostname'],         # Device name
                device['mac'],              # MAC address
                device['status'],           # 'up' or 'down'
                device.get('is_gateway', False),  # Is it the router?
                device.get('is_me', False)        # Is it my device?
                # .get() safely gets a value, returns False if not found
            ))
        
        # Save all changes at once
        conn.commit()
        print(f"✅ Saved {len(devices)} devices for scan {scan_id}")
    
    except mysql.connector.Error as e:
        print(f"❌ Error saving scan: {e}")
        conn.rollback()
        # rollback() undoes any changes if something went wrong
        # Like pressing Ctrl+Z — nothing gets saved if there's an error
    
    finally:
        cursor.close()
        conn.close()


# ============================================================
# GET SCAN HISTORY
# Returns list of all past scans for the history page
# ============================================================

def get_scan_history(limit=20):
    """
    Gets the most recent scans from the database.
    
    Parameters:
        limit (int): How many scans to return (default 20)
    
    Returns:
        list: List of scan dictionaries
    """
    
    conn = get_connection()
    if not conn:
        return []  # Return empty list if no connection
    
    try:
        # dictionary=True means return results as dictionaries
        # instead of plain tuples — much easier to work with!
        cursor = conn.cursor(dictionary=True)
        
        # SELECT gets rows FROM a table
        # ORDER BY scanned_at DESC → newest scans first
        # LIMIT %s → only return this many results
        cursor.execute("""
            SELECT id, scanned_at, total_devices
            FROM scans
            ORDER BY scanned_at DESC
            LIMIT %s
        """, (limit,))
        # Note: (limit,) is a tuple with one item — MySQL requires this format
        
        # fetchall() gets ALL the results as a list
        scans = cursor.fetchall()
        return scans
    
    except mysql.connector.Error as e:
        print(f"❌ Error getting history: {e}")
        return []
    
    finally:
        cursor.close()
        conn.close()


# ============================================================
# GET DEVICES FOR A SPECIFIC SCAN
# Used when user clicks on a scan in history page
# ============================================================

def get_scan_devices(scan_id):
    """
    Gets all devices that were found in a specific scan.
    
    Parameters:
        scan_id (int): The ID of the scan to look up
    
    Returns:
        list: List of device dictionaries
    """
    
    conn = get_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # WHERE scan_id = %s → only get devices for THIS scan
        cursor.execute("""
            SELECT ip, hostname, mac, status, is_gateway, is_me
            FROM devices
            WHERE scan_id = %s
            ORDER BY ip ASC
        """, (scan_id,))
        # ORDER BY ip ASC → sort by IP address alphabetically
        
        devices = cursor.fetchall()
        return devices
    
    except mysql.connector.Error as e:
        print(f"❌ Error getting scan devices: {e}")
        return []
    
    finally:
        cursor.close()
        conn.close()


# ============================================================
# GET CHART DATA
# Returns data for the Chart.js graphs on the home page
# ============================================================

def get_chart_data(days=7):
    """
    Gets device count data for the last N days.
    Used to draw the line chart on the home dashboard.
    
    Returns data in this format:
    {
        'labels': ['Jan 10', 'Jan 11', ...],  ← X axis (dates)
        'counts': [3, 4, 3, 5, ...]           ← Y axis (device counts)
    }
    
    Parameters:
        days (int): How many days of data to return (default 7)
    """
    
    conn = get_connection()
    if not conn:
        # Return empty chart data if no connection
        return {'labels': [], 'counts': []}
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # DATE(scanned_at) extracts just the date part (removes time)
        # AVG(total_devices) gets the average devices for that day
        # GROUP BY DATE → one row per day
        # DATE_SUB(NOW(), INTERVAL %s DAY) → only last N days
        cursor.execute("""
            SELECT 
                DATE(scanned_at) as scan_date,
                AVG(total_devices) as avg_devices,
                MAX(total_devices) as max_devices
            FROM scans
            WHERE scanned_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY DATE(scanned_at)
            ORDER BY scan_date ASC
        """, (days,))
        
        rows = cursor.fetchall()
        
        # Format the data for Chart.js
        labels = []  # Dates for X axis
        counts = []  # Device counts for Y axis
        
        for row in rows:
            # Format date as "Jan 15" style
            # strftime converts datetime to string with custom format
            # %b = short month name, %d = day number
            label = row['scan_date'].strftime('%b %d')
            labels.append(label)
            
            # Round the average to nearest whole number
            counts.append(round(float(row['avg_devices'])))
        
        return {'labels': labels, 'counts': counts}
    
    except mysql.connector.Error as e:
        print(f"❌ Error getting chart data: {e}")
        return {'labels': [], 'counts': []}
    
    finally:
        cursor.close()
        conn.close()


# ============================================================
# GET TOTAL STATS
# Returns summary numbers for the home page stat cards
# ============================================================

def get_total_stats():
    """
    Returns overall statistics about all scans ever done.
    
    Returns:
        dict: {
            'total_scans': 42,          ← How many scans run total
            'total_devices_seen': 8,    ← Unique devices ever seen
            'first_scan': '2024-01-10'  ← When monitoring started
        }
    """
    
    conn = get_connection()
    if not conn:
        return {'total_scans': 0, 'total_devices_seen': 0, 'first_scan': 'N/A'}
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # COUNT(*) counts total number of rows (total scans)
        # MIN(scanned_at) gets the earliest scan date
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                MIN(scanned_at) as first_scan
            FROM scans
        """)
        scan_stats = cursor.fetchone()
        # fetchone() gets just the first (and only) row
        
        # COUNT DISTINCT ip → count unique IP addresses ever seen
        cursor.execute("""
            SELECT COUNT(DISTINCT ip) as unique_devices
            FROM devices
        """)
        device_stats = cursor.fetchone()
        
        return {
            'total_scans'       : scan_stats['total_scans'],
            'total_devices_seen': device_stats['unique_devices'],
            'first_scan'        : scan_stats['first_scan'].strftime('%b %d, %Y') 
                                  if scan_stats['first_scan'] else 'N/A'
        }
    
    except mysql.connector.Error as e:
        print(f"❌ Error getting stats: {e}")
        return {'total_scans': 0, 'total_devices_seen': 0, 'first_scan': 'N/A'}
    
    finally:
        cursor.close()
        conn.close()