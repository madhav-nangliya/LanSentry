# 🛡️ LanSentry

A real-time LAN monitoring dashboard that scans your local network, tracks every connected device, and raises alerts for new, offline, or high-risk devices.

Built with **Python / Flask**, **MySQL**, **nmap**, and **vanilla JS + Chart.js** — no frameworks on the frontend.

---

## Features

| Feature | Detail |
|---|---|
| **Auto-scanning** | Background thread scans the network every 60 seconds |
| **Manual scan** | Trigger an instant scan from any page |
| **Device table** | IP, hostname, MAC, vendor, risk level, online/offline status |
| **Risk scoring** | Heuristic engine flags devices by open ports and vendor |
| **Alert log** | New device, device offline, and high-risk events with severity levels |
| **Scan history** | Every scan logged with device count, new devices, and duration |
| **Charts** | Line, doughnut, and stacked bar charts powered by Chart.js |
| **Dark / light mode** | Theme toggle persisted in localStorage |
| **Security headers** | CSP, X-Frame-Options, X-Content-Type-Options on every response |
| **XSS protection** | All device data escaped via `escapeHTML()` before DOM insertion |

---

## Tech Stack

- **Backend:** Python 3.10+, Flask 3.x
- **Database:** MySQL 8.x with connection pooling
- **Scanner:** python-nmap + psutil (ARP + TCP ping discovery)
- **Frontend:** Vanilla JS, Chart.js 4.4 (CDN), custom CSS (no framework)

---

## Quick Start

### 1. MySQL setup (run once)

```sql
CREATE DATABASE lansentry_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'lansentry_user'@'localhost' IDENTIFIED BY 'StrongPass123!';
GRANT ALL PRIVILEGES ON lansentry_db.* TO 'lansentry_user'@'localhost';
FLUSH PRIVILEGES;
```

Tables are created automatically by `init_db()` on first run.

### 2. Install nmap

- **Windows:** https://nmap.org/download.html (add to PATH during install)
- **Linux:** `sudo apt install nmap`
- **macOS:** `brew install nmap`

### 3. Python setup

```bash
git clone https://github.com/madhav-nangliya/LanSentry.git
cd LanSentry

python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env with your DB credentials
```

Or export variables directly:

```bash
export DB_HOST=localhost
export DB_USER=lansentry_user
export DB_PASSWORD=StrongPass123!
export DB_NAME=lansentry_db
export LANSENTRY_SECRET=your-random-secret-here
```

### 5. Run

```bash
python app.py
```

Open http://localhost:5000

> **Windows note:** Run as Administrator for full MAC address resolution via nmap ARP scan. The app works without admin rights but vendor names may show as "Unknown".

---

## Pages

| URL | Page |
|---|---|
| `/` | Dashboard — stat cards + 4 charts |
| `/devices` | Device table with live search |
| `/alerts` | Alert log with dismiss / dismiss-all |
| `/history` | Paginated scan history table |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/devices` | All devices as JSON |
| GET | `/api/scan-status` | Scanner state (running, last scan time) |
| POST | `/api/scan/trigger` | Start an immediate scan |
| GET | `/api/alerts` | Alert list (`?limit=50&unread_only=false`) |
| POST | `/api/alerts/<id>/read` | Mark one alert as read |
| POST | `/api/alerts/read-all` | Mark all alerts as read |
| GET | `/api/alerts/unread-count` | Unread badge count |
| GET | `/api/scan-history` | Scan records (`?limit=50`) |
| GET | `/api/chart/scan-history` | Line chart data (`?hours=24`) |
| GET | `/api/chart/device-status` | Doughnut chart data |
| GET | `/api/chart/risk-breakdown` | Risk doughnut data |
| GET | `/api/chart/alerts` | Bar chart data (`?days=7`) |
| GET | `/api/status` | Full system health check |

---

## Project Structure

```
LanSentry/
├── app.py          # Flask routes and startup
├── scanner.py      # nmap + ARP scanning, background thread, risk scoring
├── database.py     # MySQL connection pool, all SQL queries
├── requirements.txt
├── .env.example
├── static/
│   └── style.css   # Global CSS with dark/light CSS variables
└── templates/
    ├── home.html    # Dashboard with charts
    ├── devices.html # Device table
    ├── alerts.html  # Alert log
    └── history.html # Scan history table
```

---

## Architecture Notes

- **No Jinja2.** Flask serves HTML files as static bytes via `send_from_directory()`. All data arrives via `fetch()` calls to `/api/*` endpoints — clean separation between server and UI.
- **API-first.** Every piece of dynamic data is a JSON endpoint. The frontend is just a consumer.
- **Connection pooling.** MySQL connections are pooled (size 5) to avoid per-request TCP handshakes.
- **Thread-safe scanning.** A `threading.Lock` guards the shared `scan_cache` dict accessed by both the background scanner thread and the Flask request threads.

---

## License

MIT
