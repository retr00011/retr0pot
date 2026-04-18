<div align="center">

```
  ██▀███  ▓█████▄▄▄█████▓ ██▀███   ▒█████   ██▓███   ▒█████  ▄▄▄█████▓
 ▓██ ▒ ██▒▓█   ▀▓  ██▒ ▓▒▓██ ▒ ██▒▒██▒  ██▒▓██░  ██▒▒██▒  ██▒▓  ██▒ ▓▒
 ▓██ ░▄█ ▒▒███  ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██░  ██▒▓██░ ██▓▒▒██░  ██▒▒ ▓██░ ▒░
 ▒██▀▀█▄  ▒▓█  ▄░ ▓██▓ ░ ▒██▀▀█▄  ▒██   ██░▒██▄█▓▒ ▒▒██   ██░░ ▓██▓ ░
 ░██▓ ▒██▒░▒████▒ ▒██▒ ░ ░██▓ ▒██▒░ ████▓▒░▒██▒ ░  ░░ ████▓▒░  ▒██▒ ░
 ░ ▒▓ ░▒▓░░░ ▒░ ░ ▒ ░░   ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒▓▒░ ░  ░░ ▒░▒░▒░  ▒ ░░
   ░▒ ░ ▒░ ░ ░  ░   ░      ░▒ ░ ▒░  ░ ▒ ▒░ ░▒ ░       ░ ▒ ▒░    ░
   ░░   ░    ░    ░        ░░   ░ ░ ░ ░ ▒  ░░       ░ ░ ░ ▒   ░
    ░        ░  ░            ░         ░ ░               ░ ░
```

**Multi-Service Honeypot with Real-Time Dashboard**

[![Python](https://img.shields.io/badge/Python-3.10+-e94560?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-18ffff?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00e676?style=for-the-badge)]()

</div>

---

## 🔥 What is retr0pot?

**retr0pot** is a lightweight, multi-service honeypot designed for defensive security research. It emulates vulnerable services to attract and log attacker activity, providing real-time visibility into attack patterns through a sleek web dashboard.

> ⚠️ **For authorized security research and educational purposes only.**

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 🔐 **SSH Honeypot** | Fake OpenSSH server — captures credentials and SSH data |
| 🌐 **HTTP Honeypot** | Fake Apache with login page, robots.txt, bait `.env` files |
| 📁 **FTP Honeypot** | Fake ProFTPD — captures FTP login attempts |
| 💻 **Telnet Honeypot** | Interactive fake shell with command emulation |
| 📊 **Live Dashboard** | Real-time web UI with attack feed, stats, charts |
| 📝 **Structured Logging** | JSON event logs with daily rotation |
| 🛡️ **Rate Limiting** | Per-IP connection limits to prevent resource exhaustion |
| 🎭 **Realistic Banners** | Mimics real service versions for authenticity |

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/retr0/retr0pot.git
cd retr0pot
pip install -r requirements.txt
```

### Run the Honeypot

```bash
# Start all honeypot services
python honeypot.py

# In another terminal, start the dashboard
python dashboard/app.py
```

### Access the Dashboard

Open `http://127.0.0.1:5000` in your browser.

## 📁 Project Structure

```
retr0pot/
├── honeypot.py              # Core honeypot engine (SSH, HTTP, FTP, Telnet)
├── config.json              # Service configuration
├── requirements.txt         # Python dependencies
├── dashboard/
│   ├── app.py               # Flask dashboard backend
│   ├── templates/
│   │   └── index.html       # Dashboard UI
│   └── static/
│       ├── style.css         # Dark-mode cyberpunk styles
│       └── script.js         # Live polling & visualization
└── logs/
    └── events_YYYY-MM-DD.json  # Daily event logs
```

## ⚙️ Configuration

Edit `config.json` to customize services, ports, and behavior:

```json
{
    "services": {
        "ssh":    { "enabled": true, "port": 2222 },
        "http":   { "enabled": true, "port": 8080 },
        "ftp":    { "enabled": true, "port": 2121 },
        "telnet": { "enabled": true, "port": 2323 }
    },
    "dashboard": { "host": "127.0.0.1", "port": 5000 },
    "max_connections_per_ip": 10
}
```

## 🎯 Emulated Services

### SSH (Port 2222)
- Presents a realistic OpenSSH banner
- Captures all authentication data
- Rejects with realistic delay + error message

### HTTP (Port 8080)
- Serves a fake admin login page at `/admin`, `/login`, `/wp-admin`
- Exposes bait `robots.txt` with juicy disallow paths
- Captures POST credentials from login forms
- Fake `.env` and config files as bait

### FTP (Port 2121)
- ProFTPD banner emulation
- Full USER/PASS flow with credential capture
- Responds to SYST, LIST, QUIT

### Telnet (Port 2323)
- Interactive shell with realistic login flow
- Emulates: `ls`, `cat`, `whoami`, `id`, `ps`, `netstat`, `uname`, etc.
- Captures download attempts (`wget`, `curl`) as high-severity payloads
- Fake `/etc/passwd`, `/etc/shadow`, hostname

## 📊 Dashboard

The real-time dashboard provides:
- **Live Attack Feed** — Color-coded events streaming in real-time
- **Stats Cards** — Total events, unique IPs, captured credentials, commands
- **Service Distribution** — Visual breakdown of targeted services
- **Top Attackers** — Ranked list of most active source IPs
- **Credentials Table** — All captured username/password combos
- **Commands Table** — All commands attackers tried to execute

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with 🖤 by retr0**

*Defensive security research tool — use responsibly.*

</div>
