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

**Weaponized Deception Net [GHOST MODE]**

[![Python](https://img.shields.io/badge/Python-3.10+-e94560?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Status](https://img.shields.io/badge/Status-Underground-ff1744?style=for-the-badge)]()

</div>

---

## 💀 What is retr0pot?

Forget the basic scripts. **retr0pot** is a blackbox deception net designed to catch, exhaust, and unmask automated scanners and human adversaries alike. It doesn't just log attacks; it tarpits them, feeds them poisoned honeytokens, and tracks their every move in absolute stealth.

> ⚠️ **You know what this is. Keep it underground.**

## ⚡ Ghost Protocol Features

| Module | Description |
|---------|-------------|
| 🐌 **Abyssal Tarpitting** | Asynchronous network delays (50-300ms) that drown Nmap scanners and break static timing signatures. |
| 🎭 **Dynamic Jitter** | Randomizes protocol banners dynamically. You can't signature what constantly mutates. |
| 🍯 **Poisoned Bait** | Fake AWS/Stripe keys injected into `.env` and `.aws/credentials`. If they use it, they expose themselves. |
| 🛡️ **Blackhole Routing** | Stateful IP tracking. After 10 failed auths, the attacker's IP is silently dropped into the void. No errors, just timeouts. |
| 📡 **Shadow Export** | Real-time JSON event streaming to hidden Discord/Slack webhooks. Watch them fail in real-time. |
| 💻 **Phantom Shell** | Telnet sandbox featuring fake `/proc/cpuinfo`, `/proc/meminfo`, and randomized `ps` PIDs. It looks and bleeds like a real server. |
| 📊 **Command Center** | Cyberpunk web UI mapping out service distribution, live payloads, and top attacker IPs. |

## 🚀 Deployment

### Clone & Init

```bash
git clone https://github.com/retr00011/retr0pot.git
cd retr0pot
pip install -r requirements.txt
```

### Ignite the Net

```bash
# Boot the deception engine
python honeypot.py

# Spin up the command center (Port 5000)
python dashboard/app.py
```

## ⚙️ Core Directives (`config.json`)

Tweak the ghost engine parameters to match your target environment:

```json
{
    "evasion": {
        "tarpit_enabled": true,
        "tarpit_min_ms": 50,
        "tarpit_max_ms": 300,
        "banner_jitter": true
    },
    "honeytokens": {
        "aws_access_key_id": "AKIA_FAKE_KEY_EXAMPLE_123",
        "aws_secret_access_key": "wJalr...EXAMPLEKEY"
    },
    "security": {
        "max_connections_per_ip": 10,
        "ban_threshold": 10,
        "ban_duration_minutes": 60
    },
    "logging": {
        "webhook_url": "https://hooks.slack.com/services/FAKE_WEBHOOK/URL/12345"
    }
}
```

## 🎯 Tactical Deception

### Exhaustion (The Tarpit)
Scanners look for instant banner grabs. `retr0pot` dynamically injects async sleep states before responding. An automated scanner will time out or misclassify the port entirely, thinking it hit a real, overloaded server. 

### The Honeytoken Trap
When they breach the HTTP endpoints or drop into the Telnet shell, they hunt for credentials. `retr0pot` feeds them dead AWS keys. If you monitor those keys externally, you trace the attacker back to their own infrastructure.

### Blackhole Ban
It watches auth failures across all protocols simultaneously. Hit the limit, and the engine silently drops your socket layer. To the attacker, the server didn't block them; the server just *disappeared*.

---

<div align="center">

**Crafted in the shadows by retr0**

</div>
