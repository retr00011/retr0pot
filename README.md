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

**Enterprise-Grade Deception Framework & Honeypot**

[![Python](https://img.shields.io/badge/Python-3.10+-e94560?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-18ffff?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Enterprise-ff9100?style=for-the-badge)]()

</div>

---

## 🔥 What is retr0pot Enterprise?

**retr0pot** is not just a honeypot; it's an advanced **Deception Framework**. Designed to fool Nmap scanners, evade Red Teams, and alert Blue Teams in real-time. It traps attackers in a tarpit, feeds them poisoned Honeytokens, and streams their activity directly to your SIEM via webhooks.

> ⚠️ **For authorized corporate security research and red/blue teaming only.**

## ⚡ Enterprise Features

| Feature | Description |
|---------|-------------|
| 🐌 **Nmap Tarpitting** | Asynchronous network delays (50-300ms) to bypass static scanner signatures and simulate load |
| 🎭 **Banner Jittering** | Subtle randomization of protocol banners to evade static fingerprinting |
| 🍯 **Honeytokens** | Poisoned AWS/Stripe keys injected into fake `.env` files and `.aws/credentials` |
| 🛡️ **Auto-Ban (Fail2Ban)** | Stateful IP tracking that automatically drops connections after 10 failed auth attempts |
| 📡 **SIEM Webhooks** | Real-time JSON event streaming to Slack, Discord, Splunk, or any custom endpoint |
| 💻 **Advanced Emulation** | Telnet sandbox featuring fake `/proc/cpuinfo`, `/proc/meminfo`, and randomized `ps` PIDs |
| 📊 **Real-time Dashboard** | Cyberpunk web UI with live event feeds, service distribution charts, and attacker ranking |

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/retr00011/retr0pot.git
cd retr0pot
pip install -r requirements.txt
```

### Run the Honeypot

```bash
# Start the enterprise deception engine
python honeypot.py

# In another terminal, start the live dashboard
python dashboard/app.py
```

## ⚙️ Enterprise Configuration (`config.json`)

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

## 🎯 Deception Tactics

### Evasion & Tarpitting
Scanner detection relies heavily on timing. `retr0pot` dynamically injects async `sleep()` calls before sending banners or responses. An Nmap `-T4` scan will time out or misclassify the service, while a human attacker will simply perceive a slow, realistic corporate network.

### Honeytokens (The Poisoned Bait)
When attackers breach the HTTP honeypot or Telnet shell, they hunt for credentials. `retr0pot` feeds them fake AWS access keys and Stripe tokens. If you monitor these tokens externally, you'll know exactly who is trying to use the stolen data.

### Auto-Ban Simulation
To mimic a defended enterprise environment (like a server running Fail2Ban or CrowdStrike), the honeypot tracks failed authentication attempts statefully across all protocols. On the 10th failure, the attacker's IP is silently dropped at the socket level for 60 minutes.

---

<div align="center">

**Built with 🖤 by retr0**

*Enterprise Defensive Security Tool — Use Responsibly.*

</div>
