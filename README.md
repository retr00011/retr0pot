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

**Advanced Active Defense & Deception Framework**

[![Python](https://img.shields.io/badge/Python-3.10+-e94560?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Active_Defense-00e676?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Production_Ready-blue?style=for-the-badge)]()

</div>

---

## 🛡️ Overview

**retr0pot** is a high-interaction deception framework engineered to shift the tactical advantage back to defenders. Designed with enterprise threat intelligence in mind, it safely emulates vulnerable infrastructure, disrupts automated reconnaissance via dynamic tarpitting, and traces adversary lateral movement using embedded honeytokens.

It provides security teams with high-fidelity, real-time alerts without the noise of traditional IDS/IPS systems.

## ⚡ Core Capabilities

| Capability | Technical Implementation |
|---------|-------------|
| 🕒 **Dynamic Tarpitting** | Mitigates automated scanning (e.g., Nmap) via asynchronous connection delays (50-300ms), breaking static timing signatures and increasing attacker cost. |
| 🍯 **Honeytoken Injection** | Exposes traceable, synthetic AWS and Stripe credentials within emulated files. External usage of these tokens provides immediate attribution. |
| 🛡️ **Automated Response** | Stateful IP tracking mirroring Fail2Ban mechanics. Automatically drops connections at the socket level after repeated authentication failures. |
| 📡 **SIEM Integration** | Native webhook support for real-time threat intelligence export to Splunk, ELK, Slack, or custom SOC dashboards. |
| 💻 **High-Fidelity Emulation** | Interactive Telnet sandbox featuring accurate `/proc/cpuinfo`, memory footprints, and pseudo-randomized process tables to deceive manual inspection. |
| 📊 **Real-time Analytics** | Purpose-built dashboard for visualizing attack vectors, service distribution, and credential harvesting attempts. |

## 🚀 Deployment

### Prerequisites

```bash
git clone https://github.com/retr00011/retr0pot.git
cd retr0pot
pip install -r requirements.txt
```

### Initializing the Framework

```bash
# Initialize the deception services
python honeypot.py

# Launch the analytics dashboard (Port 5000)
python dashboard/app.py
```

## ⚙️ Configuration (`config.json`)

The framework is highly modular. Configure evasion parameters, security thresholds, and SOC integrations via `config.json`:

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

## 🎯 Architectural Philosophy

### 1. Disrupting the Kill Chain (Tarpitting)
Modern reconnaissance tools rely on predictable server response times. By injecting async delays, `retr0pot` artificially inflates the time required to scan the network, forcing automated tools to time out or misclassify services, ultimately protecting real assets.

### 2. High-Fidelity Attribution (Honeytokens)
When an adversary breaches the emulated HTTP or Telnet environments, they discover synthetic credentials. Monitoring these "poisoned" tokens (e.g., via AWS CloudTrail) provides definitive proof of lateral movement and intent, turning the attacker's own tooling against them.

### 3. Noise Reduction
Unlike standard firewalls that log every port knock, `retr0pot` focuses on interactive, high-intent activity. By correlating failed auth attempts and blocking aggressive IPs statefully, it delivers actionable intelligence directly to your SOC.

---

<div align="center">

**Developed by retr0**

*A portfolio project demonstrating advanced defensive security architecture.*

</div>
