#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║              retr0pot — Enterprise Honeypot           ║
║                   by retr0                            ║
║                                                       ║
║  Features: SIEM Webhooks, Evasion (Tarpit/Jitter),    ║
║  Honeytokens, Fail2Ban emulation, and stealth logging ║
╚══════════════════════════════════════════════════════╝
"""

import asyncio
import json
import os
import sys
import datetime
import hashlib
import logging
import random
import urllib.request
from pathlib import Path
from collections import defaultdict

# ─── Configuration ───────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent / "config.json"
LOG_DIR = Path(__file__).parent / "logs"

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

CONFIG = load_config()

# ─── Security & Evasion ──────────────────────────────────────
banned_ips = {}
failed_attempts = defaultdict(int)
connection_counts = defaultdict(int)

def check_ip_allowed(ip: str) -> bool:
    if ip in banned_ips:
        if datetime.datetime.now() < banned_ips[ip]:
            return False
        else:
            del banned_ips[ip] # Ban expired
    
    max_conn = CONFIG.get("security", {}).get("max_connections_per_ip", 10)
    if connection_counts[ip] >= max_conn:
        return False
        
    connection_counts[ip] += 1
    return True

def register_failure(ip: str):
    threshold = CONFIG.get("security", {}).get("ban_threshold", 10)
    failed_attempts[ip] += 1
    if failed_attempts[ip] >= threshold:
        ban_mins = CONFIG.get("security", {}).get("ban_duration_minutes", 60)
        banned_ips[ip] = datetime.datetime.now() + datetime.timedelta(minutes=ban_mins)
        logger.warning(f"\033[31m[!] Fail2Ban triggered: Banning {ip} for {ban_mins}m\033[0m")
        return True
    return False

def release_connection(ip: str):
    if connection_counts[ip] > 0:
        connection_counts[ip] -= 1

async def tarpit():
    if CONFIG.get("evasion", {}).get("tarpit_enabled", True):
        min_ms = CONFIG["evasion"]["tarpit_min_ms"]
        max_ms = CONFIG["evasion"]["tarpit_max_ms"]
        await asyncio.sleep(random.uniform(min_ms / 1000.0, max_ms / 1000.0))

def get_jittered_banner(base_banner: str) -> str:
    if not CONFIG.get("evasion", {}).get("banner_jitter", True):
        return base_banner
    # Add subtle variations to bypass strict Nmap signatures
    if random.random() > 0.7:
        return base_banner + " "
    return base_banner

# ─── Logging Setup ───────────────────────────────────────────
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("retr0pot")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    "\033[38;5;208m[retr0pot]\033[0m %(asctime)s │ %(message)s",
    datefmt="%H:%M:%S"
))
logger.addHandler(handler)

# ─── Event Logger ────────────────────────────────────────────
class EventLogger:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.events = []
        self._lock = asyncio.Lock()
        self.webhook_url = CONFIG.get("logging", {}).get("webhook_url", "")

    async def log_event(self, event_type: str, service: str, src_ip: str, src_port: int, data: dict = None):
        event = {
            "id": hashlib.md5(f"{datetime.datetime.now().isoformat()}{src_ip}{src_port}".encode()).hexdigest()[:12],
            "timestamp": datetime.datetime.now().isoformat(),
            "type": event_type,
            "service": service,
            "src_ip": src_ip,
            "src_port": src_port,
            "data": data or {}
        }

        async with self._lock:
            self.events.append(event)
            date_str = datetime.date.today().strftime("%Y-%m-%d")
            log_file = self.log_dir / f"events_{date_str}.json"
            
            existing = []
            if log_file.exists():
                try:
                    with open(log_file, "r") as f: existing = json.load(f)
                except: pass
            
            existing.append(event)
            with open(log_file, "w") as f:
                json.dump(existing, f, indent=2)

        # SIEM / Webhook Integration
        if self.webhook_url and event_type in ["auth_attempt", "command", "payload"]:
            asyncio.ensure_future(self._send_webhook(event))

        # Console logging
        colors = {"connection": "\033[36m", "auth_attempt": "\033[33m", "command": "\033[31m", "payload": "\033[35m", "scan": "\033[34m", "disconnect": "\033[90m"}
        color = colors.get(event_type, "\033[37m")
        logger.info(f"{color}▌ {event_type.upper():15s}\033[0m │ {service:7s} │ {src_ip}:{src_port} │ {json.dumps(data) if data else ''}")
        return event

    async def _send_webhook(self, event):
        try:
            req = urllib.request.Request(
                self.webhook_url, 
                data=json.dumps(event).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, urllib.request.urlopen, req)
        except Exception:
            pass

event_logger = EventLogger(LOG_DIR)

# ═══════════════════════════════════════════════════════════════
#  SERVICE EMULATORS
# ═══════════════════════════════════════════════════════════════

# ─── SSH Honeypot ─────────────────────────────────────────────
class SSHHoneypot(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.peer = None

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_ip_allowed(self.peer[0]):
            transport.close()
            return

        asyncio.ensure_future(self._send_banner())

    async def _send_banner(self):
        await tarpit()
        banner = get_jittered_banner(CONFIG["services"]["ssh"]["banner"])
        if self.transport and not self.transport.is_closing():
            self.transport.write(f"{banner}\r\n".encode())
            await event_logger.log_event("connection", "SSH", self.peer[0], self.peer[1])

    def data_received(self, data):
        try: decoded = data.decode("utf-8", errors="replace").strip()
        except Exception: decoded = repr(data)

        if decoded:
            asyncio.ensure_future(event_logger.log_event("auth_attempt", "SSH", self.peer[0], self.peer[1], {"raw_data": decoded[:500]}))
            if register_failure(self.peer[0]):
                self.transport.close()
                return

        async def delayed_reject():
            await tarpit()
            if self.transport and not self.transport.is_closing():
                self.transport.write(b"Permission denied (publickey,password).\r\n")
        asyncio.ensure_future(delayed_reject())

    def connection_lost(self, exc):
        if self.peer:
            release_connection(self.peer[0])
            asyncio.ensure_future(event_logger.log_event("disconnect", "SSH", self.peer[0], self.peer[1]))

# ─── HTTP Honeypot ────────────────────────────────────────────
class HTTPHoneypot(asyncio.Protocol):
    FAKE_LOGIN_PAGE = """<!DOCTYPE html><html><head><title>Admin Panel</title></head><body style="background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0"><form method="POST" action="/login" style="background:#16213e;padding:40px;border-radius:12px;"><h2 style="color:#e94560">⚡ Admin Login</h2><input type="text" name="user" placeholder="User" style="display:block;margin:10px 0;padding:8px;"><input type="password" name="pass" placeholder="Pass" style="display:block;margin:10px 0;padding:8px;"><button type="submit">Login</button></form></body></html>"""
    
    def __init__(self):
        self.transport = None
        self.peer = None

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_ip_allowed(self.peer[0]):
            transport.close()
            return
        asyncio.ensure_future(event_logger.log_event("connection", "HTTP", self.peer[0], self.peer[1]))

    def data_received(self, data):
        asyncio.ensure_future(self._handle_request(data))

    async def _handle_request(self, data):
        await tarpit()
        try: request = data.decode("utf-8", errors="replace")
        except: request = repr(data)

        lines = request.split("\r\n")
        request_line = lines[0] if lines else ""
        method = request_line.split(" ")[0] if request_line else "?"
        path = request_line.split(" ")[1] if len(request_line.split(" ")) > 1 else "/"

        headers, body, header_done = {}, "", False
        for line in lines[1:]:
            if line == "": header_done = True; continue
            if not header_done:
                if ": " in line: k, v = line.split(": ", 1); headers[k.lower()] = v
            else: body += line

        event_data = {"method": method, "path": path, "user_agent": headers.get("user-agent", "unknown")}

        if method == "POST" and body:
            event_data["post_body"] = body[:500]
            await event_logger.log_event("auth_attempt", "HTTP", self.peer[0], self.peer[1], event_data)
            register_failure(self.peer[0])
        else:
            await event_logger.log_event("scan", "HTTP", self.peer[0], self.peer[1], event_data)

        # Honeytokens Generation
        ht = CONFIG.get("honeytokens", {})
        fake_env = f"DB_HOST=127.0.0.1\nAWS_ACCESS_KEY_ID={ht.get('aws_access_key_id')}\nAWS_SECRET_ACCESS_KEY={ht.get('aws_secret_access_key')}\nSTRIPE_KEY={ht.get('stripe_key')}\n"

        if path in ("/.env", "/config", "/api/keys"):
            body_res, ctype = fake_env, "text/plain"
        elif path == "/robots.txt":
            body_res, ctype = "User-agent: *\nDisallow: /admin/\nDisallow: /.env\n", "text/plain"
        else:
            body_res, ctype = self.FAKE_LOGIN_PAGE, "text/html"

        server = get_jittered_banner(CONFIG["services"]["http"]["server_header"])
        resp = f"HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body_res)}\r\nConnection: close\r\n\r\n{body_res}"
        
        if self.transport and not self.transport.is_closing():
            self.transport.write(resp.encode())
            self.transport.close()

    def connection_lost(self, exc):
        if self.peer: release_connection(self.peer[0])

# ─── Telnet / Fake Linux Honeypot ─────────────────────────────
class TelnetHoneypot(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.peer = None
        self.state = "LOGIN_USER"
        self.username = None
        self.cwd = "/root"
        
        # Fake File System
        ht = CONFIG.get("honeytokens", {})
        self.fs = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            "/proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) Platinum 8124M CPU @ 3.00GHz\n",
            "/proc/meminfo": "MemTotal:       16393292 kB\nMemFree:         8123492 kB\nMemAvailable:   12102144 kB\n",
            "/.dockerenv": "",
            "/root/.aws/credentials": f"[default]\naws_access_key_id = {ht.get('aws_access_key_id')}\naws_secret_access_key = {ht.get('aws_secret_access_key')}\n"
        }

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_ip_allowed(self.peer[0]):
            transport.close()
            return
        asyncio.ensure_future(self._send_banner())

    async def _send_banner(self):
        await tarpit()
        banner = get_jittered_banner(CONFIG["services"]["telnet"]["banner"])
        if self.transport and not self.transport.is_closing():
            self.transport.write(f"\r\n{banner}\r\n\r\nlogin: ".encode())
            await event_logger.log_event("connection", "Telnet", self.peer[0], self.peer[1])

    def data_received(self, data):
        asyncio.ensure_future(self._handle_input(data))

    async def _handle_input(self, data):
        await tarpit()
        try: cmd = data.decode("utf-8", errors="replace").strip()
        except: return
        if not cmd: return

        if self.state == "LOGIN_USER":
            self.username = cmd
            self.state = "LOGIN_PASS"
            self.transport.write(b"Password: ")
            return

        if self.state == "LOGIN_PASS":
            await event_logger.log_event("auth_attempt", "Telnet", self.peer[0], self.peer[1], {"username": self.username, "password": cmd})
            self.state = "SHELL"
            self.transport.write(f"\r\nLast login: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1\r\n\r\n{self.username}@webserver-prod-01:{self.cwd}# ".encode())
            return

        if self.state == "SHELL":
            await event_logger.log_event("command", "Telnet", self.peer[0], self.peer[1], {"command": cmd, "cwd": self.cwd})
            res = self._emulate(cmd)
            if self.transport and not self.transport.is_closing():
                if res: self.transport.write(f"{res}\r\n".encode())
                self.transport.write(f"{self.username}@webserver-prod-01:{self.cwd}# ".encode())

    def _emulate(self, cmd):
        parts = cmd.split()
        b = parts[0]
        
        if b in ("ls", "dir"): return "Desktop  Documents  .bash_history  .ssh  .aws  backup.tar.gz" if self.cwd == "/root" else "bin boot dev etc home lib opt proc root sys tmp usr var"
        elif b == "pwd": return self.cwd
        elif b == "cd": 
            if len(parts) > 1: self.cwd = parts[1] if parts[1].startswith("/") else f"{self.cwd}/{parts[1]}"
            return ""
        elif b == "whoami": return self.username or "root"
        elif b == "cat":
            if len(parts) > 1: return self.fs.get(parts[1], f"cat: {parts[1]}: No such file or directory")
            return ""
        elif b in ("wget", "curl", "nc", "bash", "sh"):
            asyncio.ensure_future(event_logger.log_event("payload", "Telnet", self.peer[0], self.peer[1], {"command": cmd, "type": "download_execute_attempt"}))
            return f"{b}: command not found" if random.random() > 0.5 else f"{b}: connection timed out"
        elif b == "ps":
            return f"  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  412 ?        00:00:01 sshd\n {random.randint(1000,9000)} pts/0    00:00:00 bash\n {random.randint(9001,9999)} pts/0    00:00:00 ps"
        elif b == "exit":
            self.transport.close()
            return "logout"
        return f"-bash: {b}: command not found"

    def connection_lost(self, exc):
        if self.peer: release_connection(self.peer[0])

# ─── FTP Honeypot ─────────────────────────────────────────────
class FTPHoneypot(asyncio.Protocol):
    def __init__(self):
        self.transport = None; self.peer = None; self.username = None

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_ip_allowed(self.peer[0]):
            transport.close()
            return
        asyncio.ensure_future(self._send_banner())

    async def _send_banner(self):
        await tarpit()
        banner = get_jittered_banner(CONFIG["services"]["ftp"]["banner"])
        if self.transport and not self.transport.is_closing():
            self.transport.write(f"{banner}\r\n".encode())

    def data_received(self, data):
        asyncio.ensure_future(self._handle(data))

    async def _handle(self, data):
        await tarpit()
        try: cmd = data.decode("utf-8").strip()
        except: return
        
        parts = cmd.split(" ", 1); c = parts[0].upper(); arg = parts[1] if len(parts) > 1 else ""
        if c == "USER":
            self.username = arg; self.transport.write(b"331 Password required.\r\n")
        elif c == "PASS":
            await event_logger.log_event("auth_attempt", "FTP", self.peer[0], self.peer[1], {"username": self.username, "password": arg})
            register_failure(self.peer[0])
            self.transport.write(b"530 Login incorrect.\r\n")
        elif c == "QUIT": self.transport.write(b"221 Goodbye.\r\n"); self.transport.close()
        else:
            await event_logger.log_event("command", "FTP", self.peer[0], self.peer[1], {"command": cmd})
            self.transport.write(b"502 Command not implemented.\r\n")

    def connection_lost(self, exc):
        if self.peer: release_connection(self.peer[0])

# ═══════════════════════════════════════════════════════════════
#  MAIN BOOT
# ═══════════════════════════════════════════════════════════════
async def main():
    print(f"\033[38;5;196m  retr0pot Enterprise v2.0 — SIEM & Deception Enabled\033[0m")
    loop = asyncio.get_event_loop()
    servers = []

    for name, proto in [("ssh", SSHHoneypot), ("http", HTTPHoneypot), ("ftp", FTPHoneypot), ("telnet", TelnetHoneypot)]:
        if CONFIG["services"][name]["enabled"]:
            port = CONFIG["services"][name]["port"]
            try:
                srv = await loop.create_server(proto, "0.0.0.0", port)
                servers.append(srv)
                logger.info(f"\033[32m✔ {name.upper()} listening on {port}\033[0m")
            except Exception as e:
                logger.error(f"\033[31m✘ {name.upper()} port {port}: {e}\033[0m")

    logger.info(f"\033[38;5;208m═══ Active Services: {len(servers)} ═══\033[0m")
    logger.info(f"Tarpitting: {'ON' if CONFIG['evasion']['tarpit_enabled'] else 'OFF'} | Fail2Ban: ON | Webhooks: {'ON' if CONFIG['logging']['webhook_url'] else 'OFF'}")
    
    try: await asyncio.gather(*(srv.serve_forever() for srv in servers))
    except asyncio.CancelledError: pass
    finally: [srv.close() for srv in servers]

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: sys.exit(0)
