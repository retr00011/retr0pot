#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║              retr0pot — Multi-Service Honeypot        ║
║                   by retr0                            ║
║                                                       ║
║  Emulates SSH, HTTP, FTP, Telnet services to          ║
║  capture and log attacker activity in real-time.      ║
╚══════════════════════════════════════════════════════╝
"""

import asyncio
import json
import os
import sys
import signal
import datetime
import hashlib
import logging
from pathlib import Path
from collections import defaultdict

# ─── Configuration ───────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent / "config.json"
LOG_DIR = Path(__file__).parent / "logs"

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

CONFIG = load_config()

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
    """Logs all honeypot events to structured JSON files."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(exist_ok=True)
        self.events = []
        self._lock = asyncio.Lock()

    async def log_event(self, event_type: str, service: str, 
                         src_ip: str, src_port: int, data: dict = None):
        event = {
            "id": hashlib.md5(
                f"{datetime.datetime.now().isoformat()}{src_ip}{src_port}".encode()
            ).hexdigest()[:12],
            "timestamp": datetime.datetime.now().isoformat(),
            "type": event_type,
            "service": service,
            "src_ip": src_ip,
            "src_port": src_port,
            "data": data or {}
        }

        async with self._lock:
            self.events.append(event)

            # Write to daily log file
            date_str = datetime.date.today().strftime("%Y-%m-%d")
            log_file = self.log_dir / f"events_{date_str}.json"

            existing = []
            if log_file.exists():
                try:
                    with open(log_file, "r") as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    existing = []

            existing.append(event)
            with open(log_file, "w") as f:
                json.dump(existing, f, indent=2)

        severity_colors = {
            "connection": "\033[36m",      # cyan
            "auth_attempt": "\033[33m",    # yellow
            "command": "\033[31m",         # red
            "payload": "\033[35m",         # magenta
            "scan": "\033[34m",            # blue
            "disconnect": "\033[90m",      # gray
        }
        color = severity_colors.get(event_type, "\033[37m")
        reset = "\033[0m"

        logger.info(
            f"{color}▌ {event_type.upper():15s}{reset} │ "
            f"{service:7s} │ {src_ip}:{src_port} │ "
            f"{json.dumps(data) if data else ''}"
        )

        return event

    def get_recent_events(self, limit=100):
        return self.events[-limit:]

    def get_stats(self):
        stats = {
            "total_events": len(self.events),
            "by_service": defaultdict(int),
            "by_type": defaultdict(int),
            "top_ips": defaultdict(int),
            "credentials": [],
            "commands": []
        }
        for e in self.events:
            stats["by_service"][e["service"]] += 1
            stats["by_type"][e["type"]] += 1
            stats["top_ips"][e["src_ip"]] += 1
            if e["type"] == "auth_attempt":
                stats["credentials"].append({
                    "ip": e["src_ip"],
                    "service": e["service"],
                    "data": e["data"],
                    "time": e["timestamp"]
                })
            if e["type"] == "command":
                stats["commands"].append({
                    "ip": e["src_ip"],
                    "cmd": e["data"].get("command", ""),
                    "time": e["timestamp"]
                })

        stats["by_service"] = dict(stats["by_service"])
        stats["by_type"] = dict(stats["by_type"])
        stats["top_ips"] = dict(
            sorted(stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:20]
        )
        return stats


event_logger = EventLogger(LOG_DIR)

# ─── Connection Tracker ──────────────────────────────────────
connection_counts = defaultdict(int)

def check_rate_limit(ip: str) -> bool:
    max_conn = CONFIG.get("max_connections_per_ip", 10)
    if connection_counts[ip] >= max_conn:
        return False
    connection_counts[ip] += 1
    return True

def release_connection(ip: str):
    if connection_counts[ip] > 0:
        connection_counts[ip] -= 1


# ═══════════════════════════════════════════════════════════════
#  SERVICE EMULATORS
# ═══════════════════════════════════════════════════════════════

# ─── SSH Honeypot ─────────────────────────────────────────────
class SSHHoneypot(asyncio.Protocol):
    """Fake SSH server that captures authentication attempts."""

    def __init__(self):
        self.transport = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_rate_limit(self.peer[0]):
            transport.close()
            return

        banner = CONFIG["services"]["ssh"]["banner"]
        transport.write(f"{banner}\r\n".encode())
        asyncio.ensure_future(
            event_logger.log_event("connection", "SSH", self.peer[0], self.peer[1])
        )

    def data_received(self, data):
        self.buffer += data
        try:
            decoded = data.decode("utf-8", errors="replace").strip()
        except Exception:
            decoded = repr(data)

        # Capture anything that looks like auth data
        if decoded:
            asyncio.ensure_future(
                event_logger.log_event(
                    "auth_attempt", "SSH", self.peer[0], self.peer[1],
                    {"raw_data": decoded[:500], "bytes": len(data)}
                )
            )

        # Always reject with a fake delay
        async def delayed_reject():
            await asyncio.sleep(0.5)
            if self.transport and not self.transport.is_closing():
                self.transport.write(b"Permission denied (publickey,password).\r\n")

        asyncio.ensure_future(delayed_reject())

    def connection_lost(self, exc):
        if self.peer:
            release_connection(self.peer[0])
            asyncio.ensure_future(
                event_logger.log_event("disconnect", "SSH", self.peer[0], self.peer[1])
            )


# ─── HTTP Honeypot ────────────────────────────────────────────
class HTTPHoneypot(asyncio.Protocol):
    """Fake HTTP server that logs requests and serves bait pages."""

    FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Panel - Login</title></head>
<body style="font-family:Arial;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="background:#16213e;padding:40px;border-radius:12px;box-shadow:0 0 30px rgba(0,0,0,0.5)">
<h2 style="color:#e94560;text-align:center">⚡ Admin Panel</h2>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" style="display:block;width:250px;padding:10px;margin:10px 0;background:#0f3460;border:1px solid #e94560;color:#eee;border-radius:6px"><br>
<input type="password" name="password" placeholder="Password" style="display:block;width:250px;padding:10px;margin:10px 0;background:#0f3460;border:1px solid #e94560;color:#eee;border-radius:6px"><br>
<button type="submit" style="width:270px;padding:12px;background:#e94560;border:none;color:#fff;border-radius:6px;cursor:pointer;font-weight:bold">Sign In</button>
</form>
</div>
</body>
</html>"""

    ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /config/
Disallow: /backup/
Disallow: /api/keys/
Disallow: /.env
"""

    def __init__(self):
        self.transport = None
        self.peer = None

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_rate_limit(self.peer[0]):
            transport.close()
            return
        asyncio.ensure_future(
            event_logger.log_event("connection", "HTTP", self.peer[0], self.peer[1])
        )

    def data_received(self, data):
        try:
            request = data.decode("utf-8", errors="replace")
        except Exception:
            request = repr(data)

        lines = request.split("\r\n")
        request_line = lines[0] if lines else ""
        method = request_line.split(" ")[0] if request_line else "?"
        path = request_line.split(" ")[1] if len(request_line.split(" ")) > 1 else "/"

        # Extract headers
        headers = {}
        body = ""
        header_done = False
        for line in lines[1:]:
            if line == "":
                header_done = True
                continue
            if not header_done:
                if ": " in line:
                    key, val = line.split(": ", 1)
                    headers[key.lower()] = val
            else:
                body += line

        event_data = {
            "method": method,
            "path": path,
            "user_agent": headers.get("user-agent", "unknown"),
            "headers": dict(list(headers.items())[:10]),
        }

        # Log POST body (credential captures)
        if method == "POST" and body:
            event_data["post_body"] = body[:1000]
            asyncio.ensure_future(
                event_logger.log_event(
                    "auth_attempt", "HTTP", self.peer[0], self.peer[1], event_data
                )
            )
        else:
            asyncio.ensure_future(
                event_logger.log_event(
                    "scan", "HTTP", self.peer[0], self.peer[1], event_data
                )
            )

        # Serve responses based on path
        server_header = CONFIG["services"]["http"]["server_header"]

        if path == "/robots.txt":
            response_body = self.ROBOTS_TXT
            content_type = "text/plain"
        elif path in ("/admin", "/admin/", "/login", "/wp-admin", "/wp-login.php",
                       "/phpmyadmin", "/administrator"):
            response_body = self.FAKE_LOGIN_PAGE
            content_type = "text/html"
        elif path in ("/.env", "/config", "/.git/config", "/api/keys"):
            # Bait sensitive-looking files
            response_body = 'DB_HOST=internal-db.corp.local\nDB_USER=admin\nDB_PASS=Ch4ng3M3!\nAPI_KEY=sk-fake-retr0pot-honeypot-key\n'
            content_type = "text/plain"
        else:
            response_body = self.FAKE_LOGIN_PAGE
            content_type = "text/html"

        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {server_header}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            f"X-Powered-By: PHP/8.1.2\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{response_body}"
        )
        self.transport.write(response.encode())
        self.transport.close()

    def connection_lost(self, exc):
        if self.peer:
            release_connection(self.peer[0])


# ─── FTP Honeypot ─────────────────────────────────────────────
class FTPHoneypot(asyncio.Protocol):
    """Fake FTP server that captures login credentials."""

    def __init__(self):
        self.transport = None
        self.peer = None
        self.username = None
        self.state = "WAIT_USER"

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_rate_limit(self.peer[0]):
            transport.close()
            return

        banner = CONFIG["services"]["ftp"]["banner"]
        transport.write(f"{banner}\r\n".encode())
        asyncio.ensure_future(
            event_logger.log_event("connection", "FTP", self.peer[0], self.peer[1])
        )

    def data_received(self, data):
        try:
            cmd = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        parts = cmd.split(" ", 1)
        command = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if command == "USER":
            self.username = arg
            self.state = "WAIT_PASS"
            self.transport.write(b"331 Password required.\r\n")

        elif command == "PASS":
            asyncio.ensure_future(
                event_logger.log_event(
                    "auth_attempt", "FTP", self.peer[0], self.peer[1],
                    {"username": self.username or "unknown", "password": arg}
                )
            )
            # Always reject after a realistic delay
            async def reject():
                await asyncio.sleep(0.3)
                if self.transport and not self.transport.is_closing():
                    self.transport.write(b"530 Login incorrect.\r\n")
                    self.state = "WAIT_USER"
            asyncio.ensure_future(reject())

        elif command == "QUIT":
            self.transport.write(b"221 Goodbye.\r\n")
            self.transport.close()

        elif command == "SYST":
            self.transport.write(b"215 UNIX Type: L8\r\n")

        elif command == "LIST":
            asyncio.ensure_future(
                event_logger.log_event(
                    "command", "FTP", self.peer[0], self.peer[1],
                    {"command": cmd}
                )
            )
            self.transport.write(b"150 Opening data connection.\r\n")
            self.transport.write(b"226 Transfer complete.\r\n")

        else:
            asyncio.ensure_future(
                event_logger.log_event(
                    "command", "FTP", self.peer[0], self.peer[1],
                    {"command": cmd}
                )
            )
            self.transport.write(b"502 Command not implemented.\r\n")

    def connection_lost(self, exc):
        if self.peer:
            release_connection(self.peer[0])
            asyncio.ensure_future(
                event_logger.log_event("disconnect", "FTP", self.peer[0], self.peer[1])
            )


# ─── Telnet Honeypot ──────────────────────────────────────────
class TelnetHoneypot(asyncio.Protocol):
    """Fake Telnet server with interactive shell emulation."""

    FAKE_FS = {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        "/etc/shadow": "root:$6$fake$hashedpassword:19000:0:99999:7:::\n",
        "/etc/hostname": "webserver-prod-01\n",
    }

    def __init__(self):
        self.transport = None
        self.peer = None
        self.state = "LOGIN_USER"
        self.username = None
        self.authenticated = False
        self.cwd = "/root"

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        if not check_rate_limit(self.peer[0]):
            transport.close()
            return

        banner = CONFIG["services"]["telnet"]["banner"]
        transport.write(f"\r\n{banner}\r\n\r\nlogin: ".encode())
        asyncio.ensure_future(
            event_logger.log_event("connection", "Telnet", self.peer[0], self.peer[1])
        )

    def data_received(self, data):
        try:
            cmd = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not cmd:
            return

        if self.state == "LOGIN_USER":
            self.username = cmd
            self.state = "LOGIN_PASS"
            self.transport.write(b"Password: ")
            return

        if self.state == "LOGIN_PASS":
            asyncio.ensure_future(
                event_logger.log_event(
                    "auth_attempt", "Telnet", self.peer[0], self.peer[1],
                    {"username": self.username, "password": cmd}
                )
            )
            # Always "authenticate" to capture more commands
            self.authenticated = True
            self.state = "SHELL"
            self.transport.write(
                f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
                f"\r\nLast login: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1\r\n"
                f"\r\n{self.username}@webserver-prod-01:{self.cwd}$ ".encode()
            )
            return

        if self.state == "SHELL":
            asyncio.ensure_future(
                event_logger.log_event(
                    "command", "Telnet", self.peer[0], self.peer[1],
                    {"command": cmd, "cwd": self.cwd}
                )
            )
            response = self._emulate_command(cmd)
            self.transport.write(
                f"{response}\r\n{self.username}@webserver-prod-01:{self.cwd}$ ".encode()
            )

    def _emulate_command(self, cmd):
        """Emulate common shell commands with realistic output."""
        parts = cmd.split()
        if not parts:
            return ""

        binary = parts[0]

        if binary in ("ls", "dir"):
            if self.cwd == "/root":
                return "Desktop  Documents  .bash_history  .ssh  backup.tar.gz"
            return "bin  boot  dev  etc  home  lib  opt  proc  root  tmp  usr  var"

        elif binary == "pwd":
            return self.cwd

        elif binary == "cd":
            if len(parts) > 1:
                self.cwd = parts[1] if parts[1].startswith("/") else f"{self.cwd}/{parts[1]}"
            return ""

        elif binary == "whoami":
            return self.username or "root"

        elif binary == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"

        elif binary == "uname":
            return "Linux webserver-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"

        elif binary == "cat":
            if len(parts) > 1:
                path = parts[1]
                if path in self.FAKE_FS:
                    return self.FAKE_FS[path]
                return f"cat: {path}: No such file or directory"
            return ""

        elif binary == "wget" or binary == "curl":
            asyncio.ensure_future(
                event_logger.log_event(
                    "payload", "Telnet", self.peer[0], self.peer[1],
                    {"command": cmd, "type": "download_attempt"}
                )
            )
            return f"{binary}: connection timed out"

        elif binary == "exit" or binary == "logout":
            self.transport.write(b"logout\r\n")
            self.transport.close()
            return ""

        elif binary == "ifconfig" or binary == "ip":
            return "eth0: inet 192.168.1.100 netmask 255.255.255.0 broadcast 192.168.1.255"

        elif binary == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:03 systemd\n"
                "  412 ?        00:00:01 sshd\n"
                "  523 ?        00:00:00 apache2\n"
                " 1024 pts/0    00:00:00 bash\n"
                " 1337 pts/0    00:00:00 ps"
            )

        elif binary == "netstat" or binary == "ss":
            return (
                "Active Internet connections\n"
                "Proto  Local Address    Foreign Address    State\n"
                "tcp    0.0.0.0:22       0.0.0.0:*          LISTEN\n"
                "tcp    0.0.0.0:80       0.0.0.0:*          LISTEN\n"
                "tcp    0.0.0.0:3306     0.0.0.0:*          LISTEN"
            )

        else:
            return f"-bash: {binary}: command not found"

    def connection_lost(self, exc):
        if self.peer:
            release_connection(self.peer[0])
            asyncio.ensure_future(
                event_logger.log_event("disconnect", "Telnet", self.peer[0], self.peer[1])
            )


# ═══════════════════════════════════════════════════════════════
#  MAIN — Boot all services
# ═══════════════════════════════════════════════════════════════

BANNER = """
\033[38;5;196m
  ██▀███  ▓█████▄▄▄█████▓ ██▀███   ▒█████   ██▓███   ▒█████  ▄▄▄█████▓
 ▓██ ▒ ██▒▓█   ▀▓  ██▒ ▓▒▓██ ▒ ██▒▒██▒  ██▒▓██░  ██▒▒██▒  ██▒▓  ██▒ ▓▒
 ▓██ ░▄█ ▒▒███  ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██░  ██▒▓██░ ██▓▒▒██░  ██▒▒ ▓██░ ▒░
 ▒██▀▀█▄  ▒▓█  ▄░ ▓██▓ ░ ▒██▀▀█▄  ▒██   ██░▒██▄█▓▒ ▒▒██   ██░░ ▓██▓ ░ 
 ░██▓ ▒██▒░▒████▒ ▒██▒ ░ ░██▓ ▒██▒░ ████▓▒░▒██▒ ░  ░░ ████▓▒░  ▒██▒ ░ 
 ░ ▒▓ ░▒▓░░░ ▒░ ░ ▒ ░░   ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒▓▒░ ░  ░░ ▒░▒░▒░  ▒ ░░   
   ░▒ ░ ▒░ ░ ░  ░   ░      ░▒ ░ ▒░  ░ ▒ ▒░ ░▒ ░       ░ ▒ ▒░    ░    
   ░░   ░    ░    ░        ░░   ░ ░ ░ ░ ▒  ░░       ░ ░ ░ ▒   ░      
    ░        ░  ░            ░         ░ ░               ░ ░           
\033[0m
\033[38;5;208m    ╔══════════════════════════════════════════════════╗
    ║  retr0pot v1.0 — Multi-Service Honeypot          ║
    ║  Author: retr0                                    ║
    ║  Defensive Security Research Tool                 ║
    ╚══════════════════════════════════════════════════╝\033[0m
"""

async def main():
    print(BANNER)
    loop = asyncio.get_event_loop()
    servers = []

    services_config = CONFIG["services"]

    # ── SSH ──
    if services_config["ssh"]["enabled"]:
        port = services_config["ssh"]["port"]
        try:
            srv = await loop.create_server(SSHHoneypot, "0.0.0.0", port)
            servers.append(srv)
            logger.info(f"\033[32m✔ SSH honeypot listening on port {port}\033[0m")
        except PermissionError:
            logger.error(f"\033[31m✘ Cannot bind SSH to port {port} (need root?)\033[0m")
        except OSError as e:
            logger.error(f"\033[31m✘ SSH port {port}: {e}\033[0m")

    # ── HTTP ──
    if services_config["http"]["enabled"]:
        port = services_config["http"]["port"]
        try:
            srv = await loop.create_server(HTTPHoneypot, "0.0.0.0", port)
            servers.append(srv)
            logger.info(f"\033[32m✔ HTTP honeypot listening on port {port}\033[0m")
        except OSError as e:
            logger.error(f"\033[31m✘ HTTP port {port}: {e}\033[0m")

    # ── FTP ──
    if services_config["ftp"]["enabled"]:
        port = services_config["ftp"]["port"]
        try:
            srv = await loop.create_server(FTPHoneypot, "0.0.0.0", port)
            servers.append(srv)
            logger.info(f"\033[32m✔ FTP honeypot listening on port {port}\033[0m")
        except OSError as e:
            logger.error(f"\033[31m✘ FTP port {port}: {e}\033[0m")

    # ── Telnet ──
    if services_config["telnet"]["enabled"]:
        port = services_config["telnet"]["port"]
        try:
            srv = await loop.create_server(TelnetHoneypot, "0.0.0.0", port)
            servers.append(srv)
            logger.info(f"\033[32m✔ Telnet honeypot listening on port {port}\033[0m")
        except OSError as e:
            logger.error(f"\033[31m✘ Telnet port {port}: {e}\033[0m")

    if not servers:
        logger.error("No services started. Exiting.")
        return

    logger.info(f"\033[38;5;208m═══ retr0pot active — {len(servers)} services running ═══\033[0m")
    logger.info(f"\033[90mLogs → {LOG_DIR.resolve()}\033[0m")
    logger.info(f"\033[90mDashboard → http://{CONFIG['dashboard']['host']}:{CONFIG['dashboard']['port']}\033[0m")
    logger.info(f"\033[90mPress Ctrl+C to stop\033[0m")

    # Keep running
    try:
        await asyncio.gather(*(srv.serve_forever() for srv in servers))
    except asyncio.CancelledError:
        pass
    finally:
        for srv in servers:
            srv.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[38;5;208m[retr0pot]\033[0m Shutting down gracefully...")
        sys.exit(0)
