#!/usr/bin/env python3
"""
CyberGuard Linux Collector v1.0
Collects system telemetry and sends it to the CyberGuard backend.
READ-ONLY: Does NOT modify the system. Bastioning-only on explicit command.
Runs as a systemd daemon.
"""
import os
import sys
import time
import json
import logging
import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from typing import Optional
import signal

import psutil
import httpx

# Config from environment
BACKEND_URL = os.getenv("CYBERGUARD_BACKEND_URL", "https://api.cyberguard.example.com")
AGENT_TOKEN = os.getenv("CYBERGUARD_AGENT_TOKEN", "")
DEVICE_ID = os.getenv("CYBERGUARD_DEVICE_ID", "")
INTERVAL_SECONDS = int(os.getenv("CYBERGUARD_INTERVAL", "60"))
LOG_LEVEL = os.getenv("CYBERGUARD_LOG_LEVEL", "INFO")
VERSION = "1.0.0"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] cyberguard-collector %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/cyberguard-collector.log", mode="a"),
    ],
)
logger = logging.getLogger(__name__)

RUNNING = True


def handle_signal(signum, frame):
    global RUNNING
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    RUNNING = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def collect_processes() -> list[dict]:
    """Collect active process list — read-only."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent",
                                      "memory_percent", "status", "create_time", "ppid"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"] or "",
                "user": info["username"] or "",
                "cmdline": info["cmdline"] or [],
                "cpu_percent": round(info["cpu_percent"] or 0, 2),
                "memory_percent": round(info["memory_percent"] or 0, 2),
                "status": info["status"] or "",
                "create_time": info["create_time"],
                "ppid": info["ppid"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return procs


def collect_connections() -> list[dict]:
    """Collect network connections — read-only."""
    conns = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            conns.append({
                "local_address": laddr,
                "remote_address": raddr,
                "remote_port": conn.raddr.port if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
                "proto": "tcp" if conn.type == 1 else "udp",
            })
    except psutil.AccessDenied:
        logger.warning("Access denied collecting network connections (run as root for full data)")
    return conns


def collect_services() -> list[dict]:
    """Collect systemd service states — read-only."""
    services = []
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--no-pager", "--output=json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            units = json.loads(result.stdout)
            for unit in units[:50]:  # Limit to 50
                services.append({
                    "name": unit.get("unit", ""),
                    "load": unit.get("load", ""),
                    "active": unit.get("active", ""),
                    "sub": unit.get("sub", ""),
                    "description": unit.get("description", ""),
                })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return services


def collect_auth_logs(max_lines: int = 200) -> list[str]:
    """Collect recent authentication log entries — read-only."""
    log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"]
    entries = []
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", errors="ignore") as f:
                    lines = f.readlines()
                    entries.extend([line.strip() for line in lines[-max_lines:] if line.strip()])
                break
            except PermissionError:
                logger.debug(f"Permission denied reading {log_file}")
    return entries


def collect_system_info() -> dict:
    """Collect system metadata — read-only."""
    try:
        uptime = time.time() - psutil.boot_time()
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": cpu,
            "memory_total": mem.total,
            "memory_used": mem.used,
            "memory_percent": mem.percent,
            "disk_total": disk.total,
            "disk_used": disk.used,
            "disk_percent": disk.percent,
            "uptime_seconds": int(uptime),
            "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Error collecting system info: {e}")
        return {}


def collect_network_stats() -> dict:
    """Network interface statistics — read-only."""
    try:
        stats = psutil.net_io_counters(pernic=False)
        return {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errin": stats.errin,
            "errout": stats.errout,
            "dropin": stats.dropin,
            "dropout": stats.dropout,
        }
    except Exception:
        return {}


def collect_open_files_count() -> int:
    """Count open file descriptors for process anomaly detection."""
    try:
        return sum(1 for _ in psutil.Process().open_files())
    except Exception:
        return 0


def send_telemetry(payload: dict) -> bool:
    """Send telemetry to backend with retry logic."""
    url = f"{BACKEND_URL}/api/v1/devices/{DEVICE_ID}/telemetry"
    headers = {
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": f"CyberGuard-Collector/{VERSION}",
        "X-Collector-Version": VERSION,
    }

    for attempt in range(3):
        try:
            with httpx.Client(timeout=30, verify=True) as client:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 202:
                    logger.debug(f"Telemetry sent: {resp.json().get('event_id', '')}")
                    return True
                elif resp.status_code == 401:
                    logger.error("Invalid agent token — check CYBERGUARD_AGENT_TOKEN")
                    return False
                else:
                    logger.warning(f"Unexpected response {resp.status_code}: {resp.text[:200]}")
        except httpx.ConnectError:
            logger.warning(f"Connection failed (attempt {attempt+1}/3), retrying in {2**attempt}s")
            time.sleep(2 ** attempt)
        except Exception as e:
            logger.error(f"Telemetry send error: {e}")
            time.sleep(5)
    return False


def get_local_ip() -> str:
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2 and not addr.address.startswith("127."):  # IPv4, not loopback
                    return addr.address
    except Exception:
        pass
    return ""


def validate_config() -> bool:
    if not AGENT_TOKEN:
        logger.critical("CYBERGUARD_AGENT_TOKEN is not set")
        return False
    if not DEVICE_ID:
        logger.critical("CYBERGUARD_DEVICE_ID is not set")
        return False
    if not BACKEND_URL:
        logger.critical("CYBERGUARD_BACKEND_URL is not set")
        return False
    return True


def main():
    logger.info(f"CyberGuard Linux Collector {VERSION} starting")
    logger.info(f"Backend: {BACKEND_URL} | Device: {DEVICE_ID} | Interval: {INTERVAL_SECONDS}s")

    if not validate_config():
        sys.exit(1)

    while RUNNING:
        try:
            start = time.monotonic()
            logger.debug("Collecting telemetry...")

            payload = {
                "event_type": "system_telemetry",
                "agent_version": VERSION,
                "ip_address": get_local_ip(),
                "raw_data": {
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "system_info": collect_system_info(),
                    "processes": collect_processes(),
                    "connections": collect_connections(),
                    "services": collect_services(),
                    "log_entries": collect_auth_logs(),
                    "network_stats": collect_network_stats(),
                    "open_files_count": collect_open_files_count(),
                },
            }

            success = send_telemetry(payload)
            elapsed = time.monotonic() - start
            logger.info(f"Telemetry cycle: {'OK' if success else 'FAILED'} ({elapsed:.1f}s)")

        except Exception as e:
            logger.error(f"Collection error: {e}", exc_info=True)

        # Sleep in small chunks to respond to SIGTERM quickly
        for _ in range(INTERVAL_SECONDS * 2):
            if not RUNNING:
                break
            time.sleep(0.5)

    logger.info("Collector stopped")


if __name__ == "__main__":
    main()
