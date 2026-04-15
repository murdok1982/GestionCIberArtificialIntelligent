#!/usr/bin/env python3
"""
CyberGuard Windows Collector v1.0
Collects system telemetry from Windows endpoints and sends to CyberGuard backend.
READ-ONLY: Does NOT modify the system.
Runs as a Windows Service.
"""
import os
import sys
import time
import json
import logging
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
VERSION = "1.0.0"

LOG_FILE = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "CyberGuard", "collector.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] cyberguard-collector %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

RUNNING = True


def handle_signal(signum, frame):
    global RUNNING
    RUNNING = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def collect_processes() -> list[dict]:
    """Collect process list — read-only."""
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
                "proto": "tcp",
            })
    except psutil.AccessDenied:
        logger.warning("Access denied for network connections")
    return conns


def collect_windows_services() -> list[dict]:
    """Collect Windows services — read-only."""
    services = []
    try:
        result = subprocess.run(
            ["sc", "query", "type=", "all", "state=", "all"],
            capture_output=True, text=True, timeout=15, creationflags=0x08000000
        )
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if current:
                    services.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("STATE") and current:
                parts = line.split()
                current["state"] = parts[-1] if len(parts) > 1 else "UNKNOWN"
        if current:
            services.append(current)
    except Exception as e:
        logger.debug(f"Service collection error: {e}")

    return services[:100]


def collect_windows_event_logs(max_events: int = 100) -> list[dict]:
    """
    Collect recent Security and System event log entries — read-only.
    Uses PowerShell Get-EventLog (no WMI dependency).
    """
    events = []
    channels = [
        ("Security", "4624,4625,4648,4657,4688,4697,4720,4726,4732,4756"),
        ("System", "7045,7036"),
        ("Application", "1000,1001"),
    ]

    for channel, event_ids in channels:
        try:
            ps_cmd = (
                f"Get-WinEvent -FilterHashtable @{{LogName='{channel}'; Id={event_ids}}} "
                f"-MaxEvents {max_events // len(channels)} -ErrorAction SilentlyContinue "
                f"| Select-Object Id,LevelDisplayName,TimeCreated,Message "
                f"| ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=20, creationflags=0x08000000
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for evt in data:
                    events.append({
                        "channel": channel,
                        "event_id": evt.get("Id"),
                        "level": evt.get("LevelDisplayName", ""),
                        "time": str(evt.get("TimeCreated", "")),
                        "message": str(evt.get("Message", ""))[:500],
                    })
        except Exception as e:
            logger.debug(f"Event log collection error for {channel}: {e}")

    return events


def collect_registry_suspicious_keys() -> list[str]:
    """
    Check suspicious registry persistence keys — read-only.
    Only reads Run/RunOnce keys for persistence detection.
    """
    found = []
    persistence_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]

    for key in persistence_keys:
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=5, creationflags=0x08000000
            )
            if result.returncode == 0 and result.stdout.strip():
                found.append(key)
        except Exception:
            pass

    return found


def collect_system_info() -> dict:
    """System metadata — read-only."""
    try:
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")
        return {
            "hostname": platform.node(),
            "os": "Windows",
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total": mem.total,
            "memory_used": mem.used,
            "memory_percent": mem.percent,
            "disk_total": disk.total,
            "disk_used": disk.used,
            "disk_percent": disk.percent,
            "uptime_seconds": int(time.time() - psutil.boot_time()),
            "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"System info error: {e}")
        return {}


def get_local_ip() -> str:
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2 and not addr.address.startswith("127."):
                    return addr.address
    except Exception:
        pass
    return ""


def send_telemetry(payload: dict) -> bool:
    url = f"{BACKEND_URL}/api/v1/devices/{DEVICE_ID}/telemetry"
    headers = {
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": f"CyberGuard-Collector-Windows/{VERSION}",
    }

    for attempt in range(3):
        try:
            with httpx.Client(timeout=30, verify=True) as client:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 202:
                    return True
                elif resp.status_code == 401:
                    logger.error("Invalid agent token")
                    return False
        except httpx.ConnectError:
            logger.warning(f"Connection failed (attempt {attempt+1}/3)")
            time.sleep(2 ** attempt)
        except Exception as e:
            logger.error(f"Send error: {e}")
            time.sleep(5)
    return False


def validate_config() -> bool:
    if not AGENT_TOKEN:
        logger.critical("CYBERGUARD_AGENT_TOKEN not set")
        return False
    if not DEVICE_ID:
        logger.critical("CYBERGUARD_DEVICE_ID not set")
        return False
    return True


def main():
    logger.info(f"CyberGuard Windows Collector {VERSION} starting")
    if not validate_config():
        sys.exit(1)

    while RUNNING:
        try:
            start = time.monotonic()

            payload = {
                "event_type": "system_telemetry",
                "agent_version": VERSION,
                "ip_address": get_local_ip(),
                "raw_data": {
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "system_info": collect_system_info(),
                    "processes": collect_processes(),
                    "connections": collect_connections(),
                    "services": collect_windows_services(),
                    "windows_events": collect_windows_event_logs(),
                    "registry_events": collect_registry_suspicious_keys(),
                },
            }

            success = send_telemetry(payload)
            elapsed = time.monotonic() - start
            logger.info(f"Telemetry: {'OK' if success else 'FAILED'} ({elapsed:.1f}s)")

        except Exception as e:
            logger.error(f"Collection error: {e}", exc_info=True)

        for _ in range(INTERVAL_SECONDS * 2):
            if not RUNNING:
                break
            time.sleep(0.5)

    logger.info("Collector stopped")


if __name__ == "__main__":
    main()
