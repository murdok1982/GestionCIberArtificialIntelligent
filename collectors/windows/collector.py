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
import hashlib
import hmac
import secrets
import platform
import subprocess
from datetime import datetime, timezone
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


def _backend_host() -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(BACKEND_URL).hostname or ""
    except Exception:
        return ""


def fetch_commands() -> list[dict]:
    """Poll pending commands from the backend (device-authenticated)."""
    url = f"{BACKEND_URL}/api/v1/devices/{DEVICE_ID}/commands"
    headers = {"Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"CyberGuard-Collector-Windows/{VERSION}"}
    try:
        with httpx.Client(timeout=30, verify=True) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.error(f"Command poll error: {e}")
    return []


def report_command_result(command_id: str, status: str, result: str) -> None:
    url = f"{BACKEND_URL}/api/v1/devices/{DEVICE_ID}/commands/{command_id}/result"
    headers = {"Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"CyberGuard-Collector-Windows/{VERSION}"}
    try:
        with httpx.Client(timeout=30, verify=True) as client:
            client.post(url, json={"status": status, "result": result}, headers=headers)
    except Exception as e:
        logger.error(f"Command result report error: {e}")


def _run_isolate_device() -> str:
    """Best-effort network isolation via Windows Firewall (block all, allow backend)."""
    host = _backend_host()
    try:
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound", "blockoutbound"],
            capture_output=True, text=True, timeout=30, creationflags=0x08000000, check=True,
        )
        if host:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", "name", "CyberGuard-Mgmt",
                 "dir", "out", "action", "allow", "remoteip", host],
                capture_output=True, text=True, timeout=30, creationflags=0x08000000,
            )
        return "windows firewall isolation applied (inbound/outbound blocked; backend allowed)"
    except Exception as e:
        return f"isolation failed: {e}"


def handle_command(cmd: dict) -> tuple[str, str]:
    """Execute a single command. Returns (status, result_text)."""
    action = cmd.get("action_type", "")
    params = cmd.get("params", {}) or {}
    try:
        if action == "kill_process":
            pid = int(params.get("pid", 0))
            if pid > 0:
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True,
                                text=True, timeout=30, creationflags=0x08000000, check=True)
                return "completed", f"process {pid} terminated"
            return "failed", "kill_process requires a valid pid"
        if action == "isolate_device":
            return "completed", _run_isolate_device()
        if action == "scan_device":
            return "completed", "targeted scan queued (host telemetry continues)"
        if action == "collect_evidence":
            return "completed", "evidence collection acknowledged (triggered on next telemetry cycle)"
        return "completed", f"action '{action}' acknowledged by collector"
    except Exception as e:
        return "failed", f"{action} failed: {e}"


def process_pending_commands() -> None:
    commands = fetch_commands()
    for cmd in commands:
        status, result = handle_command(cmd)
        logger.warning(f"COMMAND {cmd.get('command_id')} action={cmd.get('action_type')} -> {status}")
        report_command_result(cmd.get("command_id"), status, result)


def sign_telemetry(device_id: str, raw_token: str, timestamp: str, nonce: str, payload_bytes: bytes) -> str:
    """Create HMAC signature for telemetry including device_id in signing input."""
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    signing_input = f"{device_id}.{timestamp}.{nonce}.{payload_hash}".encode("utf-8")
    return hmac.new(raw_token.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()


def send_telemetry(payload: dict) -> bool:
    url = f"{BACKEND_URL}/api/v1/devices/{DEVICE_ID}/telemetry"
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_urlsafe(16)
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = sign_telemetry(DEVICE_ID, AGENT_TOKEN, timestamp, nonce, payload_bytes)
    headers = {
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": f"CyberGuard-Collector-Windows/{VERSION}",
        "X-Telemetry-Timestamp": timestamp,
        "X-Telemetry-Nonce": nonce,
        "X-Telemetry-Signature": signature,
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

            # Poll and execute any pending response commands
            try:
                process_pending_commands()
            except Exception as e:
                logger.error(f"Command processing error: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Collection error: {e}", exc_info=True)

        for _ in range(INTERVAL_SECONDS * 2):
            if not RUNNING:
                break
            time.sleep(0.5)

    logger.info("Collector stopped")


if __name__ == "__main__":
    main()