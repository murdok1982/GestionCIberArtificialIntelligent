"""
DETECTION AGENT
Analyzes telemetry data applying Sigma-like rules and anomaly detection.
"""
import re
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Detection:
    rule_id: str
    rule_name: str
    severity: str  # info/low/medium/high/critical
    description: str
    mitre_tactic: str
    mitre_technique: str
    matched_data: dict
    iocs: list
    confidence: float  # 0.0 - 1.0


SIGMA_RULES = [
    {
        "id": "ssh_brute_force",
        "name": "SSH Brute Force Attack",
        "severity": "high",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "description": "Multiple failed SSH authentication attempts detected",
        "condition": lambda e: (
            e.get("event_type") == "auth_log" and
            len([l for l in e.get("raw_data", {}).get("log_entries", [])
                 if "Failed password" in l or "authentication failure" in l]) >= 5
        ),
    },
    {
        "id": "powershell_encoded",
        "name": "PowerShell Encoded Command Execution",
        "severity": "high",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001",
        "description": "PowerShell executing base64 encoded commands",
        "condition": lambda e: any(
            "powershell" in p.get("name", "").lower() and
            any(flag in " ".join(p.get("cmdline", [])).lower()
                for flag in ["-enc", "-encodedcommand", "-ec"])
            for p in e.get("raw_data", {}).get("processes", [])
        ),
    },
    {
        "id": "lateral_movement_smb",
        "name": "Lateral Movement via SMB",
        "severity": "critical",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.002",
        "description": "Suspicious SMB connections to multiple internal hosts",
        "condition": lambda e: (
            len(set(
                c.get("remote_address", "").split(":")[0]
                for c in e.get("raw_data", {}).get("connections", [])
                if c.get("remote_port") in (445, 139) and
                c.get("remote_address", "").startswith(("10.", "192.168.", "172."))
            )) >= 3
        ),
    },
    {
        "id": "privilege_escalation_sudo",
        "name": "Suspicious Sudo/Privilege Escalation",
        "severity": "high",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548",
        "description": "Process running with elevated privileges unexpectedly",
        "condition": lambda e: any(
            p.get("user") == "root" and
            p.get("parent_name", "") not in ("init", "systemd", "kernel", "sshd", "su", "sudo")
            and p.get("name", "") not in ("systemd", "kthreadd", "migration", "rcu_sched")
            for p in e.get("raw_data", {}).get("processes", [])
            if p.get("user") == "root"
        ),
    },
    {
        "id": "data_exfiltration_dns",
        "name": "DNS Exfiltration Pattern",
        "severity": "high",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048.003",
        "description": "Unusually high DNS query volume or long subdomain names (DNS tunneling)",
        "condition": lambda e: any(
            len(c.get("remote_address", "")) > 60 and c.get("remote_port") == 53
            for c in e.get("raw_data", {}).get("connections", [])
        ),
    },
    {
        "id": "unusual_outbound",
        "name": "Unusual Outbound Connection",
        "severity": "medium",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "description": "Connection to unusual high-numbered port or uncommon destination",
        "condition": lambda e: any(
            c.get("remote_port", 0) in range(4444, 4450) or
            c.get("remote_port", 0) in (1337, 31337, 8888, 9999)
            for c in e.get("raw_data", {}).get("connections", [])
            if not c.get("remote_address", "").startswith(("10.", "192.168.", "172."))
        ),
    },
    {
        "id": "process_injection",
        "name": "Process Injection Indicator",
        "severity": "critical",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1055",
        "description": "Process accessing memory regions of other processes",
        "condition": lambda e: any(
            any(flag in p.get("cmdline", []) for flag in ["--inject", "VirtualAllocEx", "WriteProcessMemory"])
            for p in e.get("raw_data", {}).get("processes", [])
        ),
    },
    {
        "id": "suspicious_scheduled_task",
        "name": "Suspicious Scheduled Task Creation",
        "severity": "high",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053",
        "description": "New scheduled task or cron job created by non-admin process",
        "condition": lambda e: any(
            ("schtasks" in p.get("name", "").lower() or "crontab" in p.get("name", "").lower()) and
            p.get("user", "") not in ("root", "SYSTEM", "Administrator")
            for p in e.get("raw_data", {}).get("processes", [])
        ),
    },
    {
        "id": "registry_persistence",
        "name": "Registry Persistence Key Modification",
        "severity": "high",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1547.001",
        "description": "Modification of registry run keys for persistence",
        "condition": lambda e: any(
            key in e.get("raw_data", {}).get("registry_events", [])
            for key in [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]
        ),
    },
    {
        "id": "log_clearing",
        "name": "Security Log Clearing",
        "severity": "critical",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001",
        "description": "Security or system logs are being cleared",
        "condition": lambda e: any(
            "wevtutil" in p.get("cmdline", []) or
            any("clear-eventlog" in c.lower() for c in p.get("cmdline", []))
            for p in e.get("raw_data", {}).get("processes", [])
        ),
    },
    {
        "id": "mass_file_encryption",
        "name": "Mass File Encryption (Ransomware)",
        "severity": "critical",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "description": "Rapid file extension changes or mass encryption activity",
        "condition": lambda e: (
            e.get("raw_data", {}).get("file_operations", {}).get("encryption_count", 0) > 50 or
            e.get("raw_data", {}).get("file_operations", {}).get("rename_count", 0) > 100
        ),
    },
    {
        "id": "credential_dump_lsass",
        "name": "LSASS Memory Access (Credential Dumping)",
        "severity": "critical",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001",
        "description": "Process accessing LSASS memory for credential extraction",
        "condition": lambda e: any(
            "lsass" in p.get("cmdline", []) or
            p.get("name", "").lower() in ("mimikatz", "procdump") or
            any("lsass.exe" in c.lower() for c in p.get("cmdline", []))
            for p in e.get("raw_data", {}).get("processes", [])
        ),
    },
]


class DetectionAgent:

    async def analyze_telemetry(self, event_data: dict) -> list[dict]:
        """Apply all Sigma rules to the event data."""
        detections = []
        for rule in SIGMA_RULES:
            try:
                if rule["condition"](event_data):
                    detection = {
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "mitre_technique": rule["mitre_technique"],
                        "description": rule["description"],
                        "iocs": self._extract_iocs_from_event(event_data, rule["id"]),
                        "confidence": 0.85,
                    }
                    detections.append(detection)
                    logger.info(f"Detection: {rule['id']} severity={rule['severity']}")
            except Exception as e:
                logger.debug(f"Rule {rule['id']} evaluation error: {e}")

        return detections

    async def detect_anomalies(self, device_id: str, baseline: dict, current: dict) -> list[dict]:
        """Statistical anomaly detection based on behavioral baseline."""
        anomalies = []

        cpu_baseline = baseline.get("avg_cpu", 20)
        cpu_current = current.get("cpu_percent", 0)
        if cpu_current > cpu_baseline * 3 and cpu_current > 80:
            anomalies.append({
                "rule_id": "anomaly_cpu_spike",
                "rule_name": "CPU Usage Anomaly",
                "severity": "medium",
                "mitre_tactic": "Impact",
                "mitre_technique": "T1496",
                "description": f"CPU usage {cpu_current:.0f}% vs baseline {cpu_baseline:.0f}%",
                "iocs": [],
                "confidence": 0.7,
            })

        conn_baseline = baseline.get("avg_connections", 10)
        conn_current = current.get("connection_count", 0)
        if conn_current > conn_baseline * 5:
            anomalies.append({
                "rule_id": "anomaly_connection_spike",
                "rule_name": "Network Connection Anomaly",
                "severity": "high",
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071",
                "description": f"Connection count {conn_current} vs baseline {conn_baseline}",
                "iocs": [],
                "confidence": 0.75,
            })

        return anomalies

    def _extract_iocs_from_event(self, event_data: dict, rule_id: str) -> list[dict]:
        iocs = []
        raw = event_data.get("raw_data", {})

        if "ssh" in rule_id or "brute" in rule_id:
            for log in raw.get("log_entries", []):
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)
                if ip_match:
                    iocs.append({"type": "ip", "value": ip_match.group(1)})

        for conn in raw.get("connections", []):
            remote = conn.get("remote_address", "")
            if remote and not remote.startswith(("10.", "192.168.", "172.", "127.")):
                iocs.append({"type": "ip", "value": remote.split(":")[0]})

        return iocs

    async def calculate_risk_score(self, detections: list[dict]) -> float:
        """Aggregate risk score from 0.0 to 10.0"""
        if not detections:
            return 0.0
        severity_weights = {"info": 0.5, "low": 1.0, "medium": 3.0, "high": 6.0, "critical": 10.0}
        scores = [severity_weights.get(d.get("severity", "low"), 1.0) * d.get("confidence", 0.5) for d in detections]
        return min(10.0, sum(scores) / len(scores) + (len(detections) - 1) * 0.5)
