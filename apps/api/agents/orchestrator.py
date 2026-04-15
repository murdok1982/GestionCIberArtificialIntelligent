"""
ORCHESTRATOR AGENT
Central coordinator of the multi-agent system.
- Receives events from collectors
- Evaluates imminent danger
- Dispatches to specialized agents
- Requests human approval for actions (unless imminent danger)
"""
import uuid
import logging
from datetime import datetime
from typing import Any
from dataclasses import dataclass, field
from enum import Enum

from apps.api.agents.detection_agent import DetectionAgent
from apps.api.agents.threat_intel_agent import ThreatIntelAgent
from apps.api.agents.forensic_agent import ForensicAgent
from apps.api.agents.custody_agent import CustodyAgent

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    ISOLATE_DEVICE = "isolate_device"
    KILL_PROCESS = "kill_process"
    BLOCK_CONNECTION = "block_connection"
    COLLECT_EVIDENCE = "collect_evidence"
    QUARANTINE_FILE = "quarantine_file"
    NOTIFY_ADMIN = "notify_admin"
    SCAN_DEVICE = "scan_device"


@dataclass
class RemoteAction:
    action_type: ActionType
    device_id: uuid.UUID
    params: dict
    justification: str
    risk_level: str
    requires_approval: bool = True
    auto_approved: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AgentDecision:
    alert_id: uuid.UUID | None
    severity: str
    detections: list
    threat_intel: dict | None
    llm_analysis: dict | None
    recommended_actions: list[RemoteAction]
    is_imminent_danger: bool
    auto_actions_taken: list[str]
    requires_human_approval: bool


class OrchestratorAgent:
    """
    Central orchestrator that coordinates all security agents.
    Autonomy is limited to imminent danger scenarios only.
    All other actions require human approval.
    """

    IMMINENT_DANGER_INDICATORS = {
        "ransomware_execution",
        "mass_file_encryption",
        "critical_data_exfiltration",
        "active_lateral_movement",
        "admin_credential_dump",
        "security_tool_termination",
        "backup_deletion",
    }

    def __init__(self):
        self.detection_agent = DetectionAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.forensic_agent = ForensicAgent()
        self.custody_agent = CustodyAgent()

    async def process_event(self, event_data: dict, db) -> AgentDecision:
        """
        Main entry point for event processing.
        1. Run detection analysis
        2. Check for imminent danger
        3. Enrich with threat intel if high severity
        4. Trigger LLM analysis for medium+ severity
        5. Decide on actions
        """
        from apps.api.services.event_service import EventService
        from apps.api.services.llm_service import GemmaAnalystService

        logger.info(f"Orchestrator processing event type={event_data.get('event_type')} device={event_data.get('device_id')}")

        # Step 1: Detection
        detections = await self.detection_agent.analyze_telemetry(event_data)

        if not detections:
            return AgentDecision(
                alert_id=None,
                severity="info",
                detections=[],
                threat_intel=None,
                llm_analysis=None,
                recommended_actions=[],
                is_imminent_danger=False,
                auto_actions_taken=[],
                requires_human_approval=False,
            )

        max_severity = max(d.get("severity", "low") for d in detections)
        is_imminent = await self.evaluate_imminent_danger(event_data, detections)

        # Step 2: Threat Intel enrichment for medium+ severity
        threat_intel_data = None
        if max_severity in ("medium", "high", "critical"):
            iocs = self._extract_iocs(event_data, detections)
            threat_intel_data = await self.threat_intel_agent.enrich_iocs(iocs)

        # Step 3: LLM analysis for high/critical
        llm_analysis = None
        if max_severity in ("high", "critical") or is_imminent:
            llm_service = GemmaAnalystService()
            llm_analysis = await llm_service.analyze_security_event({
                "event": event_data,
                "detections": detections,
                "threat_intel": threat_intel_data,
            })

        # Step 4: Determine actions
        recommended_actions = await self._determine_actions(
            event_data, detections, is_imminent, llm_analysis
        )

        # Step 5: Execute autonomous actions only if imminent danger
        auto_actions_taken = []
        if is_imminent:
            for action in recommended_actions:
                if action.action_type in (ActionType.ISOLATE_DEVICE, ActionType.KILL_PROCESS):
                    result = await self.execute_remote_action(
                        action.device_id, action.action_type, action.params
                    )
                    action.auto_approved = True
                    auto_actions_taken.append(f"{action.action_type}: {result}")
                    logger.warning(f"AUTO-ACTION taken (imminent danger): {action.action_type} on {action.device_id}")

        return AgentDecision(
            alert_id=None,  # Set by calling service after creating alert
            severity=max_severity,
            detections=detections,
            threat_intel=threat_intel_data,
            llm_analysis=llm_analysis,
            recommended_actions=recommended_actions,
            is_imminent_danger=is_imminent,
            auto_actions_taken=auto_actions_taken,
            requires_human_approval=len(recommended_actions) > len(auto_actions_taken),
        )

    async def evaluate_imminent_danger(self, event_data: dict, detections: list) -> bool:
        """
        Evaluates if the situation constitutes imminent danger requiring immediate autonomous action.
        Criteria:
        - Any detection matching known ransomware/wiper patterns
        - Active credential dumping with outbound C2 traffic
        - Mass file operations combined with process injection
        """
        event_type = event_data.get("event_type", "")
        detection_types = {d.get("rule_id", "") for d in detections}

        if any(indicator in detection_types for indicator in self.IMMINENT_DANGER_INDICATORS):
            logger.critical(f"IMMINENT DANGER detected: {detection_types & self.IMMINENT_DANGER_INDICATORS}")
            return True

        # Multi-indicator evaluation: process injection + C2 communication simultaneously
        has_injection = any("injection" in d.get("rule_id", "") for d in detections)
        has_c2 = any("c2" in d.get("rule_id", "") or "exfiltration" in d.get("rule_id", "") for d in detections)
        critical_count = sum(1 for d in detections if d.get("severity") == "critical")

        if has_injection and has_c2:
            logger.critical("IMMINENT DANGER: Process injection + C2 communication detected simultaneously")
            return True

        if critical_count >= 3:
            logger.critical(f"IMMINENT DANGER: {critical_count} critical detections simultaneously")
            return True

        return False

    async def execute_remote_action(self, device_id: uuid.UUID, action: str, params: dict) -> str:
        """
        Execute a remote action on a device.
        Only called autonomously for imminent danger.
        All other uses MUST have prior human approval recorded.
        """
        logger.warning(f"Executing remote action {action} on device {device_id} params={params}")
        # In production: send command via secure websocket/MQTT to device agent
        # The collector agent on the device handles execution
        return f"Action {action} dispatched to device {device_id}"

    async def request_human_approval(self, action: RemoteAction, alert_id: uuid.UUID) -> dict:
        """Creates an approval request record for human review."""
        return {
            "approval_required": True,
            "alert_id": str(alert_id),
            "action_type": action.action_type,
            "device_id": str(action.device_id),
            "params": action.params,
            "justification": action.justification,
            "risk_level": action.risk_level,
            "created_at": action.created_at.isoformat(),
        }

    def _extract_iocs(self, event_data: dict, detections: list) -> list[dict]:
        iocs = []
        raw = event_data.get("raw_data", {})

        # Extract IPs
        for conn in raw.get("connections", []):
            remote = conn.get("remote_address", "")
            if remote and not remote.startswith(("10.", "192.168.", "172.")):
                iocs.append({"type": "ip", "value": remote})

        # Extract file hashes
        for proc in raw.get("processes", []):
            if h := proc.get("md5") or proc.get("sha256"):
                iocs.append({"type": "hash", "value": h})

        # Extract domains from detections
        for det in detections:
            for ioc in det.get("iocs", []):
                iocs.append(ioc)

        return iocs

    async def _determine_actions(
        self, event_data: dict, detections: list, is_imminent: bool, llm_analysis: dict | None
    ) -> list[RemoteAction]:
        actions = []
        device_id = uuid.UUID(str(event_data.get("device_id")))

        for detection in detections:
            if detection.get("severity") == "critical":
                actions.append(RemoteAction(
                    action_type=ActionType.COLLECT_EVIDENCE,
                    device_id=device_id,
                    params={"scope": "full", "include_memory": is_imminent},
                    justification=f"Critical detection: {detection.get('rule_name')}",
                    risk_level="high",
                    requires_approval=not is_imminent,
                ))

            if "lateral_movement" in detection.get("rule_id", "") or is_imminent:
                actions.append(RemoteAction(
                    action_type=ActionType.ISOLATE_DEVICE,
                    device_id=device_id,
                    params={"allow_management": True},
                    justification=f"Lateral movement or imminent danger: {detection.get('rule_name')}",
                    risk_level="critical",
                    requires_approval=not is_imminent,
                ))

        # LLM recommendations
        if llm_analysis and llm_analysis.get("recommendations"):
            for rec in llm_analysis["recommendations"][:3]:  # Max 3 LLM-driven actions
                if rec.get("action_type") and not rec.get("requires_approval", True):
                    actions.append(RemoteAction(
                        action_type=ActionType.SCAN_DEVICE,
                        device_id=device_id,
                        params={"scan_type": "targeted"},
                        justification=rec.get("description", "LLM recommendation"),
                        risk_level="medium",
                        requires_approval=True,
                    ))

        return actions
