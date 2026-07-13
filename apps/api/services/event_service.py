"""
Event processing service - orchestrates the multi-agent pipeline.
"""
import uuid
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from apps.api.models.alert import Alert, AlertSeverity
from apps.api.agents.orchestrator import OrchestratorAgent
from apps.api.agents.detection_agent import DetectionAgent
from apps.api.agents.threat_intel_agent import ThreatIntelAgent
from apps.api.agents.forensic_agent import ForensicAgent
from apps.api.agents.custody_agent import CustodyAgent
from apps.api.services.llm_service import GemmaAnalystService
from apps.api.services.command_service import CommandService
from apps.api.services.audit_service import AuditService
from apps.api.models.audit import AuditCategory, AuditSeverity
from apps.api.tasks.event_tasks import process_event as celery_process_event

logger = logging.getLogger(__name__)


class EventService:
    """Service for processing telemetry events through the agent pipeline."""

    def __init__(
        self,
        db: AsyncSession,
        detection_agent: DetectionAgent | None = None,
        threat_intel_agent: ThreatIntelAgent | None = None,
        forensic_agent: ForensicAgent | None = None,
        custody_agent: CustodyAgent | None = None,
        llm_service: GemmaAnalystService | None = None,
    ):
        self.db = db
        self.detection_agent = detection_agent or DetectionAgent()
        self.threat_intel_agent = threat_intel_agent or ThreatIntelAgent()
        self.forensic_agent = forensic_agent or ForensicAgent()
        self.custody_agent = custody_agent or CustodyAgent()
        self.llm_service = llm_service or GemmaAnalystService()

        self.orchestrator = OrchestratorAgent(
            detection_agent=self.detection_agent,
            threat_intel_agent=self.threat_intel_agent,
            forensic_agent=self.forensic_agent,
            custody_agent=self.custody_agent,
            llm_service=self.llm_service,
        )

    async def process_event(self, event_data: dict) -> dict:
        """
        Process a telemetry event through the full agent pipeline.
        Returns the orchestration decision.
        """
        logger.info(f"Processing event {event_data.get('event_id')} for device {event_data.get('device_id')}")

        decision = await self.orchestrator.process_event(event_data, self.db)

        # If there are detections, create alert
        if decision.detections:
            alert = await self._create_alert(event_data, decision)

            # If imminent danger, execute autonomous actions (dispatched to collector)
            if decision.is_imminent_danger:
                for action in decision.recommended_actions:
                    if action.auto_approved:
                        await self._dispatch_autonomous_command(alert, action)

            # Queue any actions requiring human approval
            if decision.requires_human_approval:
                for action in decision.recommended_actions:
                    await self._queue_approval_request(alert.id, action)

        return {
            "decision": decision,
            "alert_id": str(alert.id) if decision.detections else None,
        }

    async def process_event_async(self, event_data: dict) -> str:
        """
        Queue event for async processing via Celery.
        Returns the task ID.
        """
        task = celery_process_event.delay(event_data)
        return task.id

    async def _create_alert(self, event_data: dict, decision) -> Alert:
        """Create an alert from the orchestration decision."""
        alert = Alert(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(event_data["tenant_id"]),
            device_id=uuid.UUID(event_data["device_id"]),
            event_id=uuid.UUID(event_data["event_id"]),
            severity=AlertSeverity(decision.severity),
            title=f"Detection: {', '.join(d.get('rule_name', 'Unknown') for d in decision.detections[:3])}",
            description=self._build_alert_description(decision),
            detections=[d.get("rule_id", "") for d in decision.detections],
            threat_intel=decision.threat_intel,
            llm_analysis=decision.llm_analysis,
            is_imminent_danger=decision.is_imminent_danger,
            status="open",
        )
        self.db.add(alert)
        await self.db.flush()
        return alert

    def _build_alert_description(self, decision) -> str:
        parts = []
        for d in decision.detections:
            parts.append(f"- {d.get('rule_name', 'Unknown')}: {d.get('description', 'No description')} (Severity: {d.get('severity', 'low')})")
        if decision.threat_intel:
            parts.append(f"\nThreat Intel: {decision.threat_intel}")
        if decision.llm_analysis:
            parts.append(f"\nAI Analysis: {decision.llm_analysis.get('summary', 'N/A')}")
        return "\n".join(parts)

    async def _dispatch_autonomous_command(self, alert, action) -> None:
        """Dispatch an autonomous remediation command to the endpoint's collector.

        Only invoked for imminent-danger scenarios (e.g. ransomware, active
        lateral movement). The collector executes it and reports the result.
        """
        command = await CommandService().enqueue(
            self.db,
            tenant_id=alert.tenant_id,
            device_id=alert.device_id,
            action_type=action.action_type.value,
            params=action.params,
            justification=action.justification,
            auto_triggered=True,
        )
        logger.warning(
            f"AUTONOMOUS COMMAND dispatched: {command.id} action={action.action_type.value} "
            f"device={alert.device_id} alert={alert.id}"
        )
        await AuditService().record(
            self.db, category=AuditCategory.command, action="autonomous_command",
            severity=AuditSeverity.critical, tenant_id=alert.tenant_id,
            detail={
                "alert_id": str(alert.id),
                "command_id": str(command.id),
                "action_type": action.action_type.value,
            },
        )

    async def _execute_autonomous_action(self, alert_id: uuid.UUID, action_name: str):
        """Deprecated: kept for backward compatibility. Use _dispatch_autonomous_command."""
        logger.warning(f"EXECUTING AUTONOMOUS ACTION: {action_name} for alert {alert_id}")

    async def _queue_approval_request(self, alert_id: uuid.UUID, action):
        """Queue a human approval request for a recommended action."""
        logger.info(f"Approval required for alert {alert_id}: {action.action_type}")
        # In production: create approval request record, notify admins