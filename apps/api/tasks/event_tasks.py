"""
Celery tasks for event processing and detection.
"""
import logging
from apps.api.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def process_event(self, event_data: dict):
    """Process telemetry event through the orchestrator."""
    try:
        from apps.api.services.event_service import EventService
        from apps.api.database import AsyncSessionLocal
        import asyncio

        async def _run():
            async with AsyncSessionLocal() as db:
                service = EventService(db)
                await service.process_event(event_data)

        asyncio.run(_run())
        return {"status": "processed", "event_id": event_data.get("event_id")}

    except Exception as exc:
        logger.error(f"Event processing failed: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def run_detection(self, event_data: dict):
    """Run detection analysis on telemetry."""
    try:
        from apps.api.agents.detection_agent import DetectionAgent
        import asyncio

        async def _run():
            agent = DetectionAgent()
            return await agent.analyze_telemetry(event_data)

        detections = asyncio.run(_run())
        return {"status": "completed", "detections": detections}

    except Exception as exc:
        logger.error(f"Detection failed: {exc}")
        raise self.retry(exc=exc)