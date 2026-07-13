"""
Celery tasks for detection-specific operations.
"""
import logging
from apps.api.celery_app import celery_app

logger = logging.getLogger(__name__)


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