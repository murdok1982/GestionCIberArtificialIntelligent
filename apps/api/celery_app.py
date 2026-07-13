"""
Celery configuration for background task processing.
"""
import os
from celery import Celery
from kombu import Queue

# Celery configuration
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

celery_app = Celery(
    "cyberguard",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=[
        "apps.api.tasks.event_tasks",
        "apps.api.tasks.detection_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,
    task_soft_time_limit=240,
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    task_routes={
        "apps.api.tasks.event_tasks.process_event": {"queue": "events"},
        "apps.api.tasks.detection_tasks.run_detection": {"queue": "detection"},
    },
    task_queues=(
        Queue("default", routing_key="default"),
        Queue("events", routing_key="events"),
        Queue("detection", routing_key="detection"),
    ),
    beat_schedule={},
)

# Auto-discover tasks
celery_app.autodiscover_tasks()