"""Command dispatch service: queue remediation actions to collectors.

Commands are pushed to a per-device Redis list for fast delivery and persisted
in `device_commands` as the durable, auditable record. Collectors poll pending
commands, execute them, and report results back.
"""
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.redis_client import get_redis
from apps.api.models.command import DeviceCommand, CommandStatus

logger = logging.getLogger(__name__)

_REDIS_PREFIX = "device:commands:"


class CommandService:
    async def enqueue(
        self,
        db: AsyncSession,
        *,
        tenant_id: uuid.UUID,
        device_id: uuid.UUID,
        action_type: str,
        params: dict,
        requested_by: Optional[uuid.UUID] = None,
        justification: Optional[str] = None,
        auto_triggered: bool = False,
    ) -> DeviceCommand:
        command = DeviceCommand(
            tenant_id=tenant_id,
            device_id=device_id,
            action_type=action_type,
            params=params or {},
            justification=justification,
            requested_by=requested_by,
            auto_triggered=auto_triggered,
            status=CommandStatus.pending,
        )
        db.add(command)
        await db.flush()
        await db.refresh(command)

        redis = await get_redis()
        await redis.lpush(f"{_REDIS_PREFIX}{device_id}", str(command.id))
        logger.info(
            "Command queued: %s action=%s device=%s auto=%s",
            command.id, action_type, device_id, auto_triggered,
        )
        return command

    async def fetch_pending(
        self, db: AsyncSession, *, device_id: uuid.UUID, limit: int = 10
    ) -> list[DeviceCommand]:
        """Return pending commands for a device and mark them as dispatched."""
        redis = await get_redis()
        ids = await redis.lrange(f"{_REDIS_PREFIX}{device_id}", 0, -1)
        if not ids:
            return []

        result = await db.execute(
            select(DeviceCommand).where(
                DeviceCommand.id.in_(ids),
                DeviceCommand.device_id == device_id,
                DeviceCommand.status == CommandStatus.pending,
            ).order_by(DeviceCommand.created_at.asc()).limit(limit)
        )
        commands = result.scalars().all()
        for command in commands:
            command.status = CommandStatus.dispatched
        if commands:
            await db.flush()
        return commands

    async def report_result(
        self,
        db: AsyncSession,
        *,
        command_id: uuid.UUID,
        device_id: uuid.UUID,
        status: CommandStatus,
        result: Optional[str] = None,
    ) -> Optional[DeviceCommand]:
        command = await db.get(DeviceCommand, command_id)
        if command is None or command.device_id != device_id:
            return None
        # Only pending/dispatched commands may be updated by the collector.
        if command.status not in (CommandStatus.pending, CommandStatus.dispatched):
            return command
        command.status = status
        command.result = result
        command.executed_at = datetime.now(timezone.utc)
        await db.flush()

        redis = await get_redis()
        await redis.lrem(f"{_REDIS_PREFIX}{device_id}", 0, str(command_id))
        logger.info("Command %s result=%s device=%s", command_id, status.value, device_id)
        return command
