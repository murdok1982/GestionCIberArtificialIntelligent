"""Tests for new production-hardening features: command dispatch, audit log, MFA, enrollment."""
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock

from apps.api.services.command_service import CommandService
from apps.api.services.audit_service import AuditService
from apps.api.models.command import DeviceCommand, CommandStatus
from apps.api.models.audit import AuditCategory, AuditSeverity
from apps.api.routes import devices as devices_route


@pytest.fixture
def fake_ids():
    return uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


@pytest.mark.asyncio
async def test_enqueue_persists_and_pushes_redis(mock_db, mock_redis, fake_ids, monkeypatch):
    tenant_id, device_id, user_id = fake_ids
    import apps.api.services.command_service as cs
    fake_get_redis = AsyncMock(return_value=mock_redis)
    monkeypatch.setattr(cs, "get_redis", fake_get_redis)

    svc = CommandService()
    cmd = await svc.enqueue(
        mock_db,
        tenant_id=tenant_id,
        device_id=device_id,
        action_type="isolate_device",
        params={"reason": "test"},
        requested_by=user_id,
        auto_triggered=False,
    )

    assert isinstance(cmd, DeviceCommand)
    assert cmd.tenant_id == tenant_id
    assert cmd.device_id == device_id
    assert cmd.status == CommandStatus.pending
    mock_db.add.assert_called_once()
    mock_redis.lpush.assert_awaited_once()


@pytest.mark.asyncio
async def test_report_result_updates_command(mock_db, mock_redis, fake_ids, monkeypatch):
    _, device_id, _ = fake_ids
    cmd = DeviceCommand(
        id=uuid.uuid4(), tenant_id=fake_ids[0], device_id=device_id,
        action_type="isolate_device", params={}, status=CommandStatus.pending,
    )
    mock_db.get = lambda model, cid: _coro(cmd)

    import apps.api.services.command_service as cs
    fake_get_redis = AsyncMock(return_value=mock_redis)
    monkeypatch.setattr(cs, "get_redis", fake_get_redis)

    svc = CommandService()
    result = await svc.report_result(
        mock_db, command_id=cmd.id, device_id=device_id,
        status=CommandStatus.completed, result="done",
    )
    assert result.status == CommandStatus.completed
    assert result.result == "done"
    assert result.executed_at is not None


@pytest.mark.asyncio
async def test_fetch_pending_marks_dispatched(mock_db, mock_redis, fake_ids, monkeypatch):
    import apps.api.services.command_service as cs
    monkeypatch.setattr(cs, "get_redis", AsyncMock(return_value=mock_redis))

    _, device_id, _ = fake_ids
    cmd = DeviceCommand(
        id=uuid.uuid4(), tenant_id=fake_ids[0], device_id=device_id,
        action_type="isolate_device", params={}, status=CommandStatus.pending,
    )
    mock_redis.lrange = AsyncMock(return_value=[str(cmd.id)])

    scalars = MagicMock()
    scalars.all = MagicMock(return_value=[cmd])
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)
    mock_db.execute = AsyncMock(return_value=result)

    svc = CommandService()
    cmds = await svc.fetch_pending(mock_db, device_id=device_id)
    assert len(cmds) == 1
    assert cmds[0].status == CommandStatus.dispatched
    mock_redis.lrange.assert_awaited_once()


@pytest.mark.asyncio
async def test_audit_record_persists(mock_db):
    svc = AuditService()
    entry = await svc.record(
        mock_db, category=AuditCategory.auth, action="login",
        severity=AuditSeverity.warning, tenant_id=uuid.uuid4(),
    )
    assert entry.category == AuditCategory.auth
    assert entry.action == "login"
    mock_db.add.assert_called_once()


def test_enrollment_code_hash_is_stable():
    from apps.api.routes.devices import _hash_enrollment_code
    code = "a" * 40
    assert _hash_enrollment_code(code) == _hash_enrollment_code(code)
    assert _hash_enrollment_code(code) != _hash_enrollment_code("b" * 40)


def test_install_command_uses_download_not_pipe(monkeypatch):
    import apps.api.config as cfg
    monkeypatch.setattr(cfg.settings, "BACKEND_PUBLIC_URL", "https://example.com")
    monkeypatch.setattr(cfg.settings, "ENROLL_SCRIPTS_DIR", None)

    from apps.api.models.device import OSType
    cmd = devices_route._get_install_command(OSType.linux, "CODE123", uuid.uuid4())
    assert "| bash" not in cmd
    assert "example.com/enroll.sh" in cmd
    assert "-o /tmp/cyberguard-enroll.sh" in cmd


def _coro(value):
    async def _inner():
        return value
    return _inner()
