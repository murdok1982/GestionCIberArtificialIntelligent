from functools import wraps
from typing import Callable
from fastapi import Depends, HTTPException, status
from apps.api.middleware.auth import get_current_user
from apps.api.models.user import UserRole


PERMISSIONS: dict[str, list[str]] = {
    UserRole.owner: ["*"],
    UserRole.admin: [
        "devices:read", "devices:create", "devices:update", "devices:delete",
        "alerts:read", "alerts:create", "alerts:update", "alerts:delete",
        "forensics:read", "forensics:create", "forensics:update",
        "threat_intel:read", "threat_intel:create",
        "users:read", "users:create", "users:update",
        "billing:read",
        "actions:approve",
    ],
    UserRole.analyst: [
        "devices:read",
        "alerts:read", "alerts:update",
        "forensics:read", "forensics:create",
        "threat_intel:read", "threat_intel:create",
        "actions:approve",
    ],
    UserRole.viewer: [
        "devices:read",
        "alerts:read",
        "forensics:read",
        "threat_intel:read",
    ],
}


def has_permission(user_role: str, permission: str) -> bool:
    role_perms = PERMISSIONS.get(user_role, [])
    if "*" in role_perms:
        return True
    if permission in role_perms:
        return True
    # Check wildcard resource permissions (e.g. "devices:*")
    resource = permission.split(":")[0]
    if f"{resource}:*" in role_perms:
        return True
    return False


def require_permission(permission: str):
    """FastAPI dependency for permission-based authorization."""
    def dependency(current_user=Depends(get_current_user)):
        if not has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission} required"
            )
        return current_user
    return dependency


def require_roles(*roles: UserRole):
    """FastAPI dependency for role-based authorization."""
    def dependency(current_user=Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {current_user.role} is not authorized for this action"
            )
        return current_user
    return dependency
