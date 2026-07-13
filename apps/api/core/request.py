"""Request helpers (client IP extraction behind a reverse proxy)."""
from fastapi import Request


def client_ip(request: Request) -> str | None:
    """Best-effort client IP respecting X-Forwarded-For / X-Real-IP from the proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # X-Forwarded-For: client, proxy1, proxy2
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    if request.client:
        return request.client.host
    return None
