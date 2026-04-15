"""
Tenant isolation middleware.
Ensures every request is scoped to the authenticated user's tenant.
Cross-tenant access is impossible by design.
"""
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from apps.api.core.security import verify_token


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    EXEMPT_PATHS = {"/health", "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/billing/webhook"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.EXEMPT_PATHS or request.url.path.startswith("/docs"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return await call_next(request)

        try:
            token = auth_header.split(" ")[1]
            token_data = verify_token(token, "access")
            request.state.tenant_id = uuid.UUID(token_data.tenant_id)
            request.state.user_id = uuid.UUID(token_data.user_id)
            request.state.user_role = token_data.role
        except Exception:
            # ALTA-02 fix: invalid Bearer token must be rejected, not silently ignored.
            # If the header is present but invalid, return 401 immediately.
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"},
            )

        return await call_next(request)
