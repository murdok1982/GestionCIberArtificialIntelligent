from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import redis.asyncio as redis

from apps.api.config import settings
from apps.api.database import init_db
from apps.api.middleware.tenant import TenantIsolationMiddleware
from apps.api.routes import auth, devices, alerts, forensics, billing, threat_intel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CyberGuard API starting up...")
    await init_db()
    app.state.redis = redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    logger.info("Database and Redis connected")
    yield
    await app.state.redis.close()
    logger.info("CyberGuard API shut down")


app = FastAPI(
    title="CyberGuard API",
    description="Multi-tenant cybersecurity SaaS platform — defensive monitoring, forensics, and threat intelligence",
    version="1.0.0",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url=None,
    lifespan=lifespan,
)

# CORS — never wildcard in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
)

app.add_middleware(TenantIsolationMiddleware)

# Routers
PREFIX = "/api/v1"
app.include_router(auth.router, prefix=PREFIX)
app.include_router(devices.router, prefix=PREFIX)
app.include_router(alerts.router, prefix=PREFIX)
app.include_router(forensics.router, prefix=PREFIX)
app.include_router(billing.router, prefix=PREFIX)
app.include_router(threat_intel.router, prefix=PREFIX)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "cyberguard-api", "version": "1.0.0"}


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": "Not found"})


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
