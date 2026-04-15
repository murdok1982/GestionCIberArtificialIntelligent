from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from apps.api.database import get_db
from apps.api.middleware.auth import get_current_user
from apps.api.core.rbac import require_permission
from apps.api.models.user import User
from apps.api.agents.threat_intel_agent import ThreatIntelAgent

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])
threat_intel = ThreatIntelAgent()


class EnrichRequest(BaseModel):
    ioc_type: str  # ip, hash, domain
    value: str


class BatchEnrichRequest(BaseModel):
    iocs: list[dict]  # [{"type": "ip", "value": "1.2.3.4"}]


@router.post("/enrich")
async def enrich_ioc(
    data: EnrichRequest,
    current_user: User = Depends(require_permission("threat_intel:read")),
):
    if data.ioc_type == "ip":
        result = await threat_intel.enrich_ip(data.value)
    elif data.ioc_type == "hash":
        result = await threat_intel.enrich_hash(data.value)
    elif data.ioc_type == "domain":
        result = await threat_intel.enrich_domain(data.value)
    else:
        result = {"error": f"Unknown IOC type: {data.ioc_type}"}
    return result


@router.post("/enrich/batch")
async def batch_enrich(
    data: BatchEnrichRequest,
    current_user: User = Depends(require_permission("threat_intel:read")),
):
    return await threat_intel.enrich_iocs(data.iocs)


@router.post("/campaigns")
async def identify_campaigns(
    data: BatchEnrichRequest,
    current_user: User = Depends(require_permission("threat_intel:read")),
):
    enriched = await threat_intel.enrich_iocs(data.iocs)
    campaigns = await threat_intel.identify_campaigns(enriched)
    return {"enriched_iocs": enriched, "campaigns": campaigns}
