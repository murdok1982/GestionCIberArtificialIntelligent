"""
THREAT INTEL AGENT
Enriches IOCs (IPs, hashes, domains) via external threat intelligence APIs.
Uses Redis cache to avoid redundant API calls.
"""
import json
import logging
import hashlib
from typing import Any
import httpx
from apps.api.config import settings

logger = logging.getLogger(__name__)

CACHE_TTL = 3600  # 1 hour


class ThreatIntelAgent:

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.http_client = httpx.AsyncClient(timeout=10.0)

    async def enrich_iocs(self, iocs: list[dict]) -> dict:
        """Batch enrich a list of IOCs."""
        results = {"ips": [], "hashes": [], "domains": [], "campaigns": []}
        seen = set()

        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key in seen:
                continue
            seen.add(key)

            if ioc["type"] == "ip":
                result = await self.enrich_ip(ioc["value"])
                if result:
                    results["ips"].append(result)
            elif ioc["type"] == "hash":
                result = await self.enrich_hash(ioc["value"])
                if result:
                    results["hashes"].append(result)
            elif ioc["type"] == "domain":
                result = await self.enrich_domain(ioc["value"])
                if result:
                    results["domains"].append(result)

        if results["ips"] or results["hashes"]:
            campaigns = await self.identify_campaigns(results)
            results["campaigns"] = campaigns

        return results

    async def enrich_ip(self, ip: str) -> dict | None:
        """Enrich IP via AbuseIPDB and cache result."""
        cache_key = f"threat_intel:ip:{ip}"

        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                return json.loads(cached)

        result = {
            "type": "ip",
            "value": ip,
            "abuse_confidence": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "is_tor": False,
            "is_proxy": False,
            "reports": 0,
            "threat_types": [],
            "risk_score": 0,
        }

        # AbuseIPDB
        if settings.ABUSEIPDB_API_KEY:
            try:
                resp = await self.http_client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result.update({
                        "abuse_confidence": data.get("abuseConfidenceScore", 0),
                        "country": data.get("countryCode", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "is_tor": data.get("isTor", False),
                        "reports": data.get("totalReports", 0),
                        "risk_score": min(10.0, data.get("abuseConfidenceScore", 0) / 10),
                    })
            except Exception as e:
                logger.warning(f"AbuseIPDB error for {ip}: {e}")

        if self.redis:
            await self.redis.setex(cache_key, CACHE_TTL, json.dumps(result))

        return result

    async def enrich_hash(self, file_hash: str) -> dict | None:
        """Enrich file hash via VirusTotal."""
        cache_key = f"threat_intel:hash:{file_hash}"

        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                return json.loads(cached)

        result = {
            "type": "hash",
            "value": file_hash,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "names": [],
            "threat_label": None,
            "risk_score": 0,
        }

        if settings.VIRUSTOTAL_API_KEY:
            try:
                resp = await self.http_client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result.update({
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "names": attrs.get("names", [])[:5],
                        "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                        "risk_score": min(10.0, (stats.get("malicious", 0) / max(sum(stats.values()), 1)) * 10),
                    })
            except Exception as e:
                logger.warning(f"VirusTotal error for {file_hash}: {e}")

        if self.redis:
            await self.redis.setex(cache_key, CACHE_TTL, json.dumps(result))

        return result

    async def enrich_domain(self, domain: str) -> dict | None:
        """Basic domain enrichment."""
        return {
            "type": "domain",
            "value": domain,
            "registrar": "Unknown",
            "creation_date": None,
            "categories": [],
            "risk_score": 0,
        }

    async def identify_campaigns(self, enriched_iocs: dict) -> list[dict]:
        """Attempt to correlate IOCs with known threat campaigns."""
        campaigns = []
        high_risk_ips = [ip for ip in enriched_iocs.get("ips", []) if ip.get("abuse_confidence", 0) > 80]
        malicious_hashes = [h for h in enriched_iocs.get("hashes", []) if h.get("malicious", 0) > 5]

        if len(high_risk_ips) >= 2:
            campaigns.append({
                "name": "Unknown Campaign",
                "confidence": 0.6,
                "indicators": len(high_risk_ips),
                "description": f"Multiple high-risk IPs detected: {[ip['value'] for ip in high_risk_ips[:3]]}",
            })

        if malicious_hashes:
            campaigns.append({
                "name": malicious_hashes[0].get("threat_label", "Unknown Malware"),
                "confidence": 0.8,
                "indicators": len(malicious_hashes),
                "description": f"Malicious file detected: {malicious_hashes[0].get('threat_label', 'Unknown')}",
            })

        return campaigns
