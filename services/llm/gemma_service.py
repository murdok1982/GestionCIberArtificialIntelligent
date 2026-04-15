"""
Gemma Analyst Service
Wraps Ollama API to run Gemma as a specialized security analyst.
"""
import json
import logging
import httpx
from typing import Any
from apps.api.config import settings
from services.llm.prompts import (
    SOC_ANALYST_SYSTEM_PROMPT,
    THREAT_INTEL_SYSTEM_PROMPT,
    FORENSIC_ANALYST_SYSTEM_PROMPT,
)

logger = logging.getLogger(__name__)


DEFAULT_ANALYSIS = {
    "executive_summary": "Analysis unavailable - LLM service not responding",
    "findings": [],
    "indicators": [],
    "mitre_mapping": [],
    "hypotheses": [],
    "risk_level": "medium",
    "confidence": 0.0,
    "recommendations": [],
    "forensic_next_steps": [],
    "is_imminent_danger": False,
    "imminent_danger_reason": None,
}


class GemmaAnalystService:

    def __init__(self):
        self.base_url = settings.GEMMA_API_URL
        self.model = settings.GEMMA_MODEL
        self.timeout = settings.GEMMA_TIMEOUT

    async def _call_ollama(self, system_prompt: str, user_content: str) -> dict:
        """Call Ollama API with the given prompts and return parsed JSON."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.1,
                    "num_predict": 4096,
                },
            }

            try:
                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                )
                response.raise_for_status()
                result = response.json()
                content = result.get("message", {}).get("content", "{}")
                return json.loads(content)
            except httpx.TimeoutException:
                logger.error(f"Gemma timeout after {self.timeout}s")
                return DEFAULT_ANALYSIS.copy()
            except httpx.HTTPError as e:
                logger.error(f"Gemma HTTP error: {e}")
                return DEFAULT_ANALYSIS.copy()
            except json.JSONDecodeError as e:
                logger.error(f"Gemma JSON parse error: {e}")
                return DEFAULT_ANALYSIS.copy()

    async def analyze_security_event(self, context: dict) -> dict:
        """
        Full SOC analysis of a security event.
        INPUT: {event, detections, threat_intel}
        OUTPUT: Complete security analysis with MITRE mapping, risk, recommendations
        """
        user_content = f"""Analyze this security telemetry:

DETECTED RULES TRIGGERED:
{json.dumps(context.get('detections', []), indent=2)}

RAW EVENT DATA:
{json.dumps(context.get('event', {}), indent=2)}

THREAT INTELLIGENCE ENRICHMENT:
{json.dumps(context.get('threat_intel', {}), indent=2)}

Provide a complete security analysis following the specified JSON format."""

        result = await self._call_ollama(SOC_ANALYST_SYSTEM_PROMPT, user_content)
        logger.info(f"Gemma SOC analysis complete: risk={result.get('risk_level')} confidence={result.get('confidence')}")
        return result

    async def analyze_threat_intel(self, iocs: list[dict], enrichment: dict) -> dict:
        """Threat Intelligence analysis of enriched IOCs."""
        user_content = f"""Analyze these threat intelligence indicators:

IOCs:
{json.dumps(iocs, indent=2)}

ENRICHMENT DATA:
{json.dumps(enrichment, indent=2)}

Provide threat actor attribution and campaign analysis."""

        return await self._call_ollama(THREAT_INTEL_SYSTEM_PROMPT, user_content)

    async def analyze_forensic_artifacts(self, artifacts: dict, custody_chain: list) -> dict:
        """Forensic analysis of collected evidence."""
        user_content = f"""Perform forensic analysis:

ARTIFACTS:
{json.dumps(artifacts, indent=2)}

CUSTODY CHAIN:
{json.dumps(custody_chain, indent=2)}

Reconstruct the attack timeline and provide remediation steps."""

        return await self._call_ollama(FORENSIC_ANALYST_SYSTEM_PROMPT, user_content)

    async def quick_triage(self, event_type: str, raw_data: dict) -> dict:
        """
        Fast triage for incoming events - lighter analysis for high-volume processing.
        Returns minimal analysis: severity, is_interesting, brief_description
        """
        user_content = f"""Quick triage of security event:
Type: {event_type}
Data: {json.dumps(raw_data, indent=2)[:2000]}

Respond with: {{"severity": "critical|high|medium|low|info", "is_interesting": true|false, "brief_description": "one sentence", "confidence": 0.0-1.0}}"""

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": user_content}],
                        "stream": False,
                        "format": "json",
                        "options": {"temperature": 0.1, "num_predict": 256},
                    }
                )
                result = response.json()
                return json.loads(result.get("message", {}).get("content", "{}"))
            except Exception:
                return {"severity": "info", "is_interesting": False, "brief_description": "Triage unavailable", "confidence": 0.0}
