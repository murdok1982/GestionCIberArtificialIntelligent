"""
LLM Analyst Service using Gemma via Ollama for security event analysis.
Implements LLMServiceProtocol for dependency injection.
"""
import json
import logging
from typing import Optional
import httpx
from apps.api.config import settings

logger = logging.getLogger(__name__)


class LLMServiceProtocol:
    """Protocol for LLM analysis services."""
    async def analyze_security_event(self, data: dict) -> dict: ...


class GemmaAnalystService:
    """Security-focused LLM analysis using Gemma via Ollama."""

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        self.base_url = settings.GEMMA_API_URL
        self.model = settings.GEMMA_MODEL
        self.timeout = settings.GEMMA_TIMEOUT
        self.http_client = http_client or httpx.AsyncClient(timeout=self.timeout)

    async def analyze_security_event(self, data: dict) -> dict:
        """Analyze a security event and return structured recommendations."""
        prompt = self._build_analysis_prompt(data)

        try:
            response = await self.http_client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 1024},
                },
            )
            response.raise_for_status()
            return self._parse_response(response.json().get("response", ""))
        except Exception as e:
            logger.error(f"Gemma analysis failed: {e}")
            return self._fallback_analysis()

    def _build_analysis_prompt(self, data: dict) -> str:
        event = data.get("event", {})
        detections = data.get("detections", [])
        threat_intel = data.get("threat_intel", {})

        detections_summary = "\n".join([
            f"- {d.get('rule_name', 'Unknown')}: {d.get('description', '')} (Severity: {d.get('severity', 'low')})"
            for d in detections[:5]
        ])

        threat_summary = ""
        if threat_intel:
            ips = threat_intel.get("ips", [])
            hashes = threat_intel.get("hashes", [])
            if ips:
                threat_summary += f"\nHigh-risk IPs: {', '.join(ip['value'] for ip in ips[:3] if ip.get('abuse_confidence', 0) > 50)}"
            if hashes:
                threat_summary += f"\nMalicious hashes: {', '.join(h['value'][:16] for h in hashes[:3] if h.get('malicious', 0) > 0)}"

        return f"""You are a senior SOC analyst. Analyze this security event and provide structured JSON output.

EVENT:
- Type: {event.get('event_type', 'unknown')}
- Device: {event.get('device_id', 'unknown')}
- Tenant: {event.get('tenant_id', 'unknown')}

DETECTIONS:
{detections_summary}

THREAT INTELLIGENCE:
{threat_summary}

Respond with ONLY valid JSON in this exact format:
{{
    "summary": "Brief executive summary of the incident",
    "risk_assessment": "critical|high|medium|low",
    "mitre_techniques": ["T1234", "T5678"],
    "recommendations": [
        {{"action_type": "isolate_device|kill_process|scan_device|collect_evidence|notify_admin", "description": "Detailed justification", "requires_approval": true, "priority": 1}}
    ],
    "confidence": 0.85
}}"""

    def _parse_response(self, response: str) -> dict:
        """Parse LLM response, extracting JSON."""
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        return self._fallback_analysis()

    def _fallback_analysis(self) -> dict:
        return {
            "summary": "LLM analysis unavailable",
            "risk_assessment": "medium",
            "mitre_techniques": [],
            "recommendations": [],
            "confidence": 0.5,
        }

    async def close(self):
        await self.http_client.aclose()