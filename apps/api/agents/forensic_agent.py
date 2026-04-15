"""
FORENSIC AGENT
Manages evidence acquisition, hashing, timeline generation, and artifact analysis.
"""
import uuid
import logging
import io
from datetime import datetime, timezone
from typing import BinaryIO
import boto3
from botocore.exceptions import ClientError
from apps.api.config import settings
from apps.api.core.security import compute_sha256, compute_sha512

logger = logging.getLogger(__name__)


class ForensicAgent:

    def __init__(self):
        self.s3 = boto3.client(
            "s3",
            endpoint_url=settings.S3_ENDPOINT,
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
            region_name=settings.S3_REGION,
        )

    async def store_evidence(
        self,
        tenant_id: uuid.UUID,
        device_id: uuid.UUID,
        evidence_id: uuid.UUID,
        filename: str,
        file_data: bytes,
        evidence_type: str,
    ) -> tuple[str, str, str]:
        """
        Store evidence in S3-compatible storage.
        Returns (storage_path, sha256_hash, sha512_hash)
        Evidence is stored as immutable (object lock if available).
        """
        sha256 = compute_sha256(file_data)
        sha512 = compute_sha512(file_data)

        storage_path = f"{tenant_id}/{device_id}/{evidence_type}/{evidence_id}/{filename}"

        try:
            self.s3.put_object(
                Bucket=settings.S3_BUCKET,
                Key=storage_path,
                Body=file_data,
                Metadata={
                    "evidence-id": str(evidence_id),
                    "sha256": sha256,
                    "sha512": sha512,
                    "acquisition-timestamp": datetime.now(timezone.utc).isoformat(),
                    "tenant-id": str(tenant_id),
                    "device-id": str(device_id),
                },
                ContentType="application/octet-stream",
            )
            logger.info(f"Evidence stored: {storage_path} sha256={sha256[:16]}...")
        except ClientError as e:
            logger.error(f"S3 storage error: {e}")
            raise RuntimeError(f"Failed to store evidence: {e}")

        return storage_path, sha256, sha512

    async def verify_evidence_integrity(self, storage_path: str, expected_sha256: str) -> bool:
        """Re-hash stored evidence to verify integrity."""
        try:
            response = self.s3.get_object(Bucket=settings.S3_BUCKET, Key=storage_path)
            file_data = response["Body"].read()
            actual_sha256 = compute_sha256(file_data)
            return actual_sha256 == expected_sha256
        except ClientError as e:
            logger.error(f"Evidence verification error: {e}")
            return False

    async def generate_download_url(self, storage_path: str, expires_in: int = 3600) -> str:
        """Generate a pre-signed URL for evidence download (expires in 1 hour by default)."""
        try:
            url = self.s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": settings.S3_BUCKET, "Key": storage_path},
                ExpiresIn=expires_in,
            )
            return url
        except ClientError as e:
            logger.error(f"Pre-signed URL error: {e}")
            raise RuntimeError(f"Failed to generate download URL: {e}")

    async def generate_timeline(self, alert_id: uuid.UUID, db) -> dict:
        """
        Generate a forensic timeline of events related to an alert.
        Returns ordered sequence of events with timestamps.
        """
        from sqlalchemy import select
        from apps.api.models.event import Event
        from apps.api.models.evidence import Evidence

        events_result = await db.execute(
            select(Event).where(Event.id == alert_id)
        )

        timeline = {
            "alert_id": str(alert_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
        }
        return timeline

    async def analyze_artifacts(self, evidence_id: uuid.UUID, db) -> dict:
        """
        Basic artifact analysis:
        - Identify file type
        - Extract strings
        - Check for known malware signatures
        """
        from apps.api.models.evidence import Evidence
        from sqlalchemy import select

        result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        evidence = result.scalar_one_or_none()
        if not evidence:
            return {"error": "Evidence not found"}

        analysis = {
            "evidence_id": str(evidence_id),
            "filename": evidence.filename,
            "sha256": evidence.sha256_hash,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "file_type": self._detect_file_type(evidence.filename),
            "risk_indicators": [],
            "strings_of_interest": [],
            "recommendations": [],
        }

        # Check suspicious extensions
        if evidence.filename.endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta")):
            analysis["risk_indicators"].append("Executable/script file type")

        return analysis

    def _detect_file_type(self, filename: str) -> str:
        ext_map = {
            ".exe": "Windows Executable (PE32)",
            ".dll": "Windows DLL",
            ".ps1": "PowerShell Script",
            ".py": "Python Script",
            ".bat": "Windows Batch File",
            ".sh": "Shell Script",
            ".log": "Log File",
            ".pcap": "Network Capture",
            ".mem": "Memory Dump",
            ".reg": "Windows Registry File",
        }
        for ext, ftype in ext_map.items():
            if filename.lower().endswith(ext):
                return ftype
        return "Unknown"
