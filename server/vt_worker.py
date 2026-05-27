"""Background VirusTotal enrichment worker."""

import asyncio
import time
import logging
from typing import Optional

import httpx

from shared.event_schema import VTResult
from server import storage
from server.metrics import vt_enrichments_total

logger = logging.getLogger(__name__)


class VTWorker:
    """Asynchronous VirusTotal API client with rate limiting."""

    def __init__(self, api_key: str, rate_limit: int = 4):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(rate_limit)
        self.last_request_time = 0.0

    async def enrich_event(self, db, event_id: str, sha256: Optional[str]) -> None:
        """Lookup hash in VirusTotal, store result, update event."""
        if not sha256 or not self.api_key:
            if event_id:
                storage.update_event_vt_status(db, event_id, "skipped")
            return

        # Check cache first
        cached = storage.get_hash_cache(db, sha256)
        if cached:
            vt_result = VTResult(
                malicious=cached.vt_malicious,
                suspicious=cached.vt_suspicious,
                undetected=cached.vt_undetected,
                total=cached.vt_total,
                status=cached.vt_status,
            )
            storage.update_event_vt_status(db, event_id, "enriched", vt_result)
            logger.debug(f"Cache hit for {sha256[:8]}... : {vt_result.status}")
            return

        # Rate limiting: 4 req/min = 15 seconds between requests
        async with self.semaphore:
            time_since_last = time.time() - self.last_request_time
            sleep_duration = max(0, 15 - time_since_last)
            if sleep_duration > 0:
                await asyncio.sleep(sleep_duration)

            # Query VirusTotal
            result = await self._query_vt(sha256)
            if result:
                storage.store_hash_cache(db, sha256, result)
                storage.update_event_vt_status(db, event_id, "enriched", result)
                vt_enrichments_total.labels(status="success").inc()
                logger.info(
                    f"VT enriched {sha256[:8]}... : {result.status} ({result.malicious} malicious)"
                )
            else:
                vt_enrichments_total.labels(status="failed").inc()
                logger.warning(f"VT lookup failed for {sha256[:8]}...")
                storage.update_event_vt_status(db, event_id, "skipped")

    async def _query_vt(self, sha256: str) -> Optional[VTResult]:
        """Query VirusTotal API for hash reputation."""
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, headers=headers)
                self.last_request_time = time.time()

                if response.status_code == 200:
                    data = response.json()
                    analysis = (
                        data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    return VTResult(
                        malicious=analysis.get("malicious", 0),
                        suspicious=analysis.get("suspicious", 0),
                        undetected=analysis.get("undetected", 0),
                        total=analysis.get("undetected", 0)
                        + analysis.get("malicious", 0)
                        + analysis.get("suspicious", 0),
                        status=self._determine_status(analysis),
                    )
                elif response.status_code == 404:
                    return VTResult(status="notfound")
                else:
                    logger.error(f"VT API error: {response.status_code}")
                    return None
        except Exception as e:
            logger.error(f"VT query failed: {e}")
            return None

    @staticmethod
    def _determine_status(analysis: dict) -> str:
        """Determine VT status from analysis stats."""
        if analysis.get("malicious", 0) > 0:
            return "malicious"
        elif analysis.get("suspicious", 0) > 0:
            return "suspicious"
        else:
            return "clean"
