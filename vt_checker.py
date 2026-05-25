"""VirusTotal API v3 integration with rate limiting and error handling."""

import logging
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("miniedr")


class RateLimiter:
    """Enforce request rate limiting (4 requests per minute = 15 second sleep)."""

    def __init__(self, requests_per_minute: int = 4):
        self.min_interval = 60 / requests_per_minute
        self.last_request_time = 0.0

    def wait(self):
        """Sleep if needed to enforce rate limit (BEFORE request, not after)."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()


class VirusTotalChecker:
    """VirusTotal API v3 client for file analysis."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limiter = RateLimiter(requests_per_minute=4)
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def check_file_hash(self, file_hash: str) -> Optional[dict[str, int]]:
        """Look up file hash on VirusTotal.

        Returns dict with keys: detection_count, harmless_count, undetected_count,
        or None if error/not found.
        """
        self.rate_limiter.wait()

        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                return {
                    "detection_count": stats.get("malicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                }

            elif response.status_code == 404:
                logger.debug(f"Hash not found on VirusTotal: {file_hash}")
                return {
                    "detection_count": 0,
                    "harmless_count": 0,
                    "undetected_count": 0,
                    "suspicious_count": 0,
                }

            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded (429)")
                return None

            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.Timeout:
            logger.error("VirusTotal request timeout")
            return None
        except requests.RequestException as e:
            logger.error(f"VirusTotal request error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error checking VirusTotal: {e}")
            return None

    def upload_file(self, file_path: Path) -> Optional[str]:
        """Upload file to VirusTotal for analysis.

        Returns analysis ID or None if error.
        """
        self.rate_limiter.wait()

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None

        try:
            url = f"{self.base_url}/files"
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f)}
                response = self.session.post(url, files=files, timeout=30)

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                logger.info(f"File uploaded to VirusTotal: {analysis_id}")
                return analysis_id

            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded during upload (429)")
                return None

            else:
                logger.warning(f"VirusTotal upload error: {response.status_code}")
                return None

        except requests.Timeout:
            logger.error("VirusTotal upload timeout")
            return None
        except requests.RequestException as e:
            logger.error(f"VirusTotal upload error: {e}")
            return None
        except OSError as e:
            logger.error(f"Error reading file for upload: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error uploading to VirusTotal: {e}")
            return None
