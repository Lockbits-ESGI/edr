"""Unit tests for vt_checker.py with mocked API responses."""

from pathlib import Path
from unittest.mock import Mock, patch
import time

import pytest

from ..vt_checker import VirusTotalChecker, RateLimiter


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_enforces_minimum_interval(self):
        """Test that rate limiter enforces minimum interval between requests."""
        limiter = RateLimiter(requests_per_minute=4)
        assert limiter.min_interval == 15.0

        start = time.time()
        limiter.wait()
        first_wait = time.time() - start
        assert first_wait < 0.1

        start = time.time()
        limiter.wait()
        second_wait = time.time() - start
        assert second_wait >= 14.0

    def test_rate_limiter_custom_requests_per_minute(self):
        """Test rate limiter with custom requests per minute."""
        limiter = RateLimiter(requests_per_minute=60)
        assert limiter.min_interval == 1.0


class TestVirusTotalChecker:
    """Test VirusTotal API client."""

    @pytest.fixture
    def vt_checker(self):
        """Create VirusTotalChecker instance with mock API key."""
        return VirusTotalChecker(api_key="test-api-key")

    def test_check_file_hash_found_clean(self, vt_checker):
        """Test checking file hash that is found and clean."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "harmless": 45,
                        "undetected": 5,
                        "suspicious": 0,
                    }
                }
            }
        }

        with patch.object(vt_checker.session, "get", return_value=mock_response):
            result = vt_checker.check_file_hash("abc123")
            assert result is not None
            assert result["detection_count"] == 0
            assert result["harmless_count"] == 45
            assert result["undetected_count"] == 5
            assert result["suspicious_count"] == 0

    def test_check_file_hash_found_malicious(self, vt_checker):
        """Test checking file hash that is found and malicious."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 25,
                        "harmless": 15,
                        "undetected": 10,
                        "suspicious": 0,
                    }
                }
            }
        }

        with patch.object(vt_checker.session, "get", return_value=mock_response):
            result = vt_checker.check_file_hash("malicious-hash")
            assert result is not None
            assert result["detection_count"] == 25

    def test_check_file_hash_not_found(self, vt_checker):
        """Test checking file hash that is not found (404)."""
        mock_response = Mock()
        mock_response.status_code = 404

        with patch.object(vt_checker.session, "get", return_value=mock_response):
            result = vt_checker.check_file_hash("unknown-hash")
            assert result is not None
            assert result["detection_count"] == 0

    def test_check_file_hash_rate_limit_exceeded(self, vt_checker):
        """Test checking file hash with rate limit exceeded (429)."""
        mock_response = Mock()
        mock_response.status_code = 429

        with patch.object(vt_checker.session, "get", return_value=mock_response):
            result = vt_checker.check_file_hash("any-hash")
            assert result is None

    def test_check_file_hash_timeout(self, vt_checker):
        """Test checking file hash with timeout."""
        import requests

        with patch.object(vt_checker.session, "get", side_effect=requests.Timeout()):
            result = vt_checker.check_file_hash("any-hash")
            assert result is None

    def test_check_file_hash_request_exception(self, vt_checker):
        """Test checking file hash with request exception."""
        import requests

        with patch.object(
            vt_checker.session, "get", side_effect=requests.RequestException()
        ):
            result = vt_checker.check_file_hash("any-hash")
            assert result is None

    def test_upload_file_success(self, vt_checker, tmp_path):
        """Test uploading file successfully."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "analysis-123"}}

        with patch.object(vt_checker.session, "post", return_value=mock_response):
            result = vt_checker.upload_file(test_file)
            assert result == "analysis-123"

    def test_upload_file_not_found(self, vt_checker):
        """Test uploading nonexistent file."""
        result = vt_checker.upload_file(Path("/nonexistent/file"))
        assert result is None

    def test_upload_file_rate_limit_exceeded(self, vt_checker, tmp_path):
        """Test uploading file with rate limit exceeded."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        mock_response = Mock()
        mock_response.status_code = 429

        with patch.object(vt_checker.session, "post", return_value=mock_response):
            result = vt_checker.upload_file(test_file)
            assert result is None
