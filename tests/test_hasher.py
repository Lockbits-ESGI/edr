"""Unit tests for hasher.py"""

import tempfile
from pathlib import Path

import pytest

from ..hasher import compute_md5, compute_sha256, compute_both_hashes


@pytest.fixture
def temp_file():
    """Create temporary test file."""
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(b"test content for hashing")
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink()


def test_compute_md5(temp_file):
    """Test MD5 hash computation."""
    md5_hash = compute_md5(temp_file)
    assert md5_hash == "8454e1a036eeaf298bb90b7b7c9723fd"


def test_compute_sha256(temp_file):
    """Test SHA256 hash computation."""
    sha256_hash = compute_sha256(temp_file)
    assert sha256_hash == "e25dd806d495b413931f4eea50b677a7a5c02d00460924661283f211a37f7e7f"


def test_compute_both_hashes(temp_file):
    """Test computing both hashes in single pass."""
    md5_hash, sha256_hash = compute_both_hashes(temp_file)
    assert md5_hash == "8454e1a036eeaf298bb90b7b7c9723fd"
    assert sha256_hash == "e25dd806d495b413931f4eea50b677a7a5c02d00460924661283f211a37f7e7f"


def test_compute_md5_nonexistent_file():
    """Test MD5 computation on nonexistent file returns empty string."""
    md5_hash = compute_md5(Path("/nonexistent/file"))
    assert md5_hash == ""


def test_compute_sha256_nonexistent_file():
    """Test SHA256 computation on nonexistent file returns empty string."""
    sha256_hash = compute_sha256(Path("/nonexistent/file"))
    assert sha256_hash == ""


def test_compute_both_hashes_nonexistent_file():
    """Test computing both hashes on nonexistent file returns empty strings."""
    md5_hash, sha256_hash = compute_both_hashes(Path("/nonexistent/file"))
    assert md5_hash == ""
    assert sha256_hash == ""


@pytest.fixture
def large_temp_file():
    """Create large temporary test file (1 MB) to test chunking."""
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(b"x" * 1024 * 1024)
        temp_path = Path(f.name)
    yield temp_path
    temp_path.unlink()


def test_compute_sha256_large_file(large_temp_file):
    """Test SHA256 computation on large file (tests chunking)."""
    sha256_hash = compute_sha256(large_temp_file)
    assert len(sha256_hash) == 64
    assert all(c in "0123456789abcdef" for c in sha256_hash)
