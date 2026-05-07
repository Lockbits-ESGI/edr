"""File hashing with MD5 and SHA256 using chunked I/O for memory efficiency."""

import hashlib
from pathlib import Path
from typing import Tuple


def compute_md5(file_path: Path) -> str:
    """Compute MD5 hash of file using 8KB chunks."""
    return _compute_hash(file_path, hashlib.md5())


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of file using 8KB chunks."""
    return _compute_hash(file_path, hashlib.sha256())


def compute_both_hashes(file_path: Path) -> Tuple[str, str]:
    """Compute both MD5 and SHA256 hashes in single pass."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
    except (OSError, IOError):
        return "", ""

    return md5_hash.hexdigest(), sha256_hash.hexdigest()


def _compute_hash(file_path: Path, hasher) -> str:
    """Compute hash using provided hasher object with chunked reading."""
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
    except (OSError, IOError):
        return ""

    return hasher.hexdigest()
