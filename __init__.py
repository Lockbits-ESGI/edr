"""MiniEDR — Lightweight cross-platform endpoint detection & response tool."""

__version__ = "0.1.0"
__author__ = "MiniEDR Contributors"
__license__ = "MIT"

from .config import load_config, get_config_dir
from .logger import setup_logging
from .collector import get_system_snapshot
from .hasher import compute_md5, compute_sha256
from .vt_checker import VirusTotalChecker
from .fim import start_fim_monitor
from .reporter import generate_json_report, generate_html_report

__all__ = [
    "load_config",
    "get_config_dir",
    "setup_logging",
    "get_system_snapshot",
    "compute_md5",
    "compute_sha256",
    "VirusTotalChecker",
    "start_fim_monitor",
    "generate_json_report",
    "generate_html_report",
]
