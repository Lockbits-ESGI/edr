"""Shared utilities for PyInstaller compatibility and resource management."""

import sys
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


def resource_path(relative_path: str) -> Path:
    """Get path to resource file, compatible with PyInstaller onefile packaging.
    
    When running as PyInstaller executable, resources are in sys._MEIPASS.
    When running as script, resources are relative to __file__.
    """
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).parent.parent
    
    return base / relative_path


def get_config_dir(app_name: str = "miniedr") -> Path:
    """Get platform-specific config directory for application.
    
    Windows: %APPDATA%/miniedr
    POSIX: $XDG_CONFIG_HOME/miniedr or ~/.config/miniedr
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / app_name
        return Path.home() / "AppData" / "Roaming" / app_name
    
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / app_name
    
    return Path.home() / ".config" / app_name


def get_cache_dir(app_name: str = "miniedr") -> Path:
    """Get platform-specific cache directory for application."""
    if sys.platform == "win32":
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            return Path(localappdata) / app_name / "cache"
        return Path.home() / "AppData" / "Local" / app_name / "cache"
    
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / app_name
    
    return Path.home() / ".cache" / app_name


def ensure_dir(path: Path) -> Path:
    """Create directory if it doesn't exist, return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_agent_id_file(config_dir: Optional[Path] = None) -> Path:
    """Get path to agent ID file."""
    if config_dir is None:
        config_dir = get_config_dir()
    return ensure_dir(config_dir) / "agent_id"


def get_queue_file(config_dir: Optional[Path] = None) -> Path:
    """Get path to pending events queue file."""
    if config_dir is None:
        config_dir = get_config_dir()
    return ensure_dir(config_dir / "queue") / "pending_events.jsonl"


def load_agent_id(agent_id_file: Path) -> str:
    """Load or create agent ID from file."""
    agent_id_file = Path(agent_id_file)
    
    if agent_id_file.exists():
        agent_id = agent_id_file.read_text().strip()
        if agent_id:
            return agent_id
    
    agent_id_file.parent.mkdir(parents=True, exist_ok=True)
    new_id = generate_uuid()
    agent_id_file.write_text(new_id)
    return new_id


def generate_uuid() -> str:
    """Generate a new UUID string."""
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    """Get current UTC time in ISO 8601 format with Z suffix."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
