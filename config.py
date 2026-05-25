"""Configuration management for MiniEDR with platform-specific paths."""

import os
import sys
from pathlib import Path
from typing import Any, Optional

import yaml


def get_config_dir() -> Optional[Path]:
    """Get platform-specific config directory.

    Windows: %APPDATA%/miniedr
    POSIX: $XDG_CONFIG_HOME/miniedr or ~/.config/miniedr
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "miniedr"
        return None

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "miniedr"

    home = os.environ.get("HOME")
    if home:
        return Path(home) / ".config" / "miniedr"

    return None


def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to config file. If None, uses bundled config.yaml.

    Returns:
        Configuration dict. Returns empty dict if file not found or error occurs.
    """
    if config_path is None:
        config_path = Path("config.yaml")

    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError:
        return {}
    except OSError:
        return {}


def get_config_value(config: dict[str, Any], key: str, default: Any = None) -> Any:
    """Get nested config value using dot notation.

    Examples:
        get_config_value(config, "fim.watch_dirs.linux")
        get_config_value(config, "logging.level", "INFO")
    """
    keys = key.split(".")
    value = config
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        else:
            return default
    return value if value is not None else default
