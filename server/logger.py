"""Server logging configuration with file and console handlers."""

import logging
import logging.handlers
from pathlib import Path

from server.config import get_settings

settings = get_settings()


def setup_logging(name: str = "miniedr_server") -> logging.Logger:
    """Configure logging with rotating file handler and console output."""

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # File handler - DEBUG level
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "miniedr_server.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=3,
    )
    file_handler.setLevel(logging.DEBUG)

    # Console handler - INFO level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


logger = setup_logging()
