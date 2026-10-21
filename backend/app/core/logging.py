"""Structured logging configuration for RISE-Phish backend.
"""
import logging
import sys
from backend.app.core.config import get_settings

settings = get_settings()


def setup_logging() -> logging.Logger:
    """Configures root application logging with custom format and handlers."""
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    logger = logging.getLogger("rise_phish")
    logger.setLevel(log_level)
    return logger


logger = setup_logging()
