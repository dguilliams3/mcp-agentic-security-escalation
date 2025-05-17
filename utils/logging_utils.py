# utils/logging_utils.py
import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(name="mcp_cve_client", log_file="client.log", level=logging.DEBUG):
    LOG_DIR = os.getenv("MCP_LOG_DIR", "logs")
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:  # Prevent adding handlers multiple times
        # File handler
        fh = RotatingFileHandler(
            os.path.join(LOG_DIR, log_file),
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s %(message)s"
        ))
        logger.addHandler(fh)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(message)s", datefmt="%H:%M:%S"
        ))
        logger.addHandler(ch)

    return logger
