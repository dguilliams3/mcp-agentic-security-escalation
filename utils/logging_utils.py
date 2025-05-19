# utils/logging_utils.py
import logging
import sys
from logging.handlers import RotatingFileHandler
import os
import codecs
# force the std-streams to UTF-8 on Windows


def setup_logger(name='main_security_agent_server', log_file='logs/server.log'):
    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    
    # Configure Windows console for UTF-8
    if sys.platform == 'win32':
        import locale
        # Reconfiguring failed when running from Jupyter Notebook, so we check for the attribute to avoid errors
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8')
    
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    
    # Console handler with proper encoding (same as above, we check for the attribute to avoid errors in Jupyter Notebooks)
    if sys.platform == 'win32':
        if hasattr(sys.stdout, 'buffer'):
            # Regular Windows console
            console_handler = logging.StreamHandler(codecs.getwriter('utf-8')(sys.stdout.buffer))
        else:
            # Jupyter environment
            console_handler = logging.StreamHandler(sys.stdout)
    else:
        # Non-Windows platforms
        console_handler = logging.StreamHandler(sys.stdout)
   
    # Inject the log level, default to DEBUG.
    # We're using DEBUG here, but this mimics best practices for production systems.
    VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}

    log_level_str = os.getenv('LOG_LEVEL', 'DEBUG').upper()
    # Ensure the log level is valid, otherwise default to DEBUG.
    if log_level_str not in VALID_LOG_LEVELS:
        logger.error(f"Invalid LOG_LEVEL: {log_level_str}, defaulting to DEBUG")
        log_level_str = 'DEBUG'

    log_level = getattr(logging, log_level_str)

    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                                        datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)

    # File handler with UTF-8 encoding
    file_handler = RotatingFileHandler(log_file, maxBytes=10485760,
                                     backupCount=5, encoding='utf-8')
    
    # We're just going to assume console and file handlers are at the same level for the sake of simplicity
    file_handler.setLevel(log_level)
    
    file_formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
