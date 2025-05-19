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
    logger.setLevel(logging.DEBUG)

    # Configure Windows console for UTF-8
    if sys.platform == 'win32':
        import locale
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

    # Console handler with proper encoding
    console_handler = logging.StreamHandler(codecs.getwriter('utf-8')(sys.stdout.buffer) if sys.platform == 'win32' else sys.stdout)
    # We'd make this injectable, but for now we'll just use the default
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                                        datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)

    # File handler with UTF-8 encoding
    file_handler = RotatingFileHandler(log_file, maxBytes=10485760,
                                     backupCount=5, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
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
