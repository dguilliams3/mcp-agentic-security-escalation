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

    # Get the root logger
    logger = logging.getLogger()
    
    # If logger already has handlers, return it
    if logger.handlers:
        return logger
    
    # Set the logger's level first
    log_level_str = os.getenv('LOG_LEVEL', 'DEBUG').upper()
    VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
    
    if log_level_str not in VALID_LOG_LEVELS:
        logger.error(f"Invalid LOG_LEVEL: {log_level_str}, defaulting to DEBUG")
        log_level_str = 'DEBUG'
    
    log_level = getattr(logging, log_level_str)
    logger.setLevel(log_level)  # Set the logger's level
    
    # Set httpcore to WARNING level to suppress its debug messages
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("langchain").setLevel(logging.ERROR)
    logging.getLogger("langchain_community").setLevel(logging.ERROR)
    logging.getLogger("langchain_community.tools.file_search").setLevel(logging.ERROR)
    logging.getLogger("langchain_community.tools.file_search.base").setLevel(logging.ERROR)
    logging.getLogger("langchain_community.tools.file_search.base").setLevel(logging.ERROR)
    
    # Configure Windows console for UTF-8
    if sys.platform == 'win32':
        import locale
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8')
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    
    # Console handler with proper encoding
    if sys.platform == 'win32':
        if hasattr(sys.stdout, 'buffer'):
            console_handler = logging.StreamHandler(codecs.getwriter('utf-8')(sys.stdout.buffer))
        else:
            console_handler = logging.StreamHandler(sys.stdout)
    else:
        console_handler = logging.StreamHandler(sys.stdout)
   
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(asctime)s %(levelname)-8s [%(name)s] %(message)s',
                                        datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)

    # File handler with UTF-8 encoding
    try:
        file_handler = RotatingFileHandler(log_file, maxBytes=10485760,
                                         backupCount=5, encoding='utf-8')
        file_handler.setLevel(log_level)
        
        file_formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Add handlers to logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        # Log a test message at each level to verify logging is working
        logger.debug("Debug logging initialized")
        logger.info("Info logging initialized")
        logger.warning("Warning logging initialized")
        logger.error("Error logging initialized")
        
    except Exception as e:
        print(f"Error setting up file logging: {str(e)}")
        # If file logging fails, at least ensure console logging works
        logger.addHandler(console_handler)

    return logger
