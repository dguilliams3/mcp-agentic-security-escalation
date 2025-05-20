"""Decorators for performance monitoring and caching."""

import functools
import time
import asyncio
from typing import Any, Callable, Dict, Optional
from datetime import datetime
from pathlib import Path
from utils.logging_utils import setup_logger

# Ensure logs directory exists
Path("logs").mkdir(exist_ok=True)

logger = setup_logger("decorators", "logs/timing_metrics.log")


def timing_metric(func: Callable) -> Callable:
    """Measure and log execution time of functions.

    Args:
        func: The function to be wrapped

    Returns:
        Wrapped function that logs timing metrics
    """

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = await func(*args, **kwargs)
            duration = time.perf_counter() - start
            logger.info(f"{func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            duration = time.perf_counter() - start
            logger.error(f"{func.__name__} failed after {duration:.2f}s: {str(e)}")
            raise

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            duration = time.perf_counter() - start
            logger.info(f"{func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            duration = time.perf_counter() - start
            logger.error(f"{func.__name__} failed after {duration:.2f}s: {str(e)}")
            raise

    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


def cache_result(ttl_seconds: int = 300) -> Callable:
    """Simple in-memory cache with TTL for function results.

    Args:
        ttl_seconds: Time to live for cached results in seconds (default: 300)

    Returns:
        Decorator function that implements caching
    """
    cache: Dict[str, Dict[str, Any]] = {}

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            key = f"{func.__name__}:{str(args)}:{str(kwargs)}"

            # Check if cached and not expired
            if key in cache:
                result = cache[key]
                if time.time() - result["timestamp"] < ttl_seconds:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return result["data"]

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache[key] = {"data": result, "timestamp": time.time()}
            return result

        return wrapper

    return decorator
