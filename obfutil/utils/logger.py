import logging
import functools
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from obfutil.config import LOGS_DIR

LOG_FILE = LOGS_DIR / "program.log"

def get_logger(name: str):
    """Get or create logger with file handler"""
    log = logging.getLogger(name)

    if not log.handlers:
        log.setLevel(logging.INFO)

        # FILE handler (with rotation)
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=2 * 1024 * 1024,   # 2 MB
            backupCount=5,              # up to 5 old logs
            encoding="utf-8"
        )
        file_fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        file_handler.setFormatter(logging.Formatter(file_fmt))

        # Attach only file handler
        log.addHandler(file_handler)

    return log

def logged(func):
    """Decorator to log function calls (except main)"""
    if func.__name__ == "main":
        return func

    log = logging.getLogger("MAIN")

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        log.info(f"→ {func.__name__}()")
        start = time.time()
        try:
            return func(*args, **kwargs)
        finally:
            dt = (time.time() - start) * 1000
            log.info(f"← {func.__name__}() in {dt:.1f}ms")

    return wrapper

def log_exception(logger, exc: Exception):
    """Log exception and return formatted error message"""
    logger.error(f"Exception: {exc}")
    return f"ERROR: {exc}"