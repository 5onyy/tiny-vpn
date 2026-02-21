import logging
import os
from logging.handlers import RotatingFileHandler

# Project root: .../tiny-vpn
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Central logs dir: .../tiny-vpn/logs
_LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)

_LOG_FILE = os.path.join(_LOG_DIR, "socks5.log")

# Log format
_LOG_FORMAT = "%(asctime)s (%(process)d,%(thread)d) [%(levelname)s] %(name)s: %(message)s"

def get_logger(name: str | None = None) -> logging.Logger:
    """Return a configured logger that logs to both file and stdout.

    This function is idempotent: calling it multiple times with the same name
    will not add duplicate handlers.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        fmt= _LOG_FORMAT,
        datefmt = "%Y-%m-%d %H:%M:%S", 
    )

    # File handler (rotating to avoid unbounded growth)
    file_handler = RotatingFileHandler(
        _LOG_FILE,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    # Avoid propagating to the root logger
    logger.propagate = False

    return logger

def log_raw(line: str) -> None:
    """Append a raw line to the log file without any formatting."""
    with open(_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
