from datetime import datetime
import os
import logging
import colorlog
from logging import StreamHandler
from logging.handlers import RotatingFileHandler
from typing import Dict
from onilock.core.settings import settings

# @TODO: Change logs directory to /var/log/onilock
LOGS_DIR = "/tmp/logs/onilock"


class LoggingManager:
    def __init__(
        self,
        name: str = "faslava.logging.LoggingManager",
        default_level: int = logging.INFO,
    ):
        """
        Initialize the LoggingManager with a specific logger name.

        Args:
            name (str): Name of the logger.
            default_level (int): Default logging level.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(default_level)
        self.handlers: Dict[str, logging.Handler] = {}

        # @TODO: Change logs directory to /var/log/onilock
        if not os.path.exists(LOGS_DIR):
            os.makedirs(LOGS_DIR)

    def add_console_handler(self, level: int = logging.INFO):
        """Add a console (stdout) logging handler."""
        log_format = "%(log_color)s%(asctime)s %(levelname)s%(reset)s %(message_log_color)s%(name)s%(reset)s %(message)s"

        color_formatter = colorlog.ColoredFormatter(
            log_format,
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "red,bg_white",
            },
            secondary_log_colors={
                "message": {
                    "DEBUG": "light_black",
                    "INFO": "light_black",
                    "WARNING": "light_black",
                    "ERROR": "light_black",
                    "CRITICAL": "light_black",
                },
            },
        )
        handler = StreamHandler()
        handler.setFormatter(color_formatter)
        handler.setLevel(level)
        self.logger.addHandler(handler)
        self.handlers["console"] = handler

    def add_file_handler(
        self,
        filepath: str,
        level: int = logging.INFO,
        max_bytes: int = 10485760,
        backup_count: int = 5,
    ):
        """Add a rotating file logging handler."""
        handler = RotatingFileHandler(
            filepath, maxBytes=max_bytes, backupCount=backup_count
        )
        handler.setLevel(level)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.handlers["file"] = handler

    def remove_handler(self, handler_name: str):
        """Remove a handler by name."""
        if handler_name in self.handlers:
            handler = self.handlers.pop(handler_name)
            self.logger.removeHandler(handler)

    def get_logger(self) -> logging.Logger:
        """Return the configured logger."""
        return self.logger


_log_manager = LoggingManager(
    default_level=logging.DEBUG if settings.DEBUG else logging.ERROR
)

# Add console handler
_log_manager.add_console_handler(
    level=logging.DEBUG if settings.DEBUG else logging.ERROR
)

# Add file handler
today = datetime.today().strftime("%Y%m%d")
logging_level = logging.DEBUG if settings.DEBUG else logging.ERROR
_log_manager.add_file_handler(
    filepath=os.path.join(LOGS_DIR, f"{today}.log"),
    level=logging_level,
)


logger = _log_manager.get_logger()
