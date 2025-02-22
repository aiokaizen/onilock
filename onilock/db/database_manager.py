from threading import Lock
from typing import Optional

from onilock.core.logging_manager import logger
from onilock.db.engines import JsonEngine


def create_engine(database_url: str):
    return JsonEngine(db_url=database_url)


class DatabaseManager:
    _instance = None
    _lock = Lock()

    def __new__(cls, **kwargs):
        """Implement thread-safe singleton behavior."""

        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)

        return cls._instance

    def __init__(self, *, database_url: str):
        # Initialize the database engine and session maker only once
        if not getattr(self, "_initialized", False):
            self._engines = {
                "default": create_engine(database_url),
            }
            self._initialized = True
            logger.debug("Database initialized successfully.")

    def get_engine(self, id: Optional[str] = None):
        if id:
            return self._engines[id]

        return self._engines["default"]

    def add_engine(self, id: str, db_url: str):
        if id in self._engines:
            raise Exception(f"Engine with id `{id}` already exists.")

        self._engines = {
            id: create_engine(db_url),
        }
        return self._engines[id]
