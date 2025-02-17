from threading import Lock

from core.settings import settings
from core.logging_manager import logger
from db.engines import JsonEngine


def create_engine(database_url: str):
    return JsonEngine(filepath=database_url)


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
            self._engine = create_engine(database_url)
            self._initialized = True

    def get_engine(self):
        return self._engine
