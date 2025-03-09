from threading import Lock
from typing import Optional

from onilock.core.encryption.encryption import BaseEncryptionBackend
from onilock.core.exceptions import DatabaseEngineAlreadyExistsException
from onilock.core.logging_manager import logger
from onilock.db.engines import EncryptedJsonEngine, JsonEngine


def create_engine(database_url: str):
    return JsonEngine(db_url=database_url)


def create_encrypted_engine(
    database_url: str, encryption_backend: Optional[BaseEncryptionBackend] = None
):
    return EncryptedJsonEngine(
        db_url=database_url, encryption_backend=encryption_backend
    )


class DatabaseManager:
    _instance = None
    _lock = Lock()

    def __new__(cls, **kwargs):
        """Implement thread-safe singleton behavior."""

        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    logger.debug("Creating the database manager singleton object.")
                    cls._instance = super().__new__(cls)

        return cls._instance

    def __init__(
        self,
        *,
        database_url: str,
        is_encrypted: bool = False,
        encryption_backend: Optional[BaseEncryptionBackend] = None,
    ):
        if getattr(self, "_initialized", False):
            return

        # Initialize the database engine and session maker only once
        if not is_encrypted:
            self._engines = {
                "default": create_engine(database_url),
            }
            logger.debug("Database initialized successfully.")
        else:
            self._engines = {
                "default": create_encrypted_engine(database_url, encryption_backend),
            }
            logger.debug("Encrypted database initialized successfully.")

        self._initialized = True

    def get_engine(self, id: Optional[str] = None):
        if id:
            return self._engines[id]

        logger.debug(f"Available engines: {list(self._engines.keys())}")
        return self._engines["default"]

    def add_engine(
        self,
        id: str,
        db_url: str,
        is_encrypted: bool = False,
        encryption_backend: Optional[BaseEncryptionBackend] = None,
    ):
        if id in self._engines:
            return self._engines[id]

        if is_encrypted:
            self._engines[id] = create_encrypted_engine(db_url, encryption_backend)
        else:
            self._engines[id] = create_engine(db_url)
        return self._engines[id]
