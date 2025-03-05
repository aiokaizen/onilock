import os
import json
from pathlib import Path
from typing import Any, Dict, Optional
import hashlib

from onilock.core.encryption.encryption import (
    BaseEncryptionBackend,
    EncryptionBackendManager,
)
from onilock.core.settings import settings
from onilock.core.logging_manager import logger


class Engine:
    """Base Database Engine."""

    def __init__(self, db_url: str):
        self.db_url = db_url

    def write(self, data: Any) -> None:
        raise Exception("Unimplimented")

    def read(self) -> Dict:
        raise Exception("Unimplimented")


class EncryptedEngine:
    """Base Encrypted Database Engine."""

    def __init__(
        self, db_url: str, encryption_backend: Optional[BaseEncryptionBackend] = None
    ):
        self.db_url = db_url
        self.encryption_backend = EncryptionBackendManager(encryption_backend)

    def write(self, data: Any) -> None:
        raise NotImplementedError

    def read(self) -> Dict:
        raise NotImplementedError


class JsonEngine(Engine):
    """Json Database Engine."""

    def __init__(self, db_url: str):
        self.filepath = db_url
        return super().__init__(db_url)

    def write(self, data: Dict) -> None:
        parent_dir = os.path.dirname(self.filepath)
        if parent_dir and not os.path.exists(parent_dir):
            logger.debug(f"Parent dir {parent_dir} does not exist. It will be created.")
            os.makedirs(parent_dir)

        with open(self.filepath, "w") as f:
            json.dump(data, f, indent=4)

    def read(self) -> Dict:
        if not os.path.exists(self.filepath):
            return dict()

        with open(self.filepath, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return dict()


class EncryptedJsonEngine(EncryptedEngine):
    """PGP-Encrypted JSON Database Engine."""

    def __init__(
        self, db_url: str, encryption_backend: Optional[BaseEncryptionBackend] = None
    ):
        super().__init__(db_url, encryption_backend)
        self.filepath = db_url

    def write(self, data: Dict) -> None:
        """Encrypt data and write to file."""
        parent_dir = os.path.dirname(self.filepath)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir)

        # Serialize data to JSON string
        json_data = json.dumps(data, indent=4)

        # Generate checksum
        checksum = hashlib.sha256(json_data.encode()).hexdigest()
        logger.debug(f"Calculated checksum: {checksum}")

        # Encrypt data
        encrypted_data = self.encryption_backend.encrypt(
            f"{checksum}{settings.CHECKSUM_SEPARATOR}{json_data}",
            always_trust=True,
            armor=False,  # ← This is crucial to disable base64 encoding
        )

        if not encrypted_data.ok:
            raise RuntimeError(f"Encryption failed: {encrypted_data.status}")

        # Write encrypted data as binary
        Path(self.filepath).write_bytes(encrypted_data.data)

    def read(self) -> Dict:
        """Read and decrypt data from file."""
        filepath = Path(self.filepath)

        if not filepath.exists():
            logger.debug(f"File {filepath} does not exist. Returning an empty dict.")
            return dict()

        encrypted_data = filepath.read_bytes()

        # Decrypt data
        decrypted_data = self.encryption_backend.decrypt(encrypted_data)

        if not decrypted_data.ok:
            raise RuntimeError(f"Decryption failed: {decrypted_data.status}")

        # Split checksum and data
        try:
            stored_checksum, data = decrypted_data.data.decode().split(
                settings.CHECKSUM_SEPARATOR, 1
            )
        except ValueError:
            raise ValueError("Invalid file format")

        # Verify file integrity
        current_checksum = hashlib.sha256(data.encode()).hexdigest()
        if current_checksum != stored_checksum:
            raise RuntimeError("Data corruption detected! Checksum mismatch")

        return json.loads(data)
