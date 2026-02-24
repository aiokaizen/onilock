import os
import json
import base64
from pathlib import Path
from typing import Any, Dict, Optional
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
        self._encryption_backend = encryption_backend
        self._encryption_manager: Optional[EncryptionBackendManager] = None

    @property
    def encryption_backend(self) -> EncryptionBackendManager:
        if self._encryption_manager is None:
            self._encryption_manager = EncryptionBackendManager(self._encryption_backend)
        return self._encryption_manager

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
    """Versioned encrypted JSON database engine with AEAD v2 format."""

    V2_HEADER = b"ONILOCK_V2\n"
    V2_AAD = b"onilock-v2"

    def __init__(
        self, db_url: str, encryption_backend: Optional[BaseEncryptionBackend] = None
    ):
        super().__init__(db_url, encryption_backend)
        self.filepath = db_url

    def _serialize(self, data: Dict) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def _write_v2(self, data: Dict) -> None:
        payload = self._serialize(data)
        key = base64.urlsafe_b64decode(settings.SECRET_KEY.encode())
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, payload, self.V2_AAD)
        envelope = {
            "version": 2,
            "alg": "aesgcm",
            "nonce": base64.b64encode(nonce).decode(),
            "aad": base64.b64encode(self.V2_AAD).decode(),
            "data": base64.b64encode(ciphertext).decode(),
        }
        data_bytes = self.V2_HEADER + json.dumps(envelope, sort_keys=True).encode()
        Path(self.filepath).write_bytes(data_bytes)

    def write(self, data: Dict) -> None:
        """Encrypt data and write to file."""
        parent_dir = os.path.dirname(self.filepath)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir)

        self._write_v2(data)

    def _read_v2(self, data: bytes) -> Dict:
        envelope = json.loads(data.decode())
        if envelope.get("version") != 2 or envelope.get("alg") != "aesgcm":
            raise ValueError("Unsupported vault format")
        nonce = base64.b64decode(envelope["nonce"])
        aad = base64.b64decode(envelope["aad"])
        ciphertext = base64.b64decode(envelope["data"])
        key = base64.urlsafe_b64decode(settings.SECRET_KEY.encode())
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        return json.loads(plaintext.decode())

    def _read_v1(self, encrypted_data: bytes) -> Dict:
        # Decrypt data using legacy GPG backend
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
            from onilock.core.audit import audit

            audit("vault.tamper_detected", filepath=str(self.filepath))
            raise RuntimeError("Data corruption detected! Checksum mismatch")

        return json.loads(data)

    def read(self) -> Dict:
        """Read and decrypt data from file."""
        filepath = Path(self.filepath)

        if not filepath.exists():
            logger.debug(f"File {filepath} does not exist. Returning an empty dict.")
            return dict()

        raw = filepath.read_bytes()
        if raw.startswith(self.V2_HEADER):
            return self._read_v2(raw[len(self.V2_HEADER) :])

        # Legacy v1: migrate on successful read.
        data = self._read_v1(raw)
        try:
            self._write_v2(data)
        except Exception:
            pass
        return data
