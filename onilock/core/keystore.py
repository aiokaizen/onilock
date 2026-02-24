import os
import json
import hashlib
import base64
from pathlib import Path
from typing import Dict, Optional, Set
import uuid
from abc import ABC, abstractmethod

import keyring
from cryptography.fernet import Fernet, InvalidToken
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from onilock.core.enums import KeyStoreBackendEnum
from onilock.core.exceptions.exceptions import (
    KeyRingBackendNotAvailable,
    VaultConfigurationError,
)


class KeyStore(ABC):
    """Base KeyStore class interface."""

    _passwords: Set[str] = set()

    @abstractmethod
    def __init__(self, keystore_id: str) -> None:
        self.keystore_id = keystore_id

    @abstractmethod
    def clear(self):
        KeyStore._passwords.clear()

    @abstractmethod
    def set_password(self, id: str, password: str) -> None:
        KeyStore._passwords.add(id)

    @abstractmethod
    def get_password(self, id: str) -> Optional[str]:
        if id not in KeyStore._passwords:
            KeyStore._passwords.add(id)

    @abstractmethod
    def delete_password(self, id: str) -> None:
        if id in KeyStore._passwords:
            KeyStore._passwords.remove(id)


class KeyRing(KeyStore):
    """
    Default KeyRing used by the system.

    Defaults to:
        - `KWallet` for KDE Lunux desktops.
        - `SecretService` for Gnome based distributions.
        - `Keychain` for macOS
        - `Windows Credential Locker` in Windows.
    """

    def __init__(self, keystore_id: str) -> None:
        try:
            # This line raises an error if the backend is not available.
            keyring.get_password("onilock", "x")
        except Exception as exc:
            raise KeyRingBackendNotAvailable() from exc
        super().__init__(keystore_id)

    def clear(self):
        for pwd in KeyRing._passwords:
            keyring.delete_password(self.keystore_id, pwd)
        super().clear()

    def set_password(self, id: str, password: str):
        keyring.set_password(self.keystore_id, id, password)
        super().set_password(id, password)

    def get_password(self, id: str) -> Optional[str]:
        super().get_password(id)
        return keyring.get_password(self.keystore_id, id)

    def delete_password(self, id: str):
        super().delete_password(id)
        keyring.delete_password(self.keystore_id, id)


class VaultKeyStore(KeyStore):
    """
    Fallback key store using authenticated encryption on the filesystem.
    """

    def __init__(self, keystore_id: str) -> None:
        super().__init__(keystore_id)

        self._base_dir = Path(os.path.expanduser("~")) / ".onilock" / "vault"
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._key_file = self._base_dir / ".keystore.key"
        filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, keystore_id)).split("-")[-1]
        self.filename = self._base_dir / f"{filename}.oni"
        self._fernet = Fernet(self._load_or_create_key())

    def _write_private_file(self, path: Path, data: bytes):
        path.write_bytes(data)
        os.chmod(path, 0o600)

    def _load_or_create_key(self) -> bytes:
        env_key = os.environ.get("ONI_VAULT_KEY")
        if env_key:
            key = env_key.encode()
            if len(key) == 44:
                return key
            return base64.urlsafe_b64encode(hashlib.sha256(key).digest())

        if self._key_file.exists():
            return self._key_file.read_bytes()

        key = Fernet.generate_key()
        self._write_private_file(self._key_file, key)
        return key

    def _read_keystore(self) -> Dict:
        try:
            encrypted_data = self.filename.read_bytes()
        except FileNotFoundError:
            return dict()
        try:
            plaintext = self._fernet.decrypt(encrypted_data)
        except InvalidToken as exc:
            legacy_data = self._read_legacy_keystore(encrypted_data)
            if legacy_data is not None:
                self._write_keystore(legacy_data)
                return legacy_data
            raise VaultConfigurationError("Vault keystore integrity check failed.") from exc
        return json.loads(plaintext.decode())

    def _read_legacy_keystore(self, encrypted_data: bytes) -> Optional[Dict]:
        """
        Read the previous AES-CBC keystore format and migrate it forward.
        """
        try:
            block_size = 16
            iv = encrypted_data[block_size : block_size * 2]
            ciphertext = encrypted_data[:block_size] + encrypted_data[block_size * 2 :]
            legacy_key = hashlib.sha256(__file__.encode()).hexdigest()[:32].encode()
            cipher = AES.new(legacy_key, AES.MODE_CBC, iv)
            json_bytes = unpad(cipher.decrypt(ciphertext), block_size)
            return json.loads(json_bytes.decode())
        except Exception:
            return None

    def _write_keystore(self, data):
        json_str = json.dumps(data, sort_keys=True)
        encrypted_data = self._fernet.encrypt(json_str.encode())
        self._write_private_file(self.filename, encrypted_data)

    def clear(self):
        if self.filename.exists():
            self.filename.unlink()
        if self._key_file.exists():
            self._key_file.unlink()
        super().clear()

    def set_password(self, id: str, password: str):
        data = self._read_keystore()
        data[id] = password
        self._write_keystore(data)
        super().set_password(id, password)

    def get_password(self, id: str) -> Optional[str]:
        super().get_password(id)
        data = self._read_keystore()
        return data.get(id)

    def delete_password(self, id: str):
        data = self._read_keystore()
        data.pop(id, None)
        self._write_keystore(data)
        super().delete_password(id)


class KeyStoreManager:
    """A class manager for KeyStore interface."""

    keystore: KeyStore

    def __init__(self, keystore_id: str):
        """Initialize the KeyStore manger class."""

        default_backend = os.environ.get(
            "ONI_DEFAULT_KEYSTORE_BACKEND", KeyStoreBackendEnum.KEYRING.value
        )

        if default_backend == KeyStoreBackendEnum.KEYRING.value:
            try:
                self.keystore = KeyRing(keystore_id)
            except KeyRingBackendNotAvailable:
                self.keystore = VaultKeyStore(keystore_id)
        elif default_backend == KeyStoreBackendEnum.VAULT.value:
            self.keystore = VaultKeyStore(keystore_id)

    def clear(self) -> None:
        return self.keystore.clear()

    def set_password(self, id: str, password: str) -> None:
        return self.keystore.set_password(id, password)

    def get_password(self, id: str) -> Optional[str]:
        return self.keystore.get_password(id)

    def delete_password(self, id: str) -> None:
        return self.keystore.delete_password(id)


keystore = KeyStoreManager("onilock")
