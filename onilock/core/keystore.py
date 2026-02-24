import os
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Set
import uuid
from abc import ABC, abstractmethod

import keyring
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from onilock.core.enums import KeyStoreBackendEnum
from onilock.core.exceptions.exceptions import KeyRingBackendNotAvailable


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
        # This line raises an error if the backend is not available.
        keyring.get_password("onilock", "x")
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
    Less secure key store using the filesystem to store passwords.
    """

    BLOCK_SIZE = 16

    def __init__(self, keystore_id: str) -> None:
        super().__init__(keystore_id)

        # Setup file store.
        keystore_basedir = os.path.join(os.path.expanduser("~"), ".onilock", "vault")
        if not os.path.exists(keystore_basedir):
            os.makedirs(keystore_basedir)

        self.key = self._load_or_create_key(keystore_basedir)

        filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, keystore_id)).split("-")[-1]
        self.filename = os.path.join(keystore_basedir, f"{filename}.oni")

    def _load_or_create_key(self, keystore_basedir: str) -> bytes:
        """Load the AES key from a protected file, or generate and store a new one."""
        key_file = os.path.join(keystore_basedir, ".key")
        if os.path.exists(key_file):
            return Path(key_file).read_bytes()
        key = get_random_bytes(32)
        Path(key_file).write_bytes(key)
        os.chmod(key_file, 0o600)
        return key

    def _cipher(self, iv: bytes):
        return AES.new(self.key, AES.MODE_CBC, iv)

    def _read_keystore(self) -> Dict:
        try:
            encrypted_data = Path(self.filename).read_bytes()
            iv = encrypted_data[self.BLOCK_SIZE : self.BLOCK_SIZE * 2]
            ciphertext = (
                encrypted_data[: self.BLOCK_SIZE]
                + encrypted_data[self.BLOCK_SIZE * 2 :]
            )
            json_str = unpad(self._cipher(iv).decrypt(ciphertext), self.BLOCK_SIZE)
            return json.loads(json_str)
        except FileNotFoundError:
            return dict()
        except Exception:
            # Decryption failed — attempt one-time migration from pre-v1.7.3
            # key derivation (hashlib.sha256(__file__)).
            return self._migrate_legacy_keystore()

    def _migrate_legacy_keystore(self) -> Dict:
        """Transparently migrate a keystore encrypted with the pre-v1.7.3 key."""
        import hashlib

        try:
            legacy_key = hashlib.sha256(__file__.encode()).hexdigest()[:32].encode()
            encrypted_data = Path(self.filename).read_bytes()
            iv = encrypted_data[self.BLOCK_SIZE : self.BLOCK_SIZE * 2]
            ciphertext = (
                encrypted_data[: self.BLOCK_SIZE]
                + encrypted_data[self.BLOCK_SIZE * 2 :]
            )
            cipher = AES.new(legacy_key, AES.MODE_CBC, iv)
            json_str = unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)
            data = json.loads(json_str)
            # Re-write with the new random key so migration only happens once.
            self._write_keystore(data)
            logging.getLogger(__name__).info(
                "Keystore migrated to new key format (pre-v1.7.3 → v1.7.3+)."
            )
            return data
        except Exception:
            logging.getLogger(__name__).warning(
                "Keystore decryption failed and legacy migration was unsuccessful. "
                "The keystore may be corrupted or was created by an incompatible version."
            )
            return dict()

    def _write_keystore(self, data):
        iv = get_random_bytes(self.BLOCK_SIZE)
        json_str = json.dumps(data)
        padded_data = pad(json_str.encode(), self.BLOCK_SIZE)
        encrypted_data = self._cipher(iv).encrypt(padded_data)
        iv_data = (
            encrypted_data[: self.BLOCK_SIZE]
            + iv
            + encrypted_data[self.BLOCK_SIZE :]
        )
        Path(self.filename).write_bytes(iv_data)

    def clear(self):
        os.remove(self.filename)
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
        data.pop(id)
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
            except Exception as e:
                logging.getLogger(__name__).warning(
                    "System keyring unavailable (%s), falling back to VaultKeyStore.", e
                )
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
