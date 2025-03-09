import os
import json
import hashlib
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
        backend = keyring.get_keyring()
        if backend is None or backend.name.lower() == "fail Keyring":
            raise KeyRingBackendNotAvailable("No keyring backend is available.")

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

        hashcode = hashlib.sha256(__file__.encode()).hexdigest()
        self.key = hashcode[:32].encode()
        self.iv = get_random_bytes(self.BLOCK_SIZE)

        filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, keystore_id)).split("-")[-1]
        self.filename = os.path.join(keystore_basedir, f"{filename}.oni")

    @property
    def _cipher(self):
        return AES.new(self.key, AES.MODE_CBC, self.iv)

    def _read_keystore(self) -> Dict:
        try:
            encrypted_data = Path(self.filename).read_bytes()
            self.iv = encrypted_data[self.BLOCK_SIZE : self.BLOCK_SIZE * 2]
            encrypted_data = (
                encrypted_data[: self.BLOCK_SIZE]
                + encrypted_data[self.BLOCK_SIZE * 2 :]
            )
            json_str = unpad(self._cipher.decrypt(encrypted_data), self.BLOCK_SIZE)
            return json.loads(json_str)
        except FileNotFoundError:
            return dict()

    def _write_keystore(self, data):
        json_str = json.dumps(data)
        padded_data = pad(json_str.encode(), self.BLOCK_SIZE)
        encrypted_data = self._cipher.encrypt(padded_data)
        iv_data = (
            encrypted_data[: self.BLOCK_SIZE]
            + self.iv
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
