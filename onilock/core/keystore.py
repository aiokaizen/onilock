import os
import json
import hashlib
import base64
from typing import Dict, Optional
import uuid

import keyring
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class KeyStore:
    """Base KeyStore class interface."""

    def __init__(self, keystore_id: str) -> None:
        self.keystore_id = keystore_id

    def clean(self):
        raise NotImplementedError

    def set_password(self, id: str, password: str) -> None:
        raise NotImplementedError

    def get_password(self, id: str) -> Optional[str]:
        raise NotImplementedError

    def delete_password(self, id: str) -> None:
        raise NotImplementedError


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
        # This raises an exception if the keyring is not supported.
        keyring.set_password(keystore_id, "tmp_user", "x")
        keyring.delete_password(keystore_id, "tmp_user")

        # Call super init method.
        super().__init__(keystore_id)

    def clean(self):
        return NotImplementedError("Clearing is not implemented for `KeyRing`")

    def set_password(self, id: str, password: str):
        keyring.set_password(self.keystore_id, id, password)

    def get_password(self, id: str) -> Optional[str]:
        return keyring.get_password(self.keystore_id, id)

    def delete_password(self, id: str):
        keyring.delete_password(self.keystore_id, id)


class FileKeyStore(KeyStore):
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
            with open(self.filename, "rb") as f:
                encrypted_data = f.read()
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
        with open(self.filename, "wb") as f:
            iv_data = (
                encrypted_data[: self.BLOCK_SIZE]
                + self.iv
                + encrypted_data[self.BLOCK_SIZE :]
            )
            f.write(iv_data)

    def clean(self):
        os.remove(self.filename)

    def set_password(self, id: str, password: str):
        data = self._read_keystore()
        data[id] = password
        self._write_keystore(data)

    def get_password(self, id: str) -> Optional[str]:
        data = self._read_keystore()
        return data.get(id)

    def delete_password(self, id: str):
        data = self._read_keystore()
        data.pop(id)
        self._write_keystore(data)


class KeyStoreManager(KeyStore):
    """A class manager for KeyStore interface."""

    keystore: KeyStore

    def __init__(self, keystore_id: str):
        try:
            self.keystore = KeyRing(keystore_id)
        except Exception as e:
            self.keystore = FileKeyStore(keystore_id)

    def set_password(self, id: str, password: str) -> None:
        return self.keystore.set_password(id, password)

    def get_password(self, id: str) -> Optional[str]:
        return self.keystore.get_password(id)

    def delete_password(self, id: str) -> None:
        return self.keystore.delete_password(id)


keystore = KeyStoreManager("onilock")
