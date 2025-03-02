from typing import Any, Dict, Optional
import gnupg
from onilock.core.encryption.enums import GPGKeyIDType
from onilock.core.exceptions.base_exceptions import EncryptionKeyNotFound


class BaseEncryptionBackend:
    """Base Encryption Backend Interface."""

    def generate_key(self, **data):
        raise NotImplementedError()

    def list_keys(self, secret=False):
        raise NotImplementedError()

    def get_key_info(self, key_id: Any, key_id_type: Any):
        raise NotImplementedError()

    def delete_key(self, key_id: Any, key_id_type: Any, passphrase: Any):
        raise NotImplementedError()


class EncryptionBackendManager:
    """Encryption Backend Manager."""

    def __init__(self, backend: BaseEncryptionBackend):
        self.backend = backend

    def generate_key(self, **data):
        return self.backend.generate_key(**data)

    def list_keys(self, secret=False):
        return self.backend.list_keys(secret)

    def get_key_info(self, key_id: Any, key_id_type: Any):
        return self.backend.get_key_info(key_id, key_id_type)

    def delete_key(self, key_id: Any, key_id_type: Any, passphrase: Any):
        return self.backend.delete_key(key_id, key_id_type, passphrase)


class GPGEncryptionBackend(BaseEncryptionBackend):
    """GPG Encryption Backend."""

    def __init__(self, gpg_home: Optional[str] = None):
        self.gpg = gnupg.GPG(gnupghome=gpg_home)
        super().__init__()

    def generate_key(
        self,
        **data,
    ):
        """Generate a new PGP key pair."""
        input_data = self.gpg.gen_key_input(
            key_type="RSA",
            key_length=4096,  # ALT: 3072
            name_real=data["name_real"],
            name_email=data["email"],
            passphrase=data["passphrase"],
        )
        return self.gpg.gen_key(input_data)

    def list_keys(self, secret=False):
        return self.gpg.list_keys(secret=secret)

    def get_key_info(
        self,
        key_id: str,
        key_id_type: GPGKeyIDType = GPGKeyIDType.NAME_REAL,
    ) -> Optional[Dict]:
        keys = self.gpg.list_keys()

        for key in keys:
            uids = key.get("uids", [])

            if key_id_type == GPGKeyIDType.NAME_REAL:
                if any(key_id == uid.split(" ")[0] for uid in uids):
                    return key
            elif key_id_type == GPGKeyIDType.KEY_ID:
                if key_id == key.get("keyid"):
                    return key

        return None

    def delete_key(
        self,
        key_id: str,
        key_id_type: GPGKeyIDType = GPGKeyIDType.NAME_REAL,
        passphrase: Optional[str] = None,
    ) -> None:
        """Delete PGP public and private key."""
        key_info = self.get_key_info(key_id, key_id_type)
        if not key_info:
            raise EncryptionKeyNotFound()

        fingerprint = key_info["fingerprint"]

        # Delete the secret key first
        self.gpg.delete_keys(
            fingerprint,
            secret=True,
            passphrase=passphrase,
        )

        # Then delete the public key
        self.gpg.delete_keys(fingerprint)
