from typing import Any, Dict, Optional
import os
from pathlib import Path
import gnupg

from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.enums import GPGKeyIDType
from onilock.core.exceptions.exceptions import EncryptionKeyNotFoundError


class BaseEncryptionBackend:
    """Base Encryption Backend Interface."""

    passphrase: str

    def __init__(self, **kwargs):
        self.passphrase = kwargs.get("passphrase", settings.PASSPHRASE)

    def generate_key(self, **data):
        raise NotImplementedError()

    def list_keys(self, secret=False):
        raise NotImplementedError()

    def get_key_info(self, key_id: Any, key_id_type: Any, secret: bool = False):
        raise NotImplementedError()

    def delete_key(self, key_id: Any, key_id_type: Any, passphrase: Any):
        raise NotImplementedError()

    def encrypt(self, data: str, **kwargs):
        raise NotImplementedError()

    def decrypt(self, encrypted_data: bytes):
        raise NotImplementedError()

    def encrypt_file(self, filename: str, **kwargs):
        raise NotImplementedError()

    def decrypt_file(self, encrypted_filename: str):
        raise NotImplementedError()


class EncryptionBackendManager:
    """Encryption Backend Manager."""

    backend: BaseEncryptionBackend

    def __init__(self, backend: Optional[BaseEncryptionBackend] = None):
        if backend:
            self.backend = backend
        else:
            # Defaults to GPGEncryptionBackend
            self.backend = GPGEncryptionBackend()

    def generate_key(self, **data):
        return self.backend.generate_key(**data)

    def list_keys(self, secret=False):
        return self.backend.list_keys(secret)

    def get_key_info(self, key_id: Any, key_id_type: Any, secret: bool = False):
        return self.backend.get_key_info(key_id, key_id_type, secret=secret)

    def delete_key(self, key_id: Any, key_id_type: Any, passphrase: Any):
        return self.backend.delete_key(key_id, key_id_type, passphrase)

    def encrypt(self, data: str, **kwargs):
        return self.backend.encrypt(data, **kwargs)

    def decrypt(self, encrypted_data: bytes):
        return self.backend.decrypt(encrypted_data)

    def encrypt_file(self, filename: str, **kwargs):
        return self.backend.encrypt_file(filename, **kwargs)

    def decrypt_file(self, encrypted_filename: str):
        return self.backend.decrypt_file(encrypted_filename)


class GPGEncryptionBackend(BaseEncryptionBackend):
    """GPG Encryption Backend."""

    def __init__(self, **kwargs):
        """Initialize GPG client."""

        logger.debug("Initializing GPG Encryption backend.")
        super().__init__(**kwargs)

        gpg_home = kwargs.get("gpg_home", settings.GPG_HOME)
        explicit_gpg_home = kwargs.get("gpg_home", None) is not None
        is_dev_source = getattr(settings, "IS_DEV_SOURCE", False)
        if not isinstance(is_dev_source, bool):
            is_dev_source = False
        if gpg_home:
            try:
                os.makedirs(gpg_home, exist_ok=True)
                os.chmod(gpg_home, 0o700)
            except PermissionError:
                if explicit_gpg_home:
                    raise
                if is_dev_source:
                    gpg_home = str(Path(settings.VAULT_DIR).parent / ".gnupg")
                    os.makedirs(gpg_home, exist_ok=True)
                    os.chmod(gpg_home, 0o700)
                else:
                    raise

            if is_dev_source and not os.access(gpg_home, os.W_OK):
                gpg_home = str(Path(settings.VAULT_DIR).parent / ".gnupg")
                os.makedirs(gpg_home, exist_ok=True)
                os.chmod(gpg_home, 0o700)

        self.gpg = gnupg.GPG(
            gnupghome=gpg_home,
            options=["--pinentry-mode", "loopback"],
        )

        key_info = self.get_key_info(
            settings.PGP_REAL_NAME,
            key_id_type=GPGKeyIDType.NAME_REAL,
            secret=True,
        )

        if not key_info:
            logger.info("PGP secret key was not found.")
            self.generate_key(
                name=kwargs.get("name"),
                email=kwargs.get("email", None) or settings.PGP_EMAIL,
                passphrase=self.passphrase,
            )

    def generate_key(
        self,
        **data,
    ):
        """
        Generate a new PGP key pair.

        Args:
            name (Optional[str]): The name-real of the PGP key.
            email (Optional[str]): The email recipients of the key.
            passphrase (Optional[str]): The key passphrase.
        """
        name = data.get("name", None) or settings.PGP_REAL_NAME
        logger.info(f"Generating a new PGP key {name}")
        input_data = self.gpg.gen_key_input(
            key_type="RSA",
            key_length=4096,  # ALT: 3072
            name_real=name,
            name_email=data.get("email", None) or settings.PGP_EMAIL,
            passphrase=data.get("passphrase", settings.PASSPHRASE),
        )
        key = self.gpg.gen_key(input_data)
        fingerprint = getattr(key, "fingerprint", None)
        key_str = str(key).strip() if key is not None else ""
        if not key_str or (fingerprint is not None and not fingerprint):
            stderr = getattr(key, "stderr", None)
            details = stderr.strip() if stderr else "Unknown GPG error."
            raise RuntimeError(
                "Failed to generate a PGP key. Ensure gpg and gpg-agent are installed, "
                "the GPG home directory is writable, and try again. "
                f"Details: {details}"
            )

        # Secret key listing can lag right after generation on some systems.
        if not self.get_key_info(name, key_id_type=GPGKeyIDType.NAME_REAL, secret=True):
            if fingerprint in (None, ""):
                raise RuntimeError(
                    "PGP key generation did not produce a usable secret key."
                )
            logger.warning(
                "Generated key was not immediately visible in secret key list."
            )

        logger.info(f"PGP key '{key}' generated successfully.")
        return key

    def list_keys(self, secret=False):
        logger.info("Listing all PGP keys")
        return self.gpg.list_keys(secret=secret)

    def get_key_info(
        self,
        key_id: str,
        key_id_type: GPGKeyIDType = GPGKeyIDType.NAME_REAL,
        secret: bool = False,
    ) -> Optional[Dict]:
        logger.info(f"Retreiving key '{key_id}' info.")
        keys = self.gpg.list_keys(secret=secret)

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
        logger.info(f"Deleting key '{key_id}'.")
        key_info = self.get_key_info(key_id, key_id_type)
        if not key_info:
            raise EncryptionKeyNotFoundError()

        fingerprint = key_info["fingerprint"]

        # Delete the secret key first
        self.gpg.delete_keys(
            fingerprint,
            secret=True,
            passphrase=passphrase,
        )

        # Then delete the public key
        self.gpg.delete_keys(fingerprint)

    def encrypt(self, data: str, **kwargs):
        logger.info("Encrypting data...")
        return self.gpg.encrypt(
            data,
            recipients=kwargs.get("recipients", settings.PGP_EMAIL),
            always_trust=kwargs.get("always_trust", True),
            armor=kwargs.get("armor", False),
        )

    def decrypt(self, encrypted_data: bytes):
        logger.info("Decrypting data...")
        return self.gpg.decrypt(encrypted_data, passphrase=self.passphrase)

    def encrypt_file(self, filename: str, **kwargs):
        raise NotImplementedError()

    def decrypt_file(self, encrypted_filename: str, passphrase: str):
        raise NotImplementedError()


class RemoteGPGEncryptionBackend(BaseEncryptionBackend):
    """Encrypts the data using a PGP key from a remote server."""

    pass
