import os
import json
from typing import Any, Dict
import hashlib

import gnupg

from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.gpg import generate_pgp_key, pgp_key_exists


class Engine:
    """Base Database Engine."""

    def __init__(self, db_url: str):
        self.db_url = db_url

    def write(self, data: Any) -> None:
        raise Exception("Unimplimented")

    def read(self) -> Dict:
        raise Exception("Unimplimented")


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


class EncryptedJsonEngine(JsonEngine):
    """PGP-Encrypted JSON Database Engine."""

    def __init__(self, db_url: str):
        super().__init__(db_url)

        passphrase = settings.PASSPHRASE
        gpg_home = settings.GPG_HOME
        email = settings.PGP_EMAIL
        encryption_key = settings.PGP_REAL_NAME

        self.gpg = gnupg.GPG(gnupghome=gpg_home)
        self.encryption_key = encryption_key  # Recipient key fingerprint/ID
        self.passphrase = passphrase  # Passphrase for private key

        key_generated = pgp_key_exists(
            gpg_home=gpg_home,
            real_name=encryption_key,
        )

        if not key_generated:
            generate_pgp_key(
                gpg_home=gpg_home,
                name=encryption_key,
                email=email,
                passphrase=self.passphrase,
            )

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
        encrypted_data = self.gpg.encrypt(
            f"{checksum}{settings.CHECKSUM_SEPARATOR}{json_data}",
            recipients=self.encryption_key,
            always_trust=True,
            armor=False,  # ← This is crucial to disable base64 encoding
        )

        if not encrypted_data.ok:
            raise RuntimeError(f"Encryption failed: {encrypted_data.status}")

        # Write encrypted data as binary
        with open(self.filepath, "wb") as f:
            f.write(encrypted_data.data)

    def read(self) -> Dict:
        """Read and decrypt data from file."""
        if not os.path.exists(self.filepath):
            return dict()

        with open(self.filepath, "rb") as f:
            encrypted_data = f.read()

            # Decrypt data
            decrypted_data = self.gpg.decrypt(
                encrypted_data, passphrase=self.passphrase
            )

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
