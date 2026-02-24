import os
import json
import base64
import socket
import zipfile
from typing import Optional
from pathlib import Path
import uuid
import subprocess
import tempfile

import gnupg
from cryptography.fernet import Fernet

from onilock.profile_store import get_profile_engine
from onilock.core.constants import SECRET_FILENAME_PREFIX
from onilock.core.exceptions import (
    InvalidFileIdentifierError,
    VaultConfigurationError,
    VaultNotInitializedError,
)
from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.utils import getlogin, naive_utcnow
from onilock.db.engines import Engine
from onilock.db.models import File, Profile


def get_output_filename(file_id: str):
    secret_filename = f"{SECRET_FILENAME_PREFIX}{file_id}"
    return Path(
        str(uuid.uuid5(uuid.NAMESPACE_DNS, secret_filename)).split("-")[-1] + ".oni"
    )


class FileEncryptionManager:
    """This class is responsible for all file operations."""

    gpg: gnupg.GPG
    _profile: Optional[Profile]
    _engine: Optional[Engine]

    def __init__(self, gpg_home: Optional[str] = None) -> None:
        self.gpg = gnupg.GPG(
            gnupghome=gpg_home or settings.GPG_HOME,
        )
        self._engine = None
        self._profile = None

    @property
    def profile(self) -> Profile:
        if self._profile:
            return self._profile

        data = self.engine.read()
        if not data:
            raise VaultNotInitializedError()

        profile = Profile(**data)
        self._profile = profile
        return profile

    @property
    def engine(self) -> Engine:
        if self._engine:
            return self._engine

        engine = get_profile_engine()
        self._engine = engine
        return engine

    def encrypt_bytes(self, data: bytes, output_filename: Path | str):
        """Encrypts a file and stors it in the vault."""

        output_filepath: Path = (
            output_filename
            if isinstance(output_filename, Path)
            else Path(output_filename)
        )

        encrypted_data = self.gpg.encrypt(
            data,
            recipients=[settings.PGP_REAL_NAME],  # The recipient's email or key ID
            always_trust=True,  # Avoids trust prompt
            armor=False,
        )
        if not encrypted_data.ok:
            raise VaultConfigurationError(
                f"File encryption failed: {encrypted_data.status}"
            )
        output_filepath.write_bytes(encrypted_data.data)
        logger.info("File encrypted successfully.")
        return encrypted_data

    def encrypt(
        self,
        file_id: str,
        file_to_encrypt: str,
        override: bool = False,
        update_db: bool = True,
    ):
        """Encrypts a file and stors it in the vault."""

        target_filepath = Path(file_to_encrypt)

        if not target_filepath.exists():
            raise VaultConfigurationError("File does not exist.")

        if not target_filepath.is_file():
            raise VaultConfigurationError(
                "Please make sure `filename` is a normal file. Directories are not supported in the current version."
            )

        output_filename = get_output_filename(file_id)
        output_filepath = settings.VAULT_DIR / output_filename
        logger.debug(f"Encryption filename {output_filename}")

        if output_filepath.exists() and not override:
            raise InvalidFileIdentifierError(
                "ID already exists. Please choose another id for your file."
            )

        with target_filepath.open("rb") as f:
            encrypted_data = self.encrypt_bytes(f.read(), output_filepath)
            if update_db:
                output_filepath = str(output_filepath.absolute())
                src_file_abs_path = str(target_filepath.absolute())
                owner = getlogin()
                host = socket.gethostname()
                self.profile.files.append(
                    File(
                        id=file_id,
                        location=output_filepath,
                        created_at=int(naive_utcnow().timestamp()),
                        src=src_file_abs_path,
                        user=owner,
                        host=host,
                    )
                )
                self.engine.write(self.profile.model_dump())
            return encrypted_data

    def decrypt_bytes(self, data: bytes) -> bytes:
        decrypted_data = self.gpg.decrypt(
            data,
            always_trust=True,
            passphrase=settings.PASSPHRASE,
        )
        if not decrypted_data.ok:
            raise VaultConfigurationError(
                f"File decryption failed: {decrypted_data.status}"
            )
        return decrypted_data.data

    def decrypt(self, file_id: str):
        if not self.profile.get_file(file_id):
            raise InvalidFileIdentifierError()

        encrypted_filename = get_output_filename(file_id)
        encrypted_filepath = settings.VAULT_DIR / encrypted_filename

        if not encrypted_filepath.exists():
            raise InvalidFileIdentifierError("Encrypted file not found in vault.")

        with encrypted_filepath.open("rb") as f:
            data = self.decrypt_bytes(f.read())
            return data

    def open(self, file_id: str, readonly=False):
        if not self.profile.get_file(file_id):
            raise InvalidFileIdentifierError()

        decrypted_data = self.decrypt(file_id)
        tmp_filepath: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(mode="rb+", delete=False) as tmp:
                tmp_filepath = tmp.name
                tmp.write(decrypted_data)
                tmp.flush()  # Ensure content is written

                readonly_args = []
                if readonly:
                    readonly_args = [
                        "-R",  # Read only
                        "-m",  # Forbid writes
                    ]

                subprocess.run(
                    [
                        "vim",  # Start vim with the decrypted file as input.
                        "-n",  # No swap file
                        *readonly_args,
                        tmp.name,
                    ],
                )

                if readonly:
                    return

                # else: write the new data back to the vault.
                self.encrypt(file_id, tmp.name, override=True, update_db=False)
        finally:
            if tmp_filepath:
                Path(tmp_filepath).unlink(missing_ok=True)

    def read(self, file_id: str):
        """Open encrypted file in readonly mode."""

        return self.open(file_id, readonly=True)

    def delete(self, file_id: str):
        """Delete an encrypted file from OniLock vault."""
        encrypted_filename = settings.VAULT_DIR / get_output_filename(file_id)
        if encrypted_filename.exists():
            encrypted_filename.unlink()
            self.profile.remove_file(file_id)
            self.engine.write(self.profile.model_dump())

    def export(self, file_id: Optional[str] = None, file_path: Optional[str] = None):
        """
        Decrypt and export a file to the specified new location.

        If file_id is not provided, export all files in the vault.
        """

        if file_id and not self.profile.get_file(file_id):
            raise InvalidFileIdentifierError()

        is_dir = file_path and os.path.isdir(file_path)
        default_filename: str = (
            f"onilock_{getlogin()}_vault_{naive_utcnow().strftime('%Y%m%d%H%M%s')}.oni"
        )

        if file_id:
            decrypted_data = self.decrypt(file_id)
            default_filename = (
                Path(self.profile.get_file(file_id).src).name or default_filename
            )
            if not file_path:
                output_file = Path(default_filename)
            elif is_dir:
                output_file = Path(file_path) / default_filename
            else:
                output_file = Path(file_path)

            output_file.write_bytes(decrypted_data)
            return

        default_output_filename = Path(
            f"onilock_{getlogin()}_vault_{naive_utcnow().strftime('%Y%m%d%H%M%s')}.zip"
        )
        if not file_path:
            output_file = default_output_filename
        elif is_dir:
            output_file = Path(file_path) / default_output_filename
        else:
            output_file = Path(file_path)

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Create a folder inside the zip file
            folder_name = Path("onilock_vault/")
            # Iterate over the binary strings and add each as a separate file in the folder
            for file in self.profile.files:
                # Add the binary content as a file in the zip
                bin_data = self.decrypt(file.id)
                filename = str(folder_name / Path(file.src).name)
                with zipf.open(filename, "w") as f:
                    f.write(bin_data)

    def _resolve_output_path(
        self, file_path: Optional[str], default_filename: Path
    ) -> Path:
        if not file_path:
            return default_filename
        if os.path.isdir(file_path):
            return Path(file_path) / default_filename
        return Path(file_path)

    def _decrypt_account_password(self, encrypted_password: str) -> str:
        cipher = Fernet(settings.SECRET_KEY.encode())
        encrypted = base64.b64decode(encrypted_password)
        return cipher.decrypt(encrypted).decode()

    def export_vault(self, file_path: Optional[str] = None) -> Path:
        """
        Export the raw encrypted vault artifacts as a zip archive.
        """
        default_output_filename = Path(
            f"onilock_{getlogin()}_vault_backup_{naive_utcnow().strftime('%Y%m%d%H%M%s')}.zip"
        )
        output_file = self._resolve_output_path(file_path, default_output_filename)

        profile_file = Path(getattr(self.engine, "filepath", ""))
        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            setup_file = Path(settings.SETUP_FILEPATH)
            if setup_file.exists():
                zipf.write(setup_file, arcname=f"vault/setup/{setup_file.name}")

            if profile_file.exists():
                zipf.write(profile_file, arcname=f"vault/profile/{profile_file.name}")

            for file in self.profile.files:
                file_path_obj = Path(file.location)
                if file_path_obj.exists():
                    zipf.write(file_path_obj, arcname=f"vault/files/{file_path_obj.name}")
        return output_file

    def export_user_data(self, file_path: Optional[str] = None) -> Path:
        """
        Export decrypted accounts metadata and decrypted files into a zip archive.
        """
        default_output_filename = Path(
            f"onilock_{getlogin()}_user_export_{naive_utcnow().strftime('%Y%m%d%H%M%s')}.zip"
        )
        output_file = self._resolve_output_path(file_path, default_output_filename)

        export_data = {
            "profile": self.profile.name,
            "exported_at": naive_utcnow().isoformat(),
            "accounts": [],
        }

        for account in self.profile.accounts:
            account_data = account.model_dump()
            account_data["password"] = self._decrypt_account_password(
                account_data["encrypted_password"]
            )
            account_data.pop("encrypted_password", None)
            export_data["accounts"].append(account_data)

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr(
                "onilock_export/accounts.json",
                json.dumps(export_data, indent=2),
            )

            for file in self.profile.files:
                filename = f"onilock_export/files/{Path(file.src).name}"
                bin_data = self.decrypt(file.id)
                with zipf.open(filename, "w") as f:
                    f.write(bin_data)
        return output_file

    def clear(self):
        """Delete all encrypted files in the vault."""
        for file in list(self.profile.files):
            target = Path(file.location)
            if target.exists():
                target.unlink()
        self.profile.files.clear()
        self.engine.write(self.profile.model_dump())
