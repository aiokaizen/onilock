from io import BufferedReader, RawIOBase
import zipfile
import os
from typing import BinaryIO, Optional
from pathlib import Path
import uuid
import subprocess
import tempfile

import gnupg
import typer

from onilock.core.constants import SECRET_FILENAME_PREFIX
from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.utils import getlogin, naive_utcnow


def get_output_filename(file_id: str):
    secret_filename = f"{SECRET_FILENAME_PREFIX}{file_id}"
    return Path(
        str(uuid.uuid5(uuid.NAMESPACE_DNS, secret_filename)).split("-")[-1] + ".oni"
    )


class FileEncryptionManager:
    """This class is responsible for all file operations."""

    def __init__(self, gpg_home: Optional[str] = None) -> None:
        self.gpg = gnupg.GPG(
            gnupghome=gpg_home or settings.GPG_HOME,
        )

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
        output_filepath.write_bytes(encrypted_data.data)
        logger.info("File encrypted successfully.")

    def encrypt(self, file_id: str, file_to_encrypt: str, override: bool = False):
        """Encrypts a file and stors it in the vault."""

        target_filepath = Path(file_to_encrypt)
        if not target_filepath.exists():
            typer.echo("File does not exist.")
            exit(1)

        if not target_filepath.is_file():
            typer.echo(
                "Please make sure `filename` is a normal file. Directories are not supported in the current version."
            )
            exit(1)

        output_filename = get_output_filename(file_id)
        output_filepath = settings.VAULT_DIR / output_filename
        logger.debug(f"Encryption filename {output_filename}")

        if output_filepath.exists() and not override:
            typer.echo("ID already exists. Please choose another id for your file.")
            exit(1)

        with target_filepath.open("rb") as f:
            return self.encrypt_bytes(f.read(), output_filepath)

    def decrypt_bytes(self, data: bytes):
        decrypted_data = self.gpg.decrypt(
            data,
            always_trust=True,
            passphrase=settings.PASSPHRASE,
        )
        if not decrypted_data.ok:
            raise Exception(decrypted_data.status)
        return decrypted_data

    def decrypt(self, file_id: str):
        encrypted_filename = get_output_filename(file_id)
        encrypted_filepath = settings.VAULT_DIR / encrypted_filename

        with encrypted_filepath.open("rb") as f:
            return self.decrypt_bytes(f.read())

    def open(self, file_id: str, readonly=False):
        decrypted_data = self.decrypt(file_id)

        with tempfile.NamedTemporaryFile(
            mode="rb+", delete=False, dir="/dev/shm"
        ) as tmp:
            tmp.write(decrypted_data.data)
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
            self.encrypt(file_id, tmp.name, override=True)

    def read(self, file_id: str):
        """Open encrypted file in readonly mode."""

        return self.open(file_id, readonly=True)

    def delete(self, file_id: str):
        """Delete an encrypted file from OniLock vault."""
        encrypted_filename = settings.VAULT_DIR / get_output_filename(file_id)
        encrypted_filename.unlink(missing_ok=True)

    def export(self, file_id: Optional[str] = None, filename: Optional[str] = None):
        """
        Decrypt and export a file to the specified new location.

        If file_id is not provided, export all files in the vault.
        """

        export_filenames = []

        if file_id:
            encrypted_filename = settings.VAULT_DIR / get_output_filename(file_id)

            decrypted_data = self.decrypt(file_id)
            if not filename:
                filename = f"onilock_{getlogin()}_vault_files_{naive_utcnow().strftime('%Y%m%d%H%M%s')}.oni"
            output_file = Path(filename)
            export_filenames.append((encrypted_filename, output_file))
            output_file.write_bytes(decrypted_data.data)
            return

        # Get all encrypted files in the vault.

        if filename and filename.endswith(".zip"):
            output_file = filename
        elif filename:
            output_file = f"{filename}.zip"
        else:
            output_file = f"onilock_{getlogin()}_vault_files_{naive_utcnow().strftime('%Y%m%d%H%M%s')}.zip"

        output_file = Path(output_file)

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Create a folder inside the zip file
            folder_name = "onilock_vault_files/"
            # Iterate over the binary strings and add each as a separate file in the folder
            for encrypted_filename in export_filenames:
                file_name = (
                    f"{folder_name}file_{i}.bin"  # Name each file (e.g., file_1.bin)
                )

                # Add the binary content as a file in the zip
                with zipf.open(file_name, "w") as f:
                    f.write(bin_data)
                for filename in export_filenames:
                    pass

    def clear(self):
        """Delete all encrypted files in the vault."""
        pass
