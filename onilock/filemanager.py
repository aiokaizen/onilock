import os
import socket
import zipfile
from typing import Optional
from pathlib import Path
import uuid
import subprocess
import tempfile

import gnupg

from onilock.account_manager import get_profile_engine
from onilock.core.constants import SECRET_FILENAME_PREFIX
from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.audit import audit
from onilock.core.ui import success, error
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
        home = gpg_home or settings.GPG_HOME
        if home and gpg_home is None:
            try:
                os.makedirs(home, exist_ok=True)
                os.chmod(home, 0o700)
            except PermissionError:
                if settings.IS_DEV_SOURCE:
                    home = str(Path(settings.VAULT_DIR).parent / ".gnupg")
                    os.makedirs(home, exist_ok=True)
                    os.chmod(home, 0o700)
                else:
                    raise

            if settings.IS_DEV_SOURCE and not os.access(home, os.W_OK):
                home = str(Path(settings.VAULT_DIR).parent / ".gnupg")
                os.makedirs(home, exist_ok=True)
                os.chmod(home, 0o700)
        self.gpg = gnupg.GPG(gnupghome=home)
        self._engine = None
        self._profile = None

    @property
    def profile(self) -> Profile:
        if self._profile:
            return self._profile

        data = self.engine.read()
        if not data:
            error(
                "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
            )
            exit(1)

        profile = Profile(**data)
        self._profile = profile
        return profile

    @property
    def engine(self) -> Engine:
        if self._engine:
            return self._engine

        engine = get_profile_engine()
        if not engine:
            error(
                "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
            )
            exit(1)
        self._engine = engine
        return engine

    def encrypt_bytes(self, data: bytes, output_filename: Path | str):
        """Encrypts a file and stores it in the vault."""

        output_filepath: Path = (
            output_filename
            if isinstance(output_filename, Path)
            else Path(output_filename)
        )
        output_filepath.parent.mkdir(parents=True, exist_ok=True)

        encrypted_data = self.gpg.encrypt(
            data,
            recipients=[settings.PGP_REAL_NAME],
            always_trust=True,
            armor=False,
        )
        if not encrypted_data.ok:
            raise RuntimeError(f"Encryption failed: {encrypted_data.status}")
        output_filepath.write_bytes(encrypted_data.data)
        logger.info("File encrypted successfully.")

    def encrypt(
        self,
        file_id: str,
        file_to_encrypt: str,
        override: bool = False,
        update_db: bool = True,
    ):
        """Encrypts a file and stores it in the vault."""

        target_filepath = Path(file_to_encrypt)

        if not target_filepath.exists():
            error(f"File not found: [bold]{file_to_encrypt}[/bold]")
            exit(1)

        if not target_filepath.is_file():
            error(
                "Directories are not supported. Please provide a path to a regular file."
            )
            exit(1)

        if update_db:
            _ = self.profile

        output_filename = get_output_filename(file_id)
        output_filepath = settings.VAULT_DIR / output_filename
        logger.debug(f"Encryption filename {output_filename}")

        if output_filepath.exists() and not override:
            error(
                f"ID [bold]{file_id}[/bold] already exists. Choose a different ID."
            )
            exit(1)

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
                success(f"[bold]{file_id}[/bold] encrypted and stored in vault.")
                audit("file.encrypted", file_id=file_id, src=src_file_abs_path)
            return encrypted_data

    def decrypt_bytes(self, data: bytes) -> bytes:
        decrypted_data = self.gpg.decrypt(
            data,
            always_trust=True,
            passphrase=settings.PASSPHRASE,
        )
        if not decrypted_data.ok:
            raise Exception(decrypted_data.status)
        return decrypted_data.data

    def decrypt(self, file_id: str):
        encrypted_filename = get_output_filename(file_id)
        encrypted_filepath = settings.VAULT_DIR / encrypted_filename

        with encrypted_filepath.open("rb") as f:
            data = self.decrypt_bytes(f.read())
            return data

    def open(self, file_id: str, readonly=False):
        if not self.profile.get_file(file_id):
            error(
                f"File [bold]{file_id}[/bold] not found. "
                "Run [bold]onilock list-files[/bold] to see available files."
            )
            exit(1)

        decrypted_data = self.decrypt(file_id)

        readonly_args = ["-R", "-m"] if readonly else []

        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="rb+", delete=False, dir="/dev/shm"
            )
        except (PermissionError, FileNotFoundError):
            tmp = tempfile.NamedTemporaryFile(mode="rb+", delete=False)

        with tmp:
            tmp.write(decrypted_data)
            tmp.flush()
            tmp_path = tmp.name

        try:
            subprocess.run(["vim", "-n", *readonly_args, tmp_path])
            if not readonly:
                self.encrypt(file_id, tmp_path, override=True, update_db=False)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

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
            success(f"[bold]{file_id}[/bold] removed from vault.")
            audit("file.deleted", file_id=file_id)

    def export(self, file_id: Optional[str] = None, file_path: Optional[str] = None):
        """
        Decrypt and export a file to the specified new location.

        If file_id is not provided, export all files in the vault.
        """

        if file_id and not self.profile.get_file(file_id):
            error(
                f"File [bold]{file_id}[/bold] not found. "
                "Run [bold]onilock list-files[/bold] to see available files."
            )
            exit(1)

        is_dir = file_path and os.path.isdir(file_path)
        default_filename: str = (
            f"onilock_{getlogin()}_vault_{naive_utcnow().strftime('%Y%m%d%H%M%S')}.oni"
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
            success(f"Exported to [bold]{output_file}[/bold]")
            return

        default_output_filename = Path(
            f"onilock_{getlogin()}_vault_{naive_utcnow().strftime('%Y%m%d%H%M%S')}.zip"
        )
        if not file_path:
            output_file = default_output_filename
        elif is_dir:
            output_file = Path(file_path) / default_output_filename
        else:
            output_file = Path(file_path)

        with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            folder_name = Path("onilock_vault/")
            for file in self.profile.files:
                bin_data = self.decrypt(file.id)
                filename = str(folder_name / Path(file.src).name)
                with zipf.open(filename, "w") as f:
                    f.write(bin_data)

        success(f"All files exported to [bold]{output_file}[/bold]")
        audit("files.exported", output=str(output_file))

    def clear(self):
        """Delete all encrypted files in the vault."""
        pass
