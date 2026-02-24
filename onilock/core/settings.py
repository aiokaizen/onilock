import os
import uuid
from typing import Optional
from pathlib import Path

from onilock.core.constants import DEBUG_ENV_NAME
from onilock.core.enums import DBBackEndEnum


class Settings:
    """
    A settings class containing the application configuration.
    """

    def __init__(self) -> None:
        # Importing inside the function in order to prevent circular imports.
        from onilock.core.utils import (
            get_passphrase,
            get_secret_key,
            getlogin,
            str_to_bool,
        )

        def find_project_root() -> Optional[Path]:
            path = Path(__file__).resolve()
            if "site-packages" in path.parts or "dist-packages" in path.parts:
                return None
            for parent in path.parents:
                if (parent / "pyproject.toml").exists():
                    return parent
            return None

        project_root = find_project_root()
        is_dev_source = project_root is not None
        self.IS_DEV_SOURCE = is_dev_source

        # OniLock vault directory
        default_vault_dir = (
            project_root / ".onilock_dev" / "vault"
            if is_dev_source
            else Path.home() / ".onilock" / "vault"
        )
        env_vault_dir = os.environ.get("ONI_VAULT_DIR")
        self.VAULT_DIR = Path(env_vault_dir or str(default_vault_dir))
        try:
            self.VAULT_DIR.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            if is_dev_source:
                self.VAULT_DIR = Path(project_root / ".onilock_dev" / "vault")
                self.VAULT_DIR.mkdir(parents=True, exist_ok=True)
            else:
                raise

        self.BASE_DIR = self.VAULT_DIR.parent
        self.PROFILE_PATH = self.BASE_DIR / ".profile"
        self.AUDIT_LOG = self.BASE_DIR / "audit.log"
        self.BACKUP_DIR = self.BASE_DIR / "backups"

        self.DEBUG = False
        try:
            debug = str_to_bool(os.environ.get(DEBUG_ENV_NAME, "false"))
            self.DEBUG = debug
        except ValueError:
            pass

        self.SECRET_KEY = os.environ.get("ONI_SECRET_KEY", get_secret_key())
        self.DB_BACKEND = DBBackEndEnum(os.environ.get("ONI_DB_BACKEND", "Json"))
        self.DB_URL = os.environ.get("ONI_DB_URL")
        default_db_name = f"{getlogin()}_dev" if is_dev_source else getlogin()
        profile_name = None
        if not os.environ.get("ONI_DB_NAME") and self.PROFILE_PATH.exists():
            try:
                profile_name = self.PROFILE_PATH.read_text().strip() or None
            except OSError:
                profile_name = None
        self.DB_NAME = os.environ.get("ONI_DB_NAME", profile_name or default_db_name)
        self.DB_HOST = os.environ.get("ONI_DB_HOST")
        self.DB_USER = os.environ.get("ONI_DB_USER")
        self.DB_PWD = os.environ.get("ONI_DB_PWD")

        self.PASSPHRASE: str = os.environ.get("ONI_GPG_PASSPHRASE", get_passphrase())
        default_gpg_home = (
            str(project_root / ".onilock_dev" / ".gnupg")
            if is_dev_source
            else None
        )
        env_gpg_home = os.environ.get("ONI_GPG_HOME")
        if env_gpg_home and is_dev_source:
            try:
                os.makedirs(env_gpg_home, exist_ok=True)
                os.chmod(env_gpg_home, 0o700)
                if not os.access(env_gpg_home, os.W_OK):
                    env_gpg_home = None
            except PermissionError:
                env_gpg_home = None

        self.GPG_HOME: Optional[str] = env_gpg_home or default_gpg_home
        default_pgp_name = (
            f"{self.DB_NAME}_pgp" if is_dev_source else f"{getlogin()}_onilock_pgp"
        )
        self.PGP_REAL_NAME: str = os.environ.get(
            "ONI_PGP_REAL_NAME", default_pgp_name
        )
        self.PGP_EMAIL: str = "pgp@onilock.com"
        self.CHECKSUM_SEPARATOR = "(:|?"
        self.BCRYPT_ROUNDS = int(os.environ.get("ONI_BCRYPT_ROUNDS", "12"))
        self.LOCKOUT_ATTEMPTS = int(os.environ.get("ONI_LOCKOUT_ATTEMPTS", "5"))
        self.LOCKOUT_WINDOW_SEC = int(
            os.environ.get("ONI_LOCKOUT_WINDOW_SEC", "300")
        )
        self.LOCKOUT_DURATION_SEC = int(
            os.environ.get("ONI_LOCKOUT_DURATION_SEC", "300")
        )
        self.RATE_LIMIT_BASE_DELAY = float(
            os.environ.get("ONI_RATE_LIMIT_BASE_DELAY", "0.5")
        )
        self.RATE_LIMIT_MAX_DELAY = float(
            os.environ.get("ONI_RATE_LIMIT_MAX_DELAY", "2.0")
        )
        self.CLIPBOARD_ENABLED = os.environ.get("ONI_CLIPBOARD", "true").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

        try:
            db_port = int(os.environ.get("ONI_DB_PORT", "0"))
            self.DB_PORT = db_port
        except ValueError:
            pass

        filename = str(
            uuid.uuid5(uuid.NAMESPACE_DNS, self.DB_NAME + "_oni")
        ).split("-")[
            -1
        ]
        self.SETUP_FILEPATH = os.path.join(
            self.VAULT_DIR,
            f"{filename}.oni",
        )


settings = Settings()
