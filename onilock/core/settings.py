import os
import uuid
from typing import Optional
from pathlib import Path

from dotenv import load_dotenv

from onilock.core.constants import DEBUG_ENV_NAME
from onilock.core.enums import DBBackEndEnum, KeyStoreBackendEnum


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

        # OniLock vault directory
        vault_dir = os.path.join(Path.home(), ".onilock", "vault")

        # Load environment variables if .env file is found.
        env_filenames = [
            # Order matters. envs in the bottom override envs in the top of the list.
            os.path.join(vault_dir, ".env"),
            ".env",
        ]
        for filename in env_filenames:
            if os.path.exists(filename):
                load_dotenv(filename)

        try:
            debug = str_to_bool(os.environ.get(DEBUG_ENV_NAME, "false"))
            self.DEBUG = debug
        except ValueError:
            self.DEBUG = False

        self.SECRET_KEY = os.environ.get("ONI_SECRET_KEY", get_secret_key())
        self.DB_BACKEND = DBBackEndEnum(os.environ.get("ONI_DB_BACKEND", "Json"))
        self.DB_URL = os.environ.get("ONI_DB_URL")
        self.DB_NAME = os.environ.get("ONI_DB_NAME", getlogin())
        self.DB_HOST = os.environ.get("ONI_DB_HOST")
        self.DB_USER = os.environ.get("ONI_DB_USER")
        self.DB_PWD = os.environ.get("ONI_DB_PWD")

        self.PASSPHRASE: str = os.environ.get("ONI_GPG_PASSPHRASE", get_passphrase())
        self.GPG_HOME: Optional[str] = os.environ.get("ONI_GPG_HOME", None)
        self.PGP_REAL_NAME: str = os.environ.get(
            "ONI_PGP_REAL_NAME", f"{getlogin()}_onilock_pgp"
        )
        self.PGP_EMAIL: str = "pgp@onilock.com"
        self.CHECKSUM_SEPARATOR = "(:|?"

        try:
            db_port = int(os.environ.get("ONI_DB_PORT", "0"))
            self.DB_PORT = db_port
        except ValueError:
            pass

        filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, getlogin() + "_oni")).split("-")[
            -1
        ]
        self.SETUP_FILEPATH = os.path.join(
            vault_dir,
            f"{filename}.oni",
        )


settings = Settings()
