import os
import uuid
from enum import Enum
from typing import Optional

from onilock.core.utils import get_passphrase, get_secret_key, str_to_bool


class DBBackEndEnum(Enum):
    JSON = "Json"
    SQLITE = "SQLite"  # Not implemented yet
    POSTGRES = "PostgreSQL"  # Not implemented yet


class Settings:
    """
    A settings class containing the application configuration.
    """

    def __init__(self) -> None:
        try:
            debug = str_to_bool(os.environ.get("ONI_DEBUG", "false"))
            self.DEBUG = debug
        except ValueError:
            pass

        self.SECRET_KEY = os.environ.get("ONI_SECRET_KEY", get_secret_key())
        self.DB_BACKEND = DBBackEndEnum(os.environ.get("ONI_DB_BACKEND", "Json"))
        self.DB_URL = os.environ.get("ONI_DB_URL")
        self.DB_NAME = os.environ.get("ONI_DB_NAME", os.getlogin())
        self.DB_HOST = os.environ.get("ONI_DB_HOST")
        self.DB_USER = os.environ.get("ONI_DB_USER")
        self.DB_PWD = os.environ.get("ONI_DB_PWD")

        self.PASSPHRASE: str = os.environ.get("ONI_GPG_PASSPHRASE", get_passphrase())
        self.GPG_HOME: Optional[str] = os.environ.get("ONI_GPG_HOME", None)
        self.PGP_REAL_NAME: str = os.environ.get(
            "ONI_PGP_REAL_NAME", f"{os.getlogin()}_onilock_pgp"
        )
        self.PGP_EMAIL: str = "pgp@onilock.com"
        self.CHECKSUM_SEPARATOR = "(:|?"

        try:
            db_port = int(os.environ.get("ONI_DB_PORT", "0"))
            self.DB_PORT = db_port
        except ValueError:
            pass

        filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, os.getlogin() + "_oni"))
        self.SETUP_FILEPATH = os.path.join(
            os.path.expanduser("~"),
            ".onilock",
            "vault",
            f"{filename}.oni",
        )


settings = Settings()
