import os
from enum import Enum

from onilock.core.utils import get_secret_key, str_to_bool


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
            debug = str_to_bool(os.environ.get("DEBUG", "false"))
            self.DEBUG = debug
        except ValueError:
            pass

        self.SECRET_KEY = os.environ.get("SECRET_KEY", get_secret_key())
        self.DB_BACKEND = DBBackEndEnum(os.environ.get("DB_BACKEND", "Json"))
        self.DB_URL = os.environ.get("DB_URL")
        self.DB_NAME = os.environ.get("DB_NAME", os.getlogin())
        self.DB_HOST = os.environ.get("DB_HOST")
        self.DB_USER = os.environ.get("DB_USER")
        self.DB_PWD = os.environ.get("DB_PWD")

        try:
            db_port = int(os.environ.get("DB_PORT", "0"))
            self.DB_PORT = db_port
        except ValueError:
            pass

        self.SETUP_FILEPATH = os.path.join(
            os.path.expanduser("~"), ".onilock", "shadow", "setup.json"
        )


settings = Settings()
