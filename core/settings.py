import os
from enum import Enum
from typing import Optional
from pydantic.fields import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_base_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DBBackEndEnum(Enum):
    JSON = "Json"
    SQLITE = "SQLite"
    POSTGRES = "PostgreSQL"


class Settings(BaseSettings):
    """
    A settings class containing the application configuration.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # env_prefix="PM_",  # Prefix for env variables identification.
        extra="ignore",  # Default: "forbid"
    )

    DEBUG: bool
    SECRET_KEY: str = Field(description="Project Secret Key")
    DB_BACKEND: DBBackEndEnum = DBBackEndEnum.JSON
    DB_URL: Optional[str] = None
    DB_NAME: Optional[str] = None
    DB_HOST: Optional[str] = None
    DB_USER: Optional[str] = None
    DB_PWD: Optional[str] = None
    DB_PORT: int = 0
    BASE_DIR: str = get_base_dir()


settings = Settings()
