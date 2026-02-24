import base64

from cryptography.fernet import Fernet

from onilock.core.exceptions import VaultConfigurationError, VaultNotInitializedError
from onilock.core.settings import settings
from onilock.db import DatabaseManager
from onilock.db.models import Profile


def get_profile_engine():
    cipher = Fernet(settings.SECRET_KEY.encode())

    setup_manager = DatabaseManager(database_url=settings.SETUP_FILEPATH, is_encrypted=True)
    setup_engine = setup_manager.get_engine()
    setup_data = setup_engine.read()

    profile_setup = setup_data.get(settings.DB_NAME)
    if profile_setup is None:
        raise VaultNotInitializedError()

    b64_encrypted_config_filepath = profile_setup.get("filepath")
    if not b64_encrypted_config_filepath:
        raise VaultConfigurationError("Vault setup is corrupted: missing profile path.")

    try:
        encrypted_filepath = base64.b64decode(b64_encrypted_config_filepath)
        config_filepath = cipher.decrypt(encrypted_filepath).decode()
    except Exception as exc:
        raise VaultConfigurationError(
            "Vault setup is corrupted: profile path could not be decrypted."
        ) from exc

    profile_manager = DatabaseManager(database_url=config_filepath, is_encrypted=True)
    return profile_manager.get_engine()


def load_profile() -> tuple[object, Profile]:
    engine = get_profile_engine()
    data = engine.read()
    if not data:
        raise VaultNotInitializedError()
    return engine, Profile(**data)


def save_profile(engine: object, profile: Profile) -> None:
    engine.write(profile.model_dump())
