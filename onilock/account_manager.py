from datetime import datetime
import os
from typing import Optional
import base64

from cryptography.fernet import Fernet
import pyperclip
import bcrypt
import typer

from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.utils import generate_random_password
from onilock.db import DatabaseManager
from onilock.db.models import Profile, Account


__all__ = [
    "initialize",
    "new_account",
    "copy_account_password",
    "remove_account",
]


def verify_master_password(master_password: str):
    """
    Verify that the provided master password is valid.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    engine = get_profile_engine()
    data = engine.read()
    if not data:
        typer.echo(
            "This database is not initialized. Please use the `init` command to initialize it."
        )
        exit(1)

    profile = Profile(**data)
    hashed_master_password = base64.b64decode(profile.master_password)
    return bcrypt.checkpw(master_password.encode(), hashed_master_password)


def get_profile_engine():
    """Get user config engine."""

    cipher = Fernet(settings.SECRET_KEY.encode())
    db_manager = DatabaseManager(database_url=settings.SETUP_FILEPATH)
    setup_engine = db_manager.get_engine()
    setup_data = setup_engine.read()
    b64encrypted_config_filepath = setup_data[settings.DB_NAME]["filepath"]
    encrypted_filepath = base64.b64decode(b64encrypted_config_filepath)
    config_filepath = cipher.decrypt(encrypted_filepath).decode()
    return db_manager.add_engine("data", config_filepath)


def initialize(master_password: Optional[str] = None, filepath: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
        filepath (Optional[str]): The filepath where the user wants to save their accounts data.
    """
    logger.debug("Initializing database with a master password.")

    name = settings.DB_NAME

    if not filepath:
        filepath = os.path.join(
            os.path.expanduser("~"), ".onilock", "shadow", f"{name}.json"
        )

    db_manager = DatabaseManager(database_url=filepath)
    engine = db_manager.get_engine()
    setup_engine = db_manager.add_engine("setup", settings.SETUP_FILEPATH)
    data = engine.read()
    setup_data = setup_engine.read()

    if data or name in setup_data:
        typer.echo("This database is already initialized")
        exit(1)

    if not master_password:
        logger.warning(
            "Master password not provided! A random password will be generated and returned."
        )
        master_password = generate_random_password(
            length=25, include_special_characters=True
        )
        typer.echo(
            f"Generated password: {master_password}\n"
            "This is the only time this password is visible. Make sure you copy it to a safe place before proceding."
        )

    # @TODO: Verify master password strength.

    hashed_master_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
    b64_hashed_master_password = base64.b64encode(hashed_master_password).decode()

    profile = Profile(
        name=name,
        master_password=b64_hashed_master_password,
        accounts=list(),
    )
    engine.write(profile.model_dump())

    logger.info("Updating the current setup file.")

    # Encrypting filepath
    cipher = Fernet(settings.SECRET_KEY.encode())
    logger.debug("Encrypting filepath.")
    encrypted_filepath = cipher.encrypt(filepath.encode())
    b64_encrypted_filepath = base64.b64encode(encrypted_filepath).decode()

    setup_data[name] = {
        "filepath": b64_encrypted_filepath,
    }

    setup_engine.write(setup_data)

    logger.info("Initialization completed successfully.")
    return master_password


def new_account(
    name: str,
    password: Optional[str] = None,
    username: Optional[str] = None,
    url: Optional[str] = None,
    description: Optional[str] = None,
):
    """
    Register a new account.

    Args:
        name (str): An identifier used to retrieve the password (e.g. github).
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        username (Optional[str]): The account username
        url (Optional[str]): The url / service where the password is used.
        description (Optional[str]): A password description.
    """
    engine = get_profile_engine()
    data = engine.read()
    if not data:
        typer.echo(
            "This database is not initialized. Please use the `init` command to initialize it."
        )
        exit(1)

    profile = Profile(**data)

    if not password:
        logger.warning("Password not provided, generating it randomly.")
        password = generate_random_password()

    # @TODO: Verify password strength.

    cipher = Fernet(settings.SECRET_KEY.encode())
    logger.debug("Encrypting the password.")
    encrypted_password = cipher.encrypt(password.encode())
    logger.debug(f"Encrypted password: {encrypted_password.decode()}")
    b64_encrypted_password = base64.b64encode(encrypted_password).decode()
    logger.debug(f"B64 Encrypted password: {b64_encrypted_password}")
    password_model = Account(
        id=name,
        encrypted_password=b64_encrypted_password,
        username=username or "",
        url=url,
        description=description,
        created_at=int(datetime.now().timestamp()),
    )
    profile.accounts.append(password_model)
    engine.write(profile.model_dump())
    logger.info("Password saved successfully.")
    return password


def list_accounts():
    """List all available passwords."""

    engine = get_profile_engine()
    data = engine.read()
    profile = Profile(**data)

    typer.echo(f"Accounts list for {profile.name}")

    for index, pwd in enumerate(profile.accounts):
        created_date = datetime.fromtimestamp(pwd.created_at)
        typer.echo(
            f"""
=================== [{index + 1}] {pwd.id} ===================

encrypted password: {pwd.encrypted_password[:15]}***{pwd.encrypted_password[-15:]}
               url: {pwd.url}
       description: {pwd.description}
     creation date: {created_date.strftime("%Y-%m-%d %H:%M:%S")}
        """
        )


def copy_account_password(id: str | int):
    """
    Copy the password of the account with the provided ID to the clipboard.

    Args:
        id (str): The target password identifier.
    """
    engine = get_profile_engine()
    data = engine.read()
    if not data:
        typer.echo(
            "This database is not initialized. Please use the `init` command to initialize it."
        )
        exit(1)

    profile = Profile(**data)

    account = profile.get_account(id)
    if not account:
        typer.echo("Invalid account name or index", err=True, color=True)
        exit(1)

    logger.debug(f"Raw password: {account.encrypted_password}")
    logger.debug("Decrypting the password.")
    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = base64.b64decode(account.encrypted_password)
    decrypted_password = cipher.decrypt(encrypted_password).decode()
    pyperclip.copy(decrypted_password)
    logger.info(f"Password {account.id} copied to clipboard successfully.")
    typer.echo("Password copied to clipboard successfully.")

    # @TODO: Delete password from the clipboard after a short period of time (e.g. 1m).


def remove_account(name: str):
    """
    Remove a password.

    Args:
        name (str): The target account name.
    """
    engine = get_profile_engine()
    data = engine.read()
    if not data:
        typer.echo(
            "This database is not initialized. Please use the `init` command to initialize it."
        )
        exit(1)

    profile = Profile(**data)

    account = profile.get_account(name)

    if not account:
        typer.echo("Invalid account name", err=True, color=True)
        exit(1)

    profile.remove_account(name)
    engine.write(profile.model_dump())
