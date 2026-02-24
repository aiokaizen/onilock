from pathlib import Path
import shutil
import os
from typing import Optional
import base64

import bcrypt
import typer

from onilock.core.decorators import pre_post_hooks
from onilock.core.keystore import keystore
from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.exceptions import (
    VaultAlreadyInitializedError,
    VaultAuthenticationError,
)
from onilock.core.gpg import (
    delete_pgp_key,
)
from onilock.core.utils import (
    get_passphrase,
    generate_random_password,
)
from onilock.db import DatabaseManager
from onilock.db.models import Profile
from onilock.profile_store import (
    get_profile_engine as _get_profile_engine,
    load_profile,
)
from onilock.secret_manager import secret_manager


__all__ = [
    "initialize",
    "new_account",
    "show_account",
    "search_accounts",
    "update_account",
    "rename_account",
    "copy_account_password",
    "remove_account",
    "delete_profile",
]


def pre_command():
    logger.debug("Starting pre-command hook.")
    # migrate_vault(profile.vault_version, Profile.vault_version)
    # version = get_version()


def post_command():
    logger.debug("Starting post-command hook.")


def verify_master_password(master_password: str):
    """
    Verify that the provided master password is valid.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    _, profile = load_profile()
    hashed_master_password = base64.b64decode(profile.master_password)
    return bcrypt.checkpw(master_password.encode(), hashed_master_password)


def get_profile_engine():
    """Backward-compatible import path for profile engine access."""
    return _get_profile_engine()


@pre_post_hooks(pre_command, post_command)
def initialize(master_password: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """
    logger.debug("Initializing database with a master password.")

    name = settings.DB_NAME

    filename = generate_random_password(12, include_special_characters=False) + ".oni"
    filepath = os.path.join(Path.home(), ".onilock", "vault", filename)

    db_manager = DatabaseManager(database_url=filepath, is_encrypted=True)
    engine = db_manager.get_engine()
    setup_manager = DatabaseManager(
        database_url=settings.SETUP_FILEPATH, is_encrypted=True
    )
    setup_engine = setup_manager.get_engine()
    data = engine.read()
    setup_data = setup_engine.read()

    if data or name in setup_data:
        raise VaultAlreadyInitializedError()

    if not master_password:
        logger.info(
            "Master password not provided! A random password will be generated and displayed."
        )
        master_password = generate_random_password(
            length=25, include_special_characters=True
        )
        typer.echo(
            f"\nGenerated password: {master_password}\n"
            "This is the only time this password is visible. Make sure you copy it to a safe place before proceding.\n"
        )
    else:
        # @TODO: Verify master password strength.
        pass

    hashed_master_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
    b64_hashed_master_password = base64.b64encode(hashed_master_password).decode()

    profile = Profile(
        name=name,
        master_password=b64_hashed_master_password,
        accounts=list(),
        files=[],
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


@pre_post_hooks(pre_command, post_command)
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
    return secret_manager.create(
        name=name,
        password=password,
        username=username,
        url=url,
        description=description,
    )


@pre_post_hooks(pre_command, post_command)
def list_accounts():
    """List all available accounts."""
    accounts = secret_manager.list_all()
    if not accounts:
        typer.echo("No secrets found. Use `onilock new` or `onilock secrets create`.")
        return

    typer.echo("Stored secrets")
    typer.echo("Idx  Name                 Username             URL")
    typer.echo("---  -------------------  -------------------  ------------------------------")
    for index, account in enumerate(accounts, start=1):
        url = account.url or "-"
        username = account.username or "-"
        typer.echo(f"{index:>3}  {account.id[:19]:<19}  {username[:19]:<19}  {url[:30]}")


@pre_post_hooks(pre_command, post_command)
def list_files():
    """List all available files."""

    engine = get_profile_engine()
    data = engine.read()
    if not data:
        raise VaultNotInitializedError()
    profile = Profile(**data)

    typer.echo(f"Files list for {profile.name}")

    for file in profile.files:
        created_date = datetime.fromtimestamp(file.created_at)
        typer.echo(
            f"""
=================== {file.id} ===================

       source file: {Path(file.src).name}
              UUID: {Path(file.location).stem}
             owner: {file.user}
              host: {file.host}
     creation date: {created_date.strftime("%Y-%m-%d %H:%M:%S")}
            """
        )


@pre_post_hooks(pre_command, post_command)
def copy_account_password(id: str | int):
    """
    Copy the password of the account with the provided ID to the clipboard.

    Args:
        id (str): The target password identifier.
    """
    secret_id = secret_manager.copy(id, clear_after=10)
    logger.info(f"Password {secret_id} copied to clipboard successfully.")
    typer.echo("Password copied to clipboard successfully.")
    logger.debug("Password will be cleared in 10 seconds.")


@pre_post_hooks(pre_command, post_command)
def show_account(id: str | int, reveal_password: bool = False):
    """Show account metadata and optionally reveal the password."""
    return secret_manager.show(id, reveal_password=reveal_password)


@pre_post_hooks(pre_command, post_command)
def search_accounts(query: str, field: str = "all", limit: int = 20):
    """Search accounts by query and field."""
    return secret_manager.search(query, field=field, limit=limit)


@pre_post_hooks(pre_command, post_command)
def update_account(
    id: str | int,
    *,
    name: Optional[str] = None,
    password: Optional[str] = None,
    generate_password: bool = False,
    username: Optional[str] = None,
    url: Optional[str] = None,
    description: Optional[str] = None,
):
    """Update account fields."""
    return secret_manager.update(
        id,
        name=name,
        password=password,
        generate_password=generate_password,
        username=username,
        url=url,
        description=description,
    )


@pre_post_hooks(pre_command, post_command)
def rename_account(id: str | int, new_name: str):
    """Rename an account."""
    return secret_manager.rename(id, new_name)


@pre_post_hooks(pre_command, post_command)
def remove_account(name: str | int):
    """
    Remove a password.

    Args:
        name (str | int): The target account identifier.
    """
    return secret_manager.delete(name)


@pre_post_hooks(pre_command, post_command)
def delete_profile(master_password: str):
    """
    Delete all profile data.

    Args:
        master_password (str): Profile master password.
    """
    master_password_match = verify_master_password(master_password)
    if not master_password_match:
        raise VaultAuthenticationError()

    # Get passphrase before deleting the keyring
    passphrase = get_passphrase()

    # Delete keyrings
    keystore.clear()

    # Delete PGP key
    try:
        delete_pgp_key(
            passphrase=passphrase,
            gpg_home=settings.GPG_HOME,
            real_name=settings.PGP_REAL_NAME,
        )
    except Exception as exc:
        logger.warning(f"Failed to delete PGP key: {exc}")

    shutil.rmtree(settings.VAULT_DIR, ignore_errors=True)
