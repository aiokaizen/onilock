from datetime import datetime
from pathlib import Path
import shutil
import uuid
import multiprocessing
import os
from typing import Optional
import base64

from cryptography.fernet import Fernet
import pyperclip
import bcrypt

from rich.table import Table

from onilock.core.decorators import pre_post_hooks
from onilock.core.keystore import keystore
from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.ui import console, success, error, warning, info
from onilock.core.gpg import (
    delete_pgp_key,
)
from onilock.core.utils import (
    clear_clipboard_after_delay,
    generate_random_password,
    get_passphrase,
    getlogin,
    get_version,
    is_password_strong,
    naive_utcnow,
)
from onilock.db import DatabaseManager
from onilock.db.models import Profile, Account


__all__ = [
    "initialize",
    "new_account",
    "copy_account_password",
    "remove_account",
    "delete_profile",
]


def pre_command():
    logger.debug("Starting pre-command hook.")


def post_command():
    logger.debug("Starting post-command hook.")


def verify_master_password(master_password: str):
    """
    Verify that the provided master password is valid.

    Args:
        master_password (str): The master password.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    hashed_master_password = base64.b64decode(profile.master_password)
    return bcrypt.checkpw(master_password.encode(), hashed_master_password)


def _load_setup_data(setup_engine):
    try:
        return setup_engine.read()
    except RuntimeError as exc:
        message = str(exc)
        if "no secret key" in message:
            error(
                "Unable to decrypt the setup data. The required GPG secret key is missing."
            )
            info(
                "If this is a local dev environment, set [bold]ONI_DB_NAME[/bold] and "
                "[bold]ONI_GPG_HOME[/bold], then run [bold]onilock initialize-vault[/bold]."
            )
            return None
        raise


def get_profile_engine():
    """Get user config engine."""

    cipher = Fernet(settings.SECRET_KEY.encode())
    db_manager = DatabaseManager(
        database_url=settings.SETUP_FILEPATH, is_encrypted=True
    )
    setup_engine = db_manager.get_engine()
    setup_data = _load_setup_data(setup_engine)
    if not setup_data or settings.DB_NAME not in setup_data:
        return None
    b64encrypted_config_filepath = setup_data[settings.DB_NAME]["filepath"]
    encrypted_filepath = base64.b64decode(b64encrypted_config_filepath)
    config_filepath = cipher.decrypt(encrypted_filepath).decode()
    return db_manager.add_engine("data", config_filepath, is_encrypted=True)


@pre_post_hooks(pre_command, post_command)
def initialize(master_password: Optional[str] = None):
    """
    Initialize the password manager with a master password.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """
    logger.debug("Initializing database with a master password.")

    name = settings.DB_NAME

    filename = generate_random_password(12, include_special_characters=False) + ".oni"
    filepath = str(settings.VAULT_DIR / filename)

    db_manager = DatabaseManager(database_url=filepath, is_encrypted=True)
    engine = db_manager.get_engine()
    setup_engine = db_manager.add_engine(
        "setup", settings.SETUP_FILEPATH, is_encrypted=True
    )
    data = engine.read()
    setup_data = setup_engine.read()

    if data or name in setup_data:
        error("This vault is already initialized.")
        exit(1)

    if not master_password:
        logger.info(
            "Master password not provided! A random password will be generated and displayed."
        )
        master_password = generate_random_password(
            length=25, include_special_characters=True
        )
        warning(
            f"Generated master password: [bold]{master_password}[/bold]\n"
            "  This is the [bold]only time[/bold] this password will be shown. "
            "Store it somewhere safe before continuing."
        )
    else:
        pass

    hashed_master_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
    b64_hashed_master_password = base64.b64encode(hashed_master_password).decode()

    profile = Profile(
        name=name,
        master_password=b64_hashed_master_password,
        vault_version=get_version(),
        accounts=list(),
        files=[],
    )
    engine.write(profile.model_dump())

    logger.info("Updating the current setup file.")

    cipher = Fernet(settings.SECRET_KEY.encode())
    logger.debug("Encrypting filepath.")
    encrypted_filepath = cipher.encrypt(filepath.encode())
    b64_encrypted_filepath = base64.b64encode(encrypted_filepath).decode()

    setup_data[name] = {
        "filepath": b64_encrypted_filepath,
    }

    setup_engine.write(setup_data)

    logger.info("Initialization completed successfully.")
    success("Vault initialized successfully.")
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
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)

    if not password:
        logger.warning("Password not provided, generating it randomly.")
        password = generate_random_password()

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
        is_weak_password=not is_password_strong(password),
        created_at=int(naive_utcnow().timestamp()),
    )
    profile.accounts.append(password_model)
    engine.write(profile.model_dump())
    logger.info("Password saved successfully.")
    success(f"Account [bold]{name}[/bold] added to the vault.")
    return password


@pre_post_hooks(pre_command, post_command)
def list_accounts():
    """List all available accounts."""

    engine = get_profile_engine()
    if not engine:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    data = engine.read()
    if not data:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    profile = Profile(**data)

    if not profile.accounts:
        info(
            f"No accounts found in [bold]{profile.name}[/bold]. "
            "Use [bold]onilock new[/bold] to add one."
        )
        return

    table = Table(title=f"Accounts — {profile.name}", show_lines=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Name", style="bold cyan")
    table.add_column("Username", style="green")
    table.add_column("URL", style="blue")
    table.add_column("Created", style="dim")

    for index, account in enumerate(profile.accounts):
        created_date = datetime.fromtimestamp(account.created_at).strftime("%Y-%m-%d")
        table.add_row(
            str(index + 1),
            account.id,
            account.username or "—",
            account.url or "—",
            created_date,
        )

    console.print(table)


@pre_post_hooks(pre_command, post_command)
def list_files():
    """List all available files."""

    engine = get_profile_engine()
    if not engine:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    data = engine.read()
    if not data:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    profile = Profile(**data)

    if not profile.files:
        info(
            f"No files found in [bold]{profile.name}[/bold]. "
            "Use [bold]onilock encrypt-file[/bold] to add one."
        )
        return

    table = Table(title=f"Encrypted Files — {profile.name}", show_lines=True)
    table.add_column("ID", style="bold cyan")
    table.add_column("Source File", style="green")
    table.add_column("Owner", style="dim")
    table.add_column("Host", style="dim")
    table.add_column("Created", style="dim")

    for file in profile.files:
        created_date = datetime.fromtimestamp(file.created_at).strftime("%Y-%m-%d")
        table.add_row(
            file.id,
            Path(file.src).name,
            file.user,
            file.host,
            created_date,
        )

    console.print(table)


@pre_post_hooks(pre_command, post_command)
def copy_account_password(id: str | int):
    """
    Copy the password of the account with the provided ID to the clipboard.

    Args:
        id (str | int): The target password identifier or 0-based index.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)

    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    logger.debug(f"Raw password: {account.encrypted_password}")
    logger.debug("Decrypting the password.")
    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = base64.b64decode(account.encrypted_password)
    decrypted_password = cipher.decrypt(encrypted_password).decode()
    pyperclip.copy(decrypted_password)
    logger.info(f"Password {account.id} copied to clipboard successfully.")
    success(
        f"Password for [bold]{account.id}[/bold] copied to clipboard. "
        "Clears automatically in [bold]10s[/bold]."
    )

    logger.debug("Password will be cleared in 10 seconds.")

    process = multiprocessing.Process(
        target=clear_clipboard_after_delay,
        args=(decrypted_password, 10),
    )
    process.start()

    os._exit(0)


@pre_post_hooks(pre_command, post_command)
def remove_account(name: str):
    """
    Remove a password.

    Args:
        name (str): The target account name.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)

    account = profile.get_account(name)

    if not account:
        error(
            f"Account [bold]{name}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    profile.remove_account(name)
    engine.write(profile.model_dump())
    success(f"Account [bold]{name}[/bold] removed.")


@pre_post_hooks(pre_command, post_command)
def delete_profile(master_password: str):
    """
    Delete all profile data.

    Args:
        master_password (str): Profile master password.
    """
    master_password_match = verify_master_password(master_password)
    if not master_password_match:
        error("Invalid master password.")
        exit(1)

    passphrase = get_passphrase()

    keystore.clear()

    delete_pgp_key(
        passphrase=passphrase,
        gpg_home=settings.GPG_HOME,
        real_name=settings.PGP_REAL_NAME,
    )

    shutil.rmtree(settings.VAULT_DIR)
    success("All user data has been permanently deleted.")
