from datetime import datetime
import os
import secrets
import random
import string
from typing import Optional
import base64

from cryptography.fernet import Fernet
import pyperclip
import bcrypt

from core.settings import settings
from core.logging_manager import logger
from db import DatabaseManager
from db.models import Account, Password


__all__ = [
    "initialize",
    "save_password",
    "copy_password",
    "generate_random_password",
]


def generate_random_password(
    length: int = 12, include_special_characters: bool = True
) -> str:
    """
    Generate a random password.

    Args:
        length (int): The length of the generated password
        include_special_characters (bool): If False, the password will only contain alpha-numeric characters.

    Returns:
        str : The generated password
    """
    logger.debug("Generating random password.")
    characters = string.ascii_letters + string.digits
    punctuation = "@$!%*?&_}{()-=+"
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if include_special_characters:
        password.append(secrets.choice(punctuation))
        characters += punctuation

    password += [secrets.choice(characters) for _ in range(length)]

    # Shuffle password in-place.
    random.shuffle(password)

    return "".join(password)


def verify_master_password(master_password: str):
    """
    Verify that the provided master password is valid.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    engine = get_account_engine()
    data = engine.read()
    if not data:
        raise Exception("This database is not initialized.")

    account = Account(**data)
    hashed_master_password = base64.b64decode(account.master_password)
    return bcrypt.checkpw(master_password.encode(), hashed_master_password)


def get_account_engine():
    """Get user config engine."""

    db_manager = DatabaseManager(database_url=settings.SETUP_FILEPATH)
    setup_engine = db_manager.get_engine()
    setup_data = setup_engine.read()
    b64encrypted_config_filepath = setup_data[settings.DB_NAME]["filepath"]
    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_filepath = base64.b64decode(b64encrypted_config_filepath)
    config_filepath = cipher.decrypt(encrypted_filepath).decode()

    return db_manager.add_engine("data", config_filepath)


def initialize(master_password: Optional[str] = None, filepath: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        name (Optional[str]): The account name, if ommitted, it will be taken from env.
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """
    logger.debug("Initializing database with a master password.")

    name = settings.DB_NAME

    if not filepath:
        filepath = os.path.join(
            os.path.expanduser("~"), ".passman", "shadow", f"{name}.json"
        )

    db_manager = DatabaseManager(database_url=filepath)
    engine = db_manager.get_engine()
    setup_engine = db_manager.add_engine("setup", settings.SETUP_FILEPATH)
    data = engine.read()
    setup_data = setup_engine.read()

    if data or name in setup_data:
        raise Exception("Database already initialized.")

    if not master_password:
        logger.warning(
            "Master password not provided! A random password will be generated and returned."
        )
        master_password = generate_random_password(
            length=25, include_special_characters=True
        )
        print(
            f"Generated password: {master_password}\n"
            "This is the only time this password is visible. Make sure you copy it to a safe place before proceding."
        )

    # @TODO: Verify master password strength.

    hashed_master_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
    b64_hashed_master_password = base64.b64encode(hashed_master_password).decode()

    account = Account(
        name=name,
        master_password=b64_hashed_master_password,
        passwords=list(),
    )
    engine.write(account.model_dump())

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


def save_password(
    id: str,
    password: Optional[str] = None,
    username: Optional[str] = None,
    url: Optional[str] = None,
    description: Optional[str] = None,
):
    """
    Encrypt and save a password.

    Args:
        id (str): An identifier used to retrieve the password.
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        username (Optional[str]): The account username
        url (Optional[str]): The url / service where the password is used.
        description (Optional[str]): A password description.
    """
    engine = get_account_engine()
    data = engine.read()
    if not data:
        raise Exception("This database is not initialized.")

    account = Account(**data)

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
    password_model = Password(
        id=id,
        encrypted_password=b64_encrypted_password,
        username=username or "",
        url=url,
        description=description,
        created_at=int(datetime.now().timestamp()),
    )
    account.passwords.append(password_model)
    engine.write(account.model_dump())
    logger.info("Password saved successfully.")
    return password


def list_passwords():
    """List all available passwords."""

    engine = get_account_engine()
    data = engine.read()
    account = Account(**data)

    print(f"Passwords list for {account.name}")

    for index, pwd in enumerate(account.passwords):
        created_date = datetime.fromtimestamp(pwd.created_at)
        print(
            f"""
=================== [{index + 1}] {pwd.id} ===================

encrypted password: {pwd.encrypted_password[:15]}***{pwd.encrypted_password[-15:]}
               url: {pwd.url}
       description: {pwd.description}
     creation date: {created_date.strftime("%Y-%m-%d %H:%M:%S")}
        """
        )


def copy_password(id: str | int):
    """
    Copy the password with the provided ID to the clipboard.

    Args:
        id (str): The target password identifier.
    """
    engine = get_account_engine()
    data = engine.read()
    if not data:
        raise Exception("This database is not initialized.")

    account = Account(**data)

    password = account.get_password(id)
    if not password:
        raise Exception("Password not found.")

    logger.debug(f"Raw password: {password.encrypted_password}")
    logger.debug("Decrypting the password.")
    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = base64.b64decode(password.encrypted_password)
    decrypted_password = cipher.decrypt(encrypted_password).decode()
    pyperclip.copy(decrypted_password)
    logger.info(f"Password {password.id} copied to clipboard successfully.")
    print("Password copied to clipboard successfully.")


def remove_password(id: str, master_password: str):
    """
    Remove a password.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    engine = get_account_engine()
    data = engine.read()
    if not data:
        raise Exception("This database is not initialized.")

    account = Account(**data)

    password_verified = verify_master_password(master_password)

    if not password_verified:
        raise Exception("Incorrect master password.")

    password = account.get_password(id)

    if not password:
        raise Exception("Password ID does not exist.")

    account.remove_password(id)
    engine.write(account.model_dump())
