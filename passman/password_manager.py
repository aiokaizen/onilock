import secrets
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


db_manager = DatabaseManager(database_url=settings.DB_URL)


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
    if include_special_characters:
        characters += string.punctuation
    return "".join(secrets.choice(characters) for _ in range(length))


def initialize(name: str, master_password: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        name (str): The account name.
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """
    logger.debug("Initializing database with a master password.")

    engine = db_manager.get_engine()
    data = engine.read()

    if data:
        raise Exception(f"Database already initialized.")

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
    # engine.write(account.to_dict())
    engine.write(account.model_dump())
    logger.info("Initialization completed successfully.")
    return master_password


def save_password(id: str, password: Optional[str] = None, url: Optional[str] = None):
    """
    Encrypt and save a password.

    Args:
        id (str): An identifier used to retrieve the password.
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        url (Optional[str]): The url / service where the password is used.
    """
    engine = db_manager.get_engine()
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
    b64_encrypted_password = base64.b64encode(encrypted_password).decode()
    logger.debug(f"Encrypted password: {encrypted_password.decode()}")
    logger.debug(f"B64 Encrypted password: {b64_encrypted_password}")
    password_model = Password(
        id=id,
        encrypted_password=b64_encrypted_password,
        url=url,
    )
    account.passwords.append(password_model)
    engine.write(account.model_dump())
    logger.info("Password saved successfully.")
    return password


def copy_password(id: str):
    """
    Copy the password with the provided ID to the clipboard.

    Args:
        id (str): The target password identifier.
    """
    engine = db_manager.get_engine()
    data = engine.read()
    if not data:
        raise Exception("This database is not initialized.")

    account = Account(**data)

    cipher = Fernet(settings.SECRET_KEY.encode())
    password = account.get_password(id)
    if not password:
        raise Exception("Password not found.")

    logger.debug(f"Raw password: {password.encrypted_password}")
    logger.debug("Decrypting the password.")
    encrypted_password = base64.b64decode(password.encrypted_password)
    decrypted_password = cipher.decrypt(encrypted_password).decode()
    logger.debug(f"Decrypted password: {decrypted_password}")
    pyperclip.copy(decrypted_password)


def verify_master_password(master_password: str):
    """
    Verify that the provided master password is valid.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    engine = db_manager.get_engine()
    data = engine.read()
    if not data:
        raise Exception("This database is not initialized.")

    account = Account(**data)
    hashed_master_password = base64.b64decode(account.master_password)
    password_match = bcrypt.checkpw(master_password.encode(), hashed_master_password)

    print("password_match:", password_match)

    if not password_match:
        return False

    return True


def remove_password(id: str, master_password: str):
    """
    Remove a password.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    engine = db_manager.get_engine()
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
