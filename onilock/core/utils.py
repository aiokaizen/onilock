from datetime import datetime, timezone
import importlib.metadata
import os
import getpass
from pathlib import Path
import time
import string
import secrets
import random
import uuid

from cryptography.fernet import Fernet
import pyperclip

from onilock.core.constants import TRUTHFUL_STR, UNTRUTHFUL_STR
from onilock.core.keystore import keystore


def get_base_dir():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def getlogin():
    return getpass.getuser()


def naive_utcnow():
    now = datetime.now(tz=timezone.utc)
    return now.replace(tzinfo=None)


def clear_clipboard_after_delay(content: str, delay=60):
    """Clears the clipboard after a delay if it still contains the given content."""
    time.sleep(delay)
    try:
        cb_content = pyperclip.paste()
        if cb_content == content:  # Check if clipboard still contains the password
            pyperclip.copy("")  # Clear the clipboard
    except Exception:
        pass


def get_version() -> str:
    try:
        return importlib.metadata.version("onilock")
    except ModuleNotFoundError:
        pyproject = Path("pyproject.toml")
        if not pyproject.exists():
            return "0.0.1"

        with pyproject.open() as f:
            for line in f:
                if line.startswith("version"):
                    return line.split('"')[1]

        return "0.0.1"


def generate_random_password(
    length: int = 12, include_special_characters: bool = True
) -> str:
    """
    Generate a random and secure password.

    Args:
        length (int): The length of the generated password
        include_special_characters (bool): If False, the password will only contain alpha-numeric characters.

    Returns:
        str : The generated password
    """
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


def generate_key() -> str:
    """
    Generate a random key to use as a project secret key for example.
    """
    secret_key = Fernet.generate_key()
    return secret_key.decode()


def get_secret_key() -> str:
    """
    Retrieve or generate a random secret key to use for the project.
    """

    # Retrieve key securely
    key_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, getlogin())).split("-")[-1]
    stored_key = keystore.get_password(key_name)
    if stored_key:
        return stored_key

    # Generate and store the key securely
    secret_key = generate_key()
    keystore.set_password(key_name, secret_key)

    return secret_key


def get_passphrase() -> str:
    """
    Retrieve or generate a random passphrase for the PGP key
    """

    # Retrieve key securely
    key_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, getlogin() + "_oni")).split("-")[-1]
    stored_key = keystore.get_password(key_name)
    if stored_key:
        return stored_key

    # Generate and store the key securely
    password = generate_random_password(25)
    keystore.set_password(key_name, password)

    return password


def str_to_bool(s: str) -> bool:
    """
    Evalueates a strings to either True or False.

    Args:
        s (str): The string to evaluate as a boolean.

    Raises:
        ValueError, if the argument `s` could not be evaluated to a boolean.

    Returns:
        True if the string is in: ("true", "1", "t", "yes", "on")
        True if the string is in: ("false", "0", "f", "no", "off")
    """
    if s.lower() in TRUTHFUL_STR:
        return True
    if s.lower() in UNTRUTHFUL_STR:
        return False
    raise ValueError
