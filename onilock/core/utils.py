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


def clear_clipboard_after_delay(delay=60):
    """Clears the clipboard after a delay without reading back content."""
    time.sleep(delay)
    try:
        pyperclip.copy("")
    except Exception:
        pass


def clipboard_available() -> bool:
    try:
        pyperclip.copy("")
        return True
    except Exception:
        return False


def best_effort_zero_bytes(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


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
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if include_special_characters:
        required.append(secrets.choice(punctuation))
        characters += punctuation

    remaining = max(0, length - len(required))
    password = required + [secrets.choice(characters) for _ in range(remaining)]

    # Shuffle password in-place.
    random.shuffle(password)

    return "".join(password)


def is_password_strong(password: str) -> bool:
    """
    Basic strength check for passwords.

    Strong if it has enough length and character variety.
    """
    if not password:
        return False

    length = len(password)
    if length < 12:
        return False
    if password.strip() != password:
        return False

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    categories = sum([has_lower, has_upper, has_digit, has_symbol])

    score = 0
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if categories >= 3:
        score += 1
    if categories == 4:
        score += 1

    return score >= 3


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
    password = generate_random_password(25, include_special_characters=False)
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
