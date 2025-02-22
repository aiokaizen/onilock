import os
import string
import secrets
import random
import uuid

from cryptography.fernet import Fernet
import keyring


def get_base_dir():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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


def get_secret_key() -> str:
    """
    Generate and returns a random secret key to use for your project.
    """

    # Retrieve key securely
    key_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, os.getlogin()))
    stored_key = keyring.get_password("onilock", key_name)
    if stored_key:
        return stored_key

    # Generate and store the key securely
    secret_key = Fernet.generate_key()
    keyring.set_password("onilock", key_name, secret_key.decode())

    return secret_key.decode()


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
    if s.lower() in ("true", "1", "t", "yes", "on"):
        return True
    if s.lower() in ("false", "0", "f", "no", "off"):
        return False
    raise ValueError
