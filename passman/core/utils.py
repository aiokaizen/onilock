import os
import uuid

from cryptography.fernet import Fernet
import keyring


def get_base_dir():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_secret_key() -> str:
    """
    Generate and returns a random secret key to use for your project.
    """

    # Retrieve key securely
    key_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, os.getlogin()))
    stored_key = keyring.get_password("passman", key_name)
    if stored_key:
        return stored_key

    # Generate and store the key securely
    secret_key = Fernet.generate_key()
    keyring.set_password("passman", key_name, secret_key.decode())

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
