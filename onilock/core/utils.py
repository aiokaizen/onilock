import os
import time
import string
from typing import Optional
import gnupg
import secrets
import random
import uuid

from cryptography.fernet import Fernet
import keyring
import pyperclip


def get_base_dir():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def clear_clipboard_after_delay(content: str, delay=60):
    """Clears the clipboard after a delay if it still contains the given content."""
    time.sleep(delay)
    cb_content = pyperclip.paste()
    if cb_content == content:  # Check if clipboard still contains the password
        pyperclip.copy("")  # Clear the clipboard


def generate_pgp_key(gpg_home: Optional[str], name: str, email: str, passphrase: str):
    gpg = gnupg.GPG(gnupghome=gpg_home)
    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=4096,  # 3072
        name_real=name,
        name_email=email,
        passphrase=passphrase,
    )
    return gpg.gen_key(input_data)


def key_exists(
    gpg_home: Optional[str],
    key_fingerprint: Optional[str] = None,
    key_id: Optional[str] = None,
    real_name: Optional[str] = None,
) -> bool:
    """Check if a key exists in the keyring."""
    gpg = gnupg.GPG(gnupghome=gpg_home)
    keys = gpg.list_keys()

    if key_fingerprint:
        return any(key["fingerprint"] == key_fingerprint for key in keys)

    if key_id:
        # Key IDs are the last 16 characters of the fingerprint
        return any(key_id in key.get("keyid", "") for key in keys)

    if real_name:
        return any(
            real_name == uid.split(" ")[0] for key in keys for uid in key.get("uids")
        )

    return False


def get_key_info(
    self, real_name: Optional[str] = None, key_id: Optional[str] = None
) -> dict:
    """Get key details if exists in keyring."""
    keys = self.gpg.list_keys()

    for key in keys:
        uids = key.get("uids", [])

        if real_name:
            if any(real_name == uid.split(" ")[0] for uid in uids):
                return key
        elif key_id:
            if key_id == key.get("keyid"):
                return key

    return None


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
    Retrieve or generate a random secret key to use for the project.
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


def get_passphrase() -> str:
    """
    Retrieve or generate a random passphrase for the PGP key
    """

    # Retrieve key securely
    key_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, os.getlogin() + "_oni"))
    stored_key = keyring.get_password("onilock", key_name)
    if stored_key:
        return stored_key

    # Generate and store the key securely
    secret_key = generate_random_password(25)
    keyring.set_password("onilock", key_name, secret_key)

    return secret_key


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
