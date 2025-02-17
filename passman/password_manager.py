from typing import Optional
from db import DatabaseManager


db_manager = DatabaseManager()


__all__ = [
    "initialize",
    "save_password",
    "copy_password",
]


def _generate_random_password(
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
    return "8hYrjH9$9hB="


def initialize(master_password: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """

    if not master_password:
        master_password = _generate_random_password(
            length=25, include_special_characters=True
        )

    # @TODO: Verify password strength.
    # @TODO: Encrypt password
    # Save the password.
    return master_password


def save_password(id: str, password: Optional[str] = None, url: Optional[str] = None):
    """
    Encrypt and save a password.

    Args:
        id (str): An identifier used to retrieve the password.
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        url (Optional[str]): The url / service where the password is used.
    """

    if not password:
        password = _generate_random_password()

    # @TODO: Verify password strength.
    # @TODO: Encrypt password
    # Save the password.
    return password


def copy_password(id: str):
    """
    Copy the password with the provided ID to the clipboard.

    Args:
        id (str): The target password identifier.
    """

    return ""
