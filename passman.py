from typing import Optional

import typer
from cryptography.fernet import Fernet

from passman.password_manager import (
    copy_password,
    generate_random_password,
    initialize,
    remove_password,
    save_password,
)

app = typer.Typer()


@app.command()
def init(name: str, master_password: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """
    return initialize(name, master_password)


@app.command()
def save_pwd(id: str, password: Optional[str] = None, url: Optional[str] = None):
    """
    Encrypt and save a password.

    Args:
        id (str): An identifier used to retrieve the password.
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        url (Optional[str]): The url / service where the password is used.
    """
    return save_password(id, password, url)


@app.command()
def copy_pwd(id: str):
    """
    Copy the password with the provided ID to the clipboard.

    Args:
        id (str): The target password identifier.
    """
    return copy_password(id)


@app.command()
def rm_pwd(id: str, master_password: str):
    """
    Remove a password.

    Args:
        id (str): The target password identifier.
        master_password (str): The master password.
    """
    return remove_password(id, master_password)


@app.command()
def generate_secret_key():
    """
    Generate and returns a random secret key to use for your project.
    """
    secret_key = Fernet.generate_key()
    print(secret_key.decode())


if __name__ == "__main__":
    app()
