from typing import Optional
import typer

from passman.password_manager import copy_password, initialize, save_password

app = typer.Typer()


@app.command()
def init(master_password: Optional[str] = None):
    """
    Initialize the password manager whith a master password.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """
    return initialize(master_password)


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


if __name__ == "__main__":
    app()
