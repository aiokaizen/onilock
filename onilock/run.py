from typing import Optional
import importlib.metadata

import typer

from onilock.core.utils import generate_random_password
from onilock.account_manager import (
    copy_account_password,
    delete_profile,
    initialize,
    list_accounts,
    remove_account,
    new_account,
)

app = typer.Typer()


@app.command()
def init(
    master_password: Optional[str] = None,
):
    """
    Initialize a password manager onilock profile.

    Note:
        The master password should be very secure and be saved in a safe place.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
    """

    if not master_password:
        typer.echo("\n\nEnter your Master Password:")
        typer.echo(
            "* Ensure that the password is strong and hidden safely.\n"
            "Leave empty to automatically generate a secure master password."
        )
        master_password = typer.prompt("> ", default="", hide_input=True)

    return initialize(master_password)


@app.command()
def new(
    name: str = typer.Option(..., prompt="Enter Account name (e.g. Github)"),
    password: Optional[str] = typer.Option(
        "",
        prompt="Enter Account password.",
        help="If empty, a strong password will be auto-generated.",
        hide_input=True,
    ),
    username: Optional[str] = typer.Option("", prompt="Enter Account username"),
    url: Optional[str] = typer.Option("", prompt="Enter Account URL"),
    description: Optional[str] = typer.Option("", prompt="Enter Account Description"),
):
    """
    Add new account with to onilock.

    Args:
        name (str): Account name.
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        username (Optional[str]): The account username
        url (Optional[str]): The url / service where the password is used.
        description (Optional[str]): A password description.
    """
    return new_account(name, password, username, url, description)


@app.command("list")
def accounts():
    """List all available accounts."""

    return list_accounts()


@app.command()
def copy(name: str):
    """
    Copy the password of the account with the provided name or index to the clipboard.

    N.B: You can find the index next to an account's name in the accounts list.

    Args:
        name (str): The target password identifier.
    """
    account_id: str | int = name
    try:
        account_id = int(account_id) - 1
    except ValueError:
        pass
    return copy_account_password(account_id)


@app.command()
def remove(name: str):
    """
    Remove an account.

    Args:
        name (str): The target password identifier.
    """
    return remove_account(name)


@app.command()
def generate(
    len: int = typer.Option(8, prompt="Enter password length"),
    special_chars: bool = typer.Option(True, prompt="Include special characters?"),
):
    """
    Generate and returns a random password
    """
    random_password = generate_random_password(len, special_chars)
    typer.echo(random_password)


@app.command("clear")
def clear_user_data(
    master_password: str = typer.Option(
        prompt="Enter Account's master password.",
        hide_input=True,
    ),
):
    """
    Delete all profile accounts.

    Args:
        master_password (str): Profile master password.
    """
    return delete_profile(master_password)


@app.command()
def version():
    """Print the current version of onilock and exit."""
    v = importlib.metadata.version("onilock")
    typer.echo(f"OniLock {v}")


if __name__ == "__main__":
    app()
