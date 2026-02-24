from typing import Optional

import typer

from onilock.core import env
from onilock.core.decorators import exception_handler
from onilock.core.utils import generate_random_password, get_version
from onilock.filemanager import FileEncryptionManager
from onilock.account_manager import (
    copy_account_password,
    delete_profile,
    initialize,
    list_accounts,
    list_files,
    remove_account as remove_stored_account,
    rename_account,
    search_accounts,
    new_account,
    show_account,
    update_account,
)


app = typer.Typer()
secrets_app = typer.Typer(help="Create, view, copy, update, and delete stored secrets.")
filemanager = FileEncryptionManager()
app.add_typer(secrets_app, name="secrets")


def parse_secret_identifier(value: str) -> str | int:
    value = value.strip()
    if value.isdigit():
        parsed = int(value)
        if parsed <= 0:
            return value
        return parsed - 1
    return value


def render_secret(secret: dict, include_password: bool = False) -> None:
    typer.echo(f"Name        : {secret['id']}")
    typer.echo(f"Username    : {secret.get('username') or '-'}")
    typer.echo(f"URL         : {secret.get('url') or '-'}")
    typer.echo(f"Description : {secret.get('description') or '-'}")
    if include_password:
        typer.echo(f"Password    : {secret['password']}")


def render_search_results(matches: list[dict]) -> None:
    typer.echo("Idx  Name                 Username             URL")
    typer.echo("---  -------------------  -------------------  ------------------------------")
    for item in matches:
        url = item.get("url") or "-"
        username = item.get("username") or "-"
        typer.echo(f"{item['index']:>3}  {item['id'][:19]:<19}  {username[:19]:<19}  {url[:30]}")


@secrets_app.command("create")
@exception_handler
def secrets_create(
    name: str = typer.Option(..., prompt="Secret name (e.g. Github)"),
    password: Optional[str] = typer.Option(
        "",
        prompt="Password (leave empty to auto-generate)",
        hide_input=True,
    ),
    username: Optional[str] = typer.Option("", prompt="Username"),
    url: Optional[str] = typer.Option("", prompt="URL"),
    description: Optional[str] = typer.Option("", prompt="Description"),
):
    """Create a new secret."""
    generated = not bool(password)
    cleartext_password = new_account(name, password, username, url, description)
    typer.echo(f"Secret '{name}' stored successfully.")
    if generated:
        typer.echo(f"Generated password: {cleartext_password}")


@secrets_app.command("list")
@exception_handler
def secrets_list():
    """List stored secrets in a compact table."""
    list_accounts()


@secrets_app.command("show")
@exception_handler
def secrets_show(
    identifier: str = typer.Argument(..., help="Secret name or list index (1-based)"),
    reveal: bool = typer.Option(False, "--reveal", help="Show password in plain text."),
    copy: bool = typer.Option(False, "--copy", help="Copy password to clipboard."),
):
    """Show secret metadata and optionally reveal/copy password."""
    parsed = parse_secret_identifier(identifier)
    secret = show_account(parsed, reveal_password=reveal)
    render_secret(secret, include_password=reveal)
    if copy:
        copy_account_password(parsed)


@secrets_app.command("copy")
@exception_handler
def secrets_copy(identifier: str = typer.Argument(..., help="Secret name or list index")):
    """Copy a secret password to clipboard."""
    parsed = parse_secret_identifier(identifier)
    copy_account_password(parsed)


@secrets_app.command("update")
@exception_handler
def secrets_update(
    identifier: str = typer.Argument(..., help="Secret name or list index"),
    name: Optional[str] = typer.Option(None, help="New secret name."),
    password: Optional[str] = typer.Option(None, hide_input=True, help="New password."),
    generate_password: bool = typer.Option(
        False, "--generate-password", help="Auto-generate a new password."
    ),
    username: Optional[str] = typer.Option(None, help="New username."),
    url: Optional[str] = typer.Option(None, help="New URL."),
    description: Optional[str] = typer.Option(None, help="New description."),
):
    """Update one or more secret fields."""
    parsed = parse_secret_identifier(identifier)

    if (
        name is None
        and password is None
        and not generate_password
        and username is None
        and url is None
        and description is None
    ):
        current = show_account(parsed, reveal_password=False)
        typer.echo("No fields provided. Interactive update mode:")
        name_input = typer.prompt("Name", default=current["id"])
        username_input = typer.prompt("Username", default=current.get("username") or "")
        url_input = typer.prompt("URL", default=current.get("url") or "")
        description_input = typer.prompt(
            "Description", default=current.get("description") or ""
        )
        password_input = typer.prompt(
            "Password (leave empty to keep current)",
            default="",
            hide_input=True,
        )
        name = name_input
        username = username_input
        url = url_input
        description = description_input
        password = password_input or None

    result = update_account(
        parsed,
        name=name,
        password=password,
        generate_password=generate_password,
        username=username,
        url=url,
        description=description,
    )
    if not result["updated_fields"]:
        typer.echo("No changes detected.")
        return

    typer.echo(f"Updated secret '{result['id']}' fields: {', '.join(result['updated_fields'])}")
    if result["generated_password"]:
        typer.echo(f"Generated password: {result['generated_password']}")


@secrets_app.command("rename")
@exception_handler
def secrets_rename(
    identifier: str = typer.Argument(..., help="Secret name or list index"),
    new_name: str = typer.Argument(..., help="New secret name"),
):
    """Rename a secret."""
    parsed = parse_secret_identifier(identifier)
    result = rename_account(parsed, new_name)
    if not result["changed"]:
        typer.echo("Name unchanged.")
        return
    typer.echo(f"Renamed secret '{result['old_id']}' -> '{result['new_id']}'.")


@secrets_app.command("search")
@exception_handler
def secrets_search(
    query: str = typer.Argument(..., help="Search query"),
    field: str = typer.Option(
        "all",
        "--field",
        "-f",
        help="Filter field: all, name, username, url, description",
    ),
    limit: int = typer.Option(20, "--limit", "-n", min=1, help="Maximum results."),
):
    """Search secrets by name, username, URL, or description."""
    matches = search_accounts(query, field=field, limit=limit)
    if not matches:
        typer.echo("No matching secrets found.")
        return
    render_search_results(matches)


@secrets_app.command("delete")
@exception_handler
def secrets_delete(
    identifier: str = typer.Argument(..., help="Secret name or list index"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """Delete a secret by name or index."""
    parsed = parse_secret_identifier(identifier)
    secret = show_account(parsed, reveal_password=False)
    if not yes:
        confirmed = typer.confirm(f"Delete secret '{secret['id']}'?")
        if not confirmed:
            typer.echo("Aborted.")
            return
    removed_id = remove_stored_account(parsed)
    typer.echo(f"Deleted secret '{removed_id}'.")


@app.command("init")
@exception_handler
def initialize_vault(
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
@exception_handler
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
    generated = not bool(password)
    cleartext_password = new_account(name, password, username, url, description)
    typer.echo(f"Secret '{name}' stored successfully.")
    if generated:
        typer.echo(f"Generated password: {cleartext_password}")


@app.command()
@exception_handler
def encrypt_file(file_id: str, filename: str):
    """
    Encrypt a file and save it in the vault.

    Args:
        file_id (str): To identify the file when reading and decrypting.
        filename (str): The file path to encrypt.
    """
    filemanager.encrypt(file_id, filename)


@app.command()
@exception_handler
def read_file(file_id: str):
    """
    Read the contents of an encrypted file.

    Args:
        file_id (str): To identify the file when reading and decrypting.
    """
    filemanager.read(file_id)


@app.command()
@exception_handler
def edit_file(file_id: str):
    """
    Change the contents of an encrypted file.

    Args:
        file_id (str): To identify the file when reading and decrypting.
    """
    filemanager.open(file_id)


@app.command()
@exception_handler
def delete_file(file_id: str):
    """
    Delete an enctypted file from the vault.

    Args:
        file_id (str): File id.
    """
    filemanager.delete(file_id)


@app.command()
@exception_handler
def export_file(file_id: str, output: Optional[str] = None):
    """
    Export the contents of an encrypted file back to it's original format.

    Args:
        file_id (str): To identify the file when reading and decrypting.
        output (str): The new file name (path).
    """
    filemanager.export(file_id, output)


@app.command()
@exception_handler
def export_all_files(output: Optional[str] = None):
    """
    Export ALL encrypted files in OniLock to a zip file.

    Args:
        output (str): The name of the zip file that will contain all files.
    """
    filemanager.export(file_path=output)


@app.command()
@exception_handler
def export_vault(output: Optional[str] = None):
    """
    Export ALL encrypted files in OniLock to a zip file.

    Args:
        output (str): The name of the zip file that will contain all files.
    """
    output_path = filemanager.export_vault(file_path=output)
    typer.echo(f"Encrypted vault exported to: {output_path}")


@app.command("list")
@exception_handler
def accounts():
    """List all available accounts."""

    return list_accounts()


@app.command("list-files")
@exception_handler
def list_all_files():
    """List all available files."""

    return list_files()


@app.command()
@exception_handler
def copy(name: str):
    """
    Copy the password of the account with the provided name or index to the clipboard.

    N.B: You can find the index next to an account's name in the accounts list.

    Args:
        name (str): The target password identifier.
    """
    account_id = parse_secret_identifier(name)
    return copy_account_password(account_id)


@app.command("remove")
@exception_handler
def remove(
    name: str,
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """
    Remove an account.

    Args:
        name (str): The target password identifier.
    """
    account_id = parse_secret_identifier(name)
    secret = show_account(account_id, reveal_password=False)
    if not yes:
        confirmed = typer.confirm(f"Delete secret '{secret['id']}'?")
        if not confirmed:
            typer.echo("Aborted.")
            return
    removed_id = remove_stored_account(account_id)
    typer.echo(f"Deleted secret '{removed_id}'.")


@app.command()
@exception_handler
def show(
    name: str,
    reveal: bool = typer.Option(False, "--reveal"),
    copy: bool = typer.Option(False, "--copy"),
):
    """Alias for `secrets show`."""
    account_id = parse_secret_identifier(name)
    secret = show_account(account_id, reveal_password=reveal)
    render_secret(secret, include_password=reveal)
    if copy:
        copy_account_password(account_id)


@app.command()
@exception_handler
def update(
    name: str,
    new_name: Optional[str] = typer.Option(None, "--name"),
    password: Optional[str] = typer.Option(None, hide_input=True),
    generate_password: bool = typer.Option(False, "--generate-password"),
    username: Optional[str] = typer.Option(None),
    url: Optional[str] = typer.Option(None),
    description: Optional[str] = typer.Option(None),
):
    """Alias for `secrets update`."""
    account_id = parse_secret_identifier(name)
    result = update_account(
        account_id,
        name=new_name,
        password=password,
        generate_password=generate_password,
        username=username,
        url=url,
        description=description,
    )
    if not result["updated_fields"]:
        typer.echo("No changes detected.")
        return
    typer.echo(f"Updated secret '{result['id']}' fields: {', '.join(result['updated_fields'])}")
    if result["generated_password"]:
        typer.echo(f"Generated password: {result['generated_password']}")


@app.command()
@exception_handler
def rename(name: str, new_name: str):
    """Alias for `secrets rename`."""
    account_id = parse_secret_identifier(name)
    result = rename_account(account_id, new_name)
    if not result["changed"]:
        typer.echo("Name unchanged.")
        return
    typer.echo(f"Renamed secret '{result['old_id']}' -> '{result['new_id']}'.")


@app.command()
@exception_handler
def search(
    query: str,
    field: str = typer.Option("all", "--field", "-f"),
    limit: int = typer.Option(20, "--limit", "-n", min=1),
):
    """Alias for `secrets search`."""
    matches = search_accounts(query, field=field, limit=limit)
    if not matches:
        typer.echo("No matching secrets found.")
        return
    render_search_results(matches)


@app.command("generate")
@exception_handler
def generate(
    len: int = typer.Option(8, prompt="Enter password length"),
    special_chars: bool = typer.Option(True, prompt="Include special characters?"),
):
    """
    Generate and returns a random password
    """
    random_password = generate_random_password(len, special_chars)
    typer.echo(random_password)


@app.command()
@exception_handler
def erase_user_data(
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
@exception_handler
def version():
    """Print the current version of onilock and exit."""
    v = get_version()
    typer.echo(f"OniLock {v}")


# def version_callback(ctx: typer.Context, param: typer.CallbackParam):
#     if ctx.resilient_parsing:
#         return
#     v = get_version()
#     typer.echo(f"OniLock {v}")
#     return None


# @app.command()
# @exception_handler
# def info():
#     """
#     Displays information and metadata about the user profile.
#
#     e.g.
#         - Profile name
#         - Creation time
#         - Vault version
#         - OniLock version
#         - Number of stored passwords
#         - Master password hash
#         - Number and list of Weak passwords
#     """
#     raise NotImplementedError()


@app.command()
@exception_handler
def export(dist: str = "."):
    """
    Export all user data to an external zip file.

    Args:
        dist (Optional[str]): The destination zip file path. Defaults to current directory.
    """
    output_path = filemanager.export_user_data(file_path=dist)
    typer.echo(f"User data exported to: {output_path}")


@app.callback()
def main(
    # version: bool = typer.Option(
    #     None,
    #     "--version",
    #     "-v",
    #     help="Show the current OniLock version and exit.",
    #     is_eager=True,
    #     callback=version_callback,
    # ),
):
    """
    OniLock - Secure Password Manager CLI.
    """


if __name__ == "__main__":
    app()
