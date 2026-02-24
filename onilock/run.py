from typing import Optional
import sys
import json
import base64
import zipfile
from pathlib import Path

import typer
from rich.panel import Panel

from onilock.core import env
from onilock.core.decorators import exception_handler
from onilock.core.ui import console
from onilock.core.utils import generate_random_password, get_version, naive_utcnow
from cryptography.fernet import Fernet
from onilock.core.settings import settings
from onilock.db.models import Profile
from onilock.filemanager import FileEncryptionManager
from onilock.account_manager import (
    copy_account_password,
    delete_profile,
    get_profile_engine,
    initialize,
    list_accounts,
    list_files,
    remove_account as am_remove_account,
    new_account,
)


app = typer.Typer()
filemanager = FileEncryptionManager()


@app.command()
@exception_handler
def initialize_vault(
    master_password: Optional[str] = None,
):
    """
    Initialize a password manager onilock profile.

    Note:
        The master password should be very secure and be saved in a safe place.
    """

    if not master_password:
        console.print(
            Panel(
                "[bold]Enter your master password below.[/bold]\n\n"
                "• Use a strong, unique password and store it somewhere safe.\n"
                "• Leave empty to [bold]auto-generate[/bold] a secure master password.",
                title="[cyan]Initialize OniLock Vault[/cyan]",
                border_style="cyan",
            )
        )
        master_password = typer.prompt("Master password", default="", hide_input=True)

    return initialize(master_password)


@app.command()
@exception_handler
def new(
    name: str = typer.Option(..., prompt="Account name (e.g. Github)"),
    password: Optional[str] = typer.Option(
        "",
        prompt="Password (leave empty to auto-generate)",
        help="If empty, a strong password will be auto-generated.",
        hide_input=True,
    ),
    username: Optional[str] = typer.Option("", prompt="Username"),
    url: Optional[str] = typer.Option("", prompt="URL"),
    description: Optional[str] = typer.Option("", prompt="Description"),
):
    """
    Add a new account to OniLock.
    """
    return new_account(name, password, username, url, description)


@app.command()
@exception_handler
def encrypt_file(file_id: str, filename: str):
    """
    Encrypt a file and save it in the vault.

    Args:
        file_id (str): Identifier to use when reading or decrypting the file.
        filename (str): Path to the file to encrypt.
    """
    if not get_profile_engine():
        if not sys.stdin.isatty():
            console.print(
                "[bold red]✗[/bold red] Vault is not initialized. "
                "Run [bold]onilock initialize-vault[/bold] in an interactive shell."
            )
            raise SystemExit(1)
        initialize_vault()
    filemanager.encrypt(file_id, filename)


@app.command()
@exception_handler
def read_file(file_id: str):
    """
    Open an encrypted file in read-only mode.

    Args:
        file_id (str): File identifier.
    """
    filemanager.read(file_id)


@app.command()
@exception_handler
def edit_file(file_id: str):
    """
    Open and edit an encrypted file in-place.

    Args:
        file_id (str): File identifier.
    """
    filemanager.open(file_id)


@app.command()
@exception_handler
def delete_file(file_id: str):
    """
    Permanently delete an encrypted file from the vault.

    Args:
        file_id (str): File identifier.
    """
    typer.confirm(
        f"Delete '{file_id}' from vault? This cannot be undone.",
        abort=True,
    )
    filemanager.delete(file_id)


@app.command()
@exception_handler
def export_file(file_id: str, output: Optional[str] = None):
    """
    Decrypt and export a file to its original format.

    Args:
        file_id (str): File identifier.
        output (str): Destination path (defaults to current directory).
    """
    filemanager.export(file_id, output)


@app.command()
@exception_handler
def export_all_files(output: Optional[str] = None):
    """
    Export all encrypted files in OniLock to a zip archive.

    Args:
        output (str): Destination zip file path (defaults to current directory).
    """
    filemanager.export(file_path=output)


@app.command()
@exception_handler
def export_vault(
    output: Optional[str] = None,
    passwords: bool = typer.Option(
        True, "--passwords/--no-passwords", help="Include passwords export."
    ),
    files: bool = typer.Option(
        True, "--files/--no-files", help="Include files export."
    ),
):
    """
    Export the entire OniLock vault (accounts + files).
    """
    engine = get_profile_engine()
    if not engine:
        console.print(
            "[bold red]✗[/bold red] Vault is not initialized. "
            "Run [bold]onilock initialize-vault[/bold] first."
        )
        raise SystemExit(1)

    data = engine.read()
    if not data:
        console.print(
            "[bold red]✗[/bold red] Vault is not initialized. "
            "Run [bold]onilock initialize-vault[/bold] first."
        )
        raise SystemExit(1)

    profile = Profile(**data)
    if not passwords and not files:
        console.print(
            "[bold red]✗[/bold red] Nothing to export. "
            "Enable [bold]--passwords[/bold] and/or [bold]--files[/bold]."
        )
        raise SystemExit(1)

    timestamp = naive_utcnow().strftime("%Y%m%d%H%M%S")
    default_name = f"onilock_{profile.name}_vault_{timestamp}.zip"
    output_path = Path(output) if output else Path(default_name)
    if output_path.is_dir():
        output_path = output_path / default_name
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cipher = Fernet(settings.SECRET_KEY.encode())
    accounts = []
    if passwords:
        for account in profile.accounts:
            encrypted_password = account.encrypted_password
            decrypted_password = cipher.decrypt(
                base64.b64decode(encrypted_password)
            ).decode()
            accounts.append(
                {
                    "id": account.id,
                    "username": account.username,
                    "password": decrypted_password,
                    "url": account.url,
                    "description": account.description,
                    "created_at": account.created_at,
                    "is_weak_password": account.is_weak_password,
                }
            )

    files_meta = []
    used_names = set()

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        if passwords:
            export_payload = {
                "profile": {
                    "name": profile.name,
                    "vault_version": profile.vault_version,
                    "creation_timestamp": profile.creation_timestamp,
                },
                "accounts": accounts,
            }
            zipf.writestr("accounts.json", json.dumps(export_payload, indent=2))

        if files:
            for file in profile.files:
                src_name = Path(file.src).name or f"{file.id}.bin"
                candidate = src_name
                if candidate in used_names:
                    candidate = f"{file.id}_{src_name}"
                used_names.add(candidate)

                try:
                    content = filemanager.decrypt(file.id)
                except Exception as exc:
                    console.print(
                        f"[bold yellow]![/bold yellow] Skipped file [bold]{file.id}[/bold]: {exc}"
                    )
                    continue

                archive_path = str(Path("files") / candidate)
                zipf.writestr(archive_path, content)
                files_meta.append(
                    {
                        "id": file.id,
                        "filename": candidate,
                        "src": file.src,
                        "user": file.user,
                        "host": file.host,
                        "created_at": file.created_at,
                    }
                )

            if files_meta:
                zipf.writestr("files.json", json.dumps(files_meta, indent=2))

    console.print(f"[bold green]✓[/bold green] Exported vault to {output_path}")


@app.command("list")
@exception_handler
def accounts():
    """List all stored accounts."""

    return list_accounts()


@app.command("list-files")
@exception_handler
def list_all_files():
    """List all encrypted files stored in the vault."""

    return list_files()


@app.command()
@exception_handler
def copy(name: str):
    """
    Copy an account's password to the clipboard.

    NAME can be the account name or its 1-based index from `onilock list`.
    """
    account_id: str | int = name
    try:
        account_id = int(account_id) - 1
    except ValueError:
        pass
    return copy_account_password(account_id)


@app.command()
@exception_handler
def remove_account(name: str):
    """
    Remove an account from the vault.

    Args:
        name (str): Account name.
    """
    typer.confirm(f"Remove account '{name}'?", abort=True)
    return am_remove_account(name)


@app.command()
@exception_handler
def generate_pwd(
    len: int = typer.Option(8, prompt="Password length"),
    special_chars: bool = typer.Option(True, prompt="Include special characters?"),
):
    """
    Generate a random password.
    """
    random_password = generate_random_password(len, special_chars)
    console.print(
        Panel(
            f"[bold green]{random_password}[/bold green]",
            title="[cyan]Generated Password[/cyan]",
            border_style="cyan",
        )
    )


@app.command()
@exception_handler
def generate_fernet_key():
    """
    Generate a random Fernet key.
    """
    key = Fernet.generate_key().decode()
    console.print(
        Panel(
            f"[bold green]{key}[/bold green]",
            title="[cyan]Fernet Key[/cyan]",
            border_style="cyan",
        )
    )


@app.command()
@exception_handler
def erase_user_data(
    master_password: str = typer.Option(
        prompt="Master password",
        hide_input=True,
    ),
):
    """
    Permanently delete all OniLock data for this profile.
    """
    typer.confirm(
        "This will permanently delete ALL accounts, files, and keys. Continue?",
        abort=True,
    )
    return delete_profile(master_password)


@app.command()
@exception_handler
def version():
    """Print the current OniLock version."""
    v = get_version()
    console.print(
        Panel(
            f"[bold]OniLock[/bold] [cyan]{v}[/cyan]",
            border_style="dim",
            expand=False,
        )
    )


@app.command()
@exception_handler
def export(
    dist: str = ".",
    passwords: bool = typer.Option(
        True, "--passwords/--no-passwords", help="Include passwords export."
    ),
    files: bool = typer.Option(
        True, "--files/--no-files", help="Include files export."
    ),
):
    """
    Export all user data to an external zip file.

    Args:
        dist (str): Destination path. Defaults to current directory.
    """
    return export_vault(dist, passwords=passwords, files=files)


@app.callback()
def main():
    """
    OniLock - Secure Password Manager CLI.
    """


if __name__ == "__main__":
    app()
