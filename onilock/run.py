from typing import Optional
import sys
import os
import json
import base64
import zipfile
import io
import hashlib
from pathlib import Path
import uuid
import gnupg

import typer
from rich.panel import Panel

from onilock.core import env
from onilock.core.decorators import exception_handler
from onilock.core.ui import console
from onilock.core.utils import generate_random_password, get_version, naive_utcnow
from cryptography.fernet import Fernet
from onilock.core.settings import settings
from onilock.db.models import Profile, Account, File
from onilock.db import DatabaseManager
from onilock.db.engines import EncryptedJsonEngine
from onilock.filemanager import FileEncryptionManager, get_output_filename
from onilock.account_manager import (
    copy_account_password,
    delete_profile,
    get_profile_engine,
    initialize,
    list_accounts,
    list_files,
    remove_account as am_remove_account,
    new_account,
    rotate_secret_key,
)
from onilock.core.profiles import (
    list_profiles,
    set_active_profile,
    get_active_profile,
    remove_profile,
)
from onilock.core.audit import audit
from onilock.core.gpg import get_pgp_key_info, delete_pgp_key
from onilock.core.keystore import KeyStoreManager
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


app = typer.Typer()
profiles_app = typer.Typer()
keys_app = typer.Typer()
filemanager = FileEncryptionManager()


def _derive_export_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def _encrypt_export(archive_bytes: bytes, passphrase: str) -> bytes:
    salt = hashlib.sha256(os.urandom(32)).digest()[:16]
    iterations = 200_000
    key = _derive_export_key(passphrase, salt, iterations)
    token = Fernet(key).encrypt(archive_bytes)
    payload = {
        "type": "onilock-export",
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode(),
        "data": base64.b64encode(token).decode(),
    }
    return json.dumps(payload, indent=2).encode()


def _decrypt_export(payload: bytes, passphrase: str) -> bytes:
    data = json.loads(payload.decode())
    if data.get("type") != "onilock-export":
        raise ValueError("Unsupported export format")
    salt = base64.b64decode(data["salt"])
    iterations = int(data["iterations"])
    token = base64.b64decode(data["data"])
    key = _derive_export_key(passphrase, salt, iterations)
    return Fernet(key).decrypt(token)


@app.command(rich_help_panel="Vault")
@exception_handler
def initialize_vault(
    master_password: Optional[str] = None,
):
    """
    Initialize a password manager onilock profile.

    Note:
        The master password should be very secure and be saved in a safe place.
    """
    console.print(
        Panel(
            "\n".join(
                [
                    f"[dim]Profile:[/dim] [bold]{settings.DB_NAME}[/bold]",
                    f"[dim]Vault directory:[/dim] {settings.VAULT_DIR}",
                    f"[dim]Setup file:[/dim] {settings.SETUP_FILEPATH}",
                    f"[dim]GPG home:[/dim] {settings.GPG_HOME or 'default system location'}",
                ]
            ),
            title="[cyan]Initialization Targets[/cyan]",
            border_style="cyan",
        )
    )

    if not master_password:
        if not sys.stdin.isatty():
            console.print(
                "[bold red]✗[/bold red] Master password is required in non-interactive mode. "
                "Pass it explicitly with [bold]--master-password[/bold]."
            )
            raise SystemExit(1)
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


@app.command(rich_help_panel="Passwords")
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


@app.command(rich_help_panel="Files")
@exception_handler
def encrypt_file(file_id: str, filename: str):
    """
    Encrypt a file and save it in the vault.

    Args:
        file_id (str): Identifier to use when reading or decrypting the file.
        filename (str): Path to the file to encrypt.
    """
    filemanager.encrypt(file_id, filename)


@app.command(rich_help_panel="Files")
@exception_handler
def read_file(file_id: str):
    """
    Open an encrypted file in read-only mode.

    Args:
        file_id (str): File identifier.
    """
    filemanager.read(file_id)


@app.command(rich_help_panel="Files")
@exception_handler
def edit_file(file_id: str):
    """
    Open and edit an encrypted file in-place.

    Args:
        file_id (str): File identifier.
    """
    filemanager.open(file_id)


@app.command(rich_help_panel="Files")
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


@app.command(rich_help_panel="Files")
@exception_handler
def export_file(file_id: str, output: Optional[str] = None):
    """
    Decrypt and export a file to its original format.

    Args:
        file_id (str): File identifier.
        output (str): Destination path (defaults to current directory).
    """
    filemanager.export(file_id, output)


@app.command(rich_help_panel="Files")
@exception_handler
def export_all_files(output: Optional[str] = None):
    """
    Export all encrypted files in OniLock to a zip archive.

    Args:
        output (str): Destination zip file path (defaults to current directory).
    """
    filemanager.export(file_path=output)


@app.command(rich_help_panel="Vault")
@exception_handler
def backup(
    output: Optional[str] = None,
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Passphrase to encrypt the backup."
    ),
):
    """
    Create an encrypted backup of the vault.
    """
    settings.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    default_name = (
        settings.BACKUP_DIR
        / f"onilock_{settings.DB_NAME}_backup_{naive_utcnow().strftime('%Y%m%d%H%M%S')}.zip"
    )
    output_path = output or str(default_name)
    _export_vault_impl(
        output=output_path,
        passwords=True,
        files=True,
        encrypt=True,
        passphrase=passphrase,
    )


@app.command(rich_help_panel="Vault")
@exception_handler
def restore(
    path: str,
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Passphrase to decrypt the backup."
    ),
    replace: bool = typer.Option(
        False, "--replace/--merge", help="Replace existing vault data."
    ),
):
    """
    Restore a vault backup.
    """
    import_vault(path, passwords=True, files=True, verify=True, replace=replace, passphrase=passphrase)


@app.command(rich_help_panel="Vault")
@exception_handler
def import_vault(
    path: str,
    passwords: bool = typer.Option(
        True, "--passwords/--no-passwords", help="Import passwords."
    ),
    files: bool = typer.Option(True, "--files/--no-files", help="Import files."),
    verify: bool = typer.Option(
        True, "--verify/--no-verify", help="Verify checksums when available."
    ),
    replace: bool = typer.Option(
        False, "--replace/--merge", help="Replace existing vault data."
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Passphrase for encrypted exports."
    ),
):
    """
    Import a vault export (zip or encrypted JSON export).
    """
    engine = get_profile_engine()
    if not engine:
        console.print(
            "[bold red]✗[/bold red] Vault is not initialized. "
            "Run [bold]onilock initialize-vault[/bold] first."
        )
        raise SystemExit(1)

    payload = Path(path).read_bytes()
    if payload[:1] == b"{":
        if not passphrase:
            if not sys.stdin.isatty():
                console.print(
                    "[bold red]✗[/bold red] Passphrase required in non-interactive mode. "
                    "Provide [bold]--passphrase[/bold]."
                )
                raise SystemExit(1)
            passphrase = typer.prompt("Export passphrase", hide_input=True)
        payload = _decrypt_export(payload, passphrase)

    with zipfile.ZipFile(io.BytesIO(payload)) as zipf:
        names = set(zipf.namelist())
        manifest = None
        if "manifest.json" in names:
            manifest = json.loads(zipf.read("manifest.json").decode())

        if verify and manifest:
            checksums = manifest.get("checksums", {})
            for filename, digest in checksums.items():
                if filename in names:
                    actual = hashlib.sha256(zipf.read(filename)).hexdigest()
                    if actual != digest:
                        raise RuntimeError(f"Checksum mismatch for {filename}")

        data = engine.read()
        profile = Profile(**data)
        if replace:
            profile.accounts = []
            profile.files = []

        if passwords and "accounts.json" in names:
            accounts_payload = json.loads(zipf.read("accounts.json").decode())
            accounts = accounts_payload.get("accounts", [])
            cipher = Fernet(settings.SECRET_KEY.encode())
            for account in accounts:
                account_id = account["id"]
                if profile.get_account(account_id):
                    console.print(
                        f"[bold yellow]![/bold yellow] Skipping existing account [bold]{account_id}[/bold]"
                    )
                    continue
                encrypted_password = cipher.encrypt(account["password"].encode())
                profile.accounts.append(
                    Account(
                        id=account_id,
                        encrypted_password=base64.b64encode(encrypted_password).decode(),
                        username=account.get("username", ""),
                        url=account.get("url"),
                        description=account.get("description"),
                        created_at=account.get("created_at", int(naive_utcnow().timestamp())),
                        is_weak_password=account.get("is_weak_password", False),
                    )
                )

        if files and "files.json" in names:
            files_meta = json.loads(zipf.read("files.json").decode())
            for file in files_meta:
                file_id = file["id"]
                if profile.get_file(file_id):
                    console.print(
                        f"[bold yellow]![/bold yellow] Skipping existing file [bold]{file_id}[/bold]"
                    )
                    continue
                filename = file["filename"]
                archive_path = str(Path("files") / filename)
                if archive_path not in names:
                    console.print(
                        f"[bold yellow]![/bold yellow] Missing file data for [bold]{file_id}[/bold]"
                    )
                    continue
                content = zipf.read(archive_path)
                if verify and "sha256" in file:
                    actual = hashlib.sha256(content).hexdigest()
                    if actual != file["sha256"]:
                        raise RuntimeError(f"Checksum mismatch for file {file_id}")

                output_filename = get_output_filename(file_id)
                output_path = settings.VAULT_DIR / output_filename
                filemanager.encrypt_bytes(content, output_path)
                profile.files.append(
                    File(
                        id=file_id,
                        location=str(output_path.absolute()),
                        created_at=file.get("created_at", int(naive_utcnow().timestamp())),
                        src=file.get("src", filename),
                        user=file.get("user", ""),
                        host=file.get("host", ""),
                    )
                )

        engine.write(profile.model_dump())
        console.print("[bold green]✓[/bold green] Import completed.")
        audit("vault.imported", source=path, passwords=passwords, files=files, replace=replace)


@app.command(rich_help_panel="Vault")
@exception_handler
def export_vault(
    output: Optional[str] = None,
    passwords: bool = typer.Option(
        True, "--passwords/--no-passwords", help="Include passwords export."
    ),
    files: bool = typer.Option(
        True, "--files/--no-files", help="Include files export."
    ),
    encrypt: bool = typer.Option(
        False, "--encrypt/--no-encrypt", help="Encrypt export with a passphrase."
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Passphrase used to encrypt the export."
    ),
):
    """
    Export the entire OniLock vault (accounts + files).
    """
    return _export_vault_impl(
        output=output,
        passwords=passwords,
        files=files,
        encrypt=encrypt,
        passphrase=passphrase,
    )


def _export_vault_impl(
    output: Optional[str] = None,
    passwords: bool = True,
    files: bool = True,
    encrypt: bool = False,
    passphrase: Optional[str] = None,
):
    """Internal implementation for full vault exports."""
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

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        manifest = {
            "profile": {
                "name": profile.name,
                "vault_version": profile.vault_version,
                "creation_timestamp": profile.creation_timestamp,
            },
            "exported_at": naive_utcnow().isoformat(),
            "options": {"passwords": passwords, "files": files},
            "checksums": {},
        }

        if passwords:
            export_payload = {
                "profile": manifest["profile"],
                "accounts": accounts,
            }
            accounts_json = json.dumps(export_payload, indent=2).encode()
            zipf.writestr("accounts.json", accounts_json)
            manifest["checksums"]["accounts.json"] = hashlib.sha256(accounts_json).hexdigest()

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
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )

            if files_meta:
                files_json = json.dumps(files_meta, indent=2).encode()
                zipf.writestr("files.json", files_json)
                manifest["checksums"]["files.json"] = hashlib.sha256(files_json).hexdigest()

        if settings.AUDIT_LOG.exists():
            audit_data = settings.AUDIT_LOG.read_bytes()
            zipf.writestr("audit.log", audit_data)
            manifest["checksums"]["audit.log"] = hashlib.sha256(audit_data).hexdigest()

        manifest_json = json.dumps(manifest, indent=2).encode()
        zipf.writestr("manifest.json", manifest_json)

    archive_bytes = archive_buffer.getvalue()
    if encrypt:
        if not passphrase:
            if not sys.stdin.isatty():
                console.print(
                    "[bold red]✗[/bold red] Passphrase required in non-interactive mode. "
                    "Provide [bold]--passphrase[/bold]."
                )
                raise SystemExit(1)
            passphrase = typer.prompt(
                "Export passphrase", hide_input=True, confirmation_prompt=True
            )
        encrypted_payload = _encrypt_export(archive_bytes, passphrase)
        output_path = output_path.with_suffix(".onilock-export.json")
        output_path.write_bytes(encrypted_payload)
    else:
        output_path.write_bytes(archive_bytes)

    console.print(f"[bold green]✓[/bold green] Exported vault to {output_path}")
    audit("vault.exported", output=str(output_path), passwords=passwords, files=files, encrypted=encrypt)


@app.command("list", rich_help_panel="Passwords")
@exception_handler
def accounts():
    """List all stored accounts."""

    return list_accounts()


@app.command("list-files", rich_help_panel="Files")
@exception_handler
def list_all_files():
    """List all encrypted files stored in the vault."""

    return list_files()


@profiles_app.command("list")
def profiles_list():
    """List known profiles."""
    profiles = list_profiles()
    active = get_active_profile()
    if not profiles:
        console.print("[bold yellow]![/bold yellow] No profiles registered yet.")
        return
    for name in profiles:
        marker = " (active)" if active == name else ""
        console.print(f"- {name}{marker}")


@profiles_app.command("use")
def profiles_use(name: str):
    """Set the active profile for future commands."""
    set_active_profile(name)
    console.print(
        f"[bold green]✓[/bold green] Active profile set to [bold]{name}[/bold]. "
        "Restart the command to use it."
    )


def _profile_setup_path(name: str) -> Path:
    filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, name + "_oni")).split("-")[-1]
    return Path(settings.VAULT_DIR) / f"{filename}.oni"


def _cleanup_profile_artifacts(name: str) -> dict[str, int]:
    removed = {
        "setup_file": 0,
        "vault_file": 0,
        "encrypted_files": 0,
        "backups": 0,
        "keystore_backend": 0,
    }

    setup_path = _profile_setup_path(name)
    profile_path: Optional[Path] = None

    if setup_path.exists():
        try:
            setup_engine = DatabaseManager(
                database_url=str(setup_path), is_encrypted=True
            ).get_engine()
            setup_data = setup_engine.read() or {}
            if isinstance(setup_data, dict):
                profile_info = setup_data.get(name, {})
                encrypted_fp = profile_info.get("filepath")
                if encrypted_fp:
                    cipher = Fernet(settings.SECRET_KEY.encode())
                    decrypted_fp = cipher.decrypt(
                        base64.b64decode(encrypted_fp)
                    ).decode()
                    profile_path = Path(decrypted_fp)
        except Exception:
            profile_path = None

        try:
            setup_path.unlink()
            removed["setup_file"] = 1
        except OSError:
            pass

    if profile_path and profile_path.exists():
        try:
            profile_engine = DatabaseManager(
                database_url=str(profile_path), is_encrypted=True
            ).get_engine()
            profile_data = profile_engine.read() or {}
            if isinstance(profile_data, dict):
                for file_data in profile_data.get("files", []):
                    location = file_data.get("location")
                    if not location:
                        continue
                    target = Path(location)
                    if target.exists():
                        try:
                            target.unlink()
                            removed["encrypted_files"] += 1
                        except OSError:
                            pass
        except Exception:
            pass

        try:
            profile_path.unlink()
            removed["vault_file"] = 1
        except OSError:
            pass

    backup_dir = Path(settings.BACKUP_DIR)
    if backup_dir.exists():
        for backup_file in backup_dir.glob(f"onilock_{name}_backup_*"):
            if not backup_file.is_file():
                continue
            try:
                backup_file.unlink()
                removed["backups"] += 1
            except OSError:
                pass

    if KeyStoreManager.clear_persisted_backend(name):
        removed["keystore_backend"] = 1

    return removed


@profiles_app.command("remove")
def profiles_remove(
    name: str,
    force: bool = typer.Option(
        False,
        "--force",
        help="Skip interactive confirmation prompt.",
    ),
):
    """Remove a profile and permanently delete all related local data."""
    profiles = list_profiles()
    if name not in profiles:
        console.print(f"[bold red]✗[/bold red] Profile '{name}' was not found.")
        raise SystemExit(1)

    console.print(
        Panel(
            (
                "[bold red]WARNING: This action is irreversible.[/bold red]\n\n"
                "It will permanently delete this profile's vault files, setup file, "
                "encrypted file artifacts, backups, and stored keystore backend choice."
            ),
            title="[red]Danger Zone[/red]",
            border_style="red",
        )
    )

    if not force:
        typer.confirm(
            f"Delete profile '{name}' and all related data?",
            abort=True,
        )

    removed = _cleanup_profile_artifacts(name)
    previously_active = get_active_profile()
    remove_profile(name)

    if previously_active == name:
        remaining_profiles = list_profiles()
        if remaining_profiles:
            set_active_profile(remaining_profiles[0])
            console.print(
                f"[bold yellow]![/bold yellow] Active profile switched to [bold]{remaining_profiles[0]}[/bold]."
            )
        elif settings.PROFILE_PATH.exists():
            try:
                settings.PROFILE_PATH.unlink()
            except OSError:
                pass

    audit("profile.removed", profile=name, removed=removed)
    console.print(
        f"[bold green]✓[/bold green] Profile [bold]{name}[/bold] removed. "
        f"(vault={removed['vault_file']}, setup={removed['setup_file']}, "
        f"files={removed['encrypted_files']}, backups={removed['backups']})"
    )


@app.command(rich_help_panel="Passwords")
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


@keys_app.command("list")
def keys_list():
    """List GPG keys and the active vault secret key id."""
    gpg = gnupg.GPG(gnupghome=settings.GPG_HOME)
    secret_keys = gpg.list_keys(secret=True)
    if not secret_keys:
        console.print("[bold yellow]![/bold yellow] No GPG secret keys found.")
    else:
        console.print("[bold]GPG Secret Keys[/bold]")
        for key in secret_keys:
            uid = key.get("uids", ["unknown"])[0]
            console.print(f"- {uid} ({key.get('fingerprint', 'n/a')})")

    active = get_pgp_key_info(settings.GPG_HOME, real_name=settings.PGP_REAL_NAME)
    if active:
        console.print(
            f"[bold]Active GPG Key[/bold]: {settings.PGP_REAL_NAME} ({active.get('fingerprint', 'n/a')})"
        )
    else:
        console.print("[bold yellow]![/bold yellow] Active GPG key not found.")


@keys_app.command("delete")
def keys_delete(name: Optional[str] = None, key_id: Optional[str] = None):
    """Delete a GPG key by name or key id."""
    if not name and not key_id:
        console.print("[bold red]✗[/bold red] Provide --name or --key-id.")
        raise SystemExit(1)
    target = name or key_id
    typer.confirm(f"Delete GPG key '{target}'?", abort=True)
    delete_pgp_key(
        passphrase=settings.PASSPHRASE,
        gpg_home=settings.GPG_HOME,
        real_name=name,
        key_id=key_id,
    )
    console.print("[bold green]✓[/bold green] Key deleted.")
    audit("keys.gpg.deleted", name=name, key_id=key_id)


@keys_app.command("rotate-secret")
def keys_rotate_secret():
    """Rotate the vault secret key used for password encryption."""
    rotate_secret_key()
    console.print("[bold green]✓[/bold green] Vault secret key rotated.")


@app.command(rich_help_panel="Passwords")
@exception_handler
def remove_account(name: str):
    """
    Remove an account from the vault.

    Args:
        name (str): Account name.
    """
    typer.confirm(f"Remove account '{name}'?", abort=True)
    return am_remove_account(name)


@app.command(rich_help_panel="Passwords")
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


@app.command(rich_help_panel="Utilities")
@exception_handler
def doctor():
    """
    Diagnose environment and configuration issues.
    """
    checks = []

    # Vault dir
    checks.append(
        ("Vault dir writable", os.access(settings.VAULT_DIR, os.W_OK))
    )

    # GPG home
    if settings.GPG_HOME:
        checks.append(("GPG home writable", os.access(settings.GPG_HOME, os.W_OK)))
    else:
        checks.append(("GPG home configured", False))

    # GPG binary
    try:
        import subprocess

        subprocess.run(["gpg", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        checks.append(("gpg installed", True))
    except Exception:
        checks.append(("gpg installed", False))

    # gpg-agent
    try:
        import subprocess

        subprocess.run(["gpgconf", "--launch", "gpg-agent"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        checks.append(("gpg-agent running", True))
    except Exception:
        checks.append(("gpg-agent running", False))

    # Keyring backend
    try:
        import keyring

        keyring.get_password("onilock", "doctor")
        checks.append(("keyring backend available", True))
    except Exception:
        checks.append(("keyring backend available", False))

    # Clipboard
    try:
        from onilock.core.utils import clipboard_available

        checks.append(("clipboard available", clipboard_available() and settings.CLIPBOARD_ENABLED))
    except Exception:
        checks.append(("clipboard available", False))

    for label, ok in checks:
        status = "[bold green]OK[/bold green]" if ok else "[bold red]FAIL[/bold red]"
        console.print(f"{status} {label}")


@app.command(rich_help_panel="Utilities")
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


@app.command(rich_help_panel="Vault")
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


@app.command(rich_help_panel="Utilities")
@exception_handler
def version(
    vault_format: bool = typer.Option(
        False, "--vault-format", help="Print the vault format version."
    ),
):
    """Print the current OniLock version."""
    if vault_format:
        return vault_format_cmd()

    v = get_version()
    fmt = _get_vault_format()
    created_with = _get_vault_created_version()
    lines = [f"[bold]OniLock[/bold] [cyan]{v}[/cyan]"]
    lines.append(f"[dim]Vault format:[/dim] {fmt}")
    if created_with:
        lines.append(f"[dim]Vault created with:[/dim] {created_with}")

    console.print(
        Panel(
            "\n".join(lines),
            border_style="dim",
            expand=False,
        )
    )


@app.command("vault-format", rich_help_panel="Utilities")
@exception_handler
def _get_vault_format() -> str:
    engine = get_profile_engine()
    if not engine:
        return "v2 (default for new vaults)"

    setup_path = Path(settings.SETUP_FILEPATH)
    if not setup_path.exists():
        return "v2 (default for new vaults)"

    raw = setup_path.read_bytes()
    if raw.startswith(EncryptedJsonEngine.V2_HEADER):
        return "v2 (AEAD AES-GCM)"
    return "v1 (legacy GPG + checksum)"


def _get_vault_created_version() -> Optional[str]:
    engine = get_profile_engine()
    if not engine:
        return None
    data = engine.read()
    if not data:
        return None
    profile = Profile(**data)
    return profile.vault_version or None


def vault_format_cmd():
    """Print the vault format version."""
    console.print(_get_vault_format())


@app.command(rich_help_panel="Vault")
@exception_handler
def export(
    dist: str = ".",
    passwords: bool = typer.Option(
        True, "--passwords/--no-passwords", help="Include passwords export."
    ),
    files: bool = typer.Option(
        True, "--files/--no-files", help="Include files export."
    ),
    encrypt: bool = typer.Option(
        False, "--encrypt/--no-encrypt", help="Encrypt export with a passphrase."
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Passphrase used to encrypt the export."
    ),
):
    """
    Export all user data to an external zip file.

    Args:
        dist (str): Destination path. Defaults to current directory.
    """
    return _export_vault_impl(
        output=dist,
        passwords=passwords,
        files=files,
        encrypt=encrypt,
        passphrase=passphrase,
    )


@app.callback()
def main():
    """
    OniLock - Secure Password Manager CLI.
    """


app.add_typer(profiles_app, name="profiles", rich_help_panel="Profiles")
app.add_typer(keys_app, name="keys", rich_help_panel="Keys")

if __name__ == "__main__":
    app()
