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
    add_account_tags,
    clear_account_note,
    copy_account_password,
    delete_profile,
    get_account_history,
    get_accounts_payload,
    get_files_payload,
    get_password_health_report,
    import_secrets,
    is_profile_unlocked,
    list_account_tags,
    get_profile_engine,
    get_account_secret,
    get_account_note,
    initialize,
    list_accounts,
    list_files,
    remove_account_tags,
    require_unlock_if_enabled,
    reset_profile_pin,
    search_accounts,
    set_account_note,
    rotate_account_password,
    unlock_with_pin,
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
notes_app = typer.Typer()
tags_app = typer.Typer()
pin_app = typer.Typer()
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
    pin: Optional[str] = typer.Option(
        None,
        "--pin",
        help="Optional 4-digit unlock PIN. Leave empty to disable.",
    ),
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

    if pin is None and sys.stdin.isatty():
        pin = typer.prompt(
            "Optional 4-digit PIN (leave empty to disable)",
            default="",
            hide_input=False,
        )

    return initialize(master_password, pin=pin)


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
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
    filemanager.encrypt(file_id, filename)


@app.command(rich_help_panel="Files")
@exception_handler
def read_file(file_id: str):
    """
    Open an encrypted file in read-only mode.

    Args:
        file_id (str): File identifier.
    """
    require_unlock_if_enabled()
    filemanager.read(file_id)


@app.command(rich_help_panel="Files")
@exception_handler
def edit_file(file_id: str):
    """
    Open and edit an encrypted file in-place.

    Args:
        file_id (str): File identifier.
    """
    require_unlock_if_enabled()
    filemanager.open(file_id)


@app.command(rich_help_panel="Files")
@exception_handler
def delete_file(file_id: str):
    """
    Permanently delete an encrypted file from the vault.

    Args:
        file_id (str): File identifier.
    """
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
    filemanager.export(file_id, output)


@app.command(rich_help_panel="Files")
@exception_handler
def export_all_files(output: Optional[str] = None):
    """
    Export all encrypted files in OniLock to a zip archive.

    Args:
        output (str): Destination zip file path (defaults to current directory).
    """
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
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


@app.command("import-secrets", rich_help_panel="Vault")
@exception_handler
def import_secrets_cmd(
    format_name: str = typer.Option(
        ...,
        "--format",
        help="Import format: csv or keepass-xml.",
    ),
    path: str = typer.Option(..., "--path", help="Path to import source file."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without writing."),
    replace_existing: bool = typer.Option(
        False, "--replace-existing", help="Replace existing accounts with imported values."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """Import secrets from CSV or KeePass XML export."""
    require_unlock_if_enabled()
    payload = import_secrets(
        format_name,
        path,
        dry_run=dry_run,
        replace_existing=replace_existing,
    )
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        "[bold green]✓[/bold green] Import complete "
        f"(processed={payload['processed']}, created={payload['created']}, "
        f"updated={payload['updated']}, skipped_existing={payload['skipped_existing']}, "
        f"invalid={payload['invalid']}, dry_run={payload['dry_run']})."
    )


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
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
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
def accounts(
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """List all stored accounts."""
    if json_output:
        typer.echo(json.dumps(get_accounts_payload()))
        return
    return list_accounts()


@app.command("list-files", rich_help_panel="Files")
@exception_handler
def list_all_files(
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """List all encrypted files stored in the vault."""
    if json_output:
        typer.echo(json.dumps(get_files_payload()))
        return
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
    require_unlock_if_enabled()
    account_id: str | int = name
    try:
        account_id = int(account_id) - 1
    except ValueError:
        pass
    return copy_account_password(account_id)


@app.command(rich_help_panel="Passwords")
@exception_handler
def search(
    query: str,
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum results."),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """
    Fuzzy-search accounts by id, username, URL, description, tags, and notes.
    """
    results = search_accounts(query, limit=limit)
    if json_output:
        typer.echo(json.dumps(results))
        return

    if not results:
        console.print("[bold yellow]![/bold yellow] No accounts matched your query.")
        return

    from rich.table import Table

    table = Table(title=f"Search Results — '{query}'", show_lines=True)
    table.add_column("#", style="dim", justify="right")
    table.add_column("Name", style="bold cyan")
    table.add_column("Username", style="green")
    table.add_column("URL", style="blue")
    table.add_column("Description", style="dim")
    table.add_column("Score", style="magenta", justify="right")

    for item in results:
        table.add_row(
            str(item["rank"]),
            item["id"],
            item["username"] or "—",
            item["url"] or "—",
            item["description"] or "—",
            f'{item["score"]:.4f}',
        )
    console.print(table)


@app.command(rich_help_panel="Passwords")
@exception_handler
def show(
    name: str,
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """
    Print a decrypted account secret.
    """
    require_unlock_if_enabled()
    account_id: str | int = name
    try:
        account_id = int(account_id) - 1
    except ValueError:
        pass

    payload = get_account_secret(account_id)
    if json_output:
        typer.echo(json.dumps(payload))
        return

    console.print(
        Panel(
            "\n".join(
                [
                    f"[dim]Account:[/dim] [bold]{payload['id']}[/bold]",
                    f"[dim]Username:[/dim] {payload['username'] or '—'}",
                    f"[dim]URL:[/dim] {payload['url'] or '—'}",
                    f"[bold red]Password:[/bold red] {payload['password']}",
                ]
            ),
            title="[yellow]Decrypted Secret[/yellow]",
            border_style="yellow",
        )
    )


@app.command(rich_help_panel="Passwords")
@exception_handler
def history(
    name: str,
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum history entries."),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """Show password version history for an account."""
    account_id: str | int = name
    try:
        account_id = int(account_id) - 1
    except ValueError:
        pass

    payload = get_account_history(account_id, limit=limit)
    if json_output:
        typer.echo(json.dumps(payload))
        return

    entries = payload["history"]
    if not entries:
        console.print(
            f"[bold yellow]![/bold yellow] No password history for [bold]{payload['id']}[/bold]."
        )
        return

    from rich.table import Table

    table = Table(title=f"Password History — {payload['id']}", show_lines=True)
    table.add_column("#", style="dim", justify="right")
    table.add_column("When", style="cyan")
    table.add_column("Reason", style="magenta")
    for item in entries:
        table.add_row(
            str(item["index"]),
            str(item["created_at"]),
            item["reason"],
        )
    console.print(table)


@app.command(rich_help_panel="Passwords")
@exception_handler
def rotate(
    name: str,
    len: int = typer.Option(20, "--len", min=4, help="Generated password length."),
    special_chars: bool = typer.Option(
        True,
        "--special-chars/--no-special-chars",
        help="Include special characters in the generated password.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """Rotate an account password and keep the previous value in history."""
    require_unlock_if_enabled()
    account_id: str | int = name
    try:
        account_id = int(account_id) - 1
    except ValueError:
        pass

    payload = rotate_account_password(
        account_id,
        length=len,
        include_special_chars=special_chars,
    )
    if json_output:
        typer.echo(json.dumps(payload))
        return

    health = "weak" if payload["is_weak_password"] else "strong"
    console.print(
        f"[bold green]✓[/bold green] Rotated password for [bold]{payload['id']}[/bold] "
        f"(history entries: {payload['history_size']}, health: {health})."
    )


@app.command(rich_help_panel="Passwords")
@exception_handler
def health(
    account: Optional[str] = typer.Argument(
        None, help="Account name/index. Omit when using --all."
    ),
    all: bool = typer.Option(False, "--all", help="Report health for all accounts."),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """Show password health for one account or the whole vault."""
    account_id: str | int | None = account
    if account and not all:
        try:
            account_id = int(account) - 1
        except ValueError:
            pass

    payload = get_password_health_report(account_id, all_accounts=all)
    if json_output:
        typer.echo(json.dumps(payload))
        return

    if all:
        from rich.table import Table

        summary = payload["summary"]
        console.print(
            f"[bold]Accounts:[/bold] {summary['total']}  "
            f"[green]strong:[/green] {summary['strong']}  "
            f"[yellow]weak:[/yellow] {summary['weak']}"
        )
        table = Table(title="Password Health", show_lines=True)
        table.add_column("Account", style="bold cyan")
        table.add_column("Strength", style="magenta")
        table.add_column("Entropy", style="green", justify="right")
        table.add_column("Reasons", style="dim")
        for item in payload["accounts"]:
            table.add_row(
                item["id"],
                item["strength"],
                f'{item["entropy_bits"]:.1f}',
                "; ".join(item["reasons"]) if item["reasons"] else "—",
            )
        console.print(table)
        return

    health_payload = payload["health"]
    console.print(
        f"[bold cyan]{payload['id']}[/bold cyan] "
        f"strength={health_payload['strength']} "
        f"entropy={health_payload['entropy_bits']:.1f}"
    )


@app.command(rich_help_panel="Passwords")
@exception_handler
def unlock(
    pin: Optional[str] = typer.Option(
        None,
        "--pin",
        help="4-digit PIN. If omitted in TTY mode, you will be prompted.",
    )
):
    """Unlock a PIN-protected profile for a short session."""
    value = pin
    if value is None:
        if not sys.stdin.isatty():
            console.print(
                "[bold red]✗[/bold red] PIN is required in non-interactive mode. "
                "Provide [bold]--pin[/bold]."
            )
            raise SystemExit(1)
        value = typer.prompt("PIN", hide_input=True)

    payload = unlock_with_pin(value)
    if not payload.get("pin_enabled", True):
        console.print("[bold yellow]![/bold yellow] PIN is disabled for this profile.")
        return
    console.print(
        f"[bold green]✓[/bold green] Profile unlocked for {payload['ttl_sec']} seconds."
    )


@pin_app.command("reset")
@exception_handler
def pin_reset(
    pin: Optional[str] = typer.Option(
        None,
        "--pin",
        help="4-digit PIN. Pass an empty value to disable PIN.",
    ),
):
    """Set, change, or disable the profile PIN."""
    value = pin
    if value is None:
        if not sys.stdin.isatty():
            console.print(
                "[bold red]✗[/bold red] Provide [bold]--pin[/bold] in non-interactive mode."
            )
            raise SystemExit(1)
        value = typer.prompt(
            "New 4-digit PIN (leave empty to disable)",
            default="",
            hide_input=False,
        )

    payload = reset_profile_pin(value)
    if payload["pin_enabled"]:
        console.print("[bold green]✓[/bold green] PIN updated.")
    else:
        console.print("[bold green]✓[/bold green] PIN disabled.")


@notes_app.command("set")
@exception_handler
def notes_set(
    account: str,
    text: Optional[str] = typer.Option(
        None, "--text", help="Note text content."
    ),
    note_file: Optional[str] = typer.Option(
        None, "--file", help="Path to a file containing note text."
    ),
):
    """Set an encrypted note on an account."""
    if text and note_file:
        console.print("[bold red]✗[/bold red] Use either --text or --file, not both.")
        raise SystemExit(1)
    if not text and not note_file:
        console.print("[bold red]✗[/bold red] Provide --text or --file.")
        raise SystemExit(1)

    note = text
    if note_file:
        note = Path(note_file).read_text()

    set_account_note(account, note or "")
    console.print(f"[bold green]✓[/bold green] Note set for [bold]{account}[/bold].")


@notes_app.command("get")
@exception_handler
def notes_get(
    account: str,
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """Get an account note."""
    payload = get_account_note(account)
    if json_output:
        typer.echo(json.dumps(payload))
        return

    console.print(
        Panel(
            payload["note"] or "",
            title=f"[cyan]Notes — {payload['id']}[/cyan]",
            border_style="cyan",
        )
    )


@notes_app.command("clear")
@exception_handler
def notes_clear(account: str):
    """Clear an account note."""
    clear_account_note(account)
    console.print(
        f"[bold green]✓[/bold green] Note cleared for [bold]{account}[/bold]."
    )


@tags_app.command("add")
@exception_handler
def tags_add(account: str, tags: list[str]):
    """Add one or more tags to an account."""
    payload = add_account_tags(account, tags)
    console.print(
        f"[bold green]✓[/bold green] Tags updated for [bold]{payload['id']}[/bold]: "
        f"{', '.join(payload['tags']) or '—'}"
    )


@tags_app.command("remove")
@exception_handler
def tags_remove(account: str, tags: list[str]):
    """Remove one or more tags from an account."""
    payload = remove_account_tags(account, tags)
    console.print(
        f"[bold green]✓[/bold green] Tags updated for [bold]{payload['id']}[/bold]: "
        f"{', '.join(payload['tags']) or '—'}"
    )


@tags_app.command("list")
@exception_handler
def tags_list(
    account: Optional[str] = typer.Argument(
        None, help="Account name. Omit to list tags for all accounts."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """List tags for one account or all accounts."""
    payload = list_account_tags(account)
    if json_output:
        typer.echo(json.dumps(payload))
        return

    if account:
        tags = payload.get("tags", [])
        console.print(
            f"[bold cyan]{payload['id']}[/bold cyan]: {', '.join(tags) if tags else '—'}"
        )
        return

    if not payload:
        console.print("[bold yellow]![/bold yellow] No tags found.")
        return

    from rich.table import Table

    table = Table(title="Account Tags", show_lines=True)
    table.add_column("Account", style="bold cyan")
    table.add_column("Tags", style="green")
    for item in payload:
        table.add_row(item["id"], ", ".join(item["tags"]) if item["tags"] else "—")
    console.print(table)


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
    require_unlock_if_enabled()
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


def _collect_doctor_payload(verbose: bool = False) -> dict:
    checks = []
    active_profile = get_active_profile() or settings.DB_NAME
    setup_path = Path(settings.SETUP_FILEPATH)
    backup_dir = Path(settings.BACKUP_DIR)
    audit_parent = Path(settings.AUDIT_LOG).parent

    profile_data = {}
    pin_enabled = False
    profile_engine = get_profile_engine()
    if profile_engine:
        try:
            profile_data = profile_engine.read() or {}
        except Exception:
            profile_data = {}
    if isinstance(profile_data, dict):
        pin_enabled = bool(profile_data.get("pin_enabled", False))

    checks.append(
        {
            "name": "vault_dir_writable",
            "ok": os.access(settings.VAULT_DIR, os.W_OK),
            "detail": str(settings.VAULT_DIR) if verbose else "",
        }
    )
    checks.append(
        {
            "name": "backup_dir_writable",
            "ok": os.access(backup_dir, os.W_OK),
            "detail": str(backup_dir) if verbose else "",
        }
    )
    checks.append(
        {
            "name": "audit_dir_writable",
            "ok": os.access(audit_parent, os.W_OK),
            "detail": str(audit_parent) if verbose else "",
        }
    )
    checks.append(
        {
            "name": "setup_file_exists",
            "ok": setup_path.exists(),
            "detail": str(setup_path) if verbose else "",
        }
    )
    checks.append(
        {
            "name": "profile_data_readable",
            "ok": bool(profile_data and isinstance(profile_data, dict)),
            "detail": "profile payload loaded" if verbose and profile_data else "",
        }
    )

    if settings.GPG_HOME:
        checks.append(
            {
                "name": "gpg_home_writable",
                "ok": os.access(settings.GPG_HOME, os.W_OK),
                "detail": settings.GPG_HOME if verbose else "",
            }
        )
    else:
        checks.append(
            {
                "name": "gpg_home_configured",
                "ok": False,
                "detail": "" if not verbose else "ONI_GPG_HOME is not configured",
            }
        )

    try:
        import subprocess

        subprocess.run(
            ["gpg", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        checks.append({"name": "gpg_installed", "ok": True, "detail": ""})
    except Exception as exc:
        checks.append(
            {
                "name": "gpg_installed",
                "ok": False,
                "detail": str(exc) if verbose else "",
            }
        )

    try:
        import subprocess

        subprocess.run(
            ["gpgconf", "--launch", "gpg-agent"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        checks.append({"name": "gpg_agent_running", "ok": True, "detail": ""})
    except Exception as exc:
        checks.append(
            {
                "name": "gpg_agent_running",
                "ok": False,
                "detail": str(exc) if verbose else "",
            }
        )

    try:
        import keyring

        keyring.get_password("onilock", "doctor")
        checks.append({"name": "keyring_backend_available", "ok": True, "detail": ""})
    except Exception as exc:
        checks.append(
            {
                "name": "keyring_backend_available",
                "ok": False,
                "detail": str(exc) if verbose else "",
            }
        )

    try:
        from onilock.core.utils import clipboard_available

        checks.append(
            {
                "name": "clipboard_available",
                "ok": clipboard_available() and settings.CLIPBOARD_ENABLED,
                "detail": "" if not verbose else f"enabled={settings.CLIPBOARD_ENABLED}",
            }
        )
    except Exception as exc:
        checks.append(
            {
                "name": "clipboard_available",
                "ok": False,
                "detail": str(exc) if verbose else "",
            }
        )
    keystore_backend = "unknown"
    try:
        manager = KeyStoreManager(settings.DB_NAME)
        persisted = manager._get_persisted_backend(settings.DB_NAME)
        keystore_backend = persisted or manager.keystore.__class__.__name__.lower()
        checks.append(
            {
                "name": "keystore_backend_resolved",
                "ok": True,
                "detail": keystore_backend if verbose else "",
            }
        )
    except Exception as exc:
        checks.append(
            {
                "name": "keystore_backend_resolved",
                "ok": False,
                "detail": str(exc) if verbose else "",
            }
        )

    unlock_required = pin_enabled
    unlocked = is_profile_unlocked(active_profile) if unlock_required else True

    return {
        "ok": all(item["ok"] for item in checks),
        "profile": {
            "active": active_profile,
            "pin_enabled": pin_enabled,
        },
        "unlock": {
            "required": unlock_required,
            "unlocked": unlocked,
        },
        "keystore": {
            "backend": keystore_backend,
        },
        "checks": checks,
    }


@app.command(rich_help_panel="Utilities")
@exception_handler
def doctor(
    verbose: bool = typer.Option(False, "--verbose", help="Include diagnostic details."),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON output."
    ),
):
    """
    Diagnose environment and configuration issues.
    """
    payload = _collect_doctor_payload(verbose=verbose)
    if json_output:
        typer.echo(json.dumps(payload))
        return

    console.print(
        f"[bold]Profile:[/bold] {payload['profile']['active']}  "
        f"[bold]PIN enabled:[/bold] {payload['profile']['pin_enabled']}  "
        f"[bold]Unlocked:[/bold] {payload['unlock']['unlocked']}  "
        f"[bold]Keystore:[/bold] {payload['keystore']['backend']}"
    )
    for item in payload["checks"]:
        status = "[bold green]OK[/bold green]" if item["ok"] else "[bold red]FAIL[/bold red]"
        line = f"{status} {item['name']}"
        if verbose and item["detail"]:
            line += f" ({item['detail']})"
        console.print(line)


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
    require_unlock_if_enabled()
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
    require_unlock_if_enabled()
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
app.add_typer(notes_app, name="notes", rich_help_panel="Passwords")
app.add_typer(tags_app, name="tags", rich_help_panel="Passwords")
app.add_typer(pin_app, name="pin", rich_help_panel="Passwords")

if __name__ == "__main__":
    app()
