from datetime import datetime
from pathlib import Path
import shutil
import uuid
import multiprocessing
import os
import json
import time
import csv
import re
import xml.etree.ElementTree as ET
from typing import Optional, Iterable
import base64
from difflib import SequenceMatcher

from cryptography.fernet import Fernet
import pyperclip
import bcrypt

from rich.table import Table

from onilock.core.decorators import pre_post_hooks
from onilock.core.keystore import keystore
from onilock.core.settings import settings
from onilock.core.logging_manager import logger
from onilock.core.audit import audit
from onilock.core.auth import is_locked, record_failure, clear_failures, rate_limit_delay
from onilock.core.ui import console, success, error, warning, info
from onilock.core.profiles import register_profile, remove_profile
from onilock.core.gpg import (
    delete_pgp_key,
)
from onilock.core.utils import (
    clear_clipboard_after_delay,
    generate_random_password,
    get_passphrase,
    getlogin,
    get_version,
    best_effort_zero_bytes,
    naive_utcnow,
)
from onilock.core.passwords import password_health
from onilock.db import DatabaseManager
from onilock.db.models import Profile, Account, PasswordVersion


__all__ = [
    "initialize",
    "new_account",
    "copy_account_password",
    "get_account_secret",
    "set_account_note",
    "get_account_note",
    "clear_account_note",
    "add_account_tags",
    "remove_account_tags",
    "list_account_tags",
    "replace_account_password",
    "rotate_account_password",
    "get_account_history",
    "get_password_health_report",
    "get_accounts_payload",
    "get_files_payload",
    "import_secrets",
    "unlock_with_pin",
    "reset_profile_pin",
    "require_unlock_if_enabled",
    "is_profile_unlocked",
    "search_accounts",
    "remove_account",
    "delete_profile",
    "rotate_secret_key",
]


def pre_command():
    logger.debug("Starting pre-command hook.")


def post_command():
    logger.debug("Starting post-command hook.")


def _unlock_path() -> Path:
    return Path(settings.BASE_DIR) / ".unlock.json"


def _load_unlock_cache() -> dict:
    path = _unlock_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_unlock_cache(data: dict) -> None:
    path = _unlock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _unlock_ttl_sec() -> int:
    raw = os.environ.get("ONI_UNLOCK_TTL_SEC", "600")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 600
    return value if value > 0 else 600


def _validate_pin(pin: str) -> None:
    if not pin.isdigit() or len(pin) != 4:
        error("PIN must be exactly 4 digits.")
        exit(1)


def is_profile_unlocked(profile_name: Optional[str] = None) -> bool:
    profile = profile_name or settings.DB_NAME
    data = _load_unlock_cache()
    entry = data.get(profile, {})
    expires_at = int(entry.get("expires_at", 0))
    now = int(time.time())
    if expires_at <= now:
        if profile in data:
            del data[profile]
            _save_unlock_cache(data)
        return False
    return True


def _set_profile_unlock(profile_name: str, ttl_sec: Optional[int] = None) -> int:
    ttl = ttl_sec if ttl_sec is not None else _unlock_ttl_sec()
    expires_at = int(time.time()) + ttl
    data = _load_unlock_cache()
    data[profile_name] = {"expires_at": expires_at}
    _save_unlock_cache(data)
    return expires_at


def _clear_profile_unlock(profile_name: str) -> None:
    data = _load_unlock_cache()
    if profile_name in data:
        del data[profile_name]
        _save_unlock_cache(data)


def verify_master_password(master_password: str):
    """
    Verify that the provided master password is valid.

    Args:
        master_password (str): The master password.
    """
    locked, remaining = is_locked(settings.DB_NAME)
    if locked:
        error(f"Too many failed attempts. Try again in {remaining}s.")
        audit("auth.locked", remaining=remaining)
        exit(1)

    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    hashed_master_password = base64.b64decode(profile.master_password)
    pwd_buf = bytearray(master_password.encode())
    try:
        ok = bcrypt.checkpw(bytes(pwd_buf), hashed_master_password)
    finally:
        best_effort_zero_bytes(pwd_buf)

    if not ok:
        failed = record_failure(settings.DB_NAME)
        audit("auth.failed", attempts=failed)
        rate_limit_delay(failed)
        return False

    clear_failures(settings.DB_NAME)

    # Upgrade bcrypt cost if below current target.
    target_rounds = _get_bcrypt_rounds()
    try:
        current_rounds = int(hashed_master_password.decode().split("$")[2])
    except Exception:
        current_rounds = target_rounds

    if current_rounds < target_rounds:
        new_hash = bcrypt.hashpw(
            master_password.encode(),
            bcrypt.gensalt(rounds=target_rounds),
        )
        profile.master_password = base64.b64encode(new_hash).decode()
        engine.write(profile.model_dump())
        audit("auth.kdf.upgrade", from_rounds=current_rounds, to_rounds=target_rounds)

    return True


def _load_setup_data(setup_engine):
    try:
        return setup_engine.read()
    except RuntimeError as exc:
        message = str(exc)
        if "no secret key" in message:
            error(
                "Unable to decrypt the setup data. The required GPG secret key is missing."
            )
            info(
                "If this is a local dev environment, set [bold]ONI_DB_NAME[/bold] and "
                "[bold]ONI_GPG_HOME[/bold], then run [bold]onilock initialize-vault[/bold]."
            )
            return None
        raise


def _get_bcrypt_rounds() -> int:
    rounds = getattr(settings, "BCRYPT_ROUNDS", 12)
    try:
        rounds = int(rounds)
    except (TypeError, ValueError):
        rounds = 12
    return rounds if rounds >= 4 else 12


def get_profile_engine():
    """Get user config engine."""

    cipher = Fernet(settings.SECRET_KEY.encode())
    db_manager = DatabaseManager(
        database_url=settings.SETUP_FILEPATH, is_encrypted=True
    )
    setup_engine = db_manager.get_engine()
    setup_data = _load_setup_data(setup_engine)
    if not setup_data or settings.DB_NAME not in setup_data:
        return None
    b64encrypted_config_filepath = setup_data[settings.DB_NAME]["filepath"]
    encrypted_filepath = base64.b64decode(b64encrypted_config_filepath)
    config_filepath = cipher.decrypt(encrypted_filepath).decode()
    return db_manager.add_engine("data", config_filepath, is_encrypted=True)


def reset_profile_pin(pin: Optional[str]) -> dict:
    """
    Set, change, or disable the profile PIN.
    Pass an empty string to disable PIN-based unlock gating.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    if pin is None or pin == "":
        profile.pin_enabled = False
        profile.pin_hash = None
        _clear_profile_unlock(profile.name)
        engine.write(profile.model_dump())
        audit("auth.pin.disabled", profile=profile.name)
        return {"pin_enabled": False}

    _validate_pin(pin)
    hashed = bcrypt.hashpw(pin.encode(), bcrypt.gensalt(rounds=_get_bcrypt_rounds()))
    profile.pin_hash = base64.b64encode(hashed).decode()
    profile.pin_enabled = True
    _clear_profile_unlock(profile.name)
    engine.write(profile.model_dump())
    audit("auth.pin.set", profile=profile.name)
    return {"pin_enabled": True}


def unlock_with_pin(pin: str) -> dict:
    """
    Validate PIN and create a temporary unlocked session.
    """
    _validate_pin(pin)

    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    if not profile.pin_enabled or not profile.pin_hash:
        info("PIN unlock is disabled for this profile.")
        return {"unlocked": True, "pin_enabled": False}

    try:
        pin_hash = base64.b64decode(profile.pin_hash)
    except Exception:
        error("Stored PIN hash is invalid. Reset the PIN with [bold]onilock pin reset[/bold].")
        exit(1)

    if not bcrypt.checkpw(pin.encode(), pin_hash):
        audit("auth.pin.failed", profile=profile.name)
        error("Invalid PIN.")
        exit(1)

    expires_at = _set_profile_unlock(profile.name)
    audit("auth.pin.unlocked", profile=profile.name, expires_at=expires_at)
    return {
        "unlocked": True,
        "pin_enabled": True,
        "expires_at": expires_at,
        "ttl_sec": _unlock_ttl_sec(),
    }


def require_unlock_if_enabled() -> None:
    """
    Enforce unlock gate only when PIN is enabled on the active profile.
    """
    engine = get_profile_engine()
    if not engine:
        return
    data = engine.read()
    if not data:
        return

    profile = Profile(**data)
    if not profile.pin_enabled:
        return

    if is_profile_unlocked(profile.name):
        return

    error(
        "Vault is locked. Run [bold]onilock unlock[/bold] (or pass [bold]--pin[/bold]) first."
    )
    audit("auth.pin.locked", profile=profile.name)
    exit(1)


@pre_post_hooks(pre_command, post_command)
def initialize(master_password: Optional[str] = None, pin: Optional[str] = None):
    """
    Initialize the password manager with a master password.

    Args:
        master_password (Optional[str]): The master password used to secure all the other accounts.
        pin (Optional[str]): Optional 4-digit unlock PIN.
    """
    logger.debug("Initializing database with a master password.")

    name = settings.DB_NAME

    filename = generate_random_password(12, include_special_characters=False) + ".oni"
    filepath = str(settings.VAULT_DIR / filename)

    db_manager = DatabaseManager(database_url=filepath, is_encrypted=True)
    engine = db_manager.get_engine()
    setup_engine = db_manager.add_engine(
        "setup", settings.SETUP_FILEPATH, is_encrypted=True
    )
    data = engine.read()
    setup_data = setup_engine.read()

    if data or name in setup_data:
        error("This vault is already initialized.")
        exit(1)

    if not master_password:
        logger.info(
            "Master password not provided! A random password will be generated and displayed."
        )
        master_password = generate_random_password(
            length=25, include_special_characters=True
        )
        warning(
            f"Generated master password: [bold]{master_password}[/bold]\n"
            "  This is the [bold]only time[/bold] this password will be shown. "
            "Store it somewhere safe before continuing."
        )
    else:
        pass

    hashed_master_password = bcrypt.hashpw(
        master_password.encode(), bcrypt.gensalt(rounds=_get_bcrypt_rounds())
    )
    b64_hashed_master_password = base64.b64encode(hashed_master_password).decode()

    pin_hash = None
    pin_enabled = False
    if pin is not None and pin != "":
        _validate_pin(pin)
        pin_hash = base64.b64encode(
            bcrypt.hashpw(pin.encode(), bcrypt.gensalt(rounds=_get_bcrypt_rounds()))
        ).decode()
        pin_enabled = True

    profile = Profile(
        name=name,
        master_password=b64_hashed_master_password,
        vault_version=get_version(),
        pin_hash=pin_hash,
        pin_enabled=pin_enabled,
        accounts=list(),
        files=[],
    )
    engine.write(profile.model_dump())
    audit("vault.init", profile=name, vault_version=profile.vault_version)
    register_profile(name)

    logger.info("Updating the current setup file.")

    cipher = Fernet(settings.SECRET_KEY.encode())
    logger.debug("Encrypting filepath.")
    encrypted_filepath = cipher.encrypt(filepath.encode())
    b64_encrypted_filepath = base64.b64encode(encrypted_filepath).decode()

    setup_data[name] = {
        "filepath": b64_encrypted_filepath,
    }

    setup_engine.write(setup_data)

    logger.info("Initialization completed successfully.")
    success("Vault initialized successfully.")
    return master_password


@pre_post_hooks(pre_command, post_command)
def new_account(
    name: str,
    password: Optional[str] = None,
    username: Optional[str] = None,
    url: Optional[str] = None,
    description: Optional[str] = None,
):
    """
    Register a new account.

    Args:
        name (str): An identifier used to retrieve the password (e.g. github).
        password (Optional[str]): The password to encrypt, automatically generated if not provided.
        username (Optional[str]): The account username
        url (Optional[str]): The url / service where the password is used.
        description (Optional[str]): A password description.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)

    if not password:
        logger.warning("Password not provided, generating it randomly.")
        password = generate_random_password()

    cipher = Fernet(settings.SECRET_KEY.encode())
    logger.debug("Encrypting the password.")
    encrypted_password = cipher.encrypt(password.encode())
    logger.debug(f"Encrypted password: {encrypted_password.decode()}")
    b64_encrypted_password = base64.b64encode(encrypted_password).decode()
    logger.debug(f"B64 Encrypted password: {b64_encrypted_password}")
    existing_passwords = []
    for acct in profile.accounts:
        try:
            encrypted = base64.b64decode(acct.encrypted_password)
            existing_passwords.append(cipher.decrypt(encrypted).decode())
        except Exception:
            continue

    health = password_health(password, existing_passwords)
    if health["strength"] != "strong":
        warning(
            "Password health warning: "
            + "; ".join(health["reasons"])
            + f" (entropy {health['entropy_bits']} bits)"
        )

    password_model = Account(
        id=name,
        encrypted_password=b64_encrypted_password,
        username=username or "",
        url=url,
        description=description,
        is_weak_password=health["strength"] != "strong",
        created_at=int(naive_utcnow().timestamp()),
    )
    profile.accounts.append(password_model)
    engine.write(profile.model_dump())
    logger.info("Password saved successfully.")
    success(f"Account [bold]{name}[/bold] added to the vault.")
    audit("account.added", account=name)
    return password


@pre_post_hooks(pre_command, post_command)
def list_accounts():
    """List all available accounts."""

    payload = get_accounts_payload()
    engine = get_profile_engine()
    if not engine:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    data = engine.read()
    if not data:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    profile = Profile(**data)

    if not payload:
        info(
            f"No accounts found in [bold]{profile.name}[/bold]. "
            "Use [bold]onilock new[/bold] to add one."
        )
        return

    table = Table(title=f"Accounts — {profile.name}", show_lines=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Name", style="bold cyan")
    table.add_column("Username", style="green")
    table.add_column("URL", style="blue")
    table.add_column("Created", style="dim")

    for item in payload:
        table.add_row(
            str(item["index"]),
            item["id"],
            item["username"] or "—",
            item["url"] or "—",
            item["created"],
        )

    console.print(table)


def get_accounts_payload():
    """Return accounts as JSON-safe payload."""
    engine = get_profile_engine()
    if not engine:
        return []
    data = engine.read()
    if not data:
        return []
    profile = Profile(**data)

    payload = []
    for index, account in enumerate(profile.accounts):
        payload.append(
            {
                "index": index + 1,
                "id": account.id,
                "username": account.username or "",
                "url": account.url or "",
                "created": datetime.fromtimestamp(account.created_at).strftime("%Y-%m-%d"),
            }
        )
    return payload


@pre_post_hooks(pre_command, post_command)
def list_files():
    """List all available files."""

    payload = get_files_payload()
    engine = get_profile_engine()
    if not engine:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    data = engine.read()
    if not data:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return
    profile = Profile(**data)

    if not payload:
        info(
            f"No files found in [bold]{profile.name}[/bold]. "
            "Use [bold]onilock encrypt-file[/bold] to add one."
        )
        return

    table = Table(title=f"Encrypted Files — {profile.name}", show_lines=True)
    table.add_column("ID", style="bold cyan")
    table.add_column("Source File", style="green")
    table.add_column("Owner", style="dim")
    table.add_column("Host", style="dim")
    table.add_column("Created", style="dim")

    for item in payload:
        table.add_row(
            item["id"],
            Path(item["src"]).name,
            item["user"],
            item["host"],
            item["created"],
        )

    console.print(table)


def get_files_payload():
    """Return encrypted files as JSON-safe payload."""
    engine = get_profile_engine()
    if not engine:
        return []
    data = engine.read()
    if not data:
        return []
    profile = Profile(**data)

    payload = []
    for file in profile.files:
        payload.append(
            {
                "id": file.id,
                "src": file.src,
                "user": file.user,
                "host": file.host,
                "created": datetime.fromtimestamp(file.created_at).strftime("%Y-%m-%d"),
            }
        )
    return payload


def _score_match(query: str, value: str) -> float:
    if not value:
        return 0.0

    q = query.lower().strip()
    text = value.lower().strip()
    if not q or not text:
        return 0.0

    score = SequenceMatcher(None, q, text).ratio()
    if text == q:
        score += 1.0
    elif text.startswith(q):
        score += 0.35
    elif q in text:
        score += 0.2

    return score


def search_accounts(query: str, limit: int = 10):
    """
    Fuzzy search accounts by id, username, url, description, tags and notes.
    """
    if not query or not query.strip():
        return []

    engine = get_profile_engine()
    if not engine:
        return []
    data = engine.read()
    if not data:
        return []

    profile = Profile(**data)
    q = query.strip()
    results = []
    for account in profile.accounts:
        tags = getattr(account, "tags", []) or []
        tags_str = " ".join(str(t) for t in tags)
        notes = getattr(account, "notes", "") or ""

        candidates = [
            account.id or "",
            account.username or "",
            account.url or "",
            account.description or "",
            tags_str,
            notes,
        ]
        score = max((_score_match(q, value) for value in candidates), default=0.0)
        if score < 0.45:
            continue

        results.append(
            {
                "id": account.id,
                "username": account.username or "",
                "url": account.url or "",
                "description": account.description or "",
                "score": round(score, 4),
            }
        )

    results.sort(key=lambda item: (-item["score"], item["id"].lower()))
    cap = max(1, int(limit))
    return [
        {"rank": idx + 1, **item}
        for idx, item in enumerate(results[:cap])
    ]


def get_account_secret(id: str | int):
    """
    Decrypt and return a single account secret payload.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = base64.b64decode(account.encrypted_password)
    decrypted_password = cipher.decrypt(encrypted_password).decode()
    return {
        "id": account.id,
        "username": account.username or "",
        "url": account.url or "",
        "password": decrypted_password,
    }


def _get_history_max() -> int:
    raw = getattr(settings, "ONI_HISTORY_MAX", 20)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 20
    return value if value >= 1 else 20


def replace_account_password(
    id: str | int,
    new_password: str,
    reason: str = "replace",
):
    """
    Replace an account password and keep the previous encrypted value in history.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    existing_history = getattr(account, "history", []) or []
    history = []
    for entry in existing_history:
        if isinstance(entry, PasswordVersion):
            history.append(entry)
            continue
        try:
            history.append(PasswordVersion(**entry))
        except Exception:
            continue

    history.append(
        PasswordVersion(
            encrypted_password=account.encrypted_password,
            created_at=int(naive_utcnow().timestamp()),
            reason=reason,
        )
    )
    max_items = _get_history_max()
    account.history = history[-max_items:]

    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = cipher.encrypt(new_password.encode())
    account.encrypted_password = base64.b64encode(encrypted_password).decode()

    existing_passwords = []
    for acct in profile.accounts:
        if acct.id.lower() == account.id.lower():
            continue
        try:
            encrypted = base64.b64decode(acct.encrypted_password)
            existing_passwords.append(cipher.decrypt(encrypted).decode())
        except Exception:
            continue
    health = password_health(new_password, existing_passwords)
    account.is_weak_password = health["strength"] != "strong"

    engine.write(profile.model_dump())
    audit("account.password.replaced", account=account.id, reason=reason)
    return {
        "id": account.id,
        "history_size": len(account.history),
        "reason": reason,
        "is_weak_password": account.is_weak_password,
    }


def rotate_account_password(
    id: str | int,
    length: int = 20,
    include_special_chars: bool = True,
):
    new_password = generate_random_password(length, include_special_chars)
    payload = replace_account_password(id, new_password, reason="rotate")
    return {
        "id": payload["id"],
        "rotated": True,
        "history_size": payload["history_size"],
        "is_weak_password": payload["is_weak_password"],
        "length": len(new_password),
    }


def get_account_history(id: str | int, limit: int = 10):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    history_items = []
    for entry in getattr(account, "history", []) or []:
        if isinstance(entry, PasswordVersion):
            history_items.append(entry)
            continue
        try:
            history_items.append(PasswordVersion(**entry))
        except Exception:
            continue

    ordered_history = list(enumerate(history_items))
    ordered_history.sort(key=lambda pair: (pair[1].created_at, pair[0]), reverse=True)
    cap = max(1, int(limit))
    return {
        "id": account.id,
        "history": [
            {
                "index": index + 1,
                "created_at": item.created_at,
                "reason": item.reason,
            }
            for index, (_, item) in enumerate(ordered_history[:cap])
        ],
    }


def _decrypt_account_password(cipher: Fernet, account: Account) -> Optional[str]:
    try:
        encrypted = base64.b64decode(account.encrypted_password)
        return cipher.decrypt(encrypted).decode()
    except Exception:
        return None


def get_password_health_report(
    id: str | int | None = None,
    all_accounts: bool = False,
):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    cipher = Fernet(settings.SECRET_KEY.encode())

    decrypted: dict[str, str] = {}
    for account in profile.accounts:
        password = _decrypt_account_password(cipher, account)
        if password is not None:
            decrypted[account.id] = password

    if all_accounts:
        accounts_payload = []
        for account in profile.accounts:
            current = decrypted.get(account.id)
            if current is None:
                continue
            others = [
                pwd
                for acc_id, pwd in decrypted.items()
                if acc_id.lower() != account.id.lower()
            ]
            health = password_health(current, others)
            accounts_payload.append(
                {
                    "id": account.id,
                    "strength": health["strength"],
                    "reasons": health["reasons"],
                    "entropy_bits": health["entropy_bits"],
                    "reused": health["is_reused"],
                    "is_common": health["is_common"],
                }
            )

        accounts_payload.sort(key=lambda item: item["id"].lower())
        weak_count = sum(1 for item in accounts_payload if item["strength"] != "strong")
        strong_count = len(accounts_payload) - weak_count
        return {
            "summary": {
                "total": len(accounts_payload),
                "strong": strong_count,
                "weak": weak_count,
            },
            "accounts": accounts_payload,
        }

    if id is None:
        error("Provide an account identifier or pass [bold]--all[/bold].")
        exit(1)

    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    current = decrypted.get(account.id)
    if current is None:
        return {
            "id": account.id,
            "health": {
                "strength": "unknown",
                "reasons": ["unable to decrypt password"],
                "entropy_bits": 0.0,
                "reused": False,
                "is_common": False,
            },
        }

    others = [
        pwd
        for acc_id, pwd in decrypted.items()
        if acc_id.lower() != account.id.lower()
    ]
    health = password_health(current, others)
    return {"id": account.id, "health": health}


def _split_tags(raw: str) -> list[str]:
    if not raw:
        return []
    return _normalize_tags([part for part in re.split(r"[;,]", raw) if part.strip()])


def _parse_csv_records(path: str) -> list[dict]:
    with open(path, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        records = []
        for row in reader:
            lowered = {str(k).strip().lower(): (v or "") for k, v in row.items()}
            account_id = (
                lowered.get("id")
                or lowered.get("title")
                or lowered.get("name")
                or lowered.get("account")
                or ""
            ).strip()
            tags_raw = lowered.get("tags") or lowered.get("tag") or ""
            records.append(
                {
                    "id": account_id,
                    "username": (lowered.get("username") or lowered.get("user") or "").strip(),
                    "password": (lowered.get("password") or lowered.get("pass") or "").strip(),
                    "url": (lowered.get("url") or "").strip(),
                    "notes": (lowered.get("notes") or lowered.get("note") or "").strip(),
                    "tags": _split_tags(tags_raw),
                }
            )
    return records


def _parse_keepass_xml_records(path: str) -> list[dict]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise RuntimeError(f"Invalid KeePass XML: {exc}") from exc

    records = []
    for entry in tree.findall(".//Entry"):
        values = {}
        for string_node in entry.findall("String"):
            key = (string_node.findtext("Key") or "").strip()
            value = (string_node.findtext("Value") or "").strip()
            if key:
                values[key] = value

        tags_raw = (entry.findtext("Tags") or values.get("Tags") or "").strip()
        records.append(
            {
                "id": (values.get("Title") or values.get("id") or "").strip(),
                "username": (values.get("UserName") or "").strip(),
                "password": (values.get("Password") or "").strip(),
                "url": (values.get("URL") or "").strip(),
                "notes": (values.get("Notes") or "").strip(),
                "tags": _split_tags(tags_raw),
            }
        )
    return records


def _parse_import_records(secret_format: str, path: str) -> list[dict]:
    fmt = secret_format.lower().strip()
    if fmt == "csv":
        return _parse_csv_records(path)
    if fmt == "keepass-xml":
        return _parse_keepass_xml_records(path)
    raise RuntimeError(f"Unsupported import format: {secret_format}")


def _replace_password_in_profile(profile: Profile, account: Account, new_password: str, reason: str):
    history = []
    for entry in getattr(account, "history", []) or []:
        if isinstance(entry, PasswordVersion):
            history.append(entry)
            continue
        try:
            history.append(PasswordVersion(**entry))
        except Exception:
            continue
    history.append(
        PasswordVersion(
            encrypted_password=account.encrypted_password,
            created_at=int(naive_utcnow().timestamp()),
            reason=reason,
        )
    )
    account.history = history[-_get_history_max():]

    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = cipher.encrypt(new_password.encode())
    account.encrypted_password = base64.b64encode(encrypted_password).decode()

    existing_passwords = []
    for acct in profile.accounts:
        if acct.id.lower() == account.id.lower():
            continue
        decrypted = _decrypt_account_password(cipher, acct)
        if decrypted is not None:
            existing_passwords.append(decrypted)
    health = password_health(new_password, existing_passwords)
    account.is_weak_password = health["strength"] != "strong"


def import_secrets(
    secret_format: str,
    path: str,
    dry_run: bool = False,
    replace_existing: bool = False,
):
    records = _parse_import_records(secret_format, path)
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    summary = {
        "format": secret_format.lower(),
        "processed": len(records),
        "created": 0,
        "updated": 0,
        "skipped_existing": 0,
        "invalid": 0,
        "dry_run": dry_run,
    }

    cipher = Fernet(settings.SECRET_KEY.encode())
    changed = False
    for record in records:
        account_id = record.get("id", "").strip()
        password = record.get("password", "").strip()
        if not account_id or not password:
            summary["invalid"] += 1
            continue

        account = profile.get_account(account_id)
        tags = _normalize_tags(record.get("tags", []))
        note_text = record.get("notes", "")
        note_value = (
            base64.b64encode(cipher.encrypt(note_text.encode())).decode()
            if note_text
            else None
        )

        if account:
            if not replace_existing:
                summary["skipped_existing"] += 1
                continue

            summary["updated"] += 1
            if dry_run:
                continue

            _replace_password_in_profile(profile, account, password, reason="replace")
            account.username = record.get("username", "") or account.username
            account.url = record.get("url", "") or account.url
            account.notes = note_value
            account.tags = tags
            changed = True
            continue

        summary["created"] += 1
        if dry_run:
            continue

        encrypted_password = cipher.encrypt(password.encode())
        existing_passwords = []
        for acct in profile.accounts:
            decrypted = _decrypt_account_password(cipher, acct)
            if decrypted is not None:
                existing_passwords.append(decrypted)
        health = password_health(password, existing_passwords)
        profile.accounts.append(
            Account(
                id=account_id,
                encrypted_password=base64.b64encode(encrypted_password).decode(),
                username=record.get("username", ""),
                url=record.get("url", "") or None,
                description=None,
                notes=note_value,
                tags=tags,
                is_weak_password=health["strength"] != "strong",
                created_at=int(naive_utcnow().timestamp()),
            )
        )
        changed = True

    if changed and not dry_run:
        engine.write(profile.model_dump())
        audit(
            "vault.import.secrets",
            format=summary["format"],
            created=summary["created"],
            updated=summary["updated"],
            skipped_existing=summary["skipped_existing"],
            invalid=summary["invalid"],
        )

    return summary


def set_account_note(id: str | int, note: str):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_note = cipher.encrypt(note.encode())
    account.notes = base64.b64encode(encrypted_note).decode()
    engine.write(profile.model_dump())
    audit("account.notes.set", account=account.id)
    return {"id": account.id, "updated": True}


def get_account_note(id: str | int):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    if not account.notes:
        return {"id": account.id, "note": ""}

    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_note = base64.b64decode(account.notes)
    note = cipher.decrypt(encrypted_note).decode()
    return {"id": account.id, "note": note}


def clear_account_note(id: str | int):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    account.notes = None
    engine.write(profile.model_dump())
    audit("account.notes.cleared", account=account.id)
    return {"id": account.id, "cleared": True}


def _normalize_tags(tags: Iterable[str]) -> list[str]:
    normalized = {
        str(tag).strip().lower()
        for tag in tags
        if str(tag).strip()
    }
    return sorted(normalized)


def add_account_tags(id: str | int, tags: list[str]):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    existing_tags = getattr(account, "tags", []) or []
    account.tags = _normalize_tags([*existing_tags, *tags])
    engine.write(profile.model_dump())
    audit("account.tags.added", account=account.id, tags=account.tags)
    return {"id": account.id, "tags": account.tags}


def remove_account_tags(id: str | int, tags: list[str]):
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    to_remove = set(_normalize_tags(tags))
    existing_tags = _normalize_tags(getattr(account, "tags", []) or [])
    account.tags = [tag for tag in existing_tags if tag not in to_remove]
    engine.write(profile.model_dump())
    audit("account.tags.removed", account=account.id, tags=list(to_remove))
    return {"id": account.id, "tags": account.tags}


def list_account_tags(id: str | int | None = None):
    engine = get_profile_engine()
    if not engine:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return [] if id is None else {"id": str(id), "tags": []}
    data = engine.read()
    if not data:
        info(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        return [] if id is None else {"id": str(id), "tags": []}

    profile = Profile(**data)
    if id is None:
        return [
            {"id": account.id, "tags": _normalize_tags(getattr(account, "tags", []) or [])}
            for account in profile.accounts
            if _normalize_tags(getattr(account, "tags", []) or [])
        ]

    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)
    return {"id": account.id, "tags": _normalize_tags(getattr(account, "tags", []) or [])}


@pre_post_hooks(pre_command, post_command)
def copy_account_password(id: str | int):
    """
    Copy the password of the account with the provided ID to the clipboard.

    Args:
        id (str | int): The target password identifier or 0-based index.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)

    account = profile.get_account(id)
    if not account:
        error(
            f"Account [bold]{id}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    logger.debug(f"Raw password: {account.encrypted_password}")
    logger.debug("Decrypting the password.")
    cipher = Fernet(settings.SECRET_KEY.encode())
    encrypted_password = base64.b64decode(account.encrypted_password)
    decrypted_password = cipher.decrypt(encrypted_password).decode()
    if not settings.CLIPBOARD_ENABLED:
        error("Clipboard is disabled. Set ONI_CLIPBOARD=true to enable.")
        exit(1)

    try:
        pyperclip.copy(decrypted_password)
    except Exception:
        error("Clipboard is not available on this system.")
        exit(1)
    logger.info(f"Password {account.id} copied to clipboard successfully.")
    success(
        f"Password for [bold]{account.id}[/bold] copied to clipboard. "
        "Clears automatically in [bold]10s[/bold]."
    )
    audit("account.copied", account=account.id)

    logger.debug("Password will be cleared in 10 seconds.")

    process = multiprocessing.Process(
        target=clear_clipboard_after_delay,
        args=(10,),
    )
    process.start()

    os._exit(0)


@pre_post_hooks(pre_command, post_command)
def remove_account(name: str):
    """
    Remove a password.

    Args:
        name (str): The target account name.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)
    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)

    account = profile.get_account(name)

    if not account:
        error(
            f"Account [bold]{name}[/bold] not found. "
            "Run [bold]onilock list[/bold] to see available accounts."
        )
        exit(1)

    profile.remove_account(name)
    engine.write(profile.model_dump())
    success(f"Account [bold]{name}[/bold] removed.")
    audit("account.removed", account=name)


@pre_post_hooks(pre_command, post_command)
def delete_profile(master_password: str):
    """
    Delete all profile data.

    Args:
        master_password (str): Profile master password.
    """
    master_password_match = verify_master_password(master_password)
    if not master_password_match:
        error("Invalid master password.")
        exit(1)

    passphrase = get_passphrase()

    keystore.clear()

    delete_pgp_key(
        passphrase=passphrase,
        gpg_home=settings.GPG_HOME,
        real_name=settings.PGP_REAL_NAME,
    )

    shutil.rmtree(settings.VAULT_DIR)
    success("All user data has been permanently deleted.")
    profile_name = getattr(settings, "DB_NAME", None)
    if isinstance(profile_name, str) and profile_name:
        remove_profile(profile_name)
        audit("vault.deleted", profile=profile_name)
    else:
        audit("vault.deleted")


def rotate_secret_key():
    """
    Rotate the vault secret key and re-encrypt stored passwords.
    """
    engine = get_profile_engine()
    if not engine:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    data = engine.read()
    if not data:
        error(
            "This vault is not initialized. Run [bold]onilock initialize-vault[/bold] first."
        )
        exit(1)

    profile = Profile(**data)
    old_key = settings.SECRET_KEY
    new_key = Fernet.generate_key().decode()
    cipher_old = Fernet(old_key.encode())
    cipher_new = Fernet(new_key.encode())

    for account in profile.accounts:
        encrypted_password = base64.b64decode(account.encrypted_password)
        decrypted_password = cipher_old.decrypt(encrypted_password)
        reencrypted = cipher_new.encrypt(decrypted_password)
        account.encrypted_password = base64.b64encode(reencrypted).decode()

    engine.write(profile.model_dump())

    # Re-encrypt setup file path
    db_manager = DatabaseManager(
        database_url=settings.SETUP_FILEPATH, is_encrypted=True
    )
    setup_engine = db_manager.get_engine()
    setup_data = setup_engine.read()
    entry = setup_data.get(settings.DB_NAME)
    if entry:
        encrypted_filepath = base64.b64decode(entry["filepath"])
        decrypted_path = cipher_old.decrypt(encrypted_filepath)
        entry["filepath"] = base64.b64encode(
            cipher_new.encrypt(decrypted_path)
        ).decode()
        setup_engine.write(setup_data)

    key_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, getlogin())).split("-")[-1]
    keystore.set_password(key_name, new_key)
    settings.SECRET_KEY = new_key
    audit("keys.secret.rotated")
