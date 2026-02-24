from __future__ import annotations

import base64
from typing import Optional

import pyperclip
from cryptography.fernet import Fernet

from onilock.core.exceptions import (
    InvalidAccountIdentifierError,
    VaultConfigurationError,
    VaultNotInitializedError,
)
from onilock.core.settings import settings
from onilock.core.utils import (
    generate_random_password,
    naive_utcnow,
    schedule_clipboard_clear,
)
from onilock.db.models import Account, Profile
from onilock.profile_store import load_profile, save_profile


Identifier = str | int


def _normalize_identifier(identifier: Identifier) -> Identifier:
    if isinstance(identifier, int):
        return identifier
    value = str(identifier).strip()
    if value.isdigit():
        parsed = int(value)
        if parsed <= 0:
            raise InvalidAccountIdentifierError()
        return parsed - 1
    return value


class SecretManager:
    def _load_profile(self) -> tuple[object, Profile]:
        engine, profile = load_profile()
        return engine, profile

    def _encrypt_password(self, password: str) -> str:
        cipher = Fernet(settings.SECRET_KEY.encode())
        encrypted_password = cipher.encrypt(password.encode())
        return base64.b64encode(encrypted_password).decode()

    def _decrypt_password(self, encrypted_password: str) -> str:
        cipher = Fernet(settings.SECRET_KEY.encode())
        encrypted = base64.b64decode(encrypted_password)
        return cipher.decrypt(encrypted).decode()

    def _resolve_account(self, profile: Profile, identifier: Identifier) -> Account:
        account = profile.get_account(_normalize_identifier(identifier))
        if not account:
            raise InvalidAccountIdentifierError()
        return account

    def _ensure_unique_name(
        self, profile: Profile, name: str, current_id: Optional[str] = None
    ) -> None:
        for account in profile.accounts:
            if current_id and account.id.lower() == current_id.lower():
                continue
            if account.id.lower() == name.lower():
                raise InvalidAccountIdentifierError(
                    "A secret with this name already exists."
                )

    def create(
        self,
        *,
        name: str,
        password: Optional[str] = None,
        username: Optional[str] = None,
        url: Optional[str] = None,
        description: Optional[str] = None,
    ) -> str:
        engine, profile = self._load_profile()
        self._ensure_unique_name(profile, name)

        cleartext_password = password or generate_random_password()
        account = Account(
            id=name,
            encrypted_password=self._encrypt_password(cleartext_password),
            username=username or "",
            url=url,
            description=description,
            created_at=int(naive_utcnow().timestamp()),
        )
        profile.accounts.append(account)
        save_profile(engine, profile)
        return cleartext_password

    def list_all(self) -> list[Account]:
        _, profile = self._load_profile()
        return profile.accounts

    def show(self, identifier: Identifier, *, reveal_password: bool = False) -> dict:
        _, profile = self._load_profile()
        account = self._resolve_account(profile, identifier)

        data = {
            "id": account.id,
            "username": account.username,
            "url": account.url,
            "description": account.description,
            "created_at": account.created_at,
        }
        if reveal_password:
            data["password"] = self._decrypt_password(account.encrypted_password)
        return data

    def search(
        self, query: str, *, field: str = "all", limit: int = 20
    ) -> list[dict]:
        query_str = query.strip().lower()
        if not query_str:
            raise VaultConfigurationError("Search query cannot be empty.")

        valid_fields = {"all", "name", "username", "url", "description"}
        if field not in valid_fields:
            allowed = ", ".join(sorted(valid_fields))
            raise VaultConfigurationError(f"Invalid search field. Use one of: {allowed}.")

        _, profile = self._load_profile()
        matches: list[dict] = []

        for index, account in enumerate(profile.accounts, start=1):
            fields = {
                "name": account.id,
                "username": account.username or "",
                "url": account.url or "",
                "description": account.description or "",
            }

            if field == "all":
                is_match = any(query_str in value.lower() for value in fields.values())
            else:
                is_match = query_str in fields[field].lower()

            if not is_match:
                continue

            matches.append(
                {
                    "index": index,
                    "id": account.id,
                    "username": account.username,
                    "url": account.url,
                    "description": account.description,
                }
            )
            if len(matches) >= limit:
                break

        return matches

    def copy(self, identifier: Identifier, *, clear_after: int = 10) -> str:
        _, profile = self._load_profile()
        account = self._resolve_account(profile, identifier)
        decrypted_password = self._decrypt_password(account.encrypted_password)
        pyperclip.copy(decrypted_password)
        schedule_clipboard_clear(decrypted_password, clear_after)
        return account.id

    def update(
        self,
        identifier: Identifier,
        *,
        name: Optional[str] = None,
        password: Optional[str] = None,
        generate_password: bool = False,
        username: Optional[str] = None,
        url: Optional[str] = None,
        description: Optional[str] = None,
    ) -> dict:
        if generate_password and password:
            raise VaultConfigurationError(
                "Use either `password` or `generate_password`, not both."
            )

        engine, profile = self._load_profile()
        account = self._resolve_account(profile, identifier)

        updated_fields: list[str] = []
        generated_password: Optional[str] = None

        if name is not None and name != account.id:
            self._ensure_unique_name(profile, name, current_id=account.id)
            account.id = name
            updated_fields.append("name")

        if generate_password:
            generated_password = generate_random_password()
            account.encrypted_password = self._encrypt_password(generated_password)
            updated_fields.append("password")
        elif password is not None:
            account.encrypted_password = self._encrypt_password(password)
            updated_fields.append("password")

        if username is not None and username != account.username:
            account.username = username
            updated_fields.append("username")

        if url is not None and url != account.url:
            account.url = url
            updated_fields.append("url")

        if description is not None and description != account.description:
            account.description = description
            updated_fields.append("description")

        if updated_fields:
            save_profile(engine, profile)

        return {
            "id": account.id,
            "updated_fields": updated_fields,
            "generated_password": generated_password,
        }

    def rename(self, identifier: Identifier, new_name: str) -> dict:
        target_name = new_name.strip()
        if not target_name:
            raise VaultConfigurationError("New name cannot be empty.")

        engine, profile = self._load_profile()
        account = self._resolve_account(profile, identifier)
        previous_name = account.id

        if previous_name.lower() == target_name.lower():
            return {"old_id": previous_name, "new_id": previous_name, "changed": False}

        self._ensure_unique_name(profile, target_name, current_id=previous_name)
        account.id = target_name
        save_profile(engine, profile)
        return {"old_id": previous_name, "new_id": target_name, "changed": True}

    def delete(self, identifier: Identifier) -> str:
        engine, profile = self._load_profile()
        normalized = _normalize_identifier(identifier)
        account = self._resolve_account(profile, normalized)

        if isinstance(normalized, int):
            del profile.accounts[normalized]
        else:
            profile.remove_account(account.id)

        save_profile(engine, profile)
        return account.id


secret_manager = SecretManager()
