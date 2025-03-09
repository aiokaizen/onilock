from typing import List, Optional
from pydantic import BaseModel, Field

from onilock.core.logging_manager import logger
from onilock.core.utils import naive_utcnow


# @TODO : Rename to Account
class Account(BaseModel):
    id: str = Field(description="Password Identification")
    username: str = Field(default="", description="Username")
    encrypted_password: str = Field(description="Encrypted Password")
    is_weak_password: bool = Field(default=True, description="Password is weak")
    url: Optional[str] = Field(default=None, description="URL or Service name")
    description: Optional[str] = Field(default=None, description="Description")
    created_at: int = Field(description="Creation date")


class File(BaseModel):
    id: str = Field(description="File ID")
    location: str = Field(description="File Location")
    created_at: int = Field(description="Creation date")
    src: str = Field(description="Source File")
    user: str = Field(description="Owner")
    host: str = Field(description="Owner Host")


class Profile(BaseModel):
    name: str
    master_password: str = Field(description="Hashed Master Password")
    vault_version: str = Field(default="", description="Vault version")
    creation_timestamp: float = Field(
        default=naive_utcnow().timestamp(), description="Creation time"
    )
    accounts: List[Account]
    files: List[File] = Field([])

    def get_account(self, id: str | int) -> Account | None:
        if isinstance(id, int):
            try:
                return self.accounts[id]
            except IndexError:
                logger.error("Invalid account index")
                return None

        for account in self.accounts:
            if account.id.lower() == id.lower():
                return account
        return None

    def remove_account(self, id: str):
        for index, password in enumerate(self.accounts):
            if password.id.lower() == id.lower():
                del self.accounts[index]
                break

    def get_file(self, id: str | int):
        if isinstance(id, int):
            try:
                return self.files[id]
            except IndexError:
                logger.error("Invalid file index")
                return None

        for file in self.files:
            if file.id == id:
                return file
        return None

    def remove_file(self, id: str):
        for index, file in enumerate(self.files):
            if file.id == id:
                del self.files[index]
                break
