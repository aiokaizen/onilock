from typing import List, Optional
from pydantic import BaseModel, Field


class Password(BaseModel):
    id: str = Field(description="Password Identification")
    encrypted_password: str
    url: Optional[str] = Field(default=None, description="URL or Service name")


class Account(BaseModel):
    name: str
    master_password: str = Field(description="Hashed Master Password")
    passwords: List[Password] = Field(default=list)

    def get_password(self, id: str):
        for password in self.passwords:
            if password.id == id:
                return password
