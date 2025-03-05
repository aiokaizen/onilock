from enum import Enum


class DBBackEndEnum(Enum):
    JSON = "Json"
    SQLITE = "SQLite"  # Not implemented yet
    POSTGRES = "PostgreSQL"  # Not implemented yet


class KeyStoreBackendEnum(Enum):
    VAULT = "vault"
    KEYRING = "keyring"


class GPGKeyIDType(Enum):
    """GPG Key ID Type Enum"""

    NAME_REAL = "name_real"
    KEY_ID = "key_id"
    FINGERPRINT = "fingerprint"
