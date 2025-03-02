from enum import Enum


class GPGKeyIDType(Enum):
    """GPG Key ID Type Enum"""

    NAME_REAL = "name_real"
    KEY_ID = "key_id"
    FINGERPRINT = "fingerprint"
