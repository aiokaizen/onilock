from typing import Optional
import gnupg

from onilock.core.dependencies import GNUPG, ensure_installed
from onilock.core.exceptions.exceptions import GPGNotAvailableError


def get_gpg(gpg_home: Optional[str] = None, **kwargs) -> gnupg.GPG:
    """
    Create a GPG client, offering to install GnuPG if it is missing.

    Raises:
        GPGNotAvailableError: If gpg is missing and was not installed.
    """
    try:
        return gnupg.GPG(gnupghome=gpg_home, **kwargs)
    except OSError as exc:
        if GNUPG.is_installed():
            raise
        if ensure_installed([GNUPG]):
            return gnupg.GPG(gnupghome=gpg_home, **kwargs)
        raise GPGNotAvailableError(
            "This command needs GnuPG (gpg), which is not installed."
        ) from exc


def generate_pgp_key(gpg_home: Optional[str], name: str, email: str, passphrase: str):
    """Generate a new PGP key pair."""
    gpg = get_gpg(gpg_home)
    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=4096,  # ALT: 3072
        name_real=name,
        name_email=email,
        passphrase=passphrase,
    )
    return gpg.gen_key(input_data)


def pgp_key_exists(
    gpg_home: Optional[str],
    key_fingerprint: Optional[str] = None,
    key_id: Optional[str] = None,
    real_name: Optional[str] = None,
) -> bool:
    """Check if a key exists in the keyring."""
    gpg = get_gpg(gpg_home)
    keys = gpg.list_keys()

    if key_fingerprint:
        return any(key["fingerprint"] == key_fingerprint for key in keys)

    if key_id:
        # Key IDs are the last 16 characters of the fingerprint
        return any(key_id in key.get("keyid", "") for key in keys)

    if real_name:
        return any(
            real_name == uid.split(" ")[0]
            for key in keys
            for uid in key.get("uids", [])
        )

    return False


def get_pgp_key_info(
    gpg_home: Optional[str] = None,
    real_name: Optional[str] = None,
    key_id: Optional[str] = None,
) -> dict:
    """Get key details if exists in keyring."""
    gpg = get_gpg(gpg_home)
    keys = gpg.list_keys()

    for key in keys:
        uids = key.get("uids", [])

        if real_name:
            if any(real_name == uid.split(" ")[0] for uid in uids):
                return key
        elif key_id:
            if key_id == key.get("keyid"):
                return key

    return None


def delete_pgp_key(
    *,
    passphrase: str,
    gpg_home: Optional[str] = None,
    real_name: Optional[str] = None,
    key_id: Optional[str] = None,
):
    """Delete PGP public and private key."""
    from onilock.core.exceptions.exceptions import EncryptionKeyNotFoundError

    gpg = get_gpg(gpg_home)
    key_info = get_pgp_key_info(gpg_home, real_name, key_id)
    if key_info is None:
        raise EncryptionKeyNotFoundError()
    fingerprint = key_info["fingerprint"]

    # Delete the secret key first
    gpg.delete_keys(
        fingerprint,
        secret=True,
        passphrase=passphrase,
    )

    # Then delete the public key
    gpg.delete_keys(fingerprint)
