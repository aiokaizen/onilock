from typing import Optional
import gnupg


def generate_pgp_key(gpg_home: Optional[str], name: str, email: str, passphrase: str):
    """Generate a new PGP key pair."""
    gpg = gnupg.GPG(gnupghome=gpg_home)
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
    gpg = gnupg.GPG(gnupghome=gpg_home)
    keys = gpg.list_keys()

    if key_fingerprint:
        return any(key["fingerprint"] == key_fingerprint for key in keys)

    if key_id:
        # Key IDs are the last 16 characters of the fingerprint
        return any(key_id in key.get("keyid", "") for key in keys)

    if real_name:
        return any(
            real_name == uid.split(" ")[0] for key in keys for uid in key.get("uids")
        )

    return False


def get_pgp_key_info(
    gpg_home: Optional[str] = None,
    real_name: Optional[str] = None,
    key_id: Optional[str] = None,
) -> dict:
    """Get key details if exists in keyring."""
    gpg = gnupg.GPG(gnupghome=gpg_home)
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
    gpg = gnupg.GPG(gnupghome=gpg_home)
    key_info = get_pgp_key_info(gpg_home, real_name, key_id)
    fingerprint = key_info["fingerprint"]

    # Delete the secret key first
    gpg.delete_keys(
        fingerprint,
        secret=True,
        passphrase=passphrase,
    )

    # Then delete the public key
    gpg.delete_keys(fingerprint)
