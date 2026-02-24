"""
Shared test configuration and fixtures for OniLock tests.

Bootstrap order (must happen BEFORE any onilock import):
  1. Redirect HOME → temp dir so VaultKeyStore never touches ~/.onilock/vault/
  2. Set ONI_* env vars so Settings() uses known values, not keystore lookups
  3. Stub out the `gnupg` C-extension module so FileEncryptionManager() and
     GPGEncryptionBackend.__init__() don't run real GPG at module-import time.
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock

# ── 1. Isolate home directory ────────────────────────────────────────────────
# VaultKeyStore hardcodes os.path.expanduser("~"), so redirect HOME to a fresh
# temp dir. This prevents import-time reads of any existing production vault
# files (which can fail with padding errors if written by a different install).
_TEST_HOME_DIR = tempfile.mkdtemp(prefix="onilock_test_home_")
os.environ["HOME"] = _TEST_HOME_DIR

# ── 2. Env vars (used by Settings.__init__ before keystore is ever touched) ──
from cryptography.fernet import Fernet  # noqa: E402 – must be after HOME redirect

_TEST_SECRET_KEY = Fernet.generate_key().decode()
os.environ["ONI_SECRET_KEY"] = _TEST_SECRET_KEY
os.environ["ONI_GPG_PASSPHRASE"] = "test-passphrase-for-testing"
os.environ["ONI_DEFAULT_KEYSTORE_BACKEND"] = "vault"
os.environ["ONI_DEBUG"] = "false"
os.environ["ONI_PGP_REAL_NAME"] = "test_onilock_pgp"
os.environ["ONI_DB_NAME"] = "test_profile"

# ── 3. Stub gnupg before any onilock module imports it ───────────────────────
# FileEncryptionManager() and GPGEncryptionBackend.__init__() call gnupg.GPG()
# at module/instance level; without this stub the test session would either
# require a real GPG installation or generate RSA-4096 keys on every test run.
_mock_gpg_instance = MagicMock()
_mock_gpg_instance.list_keys.return_value = []
_mock_gpg_instance.gen_key_input.return_value = "key_input_data"
_mock_gpg_instance.gen_key.return_value = MagicMock()
_mock_gpg_instance.encrypt.return_value = MagicMock(ok=True, data=b"enc", status="ok")
_mock_gpg_instance.decrypt.return_value = MagicMock(ok=True, data=b"dec", status="ok")

_mock_gnupg_module = MagicMock()
_mock_gnupg_module.GPG.return_value = _mock_gpg_instance
sys.modules["gnupg"] = _mock_gnupg_module

# ── Now it is safe to import pytest and onilock ──────────────────────────────
import pytest  # noqa: E402
from unittest.mock import patch  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset module-level singletons before and after every test."""
    from onilock.db.database_manager import DatabaseManager
    from onilock.core.keystore import KeyStore

    DatabaseManager._instance = None
    KeyStore._passwords = set()

    yield

    DatabaseManager._instance = None
    KeyStore._passwords = set()


@pytest.fixture
def tmp_vault(tmp_path, monkeypatch):
    """Temporary vault dir; patches settings.VAULT_DIR and SETUP_FILEPATH."""
    from onilock.core.settings import settings

    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    monkeypatch.setattr(settings, "VAULT_DIR", vault_dir)
    monkeypatch.setattr(settings, "SETUP_FILEPATH", str(vault_dir / "setup_test.oni"))
    return vault_dir


@pytest.fixture
def mock_gpg():
    """A fresh MagicMock simulating gnupg.GPG with sensible defaults."""
    gpg = MagicMock()
    gpg.list_keys.return_value = []
    gpg.gen_key_input.return_value = "key_input_data"
    mock_key = MagicMock()
    mock_key.__str__ = lambda self: "DEADBEEF1234"
    gpg.gen_key.return_value = mock_key

    enc = MagicMock(ok=True, data=b"encrypted_data", status="encryption ok")
    gpg.encrypt.return_value = enc

    dec = MagicMock(ok=True, data=b"decrypted_data", status="decryption ok")
    gpg.decrypt.return_value = dec

    return gpg


@pytest.fixture
def mock_engine():
    """A MagicMock simulating a DB engine."""
    engine = MagicMock()
    engine.read.return_value = {}
    engine.write.return_value = None
    return engine
