"""Tests for onilock.core.encryption.encryption."""

import unittest
from unittest.mock import MagicMock, patch

from onilock.core.encryption.encryption import (
    BaseEncryptionBackend,
    EncryptionBackendManager,
    GPGEncryptionBackend,
    RemoteGPGEncryptionBackend,
)
from onilock.core.enums import GPGKeyIDType
from onilock.core.exceptions.exceptions import EncryptionKeyNotFoundError


class TestBaseEncryptionBackend(unittest.TestCase):
    """All methods on the base class should raise NotImplementedError."""

    def setUp(self):
        # Must subclass to instantiate (abstract-ish)
        class ConcreteBackend(BaseEncryptionBackend):
            pass

        with patch("onilock.core.encryption.encryption.settings") as ms:
            ms.PASSPHRASE = "test"
            self.backend = ConcreteBackend()

    def test_generate_key_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.generate_key()

    def test_list_keys_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.list_keys()

    def test_get_key_info_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.get_key_info("id", "type")

    def test_delete_key_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.delete_key("id", "type", "pass")

    def test_encrypt_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.encrypt("data")

    def test_decrypt_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.decrypt(b"data")

    def test_encrypt_file_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.encrypt_file("file.txt")

    def test_decrypt_file_raises(self):
        with self.assertRaises(NotImplementedError):
            self.backend.decrypt_file("file.txt.gpg")


class TestEncryptionBackendManager(unittest.TestCase):
    def _make_manager(self, mock_backend):
        manager = EncryptionBackendManager.__new__(EncryptionBackendManager)
        manager.backend = mock_backend
        return manager

    def test_generate_key_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.generate_key(name="test")
        mock_b.generate_key.assert_called_with(name="test")

    def test_list_keys_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.list_keys(secret=True)
        mock_b.list_keys.assert_called_with(True)

    def test_get_key_info_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.get_key_info("key_id", GPGKeyIDType.NAME_REAL)
        mock_b.get_key_info.assert_called_with(
            "key_id", GPGKeyIDType.NAME_REAL, secret=False
        )

    def test_delete_key_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.delete_key("key_id", GPGKeyIDType.NAME_REAL, "passphrase")
        mock_b.delete_key.assert_called()

    def test_encrypt_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.encrypt("plaintext", recipients=["test@test.com"])
        mock_b.encrypt.assert_called()

    def test_decrypt_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.decrypt(b"encrypted")
        mock_b.decrypt.assert_called_with(b"encrypted")

    def test_encrypt_file_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.encrypt_file("file.txt")
        mock_b.encrypt_file.assert_called_with("file.txt")

    def test_decrypt_file_delegates(self):
        mock_b = MagicMock()
        mgr = self._make_manager(mock_b)
        mgr.decrypt_file("file.txt.gpg")
        mock_b.decrypt_file.assert_called_with("file.txt.gpg")

    def test_default_backend_is_gpg(self):
        with patch(
            "onilock.core.encryption.encryption.GPGEncryptionBackend"
        ) as MockGPG:
            MockGPG.return_value = MagicMock()
            mgr = EncryptionBackendManager()
        MockGPG.assert_called_once()

    def test_custom_backend_used(self):
        mock_b = MagicMock()
        mgr = EncryptionBackendManager(backend=mock_b)
        self.assertIs(mgr.backend, mock_b)


class TestGPGEncryptionBackend(unittest.TestCase):
    """Tests for GPGEncryptionBackend with mocked gnupg.GPG."""

    def _make_backend(self, mock_gpg_instance, key_exists=True):
        """Helper to create a GPGEncryptionBackend with mocked GPG."""
        if key_exists:
            mock_gpg_instance.list_keys.return_value = [
                {
                    "uids": ["test_onilock_pgp <pgp@onilock.com>"],
                    "keyid": "ABCDEF123456",
                }
            ]
        else:
            mock_gpg_instance.list_keys.return_value = []

        with patch(
            "onilock.core.encryption.encryption.gnupg.GPG",
            return_value=mock_gpg_instance,
        ):
            with patch("onilock.core.encryption.encryption.settings") as ms:
                ms.PASSPHRASE = "test-pass"
                ms.GPG_HOME = "/tmp/test_gpg"
                ms.PGP_REAL_NAME = "test_onilock_pgp"
                ms.PGP_EMAIL = "pgp@onilock.com"
                backend = GPGEncryptionBackend()
        return backend

    def test_init_key_exists_no_generation(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.gen_key.assert_not_called()

    def test_init_key_missing_generates_key(self):
        mock_gpg = MagicMock()
        mock_gpg.list_keys.return_value = []  # No key found
        mock_gpg.gen_key_input.return_value = "input_data"
        mock_gpg.gen_key.return_value = MagicMock()

        with patch(
            "onilock.core.encryption.encryption.gnupg.GPG", return_value=mock_gpg
        ):
            with patch("onilock.core.encryption.encryption.settings") as ms:
                ms.PASSPHRASE = "test-pass"
                ms.GPG_HOME = "/tmp/test_gpg"
                ms.PGP_REAL_NAME = "test_onilock_pgp"
                ms.PGP_EMAIL = "pgp@onilock.com"
                backend = GPGEncryptionBackend()

        mock_gpg.gen_key.assert_called_once()

    def test_generate_key(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.gen_key_input.return_value = "input"
        mock_key = MagicMock()
        mock_gpg.gen_key.return_value = mock_key

        with patch("onilock.core.encryption.encryption.settings") as ms:
            ms.PGP_REAL_NAME = "test"
            ms.PGP_EMAIL = "test@test.com"
            ms.PASSPHRASE = "pass"
            result = backend.generate_key(
                name="test_key", email="a@b.com", passphrase="p"
            )

        self.assertIs(result, mock_key)

    def test_list_keys(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.list_keys.return_value = [{"keyid": "ABC"}]
        result = backend.list_keys()
        self.assertEqual(result, [{"keyid": "ABC"}])

    def test_list_keys_secret(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        backend.list_keys(secret=True)
        mock_gpg.list_keys.assert_called_with(secret=True)

    def test_get_key_info_by_name_found(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.list_keys.return_value = [
            {
                "uids": ["mykey <email@test.com>"],
                "keyid": "ABC123",
                "fingerprint": "FP1",
            }
        ]
        result = backend.get_key_info("mykey", GPGKeyIDType.NAME_REAL)
        self.assertIsNotNone(result)
        self.assertEqual(result["keyid"], "ABC123")

    def test_get_key_info_by_name_not_found(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.list_keys.return_value = [
            {"uids": ["otherkey <email@test.com>"], "keyid": "ABC123"}
        ]
        result = backend.get_key_info("mykey", GPGKeyIDType.NAME_REAL)
        self.assertIsNone(result)

    def test_get_key_info_by_key_id_found(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.list_keys.return_value = [
            {
                "uids": ["mykey <email@test.com>"],
                "keyid": "ABC123",
                "fingerprint": "FP1",
            }
        ]
        result = backend.get_key_info("ABC123", GPGKeyIDType.KEY_ID)
        self.assertIsNotNone(result)

    def test_get_key_info_by_key_id_not_found(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.list_keys.return_value = [
            {"uids": ["mykey <email@test.com>"], "keyid": "OTHER"}
        ]
        result = backend.get_key_info("ABC123", GPGKeyIDType.KEY_ID)
        self.assertIsNone(result)

    def test_delete_key_success(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)

        key_info = {
            "fingerprint": "FINGERPRINT123",
            "uids": ["test_onilock_pgp <pgp@onilock.com>"],
            "keyid": "ABC",
        }
        mock_gpg.list_keys.return_value = [key_info]

        backend.delete_key("test_onilock_pgp", GPGKeyIDType.NAME_REAL, "passphrase")
        mock_gpg.delete_keys.assert_any_call(
            "FINGERPRINT123", secret=True, passphrase="passphrase"
        )
        mock_gpg.delete_keys.assert_any_call("FINGERPRINT123")

    def test_delete_key_not_found_raises(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_gpg.list_keys.return_value = []  # No keys

        with self.assertRaises(EncryptionKeyNotFoundError):
            backend.delete_key("nonexistent", GPGKeyIDType.NAME_REAL, "pass")

    def test_encrypt_delegates_to_gpg(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_result = MagicMock()
        mock_gpg.encrypt.return_value = mock_result

        with patch("onilock.core.encryption.encryption.settings") as ms:
            ms.PGP_EMAIL = "pgp@test.com"
            result = backend.encrypt("plaintext")
        self.assertIs(result, mock_result)

    def test_decrypt_delegates_to_gpg(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        mock_result = MagicMock()
        mock_gpg.decrypt.return_value = mock_result

        result = backend.decrypt(b"encrypted")
        self.assertIs(result, mock_result)

    def test_encrypt_file_raises(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        with self.assertRaises(NotImplementedError):
            backend.encrypt_file("file.txt")

    def test_decrypt_file_raises(self):
        mock_gpg = MagicMock()
        backend = self._make_backend(mock_gpg, key_exists=True)
        with self.assertRaises(NotImplementedError):
            backend.decrypt_file("file.gpg", "passphrase")


class TestRemoteGPGEncryptionBackend(unittest.TestCase):
    def test_instantiates_ok(self):
        with patch("onilock.core.encryption.encryption.settings") as ms:
            ms.PASSPHRASE = "test"
            backend = RemoteGPGEncryptionBackend()
        self.assertIsNotNone(backend)


if __name__ == "__main__":
    unittest.main()
