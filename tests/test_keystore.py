"""Tests for onilock.core.keystore (VaultKeyStore, KeyRing, KeyStoreManager)."""

import os
import unittest
from unittest.mock import MagicMock, patch

from onilock.core.keystore import VaultKeyStore, KeyRing, KeyStoreManager, KeyStore


class TestVaultKeyStore(unittest.TestCase):
    """Test the file-based AES-CBC key store."""

    def setUp(self):
        self.vault_dir = "/tmp/test_onilock_vault_ks"
        os.makedirs(self.vault_dir, exist_ok=True)
        self._patch_home = patch(
            "onilock.core.keystore.os.path.expanduser",
            return_value=self.vault_dir.rstrip("/vault").rstrip(
                "/test_onilock_vault_ks"
            ),
        )
        # Patch expanduser to return a controlled temp dir
        self._patcher = patch(
            "onilock.core.keystore.os.path.join",
            side_effect=self._patched_join,
        )
        self._patched_basedir = self.vault_dir

    def _patched_join(self, *args):
        """Redirect vault basedir to tmp dir."""
        if args and args[0] == os.path.expanduser("~"):
            return os.path.join(self._patched_basedir, *args[1:])
        return os.path.join(*args)

    def _make_store(self, keystore_id="test_onilock"):
        """Create a VaultKeyStore with vault dir redirected to tmp."""
        with patch.object(
            VaultKeyStore,
            "__init__",
            wraps=VaultKeyStore.__init__,
        ):
            store = VaultKeyStore.__new__(VaultKeyStore)
            store.keystore_id = keystore_id
            store.BLOCK_SIZE = 16
            from Crypto.Random import get_random_bytes
            from Crypto.Cipher import AES
            import hashlib, uuid

            keystore_basedir = self.vault_dir
            os.makedirs(keystore_basedir, exist_ok=True)
            hashcode = hashlib.sha256(__file__.encode()).hexdigest()
            store.key = hashcode[:32].encode()
            store.iv = get_random_bytes(16)
            filename = str(uuid.uuid5(uuid.NAMESPACE_DNS, keystore_id)).split("-")[-1]
            store.filename = os.path.join(keystore_basedir, f"{filename}.oni")
            return store

    def tearDown(self):
        import shutil

        if os.path.exists(self.vault_dir):
            shutil.rmtree(self.vault_dir, ignore_errors=True)

    def test_set_and_get_password(self):
        store = self._make_store()
        store.set_password("mykey", "myvalue")
        result = store.get_password("mykey")
        self.assertEqual(result, "myvalue")

    def test_get_password_missing_key_returns_none(self):
        store = self._make_store()
        result = store.get_password("nonexistent")
        self.assertIsNone(result)

    def test_delete_password(self):
        store = self._make_store()
        store.set_password("del_key", "del_val")
        store.delete_password("del_key")
        self.assertIsNone(store.get_password("del_key"))

    def test_read_keystore_file_not_found_returns_empty(self):
        store = self._make_store()
        store.filename = "/tmp/nonexistent_keystore_xyz.oni"
        result = store._read_keystore()
        self.assertEqual(result, {})

    def test_clear_removes_file(self):
        store = self._make_store()
        store.set_password("k", "v")
        self.assertTrue(os.path.exists(store.filename))
        store.clear()
        self.assertFalse(os.path.exists(store.filename))

    def test_multiple_passwords(self):
        store = self._make_store()
        store.set_password("k1", "v1")
        store.set_password("k2", "v2")
        self.assertEqual(store.get_password("k1"), "v1")
        self.assertEqual(store.get_password("k2"), "v2")


class TestKeyRing(unittest.TestCase):
    """Test the system keyring-backed key store."""

    def test_set_get_delete(self):
        with patch("onilock.core.keystore.keyring") as mock_kr:
            mock_kr.get_password.return_value = None
            store = KeyRing("test_onilock")

            store.set_password("user", "pass123")
            mock_kr.set_password.assert_called_with("test_onilock", "user", "pass123")

            mock_kr.get_password.return_value = "pass123"
            result = store.get_password("user")
            self.assertEqual(result, "pass123")

            store.delete_password("user")
            mock_kr.delete_password.assert_called()

    def test_clear(self):
        with patch("onilock.core.keystore.keyring") as mock_kr:
            mock_kr.get_password.return_value = None
            store = KeyRing("test_onilock")
            store.set_password("k1", "v1")
            store.set_password("k2", "v2")
            store.clear()
            self.assertEqual(mock_kr.delete_password.call_count, 2)

    def test_init_fails_if_keyring_unavailable(self):
        with patch("onilock.core.keystore.keyring") as mock_kr:
            mock_kr.get_password.side_effect = Exception("no keyring")
            with self.assertRaises(Exception):
                KeyRing("test_onilock")


class TestKeyStoreManager(unittest.TestCase):
    def test_selects_keyring_when_available(self):
        with patch.dict(os.environ, {"ONI_DEFAULT_KEYSTORE_BACKEND": "keyring"}):
            with patch("onilock.core.keystore.KeyRing") as MockKeyRing:
                MockKeyRing.return_value = MagicMock()
                manager = KeyStoreManager("onilock")
        self.assertIsNotNone(manager.keystore)

    def test_falls_back_to_vault_when_keyring_unavailable(self):
        with patch.dict(os.environ, {"ONI_DEFAULT_KEYSTORE_BACKEND": "keyring"}):
            with patch("onilock.core.keystore.KeyRing", side_effect=Exception("no kr")):
                manager = KeyStoreManager("onilock_fallback_test")
        self.assertIsInstance(manager.keystore, VaultKeyStore)

    def test_selects_vault_when_backend_set(self):
        with patch.dict(os.environ, {"ONI_DEFAULT_KEYSTORE_BACKEND": "vault"}):
            manager = KeyStoreManager("onilock_vault_test")
        self.assertIsInstance(manager.keystore, VaultKeyStore)

    def test_manager_delegates_set_get_delete(self):
        mock_store = MagicMock()
        with patch.dict(os.environ, {"ONI_DEFAULT_KEYSTORE_BACKEND": "vault"}):
            manager = KeyStoreManager("onilock_delegate")
        manager.keystore = mock_store

        manager.set_password("k", "v")
        mock_store.set_password.assert_called_with("k", "v")

        manager.get_password("k")
        mock_store.get_password.assert_called_with("k")

        manager.delete_password("k")
        mock_store.delete_password.assert_called_with("k")

        manager.clear()
        mock_store.clear.assert_called_once()


class TestKeyStoreAbstract(unittest.TestCase):
    """Test that KeyStore._passwords set is shared across instances."""

    def test_passwords_set_is_class_level(self):
        KeyStore._passwords = set()
        # Indirectly verify through VaultKeyStore (which calls super)
        store_dir = "/tmp/test_ks_class_level"
        os.makedirs(store_dir, exist_ok=True)
        try:
            store = VaultKeyStore.__new__(VaultKeyStore)
            store.keystore_id = "test"
            store.BLOCK_SIZE = 16
            from Crypto.Random import get_random_bytes
            import hashlib, uuid

            hashcode = hashlib.sha256(__file__.encode()).hexdigest()
            store.key = hashcode[:32].encode()
            store.iv = get_random_bytes(16)
            store.filename = os.path.join(store_dir, "test.oni")

            store.set_password("key1", "val1")
            self.assertIn("key1", KeyStore._passwords)
        finally:
            import shutil

            shutil.rmtree(store_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
