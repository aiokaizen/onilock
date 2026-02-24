"""Tests for onilock.core.utils."""

import os
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

from onilock.core.utils import (
    get_base_dir,
    getlogin,
    naive_utcnow,
    clear_clipboard_after_delay,
    get_version,
    generate_random_password,
    generate_key,
    get_secret_key,
    get_passphrase,
    str_to_bool,
)


class TestGetBaseDir(unittest.TestCase):
    def test_returns_string(self):
        result = get_base_dir()
        self.assertIsInstance(result, str)

    def test_is_directory(self):
        result = get_base_dir()
        self.assertTrue(os.path.isdir(result))


class TestGetlogin(unittest.TestCase):
    def test_returns_nonempty_string(self):
        result = getlogin()
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)


class TestNaiveUtcNow(unittest.TestCase):
    def test_returns_datetime(self):
        result = naive_utcnow()
        self.assertIsInstance(result, datetime)

    def test_no_timezone(self):
        result = naive_utcnow()
        self.assertIsNone(result.tzinfo)


class TestClearClipboardAfterDelay(unittest.TestCase):
    @patch("onilock.core.utils.pyperclip")
    @patch("onilock.core.utils.time.sleep")
    def test_clears_without_readback(self, mock_sleep, mock_pyperclip):
        clear_clipboard_after_delay(delay=0)
        mock_pyperclip.copy.assert_called_once_with("")

    @patch("onilock.core.utils.pyperclip")
    @patch("onilock.core.utils.time.sleep")
    def test_silences_exception(self, mock_sleep, mock_pyperclip):
        mock_pyperclip.copy.side_effect = Exception("clipboard error")
        # Should not raise
        clear_clipboard_after_delay(delay=0)


class TestGetVersion(unittest.TestCase):
    @patch("onilock.core.utils.importlib.metadata.version")
    def test_returns_version_from_metadata(self, mock_version):
        mock_version.return_value = "9.9.9"
        result = get_version()
        self.assertEqual(result, "9.9.9")

    @patch("onilock.core.utils.importlib.metadata.version")
    @patch("onilock.core.utils.Path")
    def test_returns_version_from_pyproject_toml(self, mock_path_cls, mock_version):
        mock_version.side_effect = ModuleNotFoundError()
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.open.return_value.__enter__.return_value = iter(
            ['name = "onilock"\n', 'version = "1.2.3"\n', "other = True\n"]
        )
        mock_path_cls.return_value = mock_path
        result = get_version()
        self.assertEqual(result, "1.2.3")

    @patch("onilock.core.utils.importlib.metadata.version")
    @patch("onilock.core.utils.Path")
    def test_returns_fallback_when_no_pyproject(self, mock_path_cls, mock_version):
        mock_version.side_effect = ModuleNotFoundError()
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_path_cls.return_value = mock_path
        result = get_version()
        self.assertEqual(result, "0.0.1")

    @patch("onilock.core.utils.importlib.metadata.version")
    @patch("onilock.core.utils.Path")
    def test_returns_fallback_when_version_not_in_pyproject(
        self, mock_path_cls, mock_version
    ):
        mock_version.side_effect = ModuleNotFoundError()
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.open.return_value.__enter__.return_value = iter(
            ['name = "onilock"\n', 'description = "test"\n']
        )
        mock_path_cls.return_value = mock_path
        result = get_version()
        self.assertEqual(result, "0.0.1")


class TestGenerateRandomPassword(unittest.TestCase):
    def test_length_is_respected(self):
        """The output length must equal the requested length."""
        for n in (8, 12, 20, 32):
            with self.subTest(length=n):
                pwd = generate_random_password(n)
                self.assertEqual(len(pwd), n)

    def test_length_without_special_chars(self):
        pwd = generate_random_password(12, include_special_characters=False)
        self.assertEqual(len(pwd), 12)

    def test_contains_uppercase(self):
        """Password must always contain at least one uppercase letter."""
        for _ in range(20):
            pwd = generate_random_password(12)
            self.assertTrue(any(c.isupper() for c in pwd))

    def test_contains_lowercase(self):
        """Password must always contain at least one lowercase letter."""
        for _ in range(20):
            pwd = generate_random_password(12)
            self.assertTrue(any(c.islower() for c in pwd))

    def test_contains_digit(self):
        """Password must always contain at least one digit."""
        for _ in range(20):
            pwd = generate_random_password(12)
            self.assertTrue(any(c.isdigit() for c in pwd))

    def test_contains_special_when_requested(self):
        """Password must include at least one special character when requested."""
        special = set("@$!%*?&_}{()-=+")
        for _ in range(20):
            pwd = generate_random_password(12, include_special_characters=True)
            self.assertTrue(any(c in special for c in pwd))

    def test_no_special_chars_when_excluded(self):
        special = "@$!%*?&_}{()-=+"
        for _ in range(20):
            pwd = generate_random_password(12, include_special_characters=False)
            self.assertFalse(any(c in special for c in pwd))

    def test_returns_string(self):
        pwd = generate_random_password()
        self.assertIsInstance(pwd, str)


class TestGenerateKey(unittest.TestCase):
    def test_returns_valid_fernet_key(self):
        key = generate_key()
        self.assertIsInstance(key, str)
        # Should be a valid Fernet key (decodable and 44 chars base64url)
        Fernet(key.encode())  # should not raise

    def test_unique_keys(self):
        k1 = generate_key()
        k2 = generate_key()
        self.assertNotEqual(k1, k2)


class TestGetSecretKey(unittest.TestCase):
    def test_returns_stored_key(self):
        with patch("onilock.core.utils.keystore") as mock_ks:
            mock_ks.get_password.return_value = "stored-key-abc"
            result = get_secret_key()
        self.assertEqual(result, "stored-key-abc")

    def test_generates_and_stores_when_missing(self):
        with patch("onilock.core.utils.keystore") as mock_ks:
            mock_ks.get_password.return_value = None
            result = get_secret_key()
        # Should have called set_password with a new key
        mock_ks.set_password.assert_called_once()
        args = mock_ks.set_password.call_args[0]
        # Second arg is the new key
        Fernet(args[1].encode())  # valid Fernet key


class TestGetPassphrase(unittest.TestCase):
    def test_returns_stored_passphrase(self):
        with patch("onilock.core.utils.keystore") as mock_ks:
            mock_ks.get_password.return_value = "stored-passphrase"
            result = get_passphrase()
        self.assertEqual(result, "stored-passphrase")

    def test_generates_and_stores_when_missing(self):
        with patch("onilock.core.utils.keystore") as mock_ks:
            mock_ks.get_password.return_value = None
            result = get_passphrase()
        mock_ks.set_password.assert_called_once()
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)


class TestStrToBool(unittest.TestCase):
    def test_truthful_values(self):
        for s in ("true", "1", "t", "yes", "on", "TRUE", "Yes", "ON"):
            with self.subTest(s=s):
                self.assertTrue(str_to_bool(s))

    def test_untruthful_values(self):
        for s in ("false", "0", "f", "no", "off", "FALSE", "No", "OFF"):
            with self.subTest(s=s):
                self.assertFalse(str_to_bool(s))

    def test_invalid_raises_value_error(self):
        for s in ("maybe", "2", "nope", "truee"):
            with self.subTest(s=s):
                with self.assertRaises(ValueError):
                    str_to_bool(s)


if __name__ == "__main__":
    unittest.main()
