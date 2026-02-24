"""Tests for onilock.core.gpg utility functions."""

import unittest
from unittest.mock import MagicMock, patch

from onilock.core.gpg import (
    generate_pgp_key,
    pgp_key_exists,
    get_pgp_key_info,
    delete_pgp_key,
)


def _make_mock_gpg(keys=None):
    """Return a MagicMock for gnupg.GPG with a configurable key list."""
    gpg = MagicMock()
    gpg.list_keys.return_value = keys or []
    return gpg


_SAMPLE_KEYS = [
    {
        "fingerprint": "ABCDEF1234567890",
        "keyid": "ABCDEF12",
        "uids": ["testkey <test@onilock.com>", "testkey (comment) <other@test.com>"],
    }
]


class TestGeneratePgpKey(unittest.TestCase):
    def test_calls_gen_key_input_and_gen_key(self):
        mock_gpg = MagicMock()
        mock_gpg.gen_key_input.return_value = "key_input"
        mock_key = MagicMock()
        mock_gpg.gen_key.return_value = mock_key

        with patch("onilock.core.gpg.gnupg.GPG", return_value=mock_gpg):
            result = generate_pgp_key(
                gpg_home="/tmp/gpg",
                name="testkey",
                email="test@onilock.com",
                passphrase="mypassphrase",
            )

        mock_gpg.gen_key_input.assert_called_once_with(
            key_type="RSA",
            key_length=4096,
            name_real="testkey",
            name_email="test@onilock.com",
            passphrase="mypassphrase",
        )
        mock_gpg.gen_key.assert_called_once_with("key_input")
        self.assertIs(result, mock_key)


class TestPgpKeyExists(unittest.TestCase):
    def test_by_fingerprint_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None, key_fingerprint="ABCDEF1234567890")
        self.assertTrue(result)

    def test_by_fingerprint_not_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None, key_fingerprint="FFFFFFFFFFFFFFFF")
        self.assertFalse(result)

    def test_by_key_id_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None, key_id="ABCDEF12")
        self.assertTrue(result)

    def test_by_key_id_not_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None, key_id="NOTFOUND")
        self.assertFalse(result)

    def test_by_real_name_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None, real_name="testkey")
        self.assertTrue(result)

    def test_by_real_name_not_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None, real_name="otherkey")
        self.assertFalse(result)

    def test_no_criteria_returns_false(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = pgp_key_exists(None)
        self.assertFalse(result)

    def test_empty_keyring_returns_false(self):
        with patch("onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg([])):
            result = pgp_key_exists(None, real_name="testkey")
        self.assertFalse(result)


class TestGetPgpKeyInfo(unittest.TestCase):
    def test_by_real_name_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = get_pgp_key_info(None, real_name="testkey")
        self.assertIsNotNone(result)
        self.assertEqual(result["fingerprint"], "ABCDEF1234567890")

    def test_by_real_name_not_found_returns_none(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = get_pgp_key_info(None, real_name="nonexistent")
        self.assertIsNone(result)

    def test_by_key_id_found(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = get_pgp_key_info(None, key_id="ABCDEF12")
        self.assertIsNotNone(result)

    def test_by_key_id_not_found_returns_none(self):
        with patch(
            "onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg(_SAMPLE_KEYS)
        ):
            result = get_pgp_key_info(None, key_id="NOTFOUND")
        self.assertIsNone(result)

    def test_empty_keyring_returns_none(self):
        with patch("onilock.core.gpg.gnupg.GPG", return_value=_make_mock_gpg([])):
            result = get_pgp_key_info(None, real_name="testkey")
        self.assertIsNone(result)


class TestDeletePgpKey(unittest.TestCase):
    def test_deletes_secret_then_public(self):
        mock_gpg = _make_mock_gpg(_SAMPLE_KEYS)

        with patch("onilock.core.gpg.gnupg.GPG", return_value=mock_gpg):
            delete_pgp_key(
                passphrase="mypass",
                gpg_home="/tmp/gpg",
                real_name="testkey",
            )

        # Should delete secret key first, then public key
        calls = mock_gpg.delete_keys.call_args_list
        self.assertEqual(len(calls), 2)
        # First call: secret=True
        self.assertTrue(
            calls[0][1].get("secret") or calls[0][0][1]
            if len(calls[0][0]) > 1
            else False or calls[0][1].get("secret", False)
        )
        # Second call: no secret flag (public key)
        self.assertEqual(calls[1][0][0], "ABCDEF1234567890")


if __name__ == "__main__":
    unittest.main()
