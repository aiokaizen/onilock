"""Tests for onilock.db.models (Account, File, Profile)."""

import unittest

from onilock.db.models import Account, File, Profile
from onilock.core.utils import naive_utcnow


def _make_account(id="github", password="enc_pwd", username="user", created_at=None):
    return Account(
        id=id,
        encrypted_password=password,
        username=username,
        created_at=created_at or int(naive_utcnow().timestamp()),
    )


def _make_file(id="file1", location="/vault/abc.oni", src="/home/user/doc.txt"):
    return File(
        id=id,
        location=location,
        created_at=int(naive_utcnow().timestamp()),
        src=src,
        user="testuser",
        host="localhost",
    )


def _make_profile(accounts=None, files=None):
    return Profile(
        name="test_profile",
        master_password="hashed_pw",
        accounts=accounts or [],
        files=files or [],
    )


class TestAccount(unittest.TestCase):
    def test_creation_valid(self):
        ts = int(naive_utcnow().timestamp())
        account = Account(
            id="github",
            encrypted_password="enc",
            username="alice",
            url="https://github.com",
            description="My GitHub account",
            created_at=ts,
        )
        self.assertEqual(account.id, "github")
        self.assertEqual(account.username, "alice")
        self.assertEqual(account.url, "https://github.com")
        self.assertEqual(account.description, "My GitHub account")
        self.assertEqual(account.created_at, ts)

    def test_default_values(self):
        account = _make_account()
        self.assertEqual(account.username, "user")
        self.assertIsNone(account.url)
        self.assertIsNone(account.description)
        self.assertTrue(account.is_weak_password)  # default

    def test_url_and_description_optional(self):
        account = Account(id="x", encrypted_password="e", username="u", created_at=0)
        self.assertIsNone(account.url)
        self.assertIsNone(account.description)


class TestFile(unittest.TestCase):
    def test_creation_valid(self):
        ts = int(naive_utcnow().timestamp())
        f = File(
            id="doc",
            location="/vault/abc.oni",
            created_at=ts,
            src="/home/user/doc.txt",
            user="alice",
            host="myhost",
        )
        self.assertEqual(f.id, "doc")
        self.assertEqual(f.user, "alice")
        self.assertEqual(f.host, "myhost")
        self.assertEqual(f.created_at, ts)


class TestProfile(unittest.TestCase):
    def test_creation_defaults(self):
        p = _make_profile()
        self.assertEqual(p.name, "test_profile")
        self.assertEqual(p.accounts, [])
        self.assertEqual(p.files, [])
        self.assertEqual(p.vault_version, "")
        self.assertIsInstance(p.creation_timestamp, float)

    # --- get_account ---

    def test_get_account_by_name_found(self):
        a = _make_account("github")
        p = _make_profile(accounts=[a])
        result = p.get_account("github")
        self.assertIs(result, a)

    def test_get_account_by_name_case_insensitive(self):
        a = _make_account("GitHub")
        p = _make_profile(accounts=[a])
        result = p.get_account("github")
        self.assertIs(result, a)

    def test_get_account_by_name_not_found(self):
        p = _make_profile()
        self.assertIsNone(p.get_account("unknown"))

    def test_get_account_by_index_found(self):
        a = _make_account("github")
        p = _make_profile(accounts=[a])
        result = p.get_account(0)
        self.assertIs(result, a)

    def test_get_account_by_index_out_of_bounds(self):
        p = _make_profile()
        self.assertIsNone(p.get_account(99))

    # --- remove_account ---

    def test_remove_account_found(self):
        a = _make_account("github")
        p = _make_profile(accounts=[a])
        p.remove_account("github")
        self.assertEqual(p.accounts, [])

    def test_remove_account_not_found(self):
        a = _make_account("github")
        p = _make_profile(accounts=[a])
        p.remove_account("nonexistent")  # should not raise
        self.assertEqual(len(p.accounts), 1)

    def test_remove_account_case_insensitive(self):
        a = _make_account("GitHub")
        p = _make_profile(accounts=[a])
        p.remove_account("github")
        self.assertEqual(p.accounts, [])

    # --- get_file ---

    def test_get_file_by_id_found(self):
        f = _make_file("doc")
        p = _make_profile(files=[f])
        result = p.get_file("doc")
        self.assertIs(result, f)

    def test_get_file_by_id_not_found(self):
        p = _make_profile()
        self.assertIsNone(p.get_file("missing"))

    def test_get_file_by_index_found(self):
        f = _make_file("doc")
        p = _make_profile(files=[f])
        result = p.get_file(0)
        self.assertIs(result, f)

    def test_get_file_by_index_out_of_bounds(self):
        p = _make_profile()
        self.assertIsNone(p.get_file(99))

    # --- remove_file ---

    def test_remove_file_found(self):
        f = _make_file("doc")
        p = _make_profile(files=[f])
        p.remove_file("doc")
        self.assertEqual(p.files, [])

    def test_remove_file_not_found(self):
        f = _make_file("doc")
        p = _make_profile(files=[f])
        p.remove_file("missing")
        self.assertEqual(len(p.files), 1)


if __name__ == "__main__":
    unittest.main()
