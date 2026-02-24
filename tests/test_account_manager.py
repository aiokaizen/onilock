import unittest
from unittest import TestCase

from tests import bootstrap as _bootstrap
from onilock.db.models import Account, Profile


class AccountManagerTests(TestCase):
    def _profile(self) -> Profile:
        return Profile(
            name="test-profile",
            master_password="hashed",
            accounts=[
                Account(
                    id="GitHub",
                    username="octo",
                    encrypted_password="enc1",
                    created_at=1,
                ),
                Account(
                    id="GitLab",
                    username="gitlab-user",
                    encrypted_password="enc2",
                    created_at=2,
                ),
            ],
            files=[],
        )

    def test_get_account_by_name_is_case_insensitive(self):
        profile = self._profile()
        account = profile.get_account("github")
        self.assertIsNotNone(account)
        self.assertEqual(account.id, "GitHub")

    def test_get_account_by_index(self):
        profile = self._profile()
        account = profile.get_account(1)
        self.assertIsNotNone(account)
        self.assertEqual(account.id, "GitLab")

    def test_remove_account_by_name_is_case_insensitive(self):
        profile = self._profile()
        profile.remove_account("gItHuB")
        self.assertEqual(len(profile.accounts), 1)
        self.assertEqual(profile.accounts[0].id, "GitLab")


if __name__ == "__main__":
    unittest.main()
