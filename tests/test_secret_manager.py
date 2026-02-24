import base64
import unittest
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

from tests import bootstrap as _bootstrap
from onilock.core.exceptions import (
    InvalidAccountIdentifierError,
    VaultConfigurationError,
)
from onilock.core.settings import settings
from onilock.db.models import Account, Profile
from onilock.secret_manager import SecretManager


class SecretManagerTests(unittest.TestCase):
    def _profile(self) -> Profile:
        cipher = Fernet(settings.SECRET_KEY.encode())
        encrypted_password = base64.b64encode(cipher.encrypt(b"pw-1")).decode()
        return Profile(
            name="profile",
            master_password="hashed",
            accounts=[
                Account(
                    id="GitHub",
                    username="octo",
                    encrypted_password=encrypted_password,
                    created_at=1,
                ),
                Account(
                    id="GitLab",
                    username="gitlab",
                    encrypted_password=encrypted_password,
                    created_at=2,
                ),
            ],
            files=[],
        )

    def test_create_rejects_duplicate_name(self):
        manager = SecretManager()
        profile = self._profile()
        with patch("onilock.secret_manager.load_profile", return_value=(MagicMock(), profile)):
            with self.assertRaises(InvalidAccountIdentifierError):
                manager.create(name="github", password="x")

    def test_update_rejects_conflicting_password_inputs(self):
        manager = SecretManager()
        with self.assertRaises(VaultConfigurationError):
            manager.update("GitHub", password="x", generate_password=True)

    def test_delete_by_index_removes_target(self):
        manager = SecretManager()
        profile = self._profile()
        engine = MagicMock()
        with patch("onilock.secret_manager.load_profile", return_value=(engine, profile)), patch(
            "onilock.secret_manager.save_profile"
        ) as save_mock:
            removed = manager.delete("2")
        self.assertEqual(removed, "GitLab")
        self.assertEqual(len(profile.accounts), 1)
        self.assertEqual(profile.accounts[0].id, "GitHub")
        save_mock.assert_called_once()

    def test_copy_copies_and_schedules_cleanup(self):
        manager = SecretManager()
        profile = self._profile()
        with patch("onilock.secret_manager.load_profile", return_value=(MagicMock(), profile)), patch(
            "onilock.secret_manager.pyperclip.copy"
        ) as copy_mock, patch(
            "onilock.secret_manager.schedule_clipboard_clear"
        ) as schedule_mock:
            copied_id = manager.copy("GitHub", clear_after=12)
        self.assertEqual(copied_id, "GitHub")
        copy_mock.assert_called_once_with("pw-1")
        schedule_mock.assert_called_once_with("pw-1", 12)

    def test_search_across_all_fields(self):
        manager = SecretManager()
        profile = self._profile()
        with patch("onilock.secret_manager.load_profile", return_value=(MagicMock(), profile)):
            matches = manager.search("git")
        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[0]["index"], 1)
        self.assertEqual(matches[1]["index"], 2)

    def test_search_validates_field_name(self):
        manager = SecretManager()
        with self.assertRaises(VaultConfigurationError):
            manager.search("x", field="invalid")

    def test_rename_changes_name(self):
        manager = SecretManager()
        profile = self._profile()
        with patch("onilock.secret_manager.load_profile", return_value=(MagicMock(), profile)), patch(
            "onilock.secret_manager.save_profile"
        ) as save_mock:
            result = manager.rename("GitHub", "GitHub-Work")
        self.assertTrue(result["changed"])
        self.assertEqual(result["old_id"], "GitHub")
        self.assertEqual(result["new_id"], "GitHub-Work")
        self.assertEqual(profile.accounts[0].id, "GitHub-Work")
        save_mock.assert_called_once()

    def test_rename_rejects_duplicate_name(self):
        manager = SecretManager()
        profile = self._profile()
        with patch("onilock.secret_manager.load_profile", return_value=(MagicMock(), profile)):
            with self.assertRaises(InvalidAccountIdentifierError):
                manager.rename("GitHub", "GitLab")
