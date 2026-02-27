"""Tests for onilock.run (CLI commands via typer.testing.CliRunner)."""

import os
import json
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile
import base64

from typer.testing import CliRunner
from cryptography.fernet import Fernet


def _get_app():
    """Import and return the typer app with mocked module-level side effects."""
    with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
        MockGPG.return_value = MagicMock()
        with patch("onilock.run.settings"):
            import importlib
            import onilock.run

            importlib.reload(onilock.run)
            return onilock.run.app


# Use a module-level runner
runner = CliRunner()


class TestVersionCommand(unittest.TestCase):
    def test_version_exits_zero(self):
        with patch("onilock.run.get_version", return_value="1.7.1"):
            from onilock.run import app

            result = runner.invoke(app, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1.7.1", result.output)


class TestGeneratePwdCommand(unittest.TestCase):
    def test_generate_pwd_outputs_password(self):
        from onilock.run import app

        result = runner.invoke(app, ["generate-pwd", "--len=12", "--special-chars"])
        self.assertEqual(result.exit_code, 0)
        # Output should contain a non-empty password
        self.assertTrue(len(result.output.strip()) > 0)

    def test_generate_pwd_no_special_chars(self):
        from onilock.run import app

        result = runner.invoke(app, ["generate-pwd", "--len=8", "--no-special-chars"])
        self.assertEqual(result.exit_code, 0)


class TestInitializeVaultCommand(unittest.TestCase):
    def test_initialize_vault_with_master_password(self):
        from onilock.run import app

        with patch("onilock.run.initialize") as mock_init:
            result = runner.invoke(
                app, ["initialize-vault", "--master-password=strongpassword"]
            )
        mock_init.assert_called_once_with("strongpassword", pin=None)
        self.assertIn("Initialization Targets", result.output)
        self.assertIn("Vault directory", result.output)

    def test_initialize_vault_prompts_when_no_password(self):
        from onilock.run import app

        with patch("onilock.run.initialize") as mock_init:
            # Provide empty input for the prompt
            result = runner.invoke(
                app,
                ["initialize-vault"],
                input="\n",
            )
        # Non-interactive mode requires explicit master password
        self.assertNotEqual(result.exit_code, 0)
        mock_init.assert_not_called()


class TestNewCommand(unittest.TestCase):
    def test_new_account_command(self):
        from onilock.run import app

        with patch("onilock.run.new_account") as mock_new:
            result = runner.invoke(
                app,
                ["new"],
                input="MyApp\nmypassword\nmyuser\nhttps://example.com\nMy App Account\n",
            )
        mock_new.assert_called_once()


class TestAccountsCommand(unittest.TestCase):
    def test_accounts_list_command(self):
        from onilock.run import app

        with patch("onilock.run.list_accounts") as mock_list:
            result = runner.invoke(app, ["list"])
        mock_list.assert_called_once()
        self.assertEqual(result.exit_code, 0)


class TestListFilesCommand(unittest.TestCase):
    def test_list_files_command(self):
        from onilock.run import app

        with patch("onilock.run.list_files") as mock_list:
            result = runner.invoke(app, ["list-files"])
        mock_list.assert_called_once()
        self.assertEqual(result.exit_code, 0)


class TestCopyCommand(unittest.TestCase):
    def test_copy_by_name(self):
        from onilock.run import app

        with patch("onilock.run.copy_account_password") as mock_copy:
            result = runner.invoke(app, ["copy", "github"])
        mock_copy.assert_called_once_with("github")

    def test_copy_by_integer_index(self):
        from onilock.run import app

        with patch("onilock.run.copy_account_password") as mock_copy:
            result = runner.invoke(app, ["copy", "1"])
        # 1 should be converted to 0 (1-based to 0-based)
        mock_copy.assert_called_once_with(0)

    def test_copy_by_non_integer_stays_string(self):
        from onilock.run import app

        with patch("onilock.run.copy_account_password") as mock_copy:
            result = runner.invoke(app, ["copy", "mygithub"])
        mock_copy.assert_called_once_with("mygithub")


class TestSearchCommand(unittest.TestCase):
    def test_search_calls_search_accounts(self):
        from onilock.run import app

        with patch("onilock.run.search_accounts", return_value=[]) as mock_search:
            result = runner.invoke(app, ["search", "github", "--limit", "5"])

        self.assertEqual(result.exit_code, 0)
        mock_search.assert_called_once_with("github", limit=5)

    def test_search_json_output(self):
        from onilock.run import app

        payload = [
            {
                "rank": 1,
                "id": "github",
                "username": "octocat",
                "url": "https://github.com",
                "description": "code hosting",
                "score": 1.0,
            }
        ]
        with patch("onilock.run.search_accounts", return_value=payload):
            result = runner.invoke(app, ["search", "github", "--json"])

        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data[0]["id"], "github")


class TestShowCommand(unittest.TestCase):
    def test_show_by_name(self):
        from onilock.run import app

        payload = {
            "id": "github",
            "username": "octocat",
            "url": "https://github.com",
            "password": "supersecret",
        }
        with patch("onilock.run.get_account_secret", return_value=payload) as mock_show:
            result = runner.invoke(app, ["show", "github"])

        self.assertEqual(result.exit_code, 0)
        mock_show.assert_called_once_with("github")
        self.assertIn("supersecret", result.output)

    def test_show_json_output(self):
        from onilock.run import app

        payload = {
            "id": "github",
            "username": "octocat",
            "url": "https://github.com",
            "password": "supersecret",
        }
        with patch("onilock.run.get_account_secret", return_value=payload):
            result = runner.invoke(app, ["show", "github", "--json"])

        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["id"], "github")
        self.assertEqual(data["password"], "supersecret")


class TestNotesCommands(unittest.TestCase):
    def test_notes_set_with_text(self):
        from onilock.run import app

        with patch("onilock.run.set_account_note") as mock_set:
            result = runner.invoke(
                app, ["notes", "set", "github", "--text", "deployment creds"]
            )
        self.assertEqual(result.exit_code, 0)
        mock_set.assert_called_once_with("github", "deployment creds")

    def test_notes_get_json(self):
        from onilock.run import app

        payload = {"id": "github", "note": "deployment creds"}
        with patch("onilock.run.get_account_note", return_value=payload):
            result = runner.invoke(app, ["notes", "get", "github", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["note"], "deployment creds")

    def test_notes_clear(self):
        from onilock.run import app

        with patch("onilock.run.clear_account_note") as mock_clear:
            result = runner.invoke(app, ["notes", "clear", "github"])
        self.assertEqual(result.exit_code, 0)
        mock_clear.assert_called_once_with("github")


class TestTagsCommands(unittest.TestCase):
    def test_tags_add(self):
        from onilock.run import app

        with patch("onilock.run.add_account_tags") as mock_add:
            result = runner.invoke(app, ["tags", "add", "github", "prod", "infra"])
        self.assertEqual(result.exit_code, 0)
        mock_add.assert_called_once_with("github", ["prod", "infra"])

    def test_tags_remove(self):
        from onilock.run import app

        with patch("onilock.run.remove_account_tags") as mock_remove:
            result = runner.invoke(app, ["tags", "remove", "github", "prod"])
        self.assertEqual(result.exit_code, 0)
        mock_remove.assert_called_once_with("github", ["prod"])

    def test_tags_list_json(self):
        from onilock.run import app

        payload = {"id": "github", "tags": ["prod", "infra"]}
        with patch("onilock.run.list_account_tags", return_value=payload):
            result = runner.invoke(app, ["tags", "list", "github", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["tags"], ["prod", "infra"])


class TestHistoryCommands(unittest.TestCase):
    def test_history_json_output(self):
        from onilock.run import app

        payload = {
            "id": "github",
            "history": [
                {"index": 1, "created_at": 1700000000, "reason": "rotate"},
                {"index": 2, "created_at": 1699999999, "reason": "replace"},
            ],
        }
        with patch("onilock.run.get_account_history", return_value=payload):
            result = runner.invoke(app, ["history", "github", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["id"], "github")
        self.assertEqual(len(data["history"]), 2)

    def test_history_limit_is_forwarded(self):
        from onilock.run import app

        with patch("onilock.run.get_account_history", return_value={"id": "github", "history": []}) as mock_history:
            result = runner.invoke(app, ["history", "github", "--limit", "3"])
        self.assertEqual(result.exit_code, 0)
        mock_history.assert_called_once_with("github", limit=3)


class TestRotateCommands(unittest.TestCase):
    def test_rotate_calls_manager(self):
        from onilock.run import app

        payload = {"id": "github", "rotated": True, "history_size": 1}
        with patch("onilock.run.rotate_account_password", return_value=payload) as mock_rotate:
            result = runner.invoke(
                app,
                ["rotate", "github", "--len", "24", "--no-special-chars"],
            )
        self.assertEqual(result.exit_code, 0)
        mock_rotate.assert_called_once_with(
            "github",
            length=24,
            include_special_chars=False,
        )

    def test_rotate_json_output(self):
        from onilock.run import app

        payload = {"id": "github", "rotated": True, "history_size": 1}
        with patch("onilock.run.rotate_account_password", return_value=payload):
            result = runner.invoke(app, ["rotate", "github", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["id"], "github")
        self.assertTrue(data["rotated"])


class TestHealthCommands(unittest.TestCase):
    def test_health_single_account(self):
        from onilock.run import app

        payload = {
            "id": "github",
            "health": {"strength": "strong", "reasons": [], "entropy_bits": 80},
        }
        with patch("onilock.run.get_password_health_report", return_value=payload) as mock_health:
            result = runner.invoke(app, ["health", "github"])
        self.assertEqual(result.exit_code, 0)
        mock_health.assert_called_once_with("github", all_accounts=False)

    def test_health_all_json(self):
        from onilock.run import app

        payload = {
            "summary": {"total": 2, "strong": 1, "weak": 1},
            "accounts": [
                {"id": "github", "strength": "weak"},
                {"id": "gitlab", "strength": "strong"},
            ],
        }
        with patch("onilock.run.get_password_health_report", return_value=payload):
            result = runner.invoke(app, ["health", "--all", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["summary"]["total"], 2)


class TestUnlockCommands(unittest.TestCase):
    def test_unlock_with_pin_option(self):
        from onilock.run import app

        with patch(
            "onilock.run.unlock_with_pin",
            return_value={"unlocked": True, "pin_enabled": True, "ttl_sec": 600},
        ) as mock_unlock:
            result = runner.invoke(app, ["unlock", "--pin", "1234"])

        self.assertEqual(result.exit_code, 0)
        mock_unlock.assert_called_once_with("1234")

    def test_pin_reset_with_pin_option(self):
        from onilock.run import app

        with patch("onilock.run.reset_profile_pin", return_value={"pin_enabled": True}) as mock_reset:
            result = runner.invoke(app, ["pin", "reset", "--pin", "1234"])

        self.assertEqual(result.exit_code, 0)
        mock_reset.assert_called_once_with("1234")

    def test_show_denied_when_unlock_gate_fails(self):
        from onilock.run import app

        with patch("onilock.run.require_unlock_if_enabled", side_effect=SystemExit(1)):
            with patch("onilock.run.get_account_secret") as mock_show:
                result = runner.invoke(app, ["show", "github"])
        self.assertNotEqual(result.exit_code, 0)
        mock_show.assert_not_called()


class TestProfilesCommand(unittest.TestCase):
    def test_profiles_remove_force(self):
        from onilock.run import app

        with patch("onilock.run.list_profiles", side_effect=[["work", "personal"], ["personal"]]):
            with patch("onilock.run._cleanup_profile_artifacts", return_value={
                "setup_file": 1,
                "vault_file": 1,
                "encrypted_files": 2,
                "backups": 1,
                "keystore_backend": 1,
            }) as mock_cleanup:
                with patch("onilock.run.get_active_profile", return_value="work"):
                    with patch("onilock.run.remove_profile") as mock_remove:
                        with patch("onilock.run.set_active_profile") as mock_set_active:
                            with patch("onilock.run.audit") as mock_audit:
                                result = runner.invoke(
                                    app, ["profiles", "remove", "work", "--force"]
                                )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("irreversible", result.output.lower())
        mock_cleanup.assert_called_once_with("work")
        mock_remove.assert_called_once_with("work")
        mock_set_active.assert_called_once_with("personal")
        mock_audit.assert_called_once()

    def test_profiles_remove_missing_profile_exits(self):
        from onilock.run import app

        with patch("onilock.run.list_profiles", return_value=["work"]):
            result = runner.invoke(app, ["profiles", "remove", "missing", "--force"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("was not found", result.output.lower())

    def test_profiles_remove_non_force_confirms(self):
        from onilock.run import app

        with patch("onilock.run.list_profiles", side_effect=[["work"], []]):
            with patch(
                "onilock.run._cleanup_profile_artifacts",
                return_value={
                    "setup_file": 0,
                    "vault_file": 0,
                    "encrypted_files": 0,
                    "backups": 0,
                    "keystore_backend": 0,
                },
            ):
                with patch("onilock.run.get_active_profile", return_value=None):
                    with patch("onilock.run.remove_profile"):
                        with patch("onilock.run.audit"):
                            result = runner.invoke(
                                app, ["profiles", "remove", "work"], input="y\n"
                            )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("irreversible", result.output.lower())

    def test_cleanup_profile_artifacts_removes_profile_files(self):
        from onilock.run import _cleanup_profile_artifacts, _profile_setup_path

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            vault_dir = base / "vault"
            backup_dir = base / "backups"
            vault_dir.mkdir()
            backup_dir.mkdir()

            secret = Fernet.generate_key().decode()
            cipher = Fernet(secret.encode())
            profile_data_path = vault_dir / "profile_data.oni"
            profile_data_path.write_text("x")

            encrypted_file_path = vault_dir / "doc1.oni"
            encrypted_file_path.write_text("enc")

            backup_path = backup_dir / "onilock_work_backup_20260101000000.zip"
            backup_path.write_text("backup")

            encrypted_filepath = base64.b64encode(
                cipher.encrypt(str(profile_data_path).encode())
            ).decode()

            setup_engine = MagicMock()
            setup_engine.read.return_value = {"work": {"filepath": encrypted_filepath}}

            profile_engine = MagicMock()
            profile_engine.read.return_value = {
                "files": [{"location": str(encrypted_file_path)}]
            }

            setup_db = MagicMock()
            setup_db.get_engine.return_value = setup_engine
            profile_db = MagicMock()
            profile_db.get_engine.return_value = profile_engine

            with patch("onilock.run.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.BACKUP_DIR = backup_dir
                ms.SECRET_KEY = secret
                setup_path = _profile_setup_path("work")
                setup_path.write_text("setup")
                with patch(
                    "onilock.run.DatabaseManager", side_effect=[setup_db, profile_db]
                ):
                    with patch(
                        "onilock.run.KeyStoreManager.clear_persisted_backend",
                        return_value=True,
                    ):
                        removed = _cleanup_profile_artifacts("work")

            self.assertEqual(removed["setup_file"], 1)
            self.assertEqual(removed["vault_file"], 1)
            self.assertEqual(removed["encrypted_files"], 1)
            self.assertEqual(removed["backups"], 1)
            self.assertEqual(removed["keystore_backend"], 1)
            self.assertFalse(profile_data_path.exists())
            self.assertFalse(encrypted_file_path.exists())
            self.assertFalse(backup_path.exists())


class TestEncryptFileCommand(unittest.TestCase):
    def test_encrypt_file_command(self):
        from onilock.run import app, filemanager

        with patch("onilock.run.get_profile_engine", return_value=MagicMock()):
            with patch.object(filemanager, "encrypt") as mock_enc:
                result = runner.invoke(app, ["encrypt-file", "doc1", "/tmp/test.txt"])
        mock_enc.assert_called_once_with("doc1", "/tmp/test.txt")


class TestReadFileCommand(unittest.TestCase):
    def test_read_file_command(self):
        from onilock.run import app, filemanager

        with patch.object(filemanager, "read") as mock_read:
            result = runner.invoke(app, ["read-file", "doc1"])
        mock_read.assert_called_once_with("doc1")


class TestEditFileCommand(unittest.TestCase):
    def test_edit_file_command(self):
        from onilock.run import app, filemanager

        with patch.object(filemanager, "open") as mock_open:
            result = runner.invoke(app, ["edit-file", "doc1"])
        mock_open.assert_called_once_with("doc1")


class TestDeleteFileCommand(unittest.TestCase):
    def test_delete_file_command(self):
        from onilock.run import app, filemanager

        with patch.object(filemanager, "delete") as mock_delete:
            result = runner.invoke(app, ["delete-file", "doc1"], input="y\n")
        mock_delete.assert_called_once_with("doc1")


class TestExportFileCommand(unittest.TestCase):
    def test_export_file_command_with_output(self):
        from onilock.run import app, filemanager

        with patch.object(filemanager, "export") as mock_export:
            result = runner.invoke(
                app, ["export-file", "doc1", "--output=/tmp/out.txt"]
            )
        mock_export.assert_called_once_with("doc1", "/tmp/out.txt")

    def test_export_file_command_without_output(self):
        from onilock.run import app, filemanager

        with patch.object(filemanager, "export") as mock_export:
            result = runner.invoke(app, ["export-file", "doc1"])
        mock_export.assert_called_once_with("doc1", None)


class TestExportAllFilesCommand(unittest.TestCase):
    def test_export_all_files_command(self):
        from onilock.run import app, filemanager

        with patch.object(filemanager, "export") as mock_export:
            result = runner.invoke(app, ["export-all-files"])
        mock_export.assert_called_once_with(file_path=None)


class TestExportVaultCommand(unittest.TestCase):
    def test_export_vault_command(self):
        from onilock.run import app

        mock_engine = MagicMock()
        mock_engine.read.return_value = {
            "name": "test_profile",
            "master_password": "hashed",
            "vault_version": "1.8.0",
            "creation_timestamp": 1.0,
            "accounts": [],
            "files": [],
        }
        artifacts_dir = Path(".onilock_artifacts")
        output_path = artifacts_dir / "export-vault-test.zip"
        with patch("onilock.run.get_profile_engine", return_value=mock_engine):
            result = runner.invoke(
                app,
                [
                    "export-vault",
                    "--no-passwords",
                    f"--output={output_path}",
                ],
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("exported vault", result.output.lower())


class TestExportCommand(unittest.TestCase):
    def test_export_command(self):
        from onilock.run import app

        mock_engine = MagicMock()
        mock_engine.read.return_value = {
            "name": "test_profile",
            "master_password": "hashed",
            "vault_version": "1.8.0",
            "creation_timestamp": 1.0,
            "accounts": [],
            "files": [],
        }
        artifacts_dir = Path(".onilock_artifacts")
        output_path = artifacts_dir / "export-test.zip"
        with patch("onilock.run.get_profile_engine", return_value=mock_engine):
            result = runner.invoke(
                app,
                [
                    "export",
                    "--no-passwords",
                    f"--dist={output_path}",
                ],
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("exported vault", result.output.lower())


class TestRemoveAccountCommand(unittest.TestCase):
    def test_remove_account_command(self):
        from onilock.run import app

        # Patch am_remove_account (the aliased import in run.py) so we verify
        # the CLI delegates to the actual business-logic function, not itself.
        with patch("onilock.run.am_remove_account") as mock_remove:
            result = runner.invoke(app, ["remove-account", "github"], input="y\n")
        mock_remove.assert_called_once_with("github")
        self.assertEqual(result.exit_code, 0)


class TestEraseUserDataCommand(unittest.TestCase):
    def test_erase_user_data_command(self):
        from onilock.run import app

        with patch("onilock.run.delete_profile") as mock_delete:
            result = runner.invoke(
                app,
                ["erase-user-data", "--master-password=strongpassword"],
                input="y\n",
            )
        mock_delete.assert_called_once_with("strongpassword")


if __name__ == "__main__":
    unittest.main()
