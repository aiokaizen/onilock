"""Tests for onilock.run (CLI commands via typer.testing.CliRunner)."""

import os
import unittest
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner


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
        mock_init.assert_called_once_with("strongpassword")

    def test_initialize_vault_prompts_when_no_password(self):
        from onilock.run import app

        with patch("onilock.run.initialize") as mock_init:
            # Provide empty input for the prompt
            result = runner.invoke(
                app,
                ["initialize-vault"],
                input="\n",
            )
        # Should have prompted and called initialize
        mock_init.assert_called_once()


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


class TestEncryptFileCommand(unittest.TestCase):
    def test_encrypt_file_command(self):
        from onilock.run import app, filemanager

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
    def test_export_vault_echoes_not_implemented(self):
        from onilock.run import app

        result = runner.invoke(app, ["export-vault"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("not implemented", result.output.lower())


class TestExportCommand(unittest.TestCase):
    def test_export_command_echoes_not_implemented(self):
        from onilock.run import app

        result = runner.invoke(app, ["export"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("not implemented", result.output.lower())


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
