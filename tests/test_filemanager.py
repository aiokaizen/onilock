"""Tests for onilock.filemanager (FileEncryptionManager)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from onilock.filemanager import FileEncryptionManager, get_output_filename
from onilock.db.models import File, Profile
from onilock.core.exceptions.exceptions import GPGNotAvailableError
from onilock.core.utils import naive_utcnow

# Secret key whose name matches the PGP_REAL_NAME the tests patch in.
_EXISTING_KEY = [{"uids": ["test_key <pgp@onilock.com>"]}]


def _make_profile(with_file=False):
    files = []
    if with_file:
        files = [
            File(
                id="doc1",
                location="/vault/abc.oni",
                created_at=int(naive_utcnow().timestamp()),
                src="/home/user/document.txt",
                user="testuser",
                host="localhost",
            )
        ]
    return Profile(
        name="test_profile",
        master_password="hashed_pw",
        accounts=[],
        files=files,
    )


class TestGetOutputFilename(unittest.TestCase):
    def test_returns_path_with_oni_suffix(self):
        result = get_output_filename("doc1")
        self.assertIsInstance(result, Path)
        self.assertEqual(result.suffix, ".oni")

    def test_deterministic(self):
        r1 = get_output_filename("doc1")
        r2 = get_output_filename("doc1")
        self.assertEqual(r1, r2)

    def test_different_ids_different_filenames(self):
        r1 = get_output_filename("doc1")
        r2 = get_output_filename("doc2")
        self.assertNotEqual(r1, r2)


class TestFileEncryptionManagerInit(unittest.TestCase):
    def test_init_does_not_start_gpg(self):
        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            manager = FileEncryptionManager()

        MockGPG.assert_not_called()
        self.assertIsNone(manager._engine)
        self.assertIsNone(manager._profile)

    def test_gpg_created_once_on_first_use(self):
        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            MockGPG.return_value = MagicMock()
            with patch("onilock.filemanager.settings") as ms:
                ms.GPG_HOME = "/tmp/gpg"
                manager = FileEncryptionManager()
                g1 = manager.gpg
                g2 = manager.gpg

        MockGPG.assert_called_once()
        self.assertIs(g1, g2)

    def test_gpg_with_gpg_home(self):
        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            MockGPG.return_value = MagicMock()
            manager = FileEncryptionManager(gpg_home="/tmp/custom/gpg")
            _ = manager.gpg

        MockGPG.assert_called_once_with(gnupghome="/tmp/custom/gpg")

    def test_gpg_missing_and_not_installed_raises(self):
        with patch(
            "onilock.filemanager.gnupg.GPG", side_effect=OSError("Unable to run gpg")
        ):
            with patch("onilock.core.gpg.GNUPG") as mock_dep:
                mock_dep.is_installed.return_value = False
                with patch("onilock.core.gpg.ensure_installed", return_value=False):
                    manager = FileEncryptionManager(gpg_home="/tmp/custom/gpg")
                    with self.assertRaises(GPGNotAvailableError):
                        _ = manager.gpg


class TestFileEncryptionManagerProperties(unittest.TestCase):
    def _make_manager(self, profile=None, empty_engine=False):
        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            MockGPG.return_value = MagicMock()
            with patch("onilock.filemanager.settings") as ms:
                ms.GPG_HOME = "/tmp/gpg"
                manager = FileEncryptionManager()

        mock_engine = MagicMock()
        if empty_engine:
            mock_engine.read.return_value = {}
        elif profile:
            mock_engine.read.return_value = profile.model_dump()
        else:
            mock_engine.read.return_value = _make_profile().model_dump()

        return manager, mock_engine

    def test_profile_property_caches(self):
        profile = _make_profile(with_file=True)
        manager, engine = self._make_manager(profile=profile)

        with patch("onilock.filemanager.get_profile_engine", return_value=engine):
            p1 = manager.profile
            p2 = manager.profile  # Should use cache

        self.assertEqual(engine.read.call_count, 1)
        self.assertIsInstance(p1, Profile)

    def test_profile_property_uninitialized_exits(self):
        manager, engine = self._make_manager(empty_engine=True)

        with patch("onilock.filemanager.get_profile_engine", return_value=engine):
            with self.assertRaises(SystemExit):
                _ = manager.profile

    def test_engine_property_caches(self):
        manager, engine = self._make_manager()
        manager._engine = None

        with patch(
            "onilock.filemanager.get_profile_engine", return_value=engine
        ) as mock_gpe:
            e1 = manager.engine
            e2 = manager.engine  # Should use cache

        self.assertEqual(mock_gpe.call_count, 1)
        self.assertIs(e1, engine)


class TestEncryptBytes(unittest.TestCase):
    def _make_manager(self):
        mock_gpg = MagicMock()
        mock_gpg.list_keys.return_value = _EXISTING_KEY
        mock_encrypted = MagicMock()
        mock_encrypted.ok = True
        mock_encrypted.data = b"encrypted_content"
        mock_gpg.encrypt.return_value = mock_encrypted
        manager = FileEncryptionManager()
        manager._gpg = mock_gpg
        return manager, mock_gpg

    def test_encrypt_bytes_writes_to_file(self, tmp_path=None):
        import tempfile

        manager, mock_gpg = self._make_manager()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "encrypted.oni"
            with patch("onilock.filemanager.settings") as ms:
                ms.PGP_REAL_NAME = "test_key"
                manager.encrypt_bytes(b"plaintext content", out_file)
        mock_gpg.encrypt.assert_called_once()

    def test_encrypt_bytes_with_string_path(self):
        import tempfile

        manager, mock_gpg = self._make_manager()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = str(Path(tmpdir) / "encrypted.oni")
            with patch("onilock.filemanager.settings") as ms:
                ms.PGP_REAL_NAME = "test_key"
                manager.encrypt_bytes(b"plaintext content", out_file)
        mock_gpg.encrypt.assert_called_once()


class TestEnsureKey(unittest.TestCase):
    def _make_manager(self, keys, gen_key_result=None):
        mock_gpg = MagicMock()
        mock_gpg.list_keys.return_value = keys
        mock_gpg.gen_key_input.return_value = "key_input"
        mock_gpg.gen_key.return_value = gen_key_result or MagicMock(
            fingerprint="ABCDEF1234567890"
        )
        mock_gpg.encrypt.return_value = MagicMock(ok=True, data=b"encrypted")
        manager = FileEncryptionManager()
        manager._gpg = mock_gpg
        return manager, mock_gpg

    def _encrypt(self, manager, out_file):
        with patch("onilock.filemanager.settings") as ms:
            ms.PGP_REAL_NAME = "test_key"
            ms.PGP_EMAIL = "pgp@onilock.com"
            ms.PASSPHRASE = "test"
            with patch("onilock.filemanager.audit"):
                manager.encrypt_bytes(b"plaintext", out_file)

    def test_generates_key_when_missing(self):
        manager, mock_gpg = self._make_manager(keys=[])
        with tempfile.TemporaryDirectory() as tmpdir:
            self._encrypt(manager, Path(tmpdir) / "encrypted.oni")

        mock_gpg.gen_key_input.assert_called_once_with(
            key_type="RSA",
            key_length=4096,
            name_real="test_key",
            name_email="pgp@onilock.com",
            passphrase="test",
        )
        mock_gpg.gen_key.assert_called_once_with("key_input")
        mock_gpg.encrypt.assert_called_once()

    def test_existing_key_is_reused(self):
        manager, mock_gpg = self._make_manager(keys=_EXISTING_KEY)
        with tempfile.TemporaryDirectory() as tmpdir:
            self._encrypt(manager, Path(tmpdir) / "encrypted.oni")

        mock_gpg.gen_key.assert_not_called()
        mock_gpg.encrypt.assert_called_once()

    def test_key_checked_once_per_manager(self):
        manager, mock_gpg = self._make_manager(keys=_EXISTING_KEY)
        with tempfile.TemporaryDirectory() as tmpdir:
            self._encrypt(manager, Path(tmpdir) / "a.oni")
            self._encrypt(manager, Path(tmpdir) / "b.oni")

        mock_gpg.list_keys.assert_called_once_with(secret=True)
        self.assertEqual(mock_gpg.encrypt.call_count, 2)

    def test_generation_failure_raises_before_encrypting(self):
        failed = MagicMock(fingerprint="", stderr="gpg-agent is not available\n")
        manager, mock_gpg = self._make_manager(keys=[], gen_key_result=failed)
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(RuntimeError) as ctx:
                self._encrypt(manager, Path(tmpdir) / "encrypted.oni")

        self.assertIn("gpg-agent is not available", str(ctx.exception))
        mock_gpg.encrypt.assert_not_called()


class TestEncrypt(unittest.TestCase):
    def _make_manager_with_mock_gpg(self):
        mock_gpg = MagicMock()
        mock_gpg.list_keys.return_value = _EXISTING_KEY
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.data = b"encrypted"
        mock_gpg.encrypt.return_value = mock_result
        manager = FileEncryptionManager()
        manager._gpg = mock_gpg
        return manager

    def test_encrypt_file_not_found_exits(self):
        manager = self._make_manager_with_mock_gpg()
        profile = _make_profile()
        engine = MagicMock()
        engine.read.return_value = profile.model_dump()
        manager._engine = engine
        manager._profile = profile

        with self.assertRaises(SystemExit):
            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = Path("/tmp/vault")
                ms.PGP_REAL_NAME = "test_key"
                manager.encrypt("doc1", "/nonexistent/file.txt")

    def test_encrypt_directory_exits(self, tmp_path=None):
        import tempfile

        manager = self._make_manager_with_mock_gpg()
        profile = _make_profile()
        engine = MagicMock()
        engine.read.return_value = profile.model_dump()
        manager._engine = engine
        manager._profile = profile

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(SystemExit):
                with patch("onilock.filemanager.settings") as ms:
                    ms.VAULT_DIR = Path(tmpdir)
                    ms.PGP_REAL_NAME = "test_key"
                    manager.encrypt("doc1", tmpdir)  # tmpdir is a directory

    def test_encrypt_id_already_exists_exits(self):
        import tempfile

        manager = self._make_manager_with_mock_gpg()
        profile = _make_profile()
        engine = MagicMock()
        engine.read.return_value = profile.model_dump()
        manager._engine = engine
        manager._profile = profile

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a source file
            src_file = Path(tmpdir) / "source.txt"
            src_file.write_text("content")

            # Simulate that output file already exists
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            output_filename = get_output_filename("doc1")
            (vault_dir / output_filename).write_bytes(b"existing")

            with self.assertRaises(SystemExit):
                with patch("onilock.filemanager.settings") as ms:
                    ms.VAULT_DIR = vault_dir
                    ms.PGP_REAL_NAME = "test_key"
                    manager.encrypt("doc1", str(src_file))

    def test_encrypt_valid_file(self):
        import tempfile

        manager = self._make_manager_with_mock_gpg()
        profile = _make_profile()
        engine = MagicMock()
        engine.read.return_value = profile.model_dump()
        manager._engine = engine
        manager._profile = profile

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "source.txt"
            src_file.write_text("secret content")
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PGP_REAL_NAME = "test_key"
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.getlogin", return_value="testuser"):
                    with patch(
                        "onilock.filemanager.socket.gethostname",
                        return_value="localhost",
                    ):
                        manager.encrypt("doc1", str(src_file))

        engine.write.assert_called_once()


class TestDecryptBytes(unittest.TestCase):
    def _make_manager(self, decrypt_ok=True):
        mock_gpg = MagicMock()
        mock_result = MagicMock()
        mock_result.ok = decrypt_ok
        mock_result.data = b"plaintext"
        mock_result.status = "decryption ok" if decrypt_ok else "decryption error"
        mock_gpg.decrypt.return_value = mock_result
        manager = FileEncryptionManager()
        manager._gpg = mock_gpg
        return manager

    def test_decrypt_bytes_success(self):
        manager = self._make_manager(decrypt_ok=True)
        with patch("onilock.filemanager.settings") as ms:
            ms.PASSPHRASE = "test"
            result = manager.decrypt_bytes(b"encrypted_data")
        self.assertEqual(result, b"plaintext")

    def test_decrypt_bytes_failure_raises(self):
        manager = self._make_manager(decrypt_ok=False)
        with patch("onilock.filemanager.settings") as ms:
            ms.PASSPHRASE = "test"
            with self.assertRaises(Exception):
                manager.decrypt_bytes(b"bad_data")


class TestDelete(unittest.TestCase):
    def test_delete_existing_file(self):
        import tempfile

        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            MockGPG.return_value = MagicMock()
            with patch("onilock.filemanager.settings") as ms:
                ms.GPG_HOME = "/tmp/gpg"
                manager = FileEncryptionManager()

        profile = _make_profile(with_file=True)
        engine = MagicMock()
        engine.read.return_value = profile.model_dump()
        manager._profile = profile
        manager._engine = engine

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                manager.delete("doc1")

        engine.write.assert_called_once()

    def test_delete_nonexistent_file_no_error(self):
        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            MockGPG.return_value = MagicMock()
            with patch("onilock.filemanager.settings") as ms:
                ms.GPG_HOME = "/tmp/gpg"
                manager = FileEncryptionManager()

        profile = _make_profile(with_file=True)
        engine = MagicMock()
        manager._profile = profile
        manager._engine = engine

        with patch("onilock.filemanager.settings") as ms:
            ms.VAULT_DIR = Path("/tmp/nonexistent_vault")
            manager.delete("doc1")  # File doesn't exist, should not raise

        engine.write.assert_not_called()


class TestExport(unittest.TestCase):
    def _make_manager_with_decrypt(self):
        mock_gpg = MagicMock()
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.data = b"decrypted content"
        mock_gpg.decrypt.return_value = mock_result
        manager = FileEncryptionManager()
        manager._gpg = mock_gpg
        return manager

    def test_export_invalid_file_id_exits(self):
        manager = self._make_manager_with_decrypt()
        profile = _make_profile()  # No files
        manager._profile = profile
        manager._engine = MagicMock()

        with self.assertRaises(SystemExit):
            with patch("onilock.filemanager.settings") as ms:
                ms.PASSPHRASE = "test"
                manager.export(file_id="nonexistent")

    def test_export_single_file_to_path(self):
        import tempfile

        manager = self._make_manager_with_decrypt()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            output_file = Path(tmpdir) / "exported.txt"

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                manager.export(file_id="doc1", file_path=str(output_file))

            self.assertTrue(output_file.exists())

    def test_export_single_file_to_dir(self):
        import tempfile

        manager = self._make_manager_with_decrypt()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.getlogin", return_value="testuser"):
                    manager.export(file_id="doc1", file_path=str(output_dir))

            # Output file should be in the directory
            exported = list(output_dir.iterdir())
            self.assertEqual(len(exported), 1)

    def test_export_single_file_default_name(self):
        import tempfile

        manager = self._make_manager_with_decrypt()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with patch("onilock.filemanager.settings") as ms:
                    ms.VAULT_DIR = vault_dir
                    ms.PASSPHRASE = "test"
                    manager.export(file_id="doc1")
            finally:
                os.chdir(old_cwd)

    def test_export_all_files_to_zip(self):
        import tempfile

        manager = self._make_manager_with_decrypt()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            output_zip = Path(tmpdir) / "all_files.zip"

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.getlogin", return_value="testuser"):
                    manager.export(file_path=str(output_zip))

            self.assertTrue(output_zip.exists())

    def test_export_all_files_default_path(self):
        """Cover the 'if not file_path' branch for all-files export."""
        import tempfile

        manager = self._make_manager_with_decrypt()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with patch("onilock.filemanager.settings") as ms:
                    ms.VAULT_DIR = vault_dir
                    ms.PASSPHRASE = "test"
                    with patch("onilock.filemanager.getlogin", return_value="testuser"):
                        # No file_path → creates zip in current directory
                        manager.export()
            finally:
                os.chdir(old_cwd)

            zips = list(Path(tmpdir).glob("*.zip"))
            self.assertEqual(len(zips), 1)

    def test_export_all_files_to_dir(self):
        """Cover the elif is_dir branch for the all-files export path."""
        import tempfile

        manager = self._make_manager_with_decrypt()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.getlogin", return_value="testuser"):
                    # file_path is an existing directory → elif is_dir branch
                    manager.export(file_path=str(output_dir))

            exported = list(output_dir.iterdir())
            self.assertEqual(len(exported), 1)
            self.assertTrue(exported[0].name.endswith(".zip"))


class TestOpen(unittest.TestCase):
    def setUp(self):
        # Assume vim is installed unless a test says otherwise.
        patcher = patch("onilock.filemanager.ensure_installed", return_value=True)
        self.mock_ensure = patcher.start()
        self.addCleanup(patcher.stop)

    def test_open_without_vim_exits_before_decrypting(self):
        from onilock.core.dependencies import VIM

        manager = self._make_manager()
        manager._profile = _make_profile(with_file=True)
        manager._engine = MagicMock()
        self.mock_ensure.return_value = False

        with self.assertRaises(SystemExit):
            manager.open("doc1", readonly=True)

        self.mock_ensure.assert_called_once_with([VIM])
        manager.gpg.decrypt.assert_not_called()

    def _make_manager(self):
        mock_gpg = MagicMock()
        mock_gpg.list_keys.return_value = _EXISTING_KEY
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.data = b"file content"
        mock_gpg.decrypt.return_value = mock_result
        manager = FileEncryptionManager()
        manager._gpg = mock_gpg
        return manager

    def test_open_invalid_file_id_exits(self):
        manager = self._make_manager()
        profile = _make_profile()  # no files
        manager._profile = profile
        manager._engine = MagicMock()

        with self.assertRaises(SystemExit):
            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = Path("/tmp/vault")
                ms.PASSPHRASE = "test"
                manager.open("nonexistent")

    def test_open_readonly_mode(self):
        import tempfile

        manager = self._make_manager()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.subprocess.run") as mock_run:
                    manager.open("doc1", readonly=True)

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn("-R", args)
        self.assertIn("-m", args)

    def test_open_edit_mode_re_encrypts(self):
        import tempfile

        manager = self._make_manager()
        profile = _make_profile(with_file=True)
        manager._profile = profile

        mock_engine = MagicMock()
        mock_engine.read.return_value = profile.model_dump()
        manager._engine = mock_engine

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            mock_enc_result = MagicMock()
            mock_enc_result.ok = True
            mock_enc_result.data = b"re-encrypted"
            manager.gpg.encrypt.return_value = mock_enc_result

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                ms.PGP_REAL_NAME = "test_key"
                with patch("onilock.filemanager.subprocess.run"):
                    manager.open("doc1", readonly=False)

    def test_read_delegates_to_open_readonly(self):
        manager = self._make_manager()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        with patch.object(manager, "open") as mock_open:
            manager.read("doc1")

        mock_open.assert_called_once_with("doc1", readonly=True)

    def test_temp_file_deleted_after_readonly(self):
        """Temp file must be cleaned up even in readonly mode."""
        manager = self._make_manager()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        created_tmp_path = None

        real_ntf = tempfile.NamedTemporaryFile

        def capturing_ntf(*args, **kwargs):
            # Force dir to a real writable temp dir instead of /dev/shm
            kwargs["dir"] = tempfile.gettempdir()
            f = real_ntf(*args, **kwargs)
            nonlocal created_tmp_path
            created_tmp_path = f.name
            return f

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.tempfile.NamedTemporaryFile", side_effect=capturing_ntf):
                    with patch("onilock.filemanager.subprocess.run"):
                        manager.open("doc1", readonly=True)

        self.assertIsNotNone(created_tmp_path)
        self.assertFalse(os.path.exists(created_tmp_path), "Temp file was not deleted after readonly open")

    def test_temp_file_deleted_on_exception(self):
        """Temp file must be cleaned up even when an exception is raised."""
        manager = self._make_manager()
        profile = _make_profile(with_file=True)
        manager._profile = profile
        manager._engine = MagicMock()

        created_tmp_path = None

        real_ntf = tempfile.NamedTemporaryFile

        def capturing_ntf(*args, **kwargs):
            kwargs["dir"] = tempfile.gettempdir()
            f = real_ntf(*args, **kwargs)
            nonlocal created_tmp_path
            created_tmp_path = f.name
            return f

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "vault"
            vault_dir.mkdir()
            encrypted_filename = vault_dir / get_output_filename("doc1")
            encrypted_filename.write_bytes(b"encrypted")

            with patch("onilock.filemanager.settings") as ms:
                ms.VAULT_DIR = vault_dir
                ms.PASSPHRASE = "test"
                with patch("onilock.filemanager.tempfile.NamedTemporaryFile", side_effect=capturing_ntf):
                    with patch("onilock.filemanager.subprocess.run", side_effect=RuntimeError("vim crashed")):
                        with self.assertRaises(RuntimeError):
                            manager.open("doc1", readonly=True)

        self.assertIsNotNone(created_tmp_path)
        self.assertFalse(os.path.exists(created_tmp_path), "Temp file was not deleted after exception")


class TestClear(unittest.TestCase):
    def test_clear_is_callable(self):
        with patch("onilock.filemanager.gnupg.GPG") as MockGPG:
            MockGPG.return_value = MagicMock()
            with patch("onilock.filemanager.settings") as ms:
                ms.GPG_HOME = "/tmp/gpg"
                manager = FileEncryptionManager()
        # clear() is a no-op stub; should not raise
        manager.clear()


if __name__ == "__main__":
    unittest.main()
