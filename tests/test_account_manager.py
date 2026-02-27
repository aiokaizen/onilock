"""Tests for onilock.account_manager."""

import base64
import os
import unittest
from unittest.mock import MagicMock, patch, call

import bcrypt
from cryptography.fernet import Fernet

from onilock.db.models import Account, File, Profile
from onilock.core.utils import naive_utcnow

# ---- Helpers ----------------------------------------------------------------

TEST_MASTER_PASSWORD = "SuperSecureTestPassword123!"
TEST_SECRET_KEY = os.environ["ONI_SECRET_KEY"]


def _make_profile(with_account=False, with_file=False):
    """Build a minimal Profile object for use in tests."""
    hashed = bcrypt.hashpw(TEST_MASTER_PASSWORD.encode(), bcrypt.gensalt())
    b64_hashed = base64.b64encode(hashed).decode()

    accounts = []
    if with_account:
        cipher = Fernet(TEST_SECRET_KEY.encode())
        encrypted = cipher.encrypt(b"mypassword")
        b64_enc = base64.b64encode(encrypted).decode()
        accounts = [
            Account(
                id="github",
                encrypted_password=b64_enc,
                username="testuser",
                url="https://github.com",
                description="Test account",
                created_at=int(naive_utcnow().timestamp()),
            )
        ]

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
        master_password=b64_hashed,
        accounts=accounts,
        files=files,
    )


def _make_engine(profile: Profile = None, empty=False):
    """Return a mock engine with canned read() output."""
    engine = MagicMock()
    if empty or profile is None:
        engine.read.return_value = {}
    else:
        engine.read.return_value = profile.model_dump()
    engine.write.return_value = None
    return engine


# ---- Tests ------------------------------------------------------------------


class TestVerifyMasterPassword(unittest.TestCase):
    def test_valid_password_returns_true(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import verify_master_password

            result = verify_master_password(TEST_MASTER_PASSWORD)

        self.assertTrue(result)

    def test_invalid_password_returns_false(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import verify_master_password

            result = verify_master_password("wrong_password")

        self.assertFalse(result)

    def test_uninitialized_db_exits(self):
        engine = _make_engine(empty=True)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import verify_master_password

            with self.assertRaises(SystemExit):
                verify_master_password(TEST_MASTER_PASSWORD)


class TestGetProfileEngine(unittest.TestCase):
    def test_returns_engine(self):
        # Setup: the setup engine read returns a setup dict with encrypted filepath
        cipher = Fernet(TEST_SECRET_KEY.encode())
        test_filepath = "/tmp/test_profile.oni"
        encrypted_filepath = cipher.encrypt(test_filepath.encode())
        b64_encrypted = base64.b64encode(encrypted_filepath).decode()

        setup_data = {"test_profile": {"filepath": b64_encrypted}}

        mock_setup_engine = MagicMock()
        mock_setup_engine.read.return_value = setup_data

        mock_db_manager = MagicMock()
        mock_db_manager.get_engine.return_value = mock_setup_engine
        mock_db_manager.add_engine.side_effect = lambda *args, **kwargs: MagicMock()

        with patch(
            "onilock.account_manager.DatabaseManager", return_value=mock_db_manager
        ):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.SETUP_FILEPATH = "/tmp/setup.oni"
                ms.DB_NAME = "test_profile"
                from onilock.account_manager import get_profile_engine

                result = get_profile_engine()

        self.assertIsNotNone(result)


class TestInitialize(unittest.TestCase):
    def _run_initialize(self, master_password=None, already_initialized=False):
        """Helper to run initialize() with mocked DatabaseManager."""
        mock_data_engine = MagicMock()
        mock_data_engine.read.return_value = (
            {"existing": True} if already_initialized else {}
        )

        mock_setup_engine = MagicMock()
        mock_setup_engine.read.return_value = (
            {"existing_profile": {}} if already_initialized else {}
        )

        mock_db_manager = MagicMock()
        mock_db_manager.get_engine.return_value = mock_data_engine
        mock_db_manager.add_engine.return_value = mock_setup_engine

        with patch(
            "onilock.account_manager.DatabaseManager", return_value=mock_db_manager
        ):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.SETUP_FILEPATH = "/tmp/setup_test.oni"
                ms.DB_NAME = "test_new_profile"
                from onilock.account_manager import initialize

                return initialize(master_password)

    def test_initialize_with_master_password_writes_profile(self):
        mock_data_engine = MagicMock()
        mock_data_engine.read.return_value = {}
        mock_setup_engine = MagicMock()
        mock_setup_engine.read.return_value = {}
        mock_db_manager = MagicMock()
        mock_db_manager.get_engine.return_value = mock_data_engine
        mock_db_manager.add_engine.return_value = mock_setup_engine

        with patch(
            "onilock.account_manager.DatabaseManager", return_value=mock_db_manager
        ):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.SETUP_FILEPATH = "/tmp/setup_test.oni"
                ms.DB_NAME = "test_new_profile"
                from onilock.account_manager import initialize

                initialize(TEST_MASTER_PASSWORD)

        mock_data_engine.write.assert_called_once()
        mock_setup_engine.write.assert_called_once()

    def test_initialize_without_master_password_generates_one(self):
        mock_data_engine = MagicMock()
        mock_data_engine.read.return_value = {}
        mock_setup_engine = MagicMock()
        mock_setup_engine.read.return_value = {}
        mock_db_manager = MagicMock()
        mock_db_manager.get_engine.return_value = mock_data_engine
        mock_db_manager.add_engine.return_value = mock_setup_engine

        with patch(
            "onilock.account_manager.DatabaseManager", return_value=mock_db_manager
        ):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.SETUP_FILEPATH = "/tmp/setup_test.oni"
                ms.DB_NAME = "test_new_profile"
                with patch("onilock.core.ui.console.print") as mock_print:
                    from onilock.account_manager import initialize

                    initialize(None)

        # Should display the generated password via the warning() helper (which uses console.print)
        mock_print.assert_called()

    def test_initialize_already_initialized_exits(self):
        mock_data_engine = MagicMock()
        mock_data_engine.read.return_value = {"existing": True}  # Already has data
        mock_setup_engine = MagicMock()
        mock_setup_engine.read.return_value = {}
        mock_db_manager = MagicMock()
        mock_db_manager.get_engine.return_value = mock_data_engine
        mock_db_manager.add_engine.return_value = mock_setup_engine

        with patch(
            "onilock.account_manager.DatabaseManager", return_value=mock_db_manager
        ):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.SETUP_FILEPATH = "/tmp/setup_test.oni"
                ms.DB_NAME = "test_new_profile"
                from onilock.account_manager import initialize

                with self.assertRaises(SystemExit):
                    initialize(TEST_MASTER_PASSWORD)

    def test_initialize_name_in_setup_data_exits(self):
        mock_data_engine = MagicMock()
        mock_data_engine.read.return_value = {}
        mock_setup_engine = MagicMock()
        # DB_NAME is already in setup data
        mock_setup_engine.read.return_value = {"test_new_profile": {"filepath": "abc"}}
        mock_db_manager = MagicMock()
        mock_db_manager.get_engine.return_value = mock_data_engine
        mock_db_manager.add_engine.return_value = mock_setup_engine

        with patch(
            "onilock.account_manager.DatabaseManager", return_value=mock_db_manager
        ):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.SETUP_FILEPATH = "/tmp/setup_test.oni"
                ms.DB_NAME = "test_new_profile"
                from onilock.account_manager import initialize

                with self.assertRaises(SystemExit):
                    initialize(TEST_MASTER_PASSWORD)


class TestNewAccount(unittest.TestCase):
    def test_new_account_with_password(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import new_account

                new_account(
                    "github", "mypassword", "user", "https://github.com", "desc"
                )

        engine.write.assert_called_once()

    def test_new_account_without_password_generates_one(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import new_account

                new_account("github", None, "user", None, None)

        engine.write.assert_called_once()

    def test_new_account_uninitialized_db_exits(self):
        engine = _make_engine(empty=True)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import new_account

                with self.assertRaises(SystemExit):
                    new_account("github", "pass", None, None, None)


class TestListAccounts(unittest.TestCase):
    def test_list_accounts_outputs(self):
        from io import StringIO
        from rich.console import Console as RichConsole

        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        buf = StringIO()
        test_console = RichConsole(file=buf, no_color=True, width=200)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.console", test_console):
                from onilock.account_manager import list_accounts

                list_accounts()

        self.assertIn("github", buf.getvalue())

    def test_list_accounts_empty(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import list_accounts

            list_accounts()  # Should not raise


class TestListFiles(unittest.TestCase):
    def test_list_files_with_files(self):
        from io import StringIO
        from rich.console import Console as RichConsole

        profile = _make_profile(with_file=True)
        engine = _make_engine(profile)

        buf = StringIO()
        test_console = RichConsole(file=buf, no_color=True, width=200)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.console", test_console):
                from onilock.account_manager import list_files

                list_files()

        self.assertIn("doc1", buf.getvalue())

    def test_list_files_empty(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import list_files

            list_files()  # Should not raise


class TestCopyAccountPassword(unittest.TestCase):
    def test_copy_valid_account_by_name(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                with patch("onilock.account_manager.pyperclip.copy"):
                    with patch("onilock.account_manager.multiprocessing.Process"):
                        with patch("onilock.account_manager.os._exit"):
                            from onilock.account_manager import copy_account_password

                            copy_account_password("github")

    def test_copy_valid_account_by_index(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                with patch("onilock.account_manager.pyperclip.copy"):
                    with patch("onilock.account_manager.multiprocessing.Process"):
                        with patch("onilock.account_manager.os._exit"):
                            from onilock.account_manager import copy_account_password

                            copy_account_password(0)

    def test_copy_invalid_account_exits(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import copy_account_password

                with self.assertRaises(SystemExit):
                    copy_account_password("nonexistent")

    def test_copy_uninitialized_db_exits(self):
        engine = _make_engine(empty=True)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import copy_account_password

                with self.assertRaises(SystemExit):
                    copy_account_password("github")

    def test_os_exit_called_after_clipboard_copy(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                with patch("onilock.account_manager.pyperclip.copy") as mock_copy:
                    with patch(
                        "onilock.account_manager.multiprocessing.Process"
                    ) as MockProc:
                        mock_proc_inst = MagicMock()
                        MockProc.return_value = mock_proc_inst
                        with patch("onilock.account_manager.os._exit") as mock_exit:
                            from onilock.account_manager import copy_account_password

                            copy_account_password("github")

        self.assertGreaterEqual(mock_copy.call_count, 1)
        self.assertEqual(mock_copy.call_args_list[-1], call("mypassword"))
        mock_exit.assert_called_once_with(0)
        mock_proc_inst.start.assert_called_once()


class TestShowDecryptedSecret(unittest.TestCase):
    def test_show_valid_account_by_name(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import get_account_secret

                result = get_account_secret("github")

        self.assertEqual(result["id"], "github")
        self.assertEqual(result["password"], "mypassword")

    def test_show_valid_account_by_index(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import get_account_secret

                result = get_account_secret(0)

        self.assertEqual(result["id"], "github")
        self.assertEqual(result["password"], "mypassword")

    def test_show_invalid_account_exits(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import get_account_secret

                with self.assertRaises(SystemExit):
                    get_account_secret("missing")


class TestAccountNotes(unittest.TestCase):
    def test_set_and_get_and_clear_note(self):
        profile = _make_profile(with_account=True)
        store = profile.model_dump()
        engine = MagicMock()
        engine.read.side_effect = lambda: store
        engine.write.side_effect = lambda payload: store.update(payload)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import (
                    set_account_note,
                    get_account_note,
                    clear_account_note,
                )

                set_account_note("github", "deployment credentials")
                note_payload = get_account_note("github")
                clear_account_note("github")

        self.assertEqual(note_payload["id"], "github")
        self.assertEqual(note_payload["note"], "deployment credentials")
        self.assertGreaterEqual(engine.write.call_count, 2)

    def test_get_note_missing_account_exits(self):
        profile = _make_profile()
        engine = _make_engine(profile)
        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                from onilock.account_manager import get_account_note

                with self.assertRaises(SystemExit):
                    get_account_note("missing")


class TestAccountTags(unittest.TestCase):
    def test_add_remove_and_list_tags(self):
        profile = _make_profile(with_account=True)
        store = profile.model_dump()
        engine = MagicMock()
        engine.read.side_effect = lambda: store
        engine.write.side_effect = lambda payload: store.update(payload)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import (
                add_account_tags,
                remove_account_tags,
                list_account_tags,
            )

            added = add_account_tags("github", ["Prod", " prod ", "Infra"])
            listed = list_account_tags("github")
            removed = remove_account_tags("github", ["prod"])
            listed_after = list_account_tags("github")

        self.assertEqual(added["tags"], ["infra", "prod"])
        self.assertEqual(listed["tags"], ["infra", "prod"])
        self.assertEqual(removed["tags"], ["infra"])
        self.assertEqual(listed_after["tags"], ["infra"])

    def test_list_all_tags(self):
        cipher = Fernet(TEST_SECRET_KEY.encode())
        pw = base64.b64encode(cipher.encrypt(b"x")).decode()
        profile = Profile(
            name="test_profile",
            master_password=base64.b64encode(
                bcrypt.hashpw(TEST_MASTER_PASSWORD.encode(), bcrypt.gensalt())
            ).decode(),
            accounts=[
                Account(
                    id="github",
                    encrypted_password=pw,
                    username="u",
                    tags=["dev"],
                    created_at=int(naive_utcnow().timestamp()),
                ),
                Account(
                    id="gitlab",
                    encrypted_password=pw,
                    username="u",
                    tags=["prod"],
                    created_at=int(naive_utcnow().timestamp()),
                ),
            ],
            files=[],
        )
        engine = _make_engine(profile)
        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import list_account_tags

            payload = list_account_tags()

        self.assertEqual(len(payload), 2)


class TestAccountHistory(unittest.TestCase):
    def test_history_append_and_order_newest_first(self):
        profile = _make_profile(with_account=True)
        store = profile.model_dump()
        engine = MagicMock()
        engine.read.side_effect = lambda: store
        engine.write.side_effect = lambda payload: store.update(payload)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.ONI_HISTORY_MAX = 20
                from onilock.account_manager import (
                    replace_account_password,
                    get_account_history,
                )

                replace_account_password("github", "new-password-1", reason="replace")
                replace_account_password("github", "new-password-2", reason="rotate")
                payload = get_account_history("github")

        self.assertEqual(payload["id"], "github")
        self.assertEqual(len(payload["history"]), 2)
        self.assertEqual(payload["history"][0]["reason"], "rotate")
        self.assertEqual(payload["history"][1]["reason"], "replace")

    def test_history_cap_truncates_old_entries(self):
        profile = _make_profile(with_account=True)
        store = profile.model_dump()
        engine = MagicMock()
        engine.read.side_effect = lambda: store
        engine.write.side_effect = lambda payload: store.update(payload)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.ONI_HISTORY_MAX = 2
                from onilock.account_manager import (
                    replace_account_password,
                    get_account_history,
                )

                replace_account_password("github", "new-password-1", reason="replace")
                replace_account_password("github", "new-password-2", reason="rotate")
                replace_account_password("github", "new-password-3", reason="rotate")
                payload = get_account_history("github")

        self.assertEqual(len(payload["history"]), 2)

    def test_history_for_account_with_no_versions(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import get_account_history

            payload = get_account_history("github")

        self.assertEqual(payload["id"], "github")
        self.assertEqual(payload["history"], [])


class TestRotateAccountPassword(unittest.TestCase):
    def test_rotate_updates_password_and_history(self):
        profile = _make_profile(with_account=True)
        store = profile.model_dump()
        engine = MagicMock()
        engine.read.side_effect = lambda: store
        engine.write.side_effect = lambda payload: store.update(payload)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.ONI_HISTORY_MAX = 20
                with patch(
                    "onilock.account_manager.generate_random_password",
                    return_value="RotatedPass!123",
                ):
                    from onilock.account_manager import (
                        rotate_account_password,
                        get_account_history,
                    )

                    payload = rotate_account_password(
                        "github",
                        length=16,
                        include_special_chars=True,
                    )
                    history = get_account_history("github")

        cipher = Fernet(TEST_SECRET_KEY.encode())
        encrypted = base64.b64decode(store["accounts"][0]["encrypted_password"])
        decrypted = cipher.decrypt(encrypted).decode()
        self.assertEqual(payload["id"], "github")
        self.assertEqual(decrypted, "RotatedPass!123")
        self.assertEqual(len(history["history"]), 1)
        self.assertEqual(history["history"][0]["reason"], "rotate")

    def test_rotate_recomputes_password_health(self):
        profile = _make_profile(with_account=True)
        store = profile.model_dump()
        engine = MagicMock()
        engine.read.side_effect = lambda: store
        engine.write.side_effect = lambda payload: store.update(payload)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch("onilock.account_manager.settings") as ms:
                ms.SECRET_KEY = TEST_SECRET_KEY
                ms.ONI_HISTORY_MAX = 20
                with patch(
                    "onilock.account_manager.generate_random_password",
                    return_value="1234",
                ):
                    from onilock.account_manager import rotate_account_password

                    payload = rotate_account_password(
                        "github",
                        length=4,
                        include_special_chars=False,
                    )

        self.assertTrue(payload["is_weak_password"])


class TestRemoveAccount(unittest.TestCase):
    def test_remove_valid_account(self):
        profile = _make_profile(with_account=True)
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import remove_account

            remove_account("github")

        engine.write.assert_called_once()

    def test_remove_invalid_account_exits(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import remove_account

            with self.assertRaises(SystemExit):
                remove_account("nonexistent")

    def test_remove_uninitialized_db_exits(self):
        engine = _make_engine(empty=True)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import remove_account

            with self.assertRaises(SystemExit):
                remove_account("github")


class TestDeleteProfile(unittest.TestCase):
    def test_delete_valid_master_password(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            with patch(
                "onilock.account_manager.get_passphrase", return_value="passphrase"
            ):
                with patch("onilock.account_manager.keystore") as mock_ks:
                    with patch("onilock.account_manager.delete_pgp_key"):
                        with patch("onilock.account_manager.shutil.rmtree"):
                            with patch("onilock.account_manager.settings") as ms:
                                ms.GPG_HOME = "/tmp/gpg"
                                ms.PGP_REAL_NAME = "test"
                                ms.VAULT_DIR = "/tmp/vault"
                                ms.DB_NAME = "test_profile"
                                from onilock.account_manager import delete_profile

                                delete_profile(TEST_MASTER_PASSWORD)

        mock_ks.clear.assert_called_once()

    def test_delete_invalid_master_password_exits(self):
        profile = _make_profile()
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import delete_profile

            with self.assertRaises(SystemExit):
                delete_profile("wrong_password")


class TestSearchAccounts(unittest.TestCase):
    def test_search_exact_and_fuzzy_match(self):
        cipher = Fernet(TEST_SECRET_KEY.encode())
        pw = base64.b64encode(cipher.encrypt(b"x")).decode()
        profile = Profile(
            name="test_profile",
            master_password=base64.b64encode(
                bcrypt.hashpw(TEST_MASTER_PASSWORD.encode(), bcrypt.gensalt())
            ).decode(),
            accounts=[
                Account(
                    id="github",
                    encrypted_password=pw,
                    username="octocat",
                    url="https://github.com",
                    description="code hosting",
                    created_at=int(naive_utcnow().timestamp()),
                ),
                Account(
                    id="gitlab",
                    encrypted_password=pw,
                    username="ops",
                    url="https://gitlab.com",
                    description="ci",
                    created_at=int(naive_utcnow().timestamp()),
                ),
            ],
            files=[],
        )
        engine = _make_engine(profile)

        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import search_accounts

            exact = search_accounts("github", limit=10)
            fuzzy = search_accounts("githb", limit=10)

        self.assertEqual(exact[0]["id"], "github")
        self.assertEqual(fuzzy[0]["id"], "github")

    def test_search_respects_limit(self):
        cipher = Fernet(TEST_SECRET_KEY.encode())
        pw = base64.b64encode(cipher.encrypt(b"x")).decode()
        profile = Profile(
            name="test_profile",
            master_password=base64.b64encode(
                bcrypt.hashpw(TEST_MASTER_PASSWORD.encode(), bcrypt.gensalt())
            ).decode(),
            accounts=[
                Account(
                    id=f"svc{i}",
                    encrypted_password=pw,
                    username="user",
                    url="https://example.com",
                    description="service",
                    created_at=int(naive_utcnow().timestamp()),
                )
                for i in range(10)
            ],
            files=[],
        )
        engine = _make_engine(profile)
        with patch("onilock.account_manager.get_profile_engine", return_value=engine):
            from onilock.account_manager import search_accounts

            results = search_accounts("svc", limit=3)
        self.assertEqual(len(results), 3)


if __name__ == "__main__":
    unittest.main()
