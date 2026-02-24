import base64
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from cryptography.fernet import Fernet

from tests import bootstrap as _bootstrap
from onilock.account_manager import copy_account_password, get_profile_engine
from onilock.core import env
from onilock.core.exceptions import VaultConfigurationError, VaultNotInitializedError
from onilock.core.settings import settings
from onilock.db.database_manager import DatabaseManager


class RegressionsTests(unittest.TestCase):
    def test_database_manager_is_not_singleton(self):
        manager_a = DatabaseManager(database_url="/tmp/onilock-a.json")
        manager_b = DatabaseManager(database_url="/tmp/onilock-b.json")

        self.assertIsNot(manager_a, manager_b)
        self.assertNotEqual(manager_a.get_engine().db_url, manager_b.get_engine().db_url)

    def test_env_loading_order_uses_override(self):
        with patch("onilock.core.env.load_dotenv") as load_dotenv_mock, patch(
            "onilock.core.env.os.path.exists", return_value=True
        ):
            env.load_env()

        expected_calls = [
            call(Path.home() / ".onilock" / ".env", override=True),
            call(env.VAULT_DIR / ".env", override=True),
            call(".env", override=True),
        ]
        self.assertEqual(load_dotenv_mock.call_args_list, expected_calls)

    def test_get_profile_engine_raises_when_setup_missing_profile(self):
        setup_engine = MagicMock()
        setup_engine.read.return_value = {}
        setup_manager = MagicMock()
        setup_manager.get_engine.return_value = setup_engine

        with patch("onilock.profile_store.DatabaseManager", side_effect=[setup_manager]):
            with self.assertRaises(VaultNotInitializedError):
                get_profile_engine()

    def test_get_profile_engine_raises_when_filepath_missing(self):
        setup_engine = MagicMock()
        setup_engine.read.return_value = {settings.DB_NAME: {}}
        setup_manager = MagicMock()
        setup_manager.get_engine.return_value = setup_engine

        with patch("onilock.profile_store.DatabaseManager", side_effect=[setup_manager]):
            with self.assertRaises(VaultConfigurationError):
                get_profile_engine()

    def test_get_profile_engine_returns_profile_engine(self):
        cipher = Fernet(settings.SECRET_KEY.encode())
        encrypted = cipher.encrypt(b"/tmp/onilock-profile.oni")
        setup_engine = MagicMock()
        setup_engine.read.return_value = {
            settings.DB_NAME: {"filepath": base64.b64encode(encrypted).decode()}
        }
        setup_manager = MagicMock()
        setup_manager.get_engine.return_value = setup_engine

        profile_engine = MagicMock()
        profile_manager = MagicMock()
        profile_manager.get_engine.return_value = profile_engine

        with patch(
            "onilock.profile_store.DatabaseManager",
            side_effect=[setup_manager, profile_manager],
        ):
            engine = get_profile_engine()
        self.assertIs(engine, profile_engine)

    def test_copy_account_password_schedules_clipboard_cleanup(self):
        with patch("onilock.account_manager.secret_manager.copy", return_value="github") as copy_mock, patch(
            "onilock.account_manager.typer.echo"
        ):
            copy_account_password("github")

        copy_mock.assert_called_once_with("github", clear_after=10)
