"""Tests for onilock.db.database_manager (DatabaseManager singleton)."""

import unittest
from unittest.mock import MagicMock, patch

from onilock.db.database_manager import (
    DatabaseManager,
    create_engine,
    create_encrypted_engine,
)


class TestFactoryFunctions(unittest.TestCase):
    def test_create_engine_returns_json_engine(self):
        from onilock.db.engines import JsonEngine

        engine = create_engine("/tmp/test.json")
        self.assertIsInstance(engine, JsonEngine)

    def test_create_encrypted_engine_returns_encrypted_json_engine(self):
        from onilock.db.engines import EncryptedJsonEngine

        with patch("onilock.db.engines.EncryptionBackendManager"):
            engine = create_encrypted_engine("/tmp/test.oni")
        self.assertIsInstance(engine, EncryptedJsonEngine)

    def test_create_encrypted_engine_with_custom_backend(self):
        from onilock.db.engines import EncryptedJsonEngine

        mock_backend = MagicMock()
        with patch("onilock.db.engines.EncryptionBackendManager"):
            engine = create_encrypted_engine("/tmp/test.oni", mock_backend)
        self.assertIsInstance(engine, EncryptedJsonEngine)


class TestDatabaseManagerSingleton(unittest.TestCase):
    def setUp(self):
        DatabaseManager._instance = None

    def tearDown(self):
        DatabaseManager._instance = None

    def test_singleton_same_instance(self):
        with patch("onilock.db.engines.EncryptionBackendManager"):
            m1 = DatabaseManager(database_url="/tmp/db1.oni", is_encrypted=True)
            m2 = DatabaseManager(database_url="/tmp/db2.oni", is_encrypted=True)
        self.assertIs(m1, m2)

    def test_plain_db_initialization(self):
        manager = DatabaseManager(database_url="/tmp/plain.json", is_encrypted=False)
        self.assertIn("default", manager._engines)

    def test_encrypted_db_initialization(self):
        with patch("onilock.db.engines.EncryptionBackendManager"):
            manager = DatabaseManager(database_url="/tmp/enc.oni", is_encrypted=True)
        self.assertIn("default", manager._engines)

    def test_get_engine_default(self):
        manager = DatabaseManager(database_url="/tmp/plain.json", is_encrypted=False)
        engine = manager.get_engine()
        self.assertIsNotNone(engine)

    def test_get_engine_by_id(self):
        manager = DatabaseManager(database_url="/tmp/plain.json", is_encrypted=False)
        # Add a custom engine
        manager._engines["custom"] = MagicMock()
        result = manager.get_engine("custom")
        self.assertIs(result, manager._engines["custom"])

    def test_add_engine_plain(self):
        manager = DatabaseManager(database_url="/tmp/plain.json", is_encrypted=False)
        engine = manager.add_engine("extra", "/tmp/extra.json", is_encrypted=False)
        self.assertIn("extra", manager._engines)
        self.assertIs(engine, manager._engines["extra"])

    def test_add_engine_encrypted(self):
        with patch("onilock.db.engines.EncryptionBackendManager"):
            manager = DatabaseManager(database_url="/tmp/enc.oni", is_encrypted=True)
            engine = manager.add_engine(
                "extra_enc", "/tmp/extra.oni", is_encrypted=True
            )
        self.assertIn("extra_enc", manager._engines)

    def test_add_engine_existing_returns_same(self):
        manager = DatabaseManager(database_url="/tmp/plain.json", is_encrypted=False)
        mock_engine = MagicMock()
        manager._engines["existing"] = mock_engine
        result = manager.add_engine("existing", "/tmp/other.json", is_encrypted=False)
        self.assertIs(result, mock_engine)

    def test_initialized_flag_prevents_reinitialization(self):
        """Second __init__ call on same singleton should be a no-op."""
        manager = DatabaseManager(database_url="/tmp/plain.json", is_encrypted=False)
        initial_engines = dict(manager._engines)
        # Call __init__ again with different URL
        manager.__init__(database_url="/tmp/other.json", is_encrypted=False)
        self.assertEqual(list(manager._engines.keys()), list(initial_engines.keys()))


if __name__ == "__main__":
    unittest.main()
