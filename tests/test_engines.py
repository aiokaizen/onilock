"""Tests for onilock.db.engines (JsonEngine, EncryptedJsonEngine)."""

import hashlib
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from onilock.db.engines import JsonEngine, EncryptedJsonEngine
from onilock.core.settings import settings


class TestJsonEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_path = "/tmp/test_onilock_json_engine"
        os.makedirs(self.tmp_path, exist_ok=True)
        self.filepath = os.path.join(self.tmp_path, "test.json")

    def tearDown(self):
        if os.path.exists(self.filepath):
            os.remove(self.filepath)

    def test_write_and_read_roundtrip(self):
        engine = JsonEngine(self.filepath)
        data = {"key": "value", "number": 42}
        engine.write(data)
        result = engine.read()
        self.assertEqual(result, data)

    def test_write_creates_parent_dirs(self):
        nested_path = os.path.join(self.tmp_path, "nested", "dir", "data.json")
        engine = JsonEngine(nested_path)
        engine.write({"a": 1})
        self.assertTrue(os.path.exists(nested_path))
        # Cleanup
        import shutil

        shutil.rmtree(os.path.join(self.tmp_path, "nested"))

    def test_read_missing_file_returns_empty_dict(self):
        engine = JsonEngine("/tmp/this_file_does_not_exist_xyz.json")
        result = engine.read()
        self.assertEqual(result, {})

    def test_read_invalid_json_returns_empty_dict(self):
        with open(self.filepath, "w") as f:
            f.write("not valid json {{{")
        engine = JsonEngine(self.filepath)
        result = engine.read()
        self.assertEqual(result, {})

    def test_write_empty_dict(self):
        engine = JsonEngine(self.filepath)
        engine.write({})
        self.assertEqual(engine.read(), {})

    def test_filepath_attribute(self):
        engine = JsonEngine(self.filepath)
        self.assertEqual(engine.filepath, self.filepath)
        self.assertEqual(engine.db_url, self.filepath)


class TestEncryptedJsonEngine(unittest.TestCase):
    """Tests for EncryptedJsonEngine using a mocked encryption backend."""

    def _make_engine(self, filepath, mock_backend=None):
        """Create an EncryptedJsonEngine with a mocked EncryptionBackendManager."""
        with patch("onilock.db.engines.EncryptionBackendManager") as MockManager:
            if mock_backend:
                MockManager.return_value = mock_backend
            engine = EncryptedJsonEngine(filepath)
        engine._encryption_manager = mock_backend or MagicMock()
        return engine

    def _build_encrypted_content(self, data: dict) -> bytes:
        """Simulate what EncryptedJsonEngine.write() stores, for read() tests."""
        json_str = json.dumps(data, indent=4)
        checksum = hashlib.sha256(json_str.encode()).hexdigest()
        payload = f"{checksum}{settings.CHECKSUM_SEPARATOR}{json_str}"
        return payload.encode()

    def setUp(self):
        self.tmp_path = "/tmp/test_onilock_enc_engine"
        os.makedirs(self.tmp_path, exist_ok=True)
        self.filepath = os.path.join(self.tmp_path, "test.oni")

    def tearDown(self):
        if os.path.exists(self.filepath):
            os.remove(self.filepath)

    def test_write_happy_path(self):
        engine = self._make_engine(self.filepath)
        engine.write({"hello": "world"})

        self.assertTrue(os.path.exists(self.filepath))
        content = open(self.filepath, "rb").read()
        self.assertTrue(content.startswith(EncryptedJsonEngine.V2_HEADER))

    def test_write_encryption_fails_raises_runtime_error(self):
        # AEAD write should not raise for normal data
        engine = self._make_engine(self.filepath)
        engine.write({"key": "val"})

    def test_write_creates_parent_dirs(self):
        nested_path = os.path.join(self.tmp_path, "sub", "data.oni")
        engine = self._make_engine(nested_path)
        engine.write({"x": 1})

        self.assertTrue(os.path.exists(nested_path))
        import shutil

        shutil.rmtree(os.path.join(self.tmp_path, "sub"))

    def test_read_missing_file_returns_empty_dict(self):
        engine = self._make_engine("/tmp/nonexistent_xyz.oni")
        result = engine.read()
        self.assertEqual(result, {})

    def test_read_happy_path(self):
        data = {"key": "value"}
        engine = self._make_engine(self.filepath)
        engine.write(data)
        result = engine.read()
        self.assertEqual(result, data)

    def test_read_decryption_fails_raises_runtime_error(self):
        mock_backend = MagicMock()
        mock_decrypt = MagicMock()
        mock_decrypt.ok = False
        mock_decrypt.status = "decryption error"
        mock_backend.decrypt.return_value = mock_decrypt

        # Write a legacy payload to force v1 path
        with open(self.filepath, "wb") as f:
            f.write(b"legacy")
        engine = self._make_engine(self.filepath, mock_backend)
        with self.assertRaises(RuntimeError):
            engine.read()

    def test_read_checksum_mismatch_raises_runtime_error(self):
        bad_payload = (
            f'wrongchecksum{settings.CHECKSUM_SEPARATOR}{{"key": "val"}}'.encode()
        )

        mock_backend = MagicMock()
        mock_decrypt = MagicMock()
        mock_decrypt.ok = True
        mock_decrypt.data = bad_payload
        mock_backend.decrypt.return_value = mock_decrypt

        with open(self.filepath, "wb") as f:
            f.write(b"legacy")
        engine = self._make_engine(self.filepath, mock_backend)
        with self.assertRaises(RuntimeError):
            engine.read()

    def test_read_missing_separator_raises_value_error(self):
        # No separator in payload
        bad_payload = b"noseparatorhere"
        mock_backend = MagicMock()
        mock_decrypt = MagicMock()
        mock_decrypt.ok = True
        mock_decrypt.data = bad_payload
        mock_backend.decrypt.return_value = mock_decrypt

        with open(self.filepath, "wb") as f:
            f.write(b"legacy")
        engine = self._make_engine(self.filepath, mock_backend)
        with self.assertRaises(ValueError):
            engine.read()


if __name__ == "__main__":
    unittest.main()
