import tempfile
import unittest
import pathlib
from unittest.mock import patch

from onilock.core import auth
from onilock.core.settings import settings


class TestAuthLockout(unittest.TestCase):
    def test_lockout_after_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(settings, "BASE_DIR", pathlib.Path(tmp)):
                with patch.object(settings, "LOCKOUT_ATTEMPTS", 2):
                    with patch.object(settings, "LOCKOUT_WINDOW_SEC", 60):
                        with patch.object(settings, "LOCKOUT_DURATION_SEC", 60):
                            profile = "test"
                            auth.clear_failures(profile)
                            auth.record_failure(profile)
                            locked, _ = auth.is_locked(profile)
                            self.assertFalse(locked)
                            auth.record_failure(profile)
                            locked, remaining = auth.is_locked(profile)
                            self.assertTrue(locked)
                            self.assertGreaterEqual(remaining, 1)
