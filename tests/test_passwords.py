import unittest

from onilock.core.passwords import password_health, estimate_entropy_bits


class TestPasswordHealth(unittest.TestCase):
    def test_entropy_increases_with_length(self):
        self.assertLess(estimate_entropy_bits("Aa1!"), estimate_entropy_bits("Aa1!Aa1!Aa1!"))

    def test_detects_common_password(self):
        health = password_health("password", [])
        self.assertTrue(health["is_common"])
        self.assertEqual(health["strength"], "weak")

    def test_detects_reuse(self):
        health = password_health("Unique123!", ["Unique123!"])
        self.assertTrue(health["is_reused"])

    def test_strong_password(self):
        health = password_health("pH$zJ?+k51XM", [])
        self.assertEqual(health["strength"], "strong")
