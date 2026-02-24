import string
import unittest

from tests import bootstrap as _bootstrap
from onilock.core.utils import generate_random_password, str_to_bool


class UtilsTests(unittest.TestCase):
    def test_generate_random_password_respects_length(self):
        password = generate_random_password(12, include_special_characters=False)
        self.assertEqual(len(password), 12)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(all(c in (string.ascii_letters + string.digits) for c in password))

    def test_generate_random_password_with_special_chars(self):
        punctuation = "@$!%*?&_}{()-=+"
        password = generate_random_password(16, include_special_characters=True)
        self.assertEqual(len(password), 16)
        self.assertTrue(any(c in punctuation for c in password))

    def test_generate_random_password_rejects_too_short_length(self):
        with self.assertRaises(ValueError):
            generate_random_password(2, include_special_characters=False)
        with self.assertRaises(ValueError):
            generate_random_password(3, include_special_characters=True)

    def test_str_to_bool(self):
        self.assertTrue(str_to_bool("yes"))
        self.assertFalse(str_to_bool("off"))
        with self.assertRaises(ValueError):
            str_to_bool("not-a-bool")
