import unittest

from tests import bootstrap as _bootstrap
from onilock.core.decorators import pre_post_hooks


class PrePostHooksTests(unittest.TestCase):
    def test_hooks_run_in_order_and_result_is_returned(self):
        events: list[str] = []

        def pre():
            events.append("pre")

        def post():
            events.append("post")

        @pre_post_hooks(pre, post)
        def multiply(a: int, b: int) -> int:
            events.append("func")
            return a * b

        result = multiply(6, 7)

        self.assertEqual(result, 42)
        self.assertEqual(events, ["pre", "func", "post"])
