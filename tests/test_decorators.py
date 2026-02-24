"""Tests for onilock.core.decorators."""

import unittest
from unittest.mock import MagicMock, patch, call

from onilock.core.decorators import exception_handler, pre_post_hooks


class TestExceptionHandler(unittest.TestCase):
    def test_normal_execution_returns_result(self):
        @exception_handler
        def my_func():
            return "ok"

        result = my_func()
        self.assertEqual(result, "ok")

    def test_not_implemented_error_echoes_message_no_raise(self):
        @exception_handler
        def my_func():
            raise NotImplementedError()

        with patch("onilock.core.decorators.typer.echo") as mock_echo:
            result = my_func()
        mock_echo.assert_called_once()
        call_args = mock_echo.call_args[0][0]
        self.assertIn("not implemented", call_args.lower())
        self.assertIsNone(result)

    def test_general_exception_echoes_no_raise_when_not_debug(self):
        @exception_handler
        def my_func():
            raise ValueError("something went wrong")

        with patch("onilock.core.decorators.settings") as mock_settings:
            mock_settings.DEBUG = False
            with patch("onilock.core.decorators.typer.echo") as mock_echo:
                result = my_func()

        mock_echo.assert_called_once()
        self.assertIsNone(result)

    def test_general_exception_reraises_in_debug_mode(self):
        @exception_handler
        def my_func():
            raise ValueError("debug error")

        with patch("onilock.core.decorators.settings") as mock_settings:
            mock_settings.DEBUG = True
            with patch("onilock.core.decorators.typer.echo"):
                with self.assertRaises(ValueError):
                    my_func()

    def test_preserves_function_metadata(self):
        @exception_handler
        def documented_func():
            """My docstring."""
            pass

        self.assertEqual(documented_func.__name__, "documented_func")
        self.assertEqual(documented_func.__doc__, "My docstring.")

    def test_passes_args_and_kwargs(self):
        @exception_handler
        def my_func(a, b, c=None):
            return (a, b, c)

        result = my_func(1, 2, c=3)
        self.assertEqual(result, (1, 2, 3))


class TestPrePostHooks(unittest.TestCase):
    def test_pre_and_post_called(self):
        pre = MagicMock()
        post = MagicMock()

        @pre_post_hooks(pre, post)
        def my_func():
            pass

        my_func()
        pre.assert_called_once_with()
        post.assert_called_once_with()

    def test_pre_called_before_func_post_after(self):
        call_order = []

        def pre():
            call_order.append("pre")

        def post():
            call_order.append("post")

        @pre_post_hooks(pre, post)
        def my_func():
            call_order.append("func")

        my_func()
        self.assertEqual(call_order, ["pre", "func", "post"])

    def test_no_pre_hook(self):
        post = MagicMock()

        @pre_post_hooks(None, post)
        def my_func():
            pass

        my_func()
        post.assert_called_once()

    def test_no_post_hook(self):
        pre = MagicMock()

        @pre_post_hooks(pre, None)
        def my_func():
            pass

        my_func()
        pre.assert_called_once()

    def test_no_hooks(self):
        @pre_post_hooks(None, None)
        def my_func():
            return 42

        # Should not raise
        my_func()

    def test_pre_kwargs_passed(self):
        pre = MagicMock()

        @pre_post_hooks(pre, None, pre_kwargs={"x": 1, "y": 2})
        def my_func():
            pass

        my_func()
        pre.assert_called_once_with(x=1, y=2)

    def test_post_kwargs_passed(self):
        post = MagicMock()

        @pre_post_hooks(None, post, post_kwargs={"result": "done"})
        def my_func():
            pass

        my_func()
        post.assert_called_once_with(result="done")

    def test_func_receives_args(self):
        received = []

        @pre_post_hooks(None, None)
        def my_func(*args, **kwargs):
            received.append((args, kwargs))

        my_func(1, 2, key="val")
        self.assertEqual(received, [((1, 2), {"key": "val"})])


if __name__ == "__main__":
    unittest.main()
