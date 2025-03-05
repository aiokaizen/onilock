import functools
from typing import Callable, Dict, Optional

import typer

from onilock.core.settings import settings


def exception_handler(func):
    """Overrides typerTyper.command() decorator."""

    # Optional. Preserve func metadata.
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except NotImplementedError:
            typer.echo(
                "This functionality is not implemented in this version.", err=True
            )
        except Exception as e:
            typer.echo(f"Unknown exception was raised in the application: {e}")
            if settings.DEBUG:
                raise e

    return wrapper


def pre_post_hooks(
    pre: Optional[Callable] = None,
    post: Optional[Callable] = None,
    *,
    pre_kwargs: Optional[Dict] = None,
    post_kwargs: Optional[Dict] = None,
):
    """
    Provides pre start and post finish hooks.

    Args:
        pre (Optional[Callable]): The hook that's called before the function starts.
        post (Optional[Callable]): The hook that's called after the function finishes.
        pre_kwargs (Optional[Dict]): Arguments for `pre` callback.
        post_kwargs (Optional[Dict]): Arguments for `post` callback.
    """

    pre_kwargs = pre_kwargs or {}
    post_kwargs = post_kwargs or {}

    def decorator(func):
        def wrapper(*args, **kwargs):
            pre(**pre_kwargs) if pre else None
            func(*args, **kwargs)
            post(**post_kwargs) if post else None

        return wrapper

    return decorator
