import functools

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
