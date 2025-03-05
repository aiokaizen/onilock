import inspect

import typer

from . import migrations


def migrate_vault(src: str, dist: str):
    def strip_v(v):
        return f'v{v.replace(".", "")}'

    # Get all functions from the module
    functions = {
        name: obj for name, obj in inspect.getmembers(migrations, inspect.isfunction)
    }
    migration_name = f"migrate_{strip_v(src)}_{strip_v(dist)}"

    for fname in functions.keys():
        if fname == migration_name:
            return functions[fname]()

    typer.echo(
        f"\nNo migration found from version '{src}' to '{dist}'.\n"
        'Hint: Make sure you provided the correct format (e.g. migrate_vault("1.0", "1.1")).\n',
        err=True,
    )
