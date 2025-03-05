from pathlib import Path

from onilock.db.models import Profile


def migrate_v10_v11():
    """
    Migrate version 1.0 to version 1.1.

    Differences:
        - New field: vault_vesrion
        - New field: creation_timestamp
    """
    print("Migrating v1.0 to v1.1")


def migrate_v11_v12():
    print("Migrating v1.1 to v1.2")
