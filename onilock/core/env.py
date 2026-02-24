import os
from pathlib import Path

from dotenv import load_dotenv


VAULT_DIR = Path.home() / ".onilock" / "vault"
_env_loaded = False


def load_env():
    # Load environment variables
    env_filenames = [
        # Order matters. Entries lower in the list override previous values.
        Path.home() / ".onilock" / ".env",
        VAULT_DIR / ".env",
        ".env",
    ]
    for filename in env_filenames:
        if os.path.exists(filename):
            load_dotenv(filename, override=True)

    global _env_loaded
    _env_loaded = True


load_env()
