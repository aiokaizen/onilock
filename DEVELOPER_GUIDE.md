# OniLock Developer Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Getting Started](#getting-started)
3. [Running the Project](#running-the-project)
4. [Running Tests](#running-tests)
5. [Code Style](#code-style)
6. [Contributing & Pull Requests](#contributing--pull-requests)

---

## Prerequisites

- Python 3.10 or higher
- [Poetry](https://python-poetry.org/) 2.0+
- GPG (required for file encryption features)
- A clipboard utility (`xclip` or `xsel` on Linux, built-in on macOS/Windows)

Install Poetry if you don't have it:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Verify the installation:

```bash
poetry --version
```

---

## Getting Started

### 1. Clone the repository

```bash
git clone git@github.com:aiokaizen/onilock.git
cd onilock
```

### 2. Install dependencies

Install all runtime and development dependencies into a Poetry-managed virtual environment:

```bash
poetry install --with dev
```

This creates an isolated virtualenv (typically under `~/.cache/pypoetry/virtualenvs/`) and installs everything listed in `pyproject.toml`.

Activate virtual environment

```bash
eval $(poetry env activate)
```

---

## Running the Project

OniLock is a CLI tool. With the virtualenv active, the `onilock` entry point is available directly:

```bash
# Show all available commands
onilock --help

# Initialize a new vault
onilock initialize-vault

# Add a new account
onilock new

# List saved accounts
onilock list

# Copy a password to the clipboard
onilock copy <account-name>

# Encrypt a file
onilock encrypt-file <path/to/file>

# Show the current version
onilock version
```

### Environment variables

The following env vars control runtime behaviour and are useful during development:

| Variable | Default | Description |
|---|---|---|
| `ONI_DEBUG` | `false` | Set to `true` to enable verbose logging and let exceptions propagate |
| `ONI_SECRET_KEY` | *(auto-generated)* | Fernet key used for vault encryption; auto-generated and stored in keystore on first run |
| `ONI_GPG_PASSPHRASE` | *(auto-generated)* | Passphrase for the GPG key used for file encryption |
| `ONI_DEFAULT_KEYSTORE_BACKEND` | `keyring` | `keyring` uses the system keyring; `vault` uses an AES-encrypted file in `~/.onilock/vault/` |
| `ONI_DB_NAME` | `profile` | Name of the active vault profile |
| `ONI_PGP_REAL_NAME` | *(username)* | Display name used when generating the GPG key pair |

Example: run with debug logging enabled:

```bash
ONI_DEBUG=true onilock list
```

---

## Running Tests

The test suite uses [pytest](https://pytest.org/) with [pytest-cov](https://pytest-cov.readthedocs.io/) for coverage reporting.

### Run all tests with coverage

```bash
python -m pytest tests/
```

The `pyproject.toml` configures pytest to:
- Look for tests in the `tests/` directory
- Measure coverage over the `onilock` package
- Print a line-by-line missing-coverage report
- Fail if total coverage drops below 95%

### Run a specific test file

```bash
python -m pytest tests/test_models.py
```

### Run a specific test case

```bash
python -m pytest tests/test_account_manager.py::TestInitialize::test_new_profile
```

### Run tests without the coverage threshold check

```bash
python -m pytest tests/ --no-cov
```

### Generate an HTML coverage report

```bash
python -m pytest tests/ --cov-report=html
# Open htmlcov/index.html in a browser
```

### Test layout

```
tests/
├── conftest.py            # Bootstrap: HOME redirect, env vars, gnupg mock, shared fixtures
├── test_models.py         # Pydantic model tests (Account, File, Profile)
├── test_engines.py        # JsonEngine and EncryptedJsonEngine
├── test_database_manager.py  # DatabaseManager singleton and factory functions
├── test_utils.py          # Utility function tests
├── test_keystore.py       # VaultKeyStore, KeyRing, KeyStoreManager
├── test_decorators.py     # exception_handler, pre_post_hooks decorators
├── test_encryption.py     # EncryptionBackendManager and GPGEncryptionBackend
├── test_gpg.py            # GPG helper functions
├── test_account_manager.py  # Account CRUD operations
├── test_filemanager.py    # FileEncryptionManager
├── test_run.py            # CLI commands via typer.testing.CliRunner
└── test_misc.py           # Targeted coverage for remaining edge cases
```

> **Important**: `tests/conftest.py` must be loaded before any `onilock` import. It redirects `HOME` to a temporary directory and injects a mock `gnupg` module so tests never touch the production vault or perform real GPG operations.

---

## Code Style

OniLock uses [Black](https://black.readthedocs.io/) for formatting:

```bash
# Format all source files
black onilock/ tests/

# Check formatting without modifying files
black --check onilock/ tests/
```

---

## Contributing & Pull Requests

### Branching strategy

- `master` — stable, production-ready code; all PRs target this branch
- Feature/fix branches: use descriptive names such as `feat/file-export-zip` or `fix/clipboard-clear-race`

### Workflow

```bash
# 1. Create a feature branch off master
git checkout master
git pull origin master
git checkout -b feat/your-feature-name

# 2. Make your changes, then run the full test suite
python -m pytest tests/

# 3. Format your code
black onilock/ tests/

# 4. Commit with a clear message
git add <files>
git commit -m "feat: short description of what and why"

# 5. Push the branch and open a PR
git push -u origin feat/your-feature-name
gh pr create --base master --title "feat: your feature" --body "Description of the changes"
```

### PR checklist

- [ ] All existing tests pass (`python -m pytest tests/`)
- [ ] New code is covered by tests (coverage remains ≥ 95%)
- [ ] Code is formatted with Black
- [ ] Commit messages are descriptive and reference any related issues
- [ ] `CHANGELOG.md` is updated if the change is user-facing

### Reporting issues

Open an issue at <https://github.com/aiokaizen/onilock/issues> with:
- A short description of the problem
- Steps to reproduce
- Expected vs. actual behaviour
- Python version and OS
