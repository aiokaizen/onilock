# OniLock - Secure Password Manager CLI

OniLock is a command-line password manager that allows you to securely store, retrieve, and manage your passwords with ease. Designed for simplicity and security, OniLock offers encryption and clipboard integration to keep your credentials safe.


## 📖 Introduction
Most password managers focus on graphical interfaces, leaving terminal enthusiasts behind. Onilock changes that by offering a sleek, terminal-based user experience paired with a comprehensive set of command-line options.

It’s designed for those working without a graphical interface, users who need quick password access over SSH, or anyone who simply prefers the command line over traditional GUI tools.

With full support for command-line arguments, Onilock empowers users to create custom aliases and streamline password management to fit their unique workflows.


## 🚀 Features
- **Initialize a secure profile** using `onilock initialize-vault`
- **Store new accounts** with `onilock new`
- **List stored accounts** using `onilock list`
- **Copy passwords to clipboard** securely with `onilock copy`
- **Remove accounts** using `onilock remove-account`
- **Generate strong passwords** with `onilock generate-pwd`
- **Export/import vaults** with `onilock export-vault` and `onilock import-vault`
- **Encrypted backups** with `onilock backup` and `onilock restore`
- **Profile management** with `onilock profiles list|use`
- **Key management** with `onilock keys list|delete|rotate-secret`
- **Environment diagnostics** with `onilock doctor`
- **Shell completion support** for faster command-line usage


## 🛠 Installation

OniLock is best installed using `pipx` to keep it isolated:

1. **Install pipx**
```sh
sudo apt install pipx
```

2. **Install OniLock systemwide**

N.B. Make sure you don't have any active virtual environments before executing this command.

```sh
pipx install onilock
```


## ⚠️  Issues

If you encounter any issues with the `initialize-vault` command, make sure the following dependencies are setup in your system:

1. **Ensure xclip and gpg are installed**. If not, run the following command
```sh
sudo apt install xclip gpg
```


## 📌 Usage
Once installed, you can use `onilock` directly from your terminal:

```sh
onilock --help
```

### 🔹 Initialize OniLock
Before using OniLock, initialize your profile:
```sh
onilock initialize-vault
```

### 🔹 Add a New Account
```sh
onilock new
```
You will be prompted to enter the account name, username, and password.

### 🔹 List Stored Accounts
```sh
onilock list
```
Displays all saved accounts.

### 🔹 Search Accounts
```sh
onilock search github
onilock search git --limit 5
onilock search github --json
```
Fuzzy-searches accounts by name, username, URL, description, tags, and notes.

### 🔹 Copy a Password to Clipboard
```sh
onilock copy <account_name>
```
This copies the password to your clipboard securely.

### 🔹 Show a Decrypted Secret
```sh
onilock show github
onilock show 1 --json
```
Prints a decrypted secret intentionally for inspection/scripting.

### 🔹 Account Notes
```sh
onilock notes set github --text "Production deployment credentials"
onilock notes get github
onilock notes clear github
```
Stores and retrieves encrypted per-account notes.

### 🔹 Account Tags
```sh
onilock tags add github prod infra
onilock tags list github
onilock tags remove github infra
onilock tags list --json
```
Adds, removes, and lists normalized tags per account.

### 🔹 Password History
```sh
onilock history github
onilock history github --limit 5
onilock history github --json
```
Shows stored password version metadata (newest first).

### 🔹 Rotate Password
```sh
onilock rotate github
onilock rotate github --len 24 --no-special-chars
onilock rotate github --json
```
Generates a new password, stores it, and pushes the previous secret into history.

### 🔹 Remove an Account
```sh
onilock remove-account <account_name>
```
Deletes the stored credentials.

### 🔹 Generate a Secure Password
```sh
onilock generate-pwd
```
Creates a strong random password.

### 🔹 Vault Format Version
```sh
onilock version
```
Prints the current vault format version (v2 for AEAD vaults).

Note: In non-interactive environments, `initialize-vault` and encrypted export/import
require explicit flags (e.g., `--master-password`, `--passphrase`).


## 🔒 Security
- OniLock encrypts stored passwords and prevents direct file access.
- Uses the system keyring for secure storage (if available).
- Passwords copied to the clipboard are automatically cleared after a short period.
- Master password protection includes rate limiting and lockouts on repeated failures.
- Exported vaults can be encrypted with a user-provided passphrase.
- An audit log is maintained for key vault events.

### Threat Model
OniLock is a local‑only CLI password manager. It does not sync, upload, or transmit
vault data. It protects against offline access to the vault files and casual
local inspection, but **does not** protect against a compromised OS, keyloggers,
or an attacker with access to the running process. Filenames and timestamps can
be visible unless explicitly exported with encryption.

### Vault Format & Integrity
Vault data uses a **versioned format** with AEAD integrity protection (v2 uses
AES‑GCM). Legacy v1 data is migrated on successful read.

## 📘 Advanced Usage
See `ADVANCED_USAGE.md` for in-depth workflows, export/import formats, and power-user options.


## 🖥️ Shell Autocompletion
Enable shell autocompletion for easier usage:
```sh
onilock --install-completion
```


## 📜 License
OniLock is open-source and licensed under the Apache 2.0 License.


## 🤝 Contributing
Contributions are welcome! Feel free to submit issues and pull requests.


## 📝 Changelog

### v1.8.0
- Introduce versioned AEAD vault format (v2, AES-GCM) with automatic legacy migration.
- Add export/import encryption, audit logging, and backup/restore workflows.
- Add profile management, key management commands, and environment diagnostics.
- Harden master-password handling with rate limiting, lockouts, and KDF upgrades.
- Add password health checks (entropy, reuse, common password detection) and improved clipboard hygiene.
- Add Poweruser guide and expanded documentation.

### v1.7.3
- Fix infinite recursion in `remove-account`, wrong password length in `generate_random_password`, and temp file leak in `edit-file`/`read-file`.
- Fix AES-CBC IV reuse and weak key derivation in `VaultKeyStore`; keys are now random and stored in a protected file.
- Fix GPG utility crashes when a key has no UIDs or when deleting a non-existent key.
- Fix Pydantic mutable default shared across model instances.
- Expand test suite to 243 tests; replace observed-behavior assertions with contract-based assertions.

### v1.7.2
- Introduce comprehensive test suite with 238 tests achieving 99%+ code coverage.
- Migrate test runner from `unittest` to `pytest` with `pytest-cov`; enforce 95% coverage threshold on every run.
- Overhaul CI/CD pipeline: tests run automatically on PRs and pushes to `master`; releases and PyPI publication are now fully automated on version bump.
- Add `DEVELOPER_GUIDE.md` covering setup, testing, and the contribution workflow.

### v1.7.0
- Implement file encryption capabilities.
    - Possibility to encrypt any file in your system and add it to the vault.
    - View, and Edit files directly in the vault without exposing them to external threats.
    - Ability to export a single file or all files in the vault to a zip file.
- Introduce env.py to fix the circular import problem.
- Other bug fixes and improvements

### v1.6.0
- Fix some bugs.
- Implement support for terminal-based distros.
- Implement git-hub actions for auto-deployment when a new release is created.
- Improve project structure, and implement some design patterns

View full changelog history on `CHANGELOG.md` file.


## 📧 Contact
Author: Mouad Kommir  
Email: mouadkommir@gmail.com
