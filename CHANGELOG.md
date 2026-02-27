# Version 1

## v1.9.0
- Add `search` command with fuzzy account matching, result limits, and JSON output.
- Add `show` command to print a decrypted secret by account name/index with optional JSON output.

## v1.8.0
- Introduce versioned AEAD vault format (v2, AES-GCM) with automatic legacy migration.
- Add export/import encryption, audit logging, and backup/restore workflows.
- Add profile management, key management commands, and environment diagnostics.
- Harden master-password handling with rate limiting, lockouts, and KDF upgrades.
- Add password health checks (entropy, reuse, common password detection) and improved clipboard hygiene.
- Add Poweruser guide and expand documentation.

## v1.7.3
- Fix infinite recursion in `remove-account` CLI command caused by name shadowing between the CLI function and the imported business-logic function.
- Fix `generate_random_password` producing `length + 3/4` characters instead of exactly `length` characters.
- Fix encrypted temp file not being deleted from `/dev/shm` after `read-file` (readonly) or on any exception during `edit-file`.
- Fix `strftime` format string using `%s` (Unix timestamp, non-portable) instead of `%S` (seconds) in exported vault filenames.
- Fix `pre_post_hooks` decorator silently discarding the wrapped function's return value.
- Fix `VaultKeyStore` reusing the same AES-CBC IV across writes, enabling ciphertext pattern analysis; now generates a fresh IV per write.
- Fix `VaultKeyStore` deriving its AES key from the installation file path (predictable and attacker-reproducible); now generates a random 32-byte key stored in `~/.onilock/vault/.key` (mode 600).
- Fix `pgp_key_exists` crashing with `TypeError` when a GPG key has no UIDs.
- Fix `delete_pgp_key` crashing with `TypeError` when the target key does not exist; now raises `EncryptionKeyNotFoundError`.
- Fix Pydantic `Field([])` mutable default shared across model instances; replaced with `Field(default_factory=list)`.
- Expand test suite from 238 to 243 tests; add contract-based assertions replacing observed-behavior confirmations.

## v1.7.2
- Introduce comprehensive test suite with 238 tests achieving 99%+ code coverage.
- Migrate test runner from `unittest` to `pytest` with `pytest-cov`; enforce 95% coverage threshold on every run.
- Overhaul CI/CD pipeline: replace manual `publish-release.sh` workflow with fully automated GitHub Actions.
    - Pull requests to `master` trigger the test suite automatically.
    - Pushes to `master` run tests and, on a new version, create the git tag, GitHub release, and PyPI publication in a single atomic pipeline step.
- Add `DEVELOPER_GUIDE.md` covering setup, running the project, testing, code style, and the PR workflow.
- Minor bug fixes.

## v1.7.0
- Implement file encryption capabilities.
    - Possibility to encrypt any file in your system and add it to the vault.
    - View, and Edit files directly in the vault without exposing them to external threats.
    - Ability to export a single file or all files in the vault to a zip file.
- Introduce env.py to fix the circular import problem.
- Other bug fixes and improvements

## v1.6.2
- Implement pre / post hooks for all commands.
- Add is_weak_password attribute to Account model.
- Implement exception handler decorator to handle all exceptions gracefully.
- Implement Design patterns to GPG encryption.
- Include vault version and creation timestamp in the profile data.
- Reduce dependency for base modules.

## v1.6.1
- Fix issue #6 | Delete password from clipboard raises an exception on WSL.

## v1.6.0
- Fix some bugs.
- Implement support for terminal-based distros.
- Implement git-hub actions for auto-deployment when a new release is created.
- Improve project structure, and implement some design patterns

## v1.5.5
- Update license
- Automate publishing to pypi using Github Actions

## v1.5.4
- Update `version` command
- Ignore case for `delete` and `copy` commands
- Detect file corruption and manipulation using checksums

## v1.5.3
- Introduce `clear` command

## v1.5.2
- Introduce `version` command

## v1.5.0
- Rename shadow to vault
- Clear clipboard after 25 seconds if it still contains the password.
- Encrypt json files using PGP key instead of storing them as raw json file.
- Detect file corruption and manipulation using checksums

## v1.4.0
- Publish the project under the Apache 2.0 license
- Multiple refactoring
- Big upgrade to README.md file.

## v1.3.2
- Prepare for publishing to PyPi

## v1.3.1
- Renamed Account to Profile
- Renamed Password to Account
- Renamed the `accounts` command to `list`
- Remove exceptions and replace them with meaningful messages.

## v1.3.0
- Removed .env support
- Implement keyring secret storage.
- Introduce prompts to facilitate user input
