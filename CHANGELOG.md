# Version 1

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
