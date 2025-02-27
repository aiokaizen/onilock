# Version 1

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
