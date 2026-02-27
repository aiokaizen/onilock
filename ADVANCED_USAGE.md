# OniLock Advanced Usage Guide

This guide is for power users who want to understand OniLock’s internal behavior,
security boundaries, and advanced workflows. It is a practical, command‑focused
reference for day‑to‑day operations and troubleshooting.

## Profiles
OniLock supports multiple profiles that are isolated by profile name and vault directory.

- List profiles:
```sh
onilock profiles list
```

- Set active profile (used on subsequent commands):
```sh
onilock profiles use work
```

If `ONI_DB_NAME` is set, it overrides the active profile file.

## Vault Initialization
Initialize a vault once per profile:
```sh
onilock initialize-vault
```

This records `vault_version` at creation time and enables migrations later.

## Password Health
When adding new accounts, OniLock checks for:
- Minimum length
- Character variety
- Entropy estimate
- Reuse across existing accounts
- Common password list match

Weak passwords are accepted but flagged and reported.

## Account Search
Use fuzzy search to quickly find accounts by:
- account id/name
- username
- URL
- description
- tags and notes (when present)

Examples:
```sh
onilock search github
onilock search prod --limit 10
onilock search git --json
```

`--json` is useful for scripts and shell pipelines.

## Decrypted Secret Output
Use `show` when you explicitly need the decrypted password printed:
```sh
onilock show github
onilock show 1 --json
```

Security note:
- `show` prints secrets to terminal/stdout by design.
- Avoid using it in shared terminals, shell history, or CI logs.

## Account Notes
Notes are encrypted with the same vault secret key and stored per account.

Examples:
```sh
onilock notes set github --text "Use SSO fallback account for emergencies."
onilock notes set github --file ./note.txt
onilock notes get github
onilock notes get github --json
onilock notes clear github
```

## Account Tags
Tags are normalized to lowercase, trimmed, deduplicated, and sorted.

Examples:
```sh
onilock tags add github prod infra "team-a"
onilock tags remove github infra
onilock tags list github
onilock tags list --json
```

Usage tips:
- Use short operational tags (`prod`, `staging`, `finance`, `shared`).
- Pair with fuzzy search (`onilock search prod`) for quick filtering.

## Password History
OniLock tracks previous encrypted passwords when a password is replaced or rotated.
History is metadata-only output (timestamp and reason), not plaintext secrets.

Examples:
```sh
onilock history github
onilock history github --limit 5
onilock history github --json
```

Defaults:
- Newest-first display order.
- Maximum stored history entries per account controlled by `ONI_HISTORY_MAX` (default `20`).

## Password Rotation
Use `rotate` to generate and store a new password for an account.
The previous encrypted secret is automatically saved to history with reason `rotate`.

Examples:
```sh
onilock rotate github
onilock rotate github --len 24 --no-special-chars
onilock rotate github --json
```

Notes:
- Human output prints a summary only, not the raw password.
- Password health is recalculated after rotation.

## Password Health Reports
Use `health` to review weak/reused/common passwords and entropy scores.

Examples:
```sh
onilock health github
onilock health --all
onilock health --all --json
```

Report details include:
- strength classification (`strong`, `medium`, `weak`)
- entropy estimate
- reuse/common-password flags
- remediation reasons

## PIN Unlock Sessions
OniLock supports an optional profile PIN (4 digits) for sensitive-command gating.

Lifecycle:
- Set at initialization with `onilock initialize-vault --pin 1234`.
- Set/change later with `onilock pin reset --pin 1234`.
- Disable by clearing PIN with `onilock pin reset` and submitting empty input.

Unlock flow:
```sh
onilock unlock --pin 1234
```

Session behavior:
- Unlock state is cached in `.unlock.json` under OniLock base directory.
- Session timeout is controlled by `ONI_UNLOCK_TTL_SEC` (default `600` seconds).
- Sensitive commands require an unlocked session only when PIN is enabled.

## Shell-Safe JSON Outputs
Core commands support deterministic `--json` output for automation.

Examples:
```sh
onilock list --json | jq .
onilock list-files --json | jq .
onilock search github --json | jq .
onilock show github --json | jq .
onilock history github --json | jq .
onilock health --all --json | jq .
onilock doctor --json | jq .
```

JSON mode rules:
- No rich markup/table formatting is emitted.
- Keys are stable and command-specific.
- Prefer JSON mode for scripts, CI checks, and wrappers.

## Secure Imports (CSV + KeePass XML)
Import secrets from structured files without exposing plaintext in command output.

Supported formats:
- `csv`
- `keepass-xml` (XML export, not `.kdbx` binary files)

Examples:
```sh
onilock import-secrets --format csv --path ./secrets.csv --dry-run
onilock import-secrets --format csv --path ./secrets.csv --replace-existing
onilock import-secrets --format keepass-xml --path ./keepass-export.xml
onilock import-secrets --format keepass-xml --path ./keepass-export.xml --json
```

Behavior:
- Missing `id` or `password` rows are counted as invalid.
- Existing accounts are skipped unless `--replace-existing` is passed.
- `--dry-run` validates/parses inputs and reports counts without writing to vault.

## Vault Check / Repair
Use integrity commands to detect and repair recoverable metadata issues.

Examples:
```sh
onilock vault check
onilock vault check --json
onilock vault repair
onilock vault repair --apply
onilock vault repair --apply --json
```

`vault check` detects:
- missing setup file linkage
- dangling encrypted file metadata
- malformed account tags/history structures

`vault repair` behavior:
- default mode is dry-run (plan only)
- `--apply` performs mutations
- repair is idempotent (re-running after a successful repair produces no further changes)

## Master Password Security
Master password handling includes:
- Bcrypt KDF with configurable rounds (`ONI_BCRYPT_ROUNDS`)
- Rate limiting and lockouts (`ONI_LOCKOUT_*`)
- Best‑effort memory zeroing of master password buffers

## Export / Import
Export the vault (passwords, files, or both):
```sh
onilock export-vault --no-files
onilock export-vault --no-passwords
```

Encrypt the export with a passphrase:
```sh
onilock export-vault --encrypt
```

Import an export:
```sh
onilock import-vault path/to/export.zip
onilock import-vault path/to/export.onilock-export.json --passphrase <pass>
```

Imports can merge or replace existing data:
```sh
onilock import-vault export.zip --replace
```

Exports include:
- `accounts.json` (if passwords are exported)
- `files/` (if files are exported)
- `files.json` (metadata)
- `manifest.json` (checksums)
- `audit.log` (if present)

## Inspecting Exports and Backups
OniLock exports are either:
- Plain ZIP archives (`.zip`)
- Encrypted JSON payloads (`.onilock-export.json`)

Use the workflow below based on the file type.

### 1) Inspect a plain ZIP export
List archive contents:
```sh
unzip -l path/to/export.zip
```

Read important files without extracting:
```sh
unzip -p path/to/export.zip manifest.json
unzip -p path/to/export.zip accounts.json
unzip -p path/to/export.zip files.json
```

Pretty-print JSON with `jq`:
```sh
unzip -p path/to/export.zip manifest.json | jq .
unzip -p path/to/export.zip accounts.json | jq .
unzip -p path/to/export.zip files.json | jq .
```

If `jq` is unavailable, use Python:
```sh
python -m json.tool <(unzip -p path/to/export.zip manifest.json)
```

Extract to an inspection directory:
```sh
mkdir -p /tmp/onilock-inspect
unzip path/to/export.zip -d /tmp/onilock-inspect
```

### 2) Inspect an encrypted export (`.onilock-export.json`)
Encrypted exports are not directly human-readable. The recommended workflow is:

1. Create an isolated temporary profile.
2. Import the encrypted export with the passphrase.
3. Inspect through OniLock commands.
4. Delete the temporary profile.

Example:
```sh
ONI_DB_NAME=inspect_tmp onilock initialize-vault --master-password "temp-strong-pass"
ONI_DB_NAME=inspect_tmp onilock import-vault path/to/export.onilock-export.json --passphrase "<export-passphrase>"
ONI_DB_NAME=inspect_tmp onilock list
ONI_DB_NAME=inspect_tmp onilock list-files
```

Inspect specific accounts/files:
```sh
ONI_DB_NAME=inspect_tmp onilock copy github
ONI_DB_NAME=inspect_tmp onilock export-file notes --output /tmp/notes.txt
```

Cleanup when done:
```sh
onilock profiles remove inspect_tmp --force
```

### 3) Verify archive integrity metadata
Exports include checksums in `manifest.json`. To compare expected vs actual hashes:
```sh
unzip -p path/to/export.zip manifest.json | jq '.checksums'
```

Check a specific file digest:
```sh
unzip -p path/to/export.zip accounts.json | sha256sum
```

Compare the computed hash with the value in `manifest.json`.

### 4) Safety recommendations for inspection
- Prefer inspecting in a temporary profile.
- Do not inspect sensitive exports in shared directories.
- Remove temporary extracted files after review.
- Use encrypted exports (`--encrypt`) for long-term storage and transfer.
- Keep export passphrases separate from vault credentials.

## Backup / Restore
Encrypted backups are built-in:
```sh
onilock backup
onilock restore path/to/backup.onilock-export.json
```

## File Encryption
Encrypt files into the vault:
```sh
onilock encrypt-file notes ./notes.txt
```

List or export files:
```sh
onilock list-files
onilock export-file notes
```

## Key Management
List GPG keys and the active key:
```sh
onilock keys list
```

Delete a GPG key:
```sh
onilock keys delete --name mykey
```

Rotate the vault secret key (re-encrypts stored passwords):
```sh
onilock keys rotate-secret
```

## Audit Log
Audit events are appended to `audit.log` under the base OniLock directory.
Events include vault initialization, account changes, exports/imports, and file operations.

## Environment Diagnostics
Validate your environment:
```sh
onilock doctor
onilock doctor --verbose
onilock doctor --json
```

This checks:
- Active profile and setup/profile readability
- Unlock/PIN session state
- Keystore backend resolution
- Vault/backup/audit write permissions
- Vault and GPG paths
- gpg/gpg-agent availability
- keyring backend
- clipboard support

## Environment Variables
Common settings:
- `ONI_DB_NAME`: active profile name
- `ONI_VAULT_DIR`: vault directory
- `ONI_GPG_HOME`: GPG home
- `ONI_BCRYPT_ROUNDS`: master password KDF cost
- `ONI_LOCKOUT_*`: lockout controls
- `ONI_CLIPBOARD`: enable/disable clipboard

## Security Notes
OniLock is a local CLI tool. It does not sync data or send it anywhere.
Exported data should be protected with encryption and stored securely.

### Threat Model
- Protects against offline access to encrypted vault files.
- Does not protect against a compromised OS, keyloggers, or runtime memory inspection.
- Metadata (filenames, timestamps, sizes) may be visible unless export encryption is used.

### Vault Format & Migrations
Vault data is stored in a **versioned format**. Current format:
- v2: AEAD AES‑GCM envelope (`ONILOCK_V2` header)
- v1: legacy GPG‑encrypted with checksum

On read, v1 data is migrated to v2 when possible.

### Cross‑Platform Behaviors & Fallbacks
- Non‑TTY mode requires explicit flags for sensitive prompts.
- `onilock doctor` also reports profile/unlock/keystore state and supports JSON output.
- Clipboard can be disabled with `ONI_CLIPBOARD=false`.
