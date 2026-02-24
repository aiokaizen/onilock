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
```

This checks:
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
- `onilock doctor` checks gpg, gpg-agent, clipboard, and path permissions.
- Clipboard can be disabled with `ONI_CLIPBOARD=false`.
