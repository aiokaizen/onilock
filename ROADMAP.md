# OniLock roadmap

Planned work, in order. Each item says what is wrong, where it is in the code, and when it counts as done. Line numbers refer to `master` at v1.8.3. The `v1.9.0` branch has the same problems.

Last updated: 2026-10-14

## 1. Fix `onilock vault-format`

`onilock vault-format` prints nothing.

In `onilock/run.py`, the `vault-format` command is registered on `_get_vault_format()` (line 985). That function returns the format string instead of printing it, and Typer ignores return values, so the command exits without output. `vault_format_cmd()` (line 1013) prints the same value, but it is not registered as a command. It only runs through `onilock version --vault-format`. On `v1.9.0` the same code is at lines 1692 to 1720.

Done when:

- `vault-format` is registered on `vault_format_cmd()`, and `_get_vault_format()` is a plain helper again.
- A test in `tests/test_run.py` runs `onilock vault-format` with `CliRunner` and checks that the output contains the format, for example `v2 (AEAD AES-GCM)`.

## 2. Support macOS

The package classifiers list macOS and onilock.com says "Linux and macOS", but OniLock does not work on a stock Mac yet. The problems below were found on 2026-10-14 by running 1.8.3 on macOS (Python 3.12, gpg not installed) and by reading the code.

Fix:

- Every command crashes when gpg is missing, including `onilock doctor` and `onilock version`. `onilock/run.py:54` creates `FileEncryptionManager()` when the module is imported, and `gnupg.GPG()` raises `OSError: Unable to run gpg (gpg) - it may not be available.` macOS does not ship gpg. Create the GPG objects only when a command needs them, and turn a missing gpg into one clear message that says how to install it (`brew install gnupg`). `doctor` has to run without gpg, because reporting a missing gpg is its job.
- Decrypted files are written to disk on macOS. `read-file` and `edit-file` put the decrypted copy in `/dev/shm` when it exists (`onilock/filemanager.py:203`). macOS has no `/dev/shm`, so the copy goes to `$TMPDIR`, which is on disk. Find a memory-backed location on macOS, or keep the file private (mode 600) and short-lived and say so in the docs.
- The install guide covers apt only. Add the Homebrew steps (`brew install pipx gnupg`) to `README.md`, as onilock.com already shows.
- CI runs on Ubuntu only. Add a macOS job to `.github/workflows/ci.yml` (`runs-on: macos-latest`, with `brew install gnupg`).

Check on a real Mac, with gpg installed:

- The clipboard is cleared after 10 seconds. `copy` starts a `multiprocessing.Process` and then calls `os._exit(0)` (`onilock/account_manager.py:459`). macOS starts child processes with "spawn", so the child imports `onilock.run` again before it clears the clipboard. The same pattern worked in a standalone script, but OniLock itself has not been tested this way.
- The keyring backend is the macOS Keychain, and `onilock keys rotate-secret` works with it.
- `onilock doctor` passes every check.

Done when a Mac with Homebrew can follow the README, create a vault, add, list and copy a password, and encrypt, read and edit a file, and CI passes on macOS.

## 3. Remove Claude attribution from the repository

Remove every occurrence of Claude attribution from the repository.

As of 2026-10-14 there is one: a `Co-Authored-By` trailer on commit `eb16663` ("Fix security, correctness, and robustness issues across core modules", 2026-02-24). No tracked file, pull request description or release note has one.

That commit is on `master`, `v1.8`, `v1.8.2`, `v1.8.3`, `v1.9.0` and `bugfix/cleanup-and-optimization`, and inside the tags `v1.8.0`, `v1.8.1` and `v1.8.3`. A trailer can only be removed by rewriting history:

- Rewrite the message with `git filter-repo --message-callback`, then force-push every branch and tag that contains it.
- Commit IDs change from `eb16663` onward. Check that the GitHub releases for `v1.8.0`, `v1.8.1` and `v1.8.3` still point at the right tags, and re-clone any local copies.
- Packages already on PyPI are not affected.

Done when `git log --all --format=%B | grep -ci co-authored-by` prints `0`.
