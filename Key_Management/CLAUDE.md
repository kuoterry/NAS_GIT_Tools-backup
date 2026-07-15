# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this folder.

## What this is

Single-file PyQt6 GUI tool (`key_management.py`) that scans the local machine for SSH keys (OpenSSH format + PuTTY `.ppk`), organizes them into a report, and provides management actions (generate, archive/delete, backup, restore). It is **completely independent** of the sibling `NAS_GIT_Tools` project one directory up — no imports, no shared config, no shared state. Treat this as its own project.

## Commands

```
pip install -r requirements.txt   # PyQt6
python .\key_management.py        # run the GUI
build_exe.bat                     # build dist\KeyManagement.exe (onefile/windowed, via PyInstaller)
```

No test suite, linter, or CI config — verification is manual (`python -c "import key_management"` for a syntax/import check; the module's pure functions like `build_records()` can also be exercised directly from a Python REPL without touching Qt).

Current version is tracked in the `__version__` constant near the top of `key_management.py` and shown in the window title; bump it whenever a feature-level change lands. `build_exe.bat` produces two files in `dist\`: the stable `KeyManagement.exe` (desktop-shortcut target, name never changes) and a versioned copy `KeyManagement_v<__version__>.exe` (auto-copied, version read out of the `.py` source) — same convention as the sibling `NAS_GIT_Tools` project's `build_exe.bat`.

## Architecture

- **Pure functions first** (`parse_pubkey_line`, `parse_rfc4716_pubkey`, `parse_pubkey_file`, `ssh_fingerprint`, `describe_key_strength`, `classify_private_key_file`, `parse_ppk_pubkey`, `derive_pubkey_via_sshkeygen`, `scan_folder`, `build_advisories`, `build_records`) — no Qt dependency, so they're testable by direct import. `build_records(folders)` is the main entry point: walks folders, classifies every file as public key / private key / PuTTY `.ppk`, pairs pub+priv by matching basename in the same directory, computes fingerprint/strength/advisories, and returns a list of record dicts.
- **`Worker(QThread)`** — same pattern as the sibling NAS tool (all filesystem/subprocess work happens off the UI thread), but this is an independent implementation, not shared code. Modes: `scan`, `generate`, `delete` (archive or hard, via `hard` param), `backup`, `list_archive`, `restore_archive`, `purge_archive`, `read_private_raw`.
- **`MainWindow`** — folder list (default `~/.ssh`, user can add more, e.g. wherever `.ppk` files live) → scan → `QTableWidget` report → per-row actions (generate new pair, archive/hard-delete selected, backup, view raw private content, copy public key, open containing folder) → archive-region management dialog (`ArchiveManageDialog`) → audit log viewer (`AuditLogDialog`) → CSV export.

### Public key format support

Two on-disk public key formats are recognized, both routed through `parse_pubkey_file(path)`:
- Single-line OpenSSH (`ssh-rsa AAAA... comment`) — `parse_pubkey_line`.
- Multi-line RFC 4716 / SSH2 (`---- BEGIN SSH2 PUBLIC KEY ----` ... `Comment: "..."` ... base64 body ... `---- END`) — `parse_rfc4716_pubkey`. This is what some PuTTYgen versions produce for "export OpenSSH key" instead of the single-line form; found and fixed by testing against the user's real `~/.ssh` (`putty_id_rsa.pub` was silently unparsed before this was added — always test new key-file-format code against real key files, not just synthetic ones).

`.ppk` files are handled separately (`parse_ppk_pubkey` extracts the `Public-Lines:` block directly — always plaintext even when the private part is encrypted) since they bundle pub+priv in one file rather than needing basename pairing.

### Security boundaries (these are load-bearing, not just comments)

- **Private key content is never read except in exactly one place**: `Worker._run_read_private_raw`, which only runs when the user explicitly clicks "檢視私鑰原始內容…" and confirms a warning dialog — and that action is itself written to the audit log. Every other code path that touches a private key file (`classify_private_key_file`, `_is_openssh_v1_encrypted`) only reads header bytes / wire-format metadata (format, encrypted true/false) — never the key material itself.
- **`derive_pubkey_via_sshkeygen`** only runs against private keys already confirmed unencrypted (`priv_encrypted is False`) — it shells out to local `ssh-keygen -y -f <path>` with `input=""` and a 5s timeout so it can't hang waiting on a passphrase prompt it was never meant to trigger.
- **CSV export defaults to excluding private key content.** `on_export_csv` always asks (Yes/No, default No) before including raw private key text as an extra column — because a CSV, unlike the GUI, is a file that gets emailed/copied/uploaded, so this is the one export path where accidental broad exposure is a real risk distinct from the user's own read access to their own files.
- None of the above is about restricting the user (this tool assumes the user is the sole admin of their own machine) — it's about not being the thing that turns "a private key sitting in a folder" into "a private key sitting in an easily-shared report."

### Local state: `~/.key_management/`

- `registry.json` — persistent key inventory, keyed by fingerprint (falls back to file path for keys that can't be fingerprinted, e.g. encrypted orphan private keys with no matching public key). Updated on every scan via `update_registry_from_scan()`: upserts `last_seen`/metadata for everything found, and flips previously-`active` entries not seen in the current scan to `status: "missing"` (not `"deleted"` — the tool doesn't assume *why* something vanished, it just wasn't found in this scan's folder set). Each entry accumulates a `history` list of `{ts, action}` events. This is what makes the tool's "紀錄" (record-keeping) promise real — the report table is a live snapshot, the registry is the durable history.
- `audit.log` — plain append-only line per management action (`generate`, `archive`, `delete_hard`, `backup`, `restore`, `purge_archive`, `view_private_raw`, `export_csv`), same tab-separated timestamp/action/detail convention as the sibling NAS tool's `audit_log()`, but this is a separate function/file, not shared.
- `archive/<timestamp>/` — where "封存（安全刪除）" moves files (default, reversible delete path); "永久刪除…" requires typing the exact filename to confirm and skips the archive entirely (same two-tier delete philosophy as the sibling tool's repo deletion, reused here for keys).

## Scope notes

This was built as a genuine management tool (not read-only reporting) at the user's explicit request — "我公私鑰都要有管理與紀錄功能，把我當作超級管理者" (both public and private key management with record-keeping, treat me as the super-admin). It does not currently do: key rotation orchestration (e.g. auto-generate-and-swap), pushing new keys to remote `authorized_keys` files anywhere, or scanning any location other than folders the user explicitly adds (no automatic whole-disk search).

The one place this tool is *read* (never written) from outside itself: the sibling `NAS_GIT_Tools` project has a "從 Key_Management 匯入…" button in several of its dialogs that peeks at this tool's `registry.json` to let the admin pick a pubkey instead of copy-pasting it. That coupling lives entirely on the `NAS_GIT_Tools` side (`key_management_registry_pubkeys()` in `nas_git_connector.py`) — nothing in this file imports or knows about `NAS_GIT_Tools`, and the registry format here is unaffected. If `registry.json`'s schema changes (keys read: `status`, `pub_path`, `comment`, `type`, `fingerprint`), that reader needs updating too.
