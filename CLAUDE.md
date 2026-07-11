# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Single-file PyQt6 GUI tool (`nas_git_connector.py`, ~2800 lines) that connects a local project folder to a Synology NAS Git server (`kcc3713.synology.me`, bare repos under `/volume1/Git_Server`). It also manages that Git server: browsing repos, per-repo CI policy, archive/restore, health checks, log viewing, GitHub mirror registration/sync. Written for a single user's home/office dual-machine workflow.

## Commands

```
pip install -r requirements.txt   # PyQt6 (runtime); pyinstaller only needed to build the exe
python .\nas_git_connector.py     # run the GUI directly
build_exe.bat                     # build dist\NasGitConnector.exe (onefile/windowed, via PyInstaller)
```

No test suite, linter, or CI config exists in this repo — verification is manual (run the GUI, or `python -c "import nas_git_connector"` for a quick syntax/import check).

## Architecture

Everything lives in `nas_git_connector.py`:

- **`Worker(QThread)`** — the only thing allowed to touch the network/filesystem/subprocess. Runs one "mode" per instantiation (`connect`, `test`, `list`, `delete`, `hooks`, `ci_status`, `set_ci`, `set_ci_batch`, `repo_detail`, `repo_files`, `file_content`, `repo_gc`, `repo_log`, `repo_branches`, `merged_branches`, `grep_all`, `repo_diff`, `tag_list`, `tag_create`, `tag_delete`, `file_blame`, `ssh_keys_list`, `ssh_keys_add`, `ssh_keys_delete`, `clone`, `create_mirror`, `sync_mirrors`, `upgrade_engine`, `healthcheck`, `repair`, `log`, `create_repo`, `ci_selftest`, `archive_list`, `archive_restore`, `archive_purge`). Communicates back to the UI only via Qt signals (`log`, `done`, `repos`, `hooks`) — never touches widgets directly, to avoid cross-thread crashes. All NAS interaction goes through `_ssh()` (keyless `ssh` by default, or `plink -pw` if a password is set) and remote commands are shell scripts built as `"\n".join([...])` heredoc-style, delimited by `___BEGIN___`/`___END___` markers that `_between()` strips out to filter SSH login banners. Values that aren't whitelist-checked by `is_safe_name` (branch names, file paths, search patterns, SSH key lines) go through `shq()` for POSIX single-quote escaping before being interpolated into a remote command.
- **`MainWindow(QMainWindow)`** — one window, three tabs sharing a profile/identity panel at the top (SSH user/host/remote root/password):
  1. **串接專案 (Connect)** — pick a local folder, git-init/add-remote/push it to a new/existing bare repo on the NAS.
  2. **瀏覽倉庫 / Clone URL (Browse)** — list remote repos (flags empty repos and GitHub mirrors), view/set per-repo CI policy, view repo details, browse files and preview file content without cloning (renders `.md` as Markdown, supports `git blame`), browse commit log, list merged branches, diff two refs, run `git gc`, manage annotated tags as lightweight releases, full-text search across all repos, see a cross-repo recent-activity dashboard, manage the current SSH identity's own `authorized_keys`, clone locally, archive/delete repos, register a GitHub mirror (`git clone --mirror` on the NAS) and sync selected/all mirrors on demand.
  3. **維運 / 日誌 (Maintenance/Logs)** — health check, one-click repair (reapply hook templates + fix group perms), tail server logs.
- Every long-running UI action follows the same pattern: collect a `cfg` dict → spawn a `Worker(cfg, mode=...)` → connect its signals → `worker.start()`. `set_busy()` disables the relevant buttons while a worker runs.
- **Dialogs** (`DeleteRepoDialog`, `TextViewDialog`, `RepoFilesDialog`, `RepoLogDialog`, `RepoDiffDialog`, `CreateTagDialog`, `TagDialog`, `ActivityDialog`, `SshKeysDialog`, `SetCiDialog`, `CreateRepoDialog`, `ArchiveDialog`, `MirrorDialog`) are small, single-purpose, and follow the same Worker pattern for anything that hits the network. `RepoFilesDialog`/`RepoLogDialog`/`RepoDiffDialog`/`TagDialog`/`ActivityDialog`/`SshKeysDialog` self-manage their own Worker calls rather than going through `MainWindow`'s `on_ci_result`/`on_ci_done` pair. `TextViewDialog(markdown=True)` swaps the read-only `QPlainTextEdit` for a `QTextBrowser.setMarkdown()` render, used for `.md`/`.markdown` file previews.

### Server-side CI system

The NAS runs a shared `pre-receive.ci` hook engine (one copy for all repos) that self-loads a per-repo policy file from `ci_policies/<repo>.policy` (`POLICY=none|soft|strict`). `PATCHED_ENGINE_B64` in this file is a base64-encoded copy of that engine script, pushed to the NAS by the "升級 CI 引擎" (upgrade engine) action — keep it in sync with `hooks_template/pre-receive.ci` on the server if that script changes. Policy rules enforced: branch name must match `develop|feature/*|release/*`, commit message must start with `feat:`/`fix:`/`chore:`/`docs:` or contain `[JIRA-n]`/`[TASK-n]`. `soft` warns via Telegram only; `strict` blocks the push.

### GitHub mirrors

`sync_github_mirrors.sh` is a standalone server-side script (not run from the GUI) meant to be deployed to the NAS at `/volume1/Git_Server/tools/` and scheduled via DSM 任務排程表. It loops all `*.git` repos, skips any without `remote.origin.mirror=true`, and runs `git remote update --prune` on the rest, logging to `logs/mirror_sync.log` and optionally notifying Telegram (reads token/chat id from `config/tg_bot.conf` on the NAS — never hardcode credentials in this script). It's the scheduled counterpart to the GUI's on-demand "同步鏡像" button (`sync_mirrors` Worker mode), which runs the same `remote update --prune` logic over SSH instead of a local cron job.

### Safety mechanisms baked into the code

- `CONTAINER_ROOTS` (`D:\git`, `D:\GIT`) and disk roots are hard-blocked from being connected as a "project" (`is_container_root`) — prevents accidentally git-initing an entire drive/container folder.
- `find_nested_repos` detects git repos nested inside the chosen folder and forces a "I understand the risk" checkbox before proceeding (they'd otherwise become gitlinks).
- `is_safe_name` whitelists repo/archive names via `^[^\W_][\w.-]*$` (Unicode-aware — first char must be alnum/CJK, not `_` or punctuation; rest can include `.`/`-`), rejecting `.`, `..`, `_archived` — every remote path built from user input goes through this before being interpolated into a shell command.
- Repo deletion defaults to "safe takedown" (move to `_archived/`) rather than `rm -rf`; hard delete requires typing the exact repo name to confirm.
- `ArchiveDialog` flags (but never auto-deletes) archived items older than `ARCHIVE_STALE_DAYS` (90 days), parsed client-side from the `<name>.YYYYMMDD-HHMMSS[.tar.gz]` timestamp suffix that `_run_delete` appends on archive.
- SSH passwords are masked in the log output (`_mask`) and only persisted to the registry (`QSettings`) if the user explicitly opts in via "記住此身份的密碼".
- `SshKeysDialog` only ever touches `$HOME/.ssh/authorized_keys` for the *currently connected* SSH identity (never another user, never system-wide) and backs up the file (`.bak-<timestamp>`) before removing a key.

### Persistence

Settings/profiles (SSH user/host/remote root, optional saved password, per-machine profile binding, last-used folder) are stored via `QSettings("TerryTools", "NasGitConnector")` — on Windows this is the registry, not a file in this repo. Multiple named "profiles" (e.g. 家中/公司) can each auto-select based on `socket.gethostname()`.
