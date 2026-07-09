# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Single-file PyQt6 GUI tool (`nas_git_connector.py`, ~2600 lines) that connects a local project folder to a Synology NAS Git server (`kcc3713.synology.me`, bare repos under `/volume1/Git_Server`). It also manages that Git server: browsing repos, per-repo CI policy, archive/restore, health checks, log viewing. Written for a single user's home/office dual-machine workflow.

## Commands

```
pip install -r requirements.txt   # PyQt6 (runtime); pyinstaller only needed to build the exe
python .\nas_git_connector.py     # run the GUI directly
build_exe.bat                     # build dist\NasGitConnector.exe (onefile/windowed, via PyInstaller)
```

No test suite, linter, or CI config exists in this repo — verification is manual (run the GUI, or `python -c "import nas_git_connector"` for a quick syntax/import check).

## Architecture

Everything lives in `nas_git_connector.py`:

- **`Worker(QThread)`** — the only thing allowed to touch the network/filesystem/subprocess. Runs one "mode" per instantiation (`connect`, `test`, `list`, `delete`, `hooks`, `ci_status`, `set_ci`, `set_ci_batch`, `repo_detail`, `clone`, `upgrade_engine`, `healthcheck`, `repair`, `log`, `create_repo`, `ci_selftest`, `archive_list`, `archive_restore`, `archive_purge`). Communicates back to the UI only via Qt signals (`log`, `done`, `repos`, `hooks`) — never touches widgets directly, to avoid cross-thread crashes. All NAS interaction goes through `_ssh()` (keyless `ssh` by default, or `plink -pw` if a password is set) and remote commands are shell scripts built as `"\n".join([...])` heredoc-style, delimited by `___BEGIN___`/`___END___` markers that `_between()` strips out to filter SSH login banners.
- **`MainWindow(QMainWindow)`** — one window, three tabs sharing a profile/identity panel at the top (SSH user/host/remote root/password):
  1. **串接專案 (Connect)** — pick a local folder, git-init/add-remote/push it to a new/existing bare repo on the NAS.
  2. **瀏覽倉庫 / Clone URL (Browse)** — list remote repos, view/set per-repo CI policy, view repo details, clone locally, archive/delete repos.
  3. **維運 / 日誌 (Maintenance/Logs)** — health check, one-click repair (reapply hook templates + fix group perms), tail server logs.
- Every long-running UI action follows the same pattern: collect a `cfg` dict → spawn a `Worker(cfg, mode=...)` → connect its signals → `worker.start()`. `set_busy()` disables the relevant buttons while a worker runs.
- **Dialogs** (`DeleteRepoDialog`, `TextViewDialog`, `SetCiDialog`, `CreateRepoDialog`, `ArchiveDialog`) are small, single-purpose, and follow the same Worker pattern for anything that hits the network.

### Server-side CI system

The NAS runs a shared `pre-receive.ci` hook engine (one copy for all repos) that self-loads a per-repo policy file from `ci_policies/<repo>.policy` (`POLICY=none|soft|strict`). `PATCHED_ENGINE_B64` in this file is a base64-encoded copy of that engine script, pushed to the NAS by the "升級 CI 引擎" (upgrade engine) action — keep it in sync with `hooks_template/pre-receive.ci` on the server if that script changes. Policy rules enforced: branch name must match `develop|feature/*|release/*`, commit message must start with `feat:`/`fix:`/`chore:`/`docs:` or contain `[JIRA-n]`/`[TASK-n]`. `soft` warns via Telegram only; `strict` blocks the push.

### Safety mechanisms baked into the code

- `CONTAINER_ROOTS` (`D:\git`, `D:\GIT`) and disk roots are hard-blocked from being connected as a "project" (`is_container_root`) — prevents accidentally git-initing an entire drive/container folder.
- `find_nested_repos` detects git repos nested inside the chosen folder and forces a "I understand the risk" checkbox before proceeding (they'd otherwise become gitlinks).
- `is_safe_name` whitelists repo/archive names to `[A-Za-z0-9][A-Za-z0-9._-]*`, rejecting `.`, `..`, `_archived` — every remote path built from user input goes through this before being interpolated into a shell command.
- Repo deletion defaults to "safe takedown" (move to `_archived/`) rather than `rm -rf`; hard delete requires typing the exact repo name to confirm.
- SSH passwords are masked in the log output (`_mask`) and only persisted to the registry (`QSettings`) if the user explicitly opts in via "記住此身份的密碼".

### Persistence

Settings/profiles (SSH user/host/remote root, optional saved password, per-machine profile binding, last-used folder) are stored via `QSettings("TerryTools", "NasGitConnector")` — on Windows this is the registry, not a file in this repo. Multiple named "profiles" (e.g. 家中/公司) can each auto-select based on `socket.gethostname()`.
