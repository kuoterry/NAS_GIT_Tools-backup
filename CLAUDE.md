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

- **`Worker(QThread)`** — the only thing allowed to touch the network/filesystem/subprocess. Runs one "mode" per instantiation (`connect`, `test`, `list`, `delete`, `rename_repo`, `hooks`, `ci_status`, `set_ci`, `set_ci_batch`, `repo_detail`, `repo_desc_get`, `repo_desc_set`, `repo_files`, `file_content`, `repo_gc`, `repo_log`, `repo_branches`, `merged_branches`, `grep_all`, `repo_diff`, `tag_list`, `tag_create`, `tag_delete`, `file_blame`, `branch_protect_get`, `branch_protect_set`, `ssh_keys_list`, `ssh_keys_add`, `ssh_keys_delete`, `prep_new_user`, `clone`, `create_mirror`, `sync_mirrors`, `upgrade_engine`, `healthcheck`, `disk_usage`, `repair`, `log`, `create_repo`, `ci_selftest`, `archive_list`, `archive_restore`, `archive_purge`, `tg_conf_get`, `tg_conf_set`). Communicates back to the UI only via Qt signals (`log`, `done`, `repos`, `hooks`) — never touches widgets directly, to avoid cross-thread crashes. All NAS interaction goes through `_ssh()` (keyless `ssh` by default, or `plink -pw` if a password is set) and remote commands are shell scripts built as `"\n".join([...])` heredoc-style, delimited by `___BEGIN___`/`___END___` markers that `_between()` strips out to filter SSH login banners. Values that aren't whitelist-checked by `is_safe_name` (branch names, file paths, search patterns, SSH key lines) go through `shq()` for POSIX single-quote escaping before being interpolated into a remote command. Multi-line/binary-ish payloads (repo description text, README/.gitignore template content) are instead base64-encoded client-side and piped through `base64 -d` on the remote end, the same convention `PATCHED_ENGINE_B64` already used — avoids quoting hell entirely rather than trying to shell-escape arbitrary text.
- **`MainWindow(QMainWindow)`** — one window, three tabs sharing a profile/identity panel at the top (SSH user/host/remote root/password):
  1. **串接專案 (Connect)** — pick a local folder, git-init/add-remote/push it to a new/existing bare repo on the NAS.
  2. **瀏覽倉庫 / Clone URL (Browse)** — list remote repos (flags empty repos and GitHub mirrors; sortable by name/size/recent-activity), rename a repo in place (moves the bare dir and its `ci_policies/<repo>.policy` together), view/set per-repo CI policy, view repo details (now includes the repo's `description` file content), edit that description, set git-native branch protection, browse files and preview file content without cloning (renders `.md` as Markdown, supports `git blame`), browse commit log, list merged branches, diff two refs, run `git gc`, manage annotated tags as lightweight releases, full-text search across all repos with clickable results that jump straight to the matching line, see a cross-repo recent-activity dashboard, manage the current SSH identity's own `authorized_keys` (now shown with SHA256 fingerprints), clone locally, archive/delete repos, batch-clean checked archive entries, register a GitHub mirror (`git clone --mirror` on the NAS) and sync selected/all mirrors on demand. New-repo creation can optionally seed an initial commit from a README.md/.gitignore template.
  3. **維運 / 日誌 (Maintenance/Logs)** — health check (incl. LFS-candidate large-file scan), server disk-usage dashboard (`df` free space + total Git_Server usage + top-10 largest repos), one-click repair (reapply hook templates + fix group perms), generate a new `git_devs` account setup script, edit the shared Telegram notification config, tail server logs, view the local audit log.
- Every long-running UI action follows the same pattern: collect a `cfg` dict → spawn a `Worker(cfg, mode=...)` → connect its signals → `worker.start()`. `set_busy()` disables the relevant buttons while a worker runs.
- **Dialogs** (`DeleteRepoDialog`, `TextViewDialog`, `RepoFilesDialog`, `RepoLogDialog`, `RepoDiffDialog`, `CreateTagDialog`, `TagDialog`, `ActivityDialog`, `SshKeysDialog`, `CreateGitDevsUserDialog`, `GrepResultsDialog`, `SetCiDialog`, `CreateRepoDialog`, `BranchProtectDialog`, `NotifyConfigDialog`, `ArchiveDialog`, `MirrorDialog`) are small, single-purpose, and follow the same Worker pattern for anything that hits the network. `RepoFilesDialog`/`RepoLogDialog`/`RepoDiffDialog`/`TagDialog`/`ActivityDialog`/`SshKeysDialog`/`CreateGitDevsUserDialog`/`GrepResultsDialog`/`BranchProtectDialog`/`NotifyConfigDialog` self-manage their own Worker calls rather than going through `MainWindow`'s `on_ci_result`/`on_ci_done` pair. `TextViewDialog(markdown=True)` swaps the read-only `QPlainTextEdit` for a `QTextBrowser.setMarkdown()` render, used for `.md`/`.markdown` file previews; `TextViewDialog(goto_line=N)` scrolls/positions the cursor at that line, used by `GrepResultsDialog` to jump straight to a search hit.

### Server-side CI system

The NAS runs a shared `pre-receive.ci` hook engine (one copy for all repos) that self-loads a per-repo policy file from `ci_policies/<repo>.policy` (`POLICY=none|soft|strict`). `PATCHED_ENGINE_B64` in this file is a base64-encoded copy of that engine script, pushed to the NAS by the "升級 CI 引擎" (upgrade engine) action — keep it in sync with `hooks_template/pre-receive.ci` on the server if that script changes. Policy rules enforced: branch name must match `develop|feature/*|release/*`, commit message must start with `feat:`/`fix:`/`chore:`/`docs:` or contain `[JIRA-n]`/`[TASK-n]`. `soft` warns via Telegram only; `strict` blocks the push.

### GitHub mirrors

`sync_github_mirrors.sh` is a standalone server-side script (not run from the GUI) meant to be deployed to the NAS at `/volume1/Git_Server/tools/` and scheduled via DSM 任務排程表. It loops all `*.git` repos, skips any without `remote.origin.mirror=true`, and runs `git remote update --prune` on the rest, logging to `logs/mirror_sync.log` and optionally notifying Telegram (reads token/chat id from `config/tg_bot.conf` on the NAS — never hardcode credentials in this script). It's the scheduled counterpart to the GUI's on-demand "同步鏡像" button (`sync_mirrors` Worker mode), which runs the same `remote update --prune` logic over SSH instead of a local cron job.

### Multi-identity push permissions

Repos are pushed to from multiple SSH identities (e.g. 家中/kuoterry and 公司/Git_User1), each a different Unix user sharing the `git_devs` group. Git's default loose-object permissions are owner-only-write, so a bare repo touched by two different users can end up with subdirectories (`objects/xx/`) that one identity can't write into even though both are in `git_devs` — group membership doesn't let you `chmod`/`chown` files you don't own, only root or the owner can. `_run_create_repo` and `_run_connect` set `core.sharedRepository=group` right after `git init --bare` so all objects git creates from then on are group-writable; `_run_repair` re-applies that config to every existing repo, and `_run_healthcheck` flags any repo missing it. None of this retroactively fixes directories that already exist with the wrong mode — that still needs a one-time privileged `chmod -R g+rwX` (as root, or as the original owning identity) on the affected repo.

### Creating new `git_devs` accounts

`CreateGitDevsUserDialog` does **not** create DSM accounts itself — the tool has no passwordless sudo on this NAS (verified: `sudo -n true` fails), so anything requiring root can't run silently in the background. Instead it: (1) runs `prep_new_user` (read-only) to fetch the current `git_devs` membership via `getent group git_devs` and check whether the requested username already exists via `id`; (2) builds a shell script — `synouser --add` for the DSM user, `synogroup --member git_devs <ALL existing members> <new user>` (this Synology command *replaces* the member list rather than appending, so the script always includes the full existing membership it just queried, to avoid silently kicking people out of the group), SSH key setup under `/var/services/homes/<user>/.ssh`, and the same `chmod -R g+rwX` / `core.sharedRepository=group` sync from the multi-identity fix above; (3) shows that script in a `TextViewDialog` for the user to copy and paste into their own privileged SSH session. `synouser`'s exact argument order is DSM-version-dependent and unverified against this NAS, so the generated script tells the user to check `synouser --help` first if it errors.

### Branch protection is independent of the CI policy engine

`BranchProtectDialog` sets git's own `receive.denyDeletes` / `receive.denyNonFastForwards` config directly on a repo (`branch_protect_get`/`branch_protect_set` Worker modes) — this is a *separate* mechanism from the `PROTECT_MASTER` field inside the CI engine's `ci_profiles/<policy>.conf` (which `_run_repo_detail`/`hooks` report read-only and this tool has never had a GUI to edit, since it's a shared profile file affecting every repo on that policy, not a single repo). Native git denies happen at the transport level regardless of CI policy/soft/strict; the CI engine's checks are a separate pre-receive hook layer on top. Don't conflate the two when troubleshooting a rejected push — check both.

### Repo description, disk usage, and Telegram notification config

- Bare repos have a built-in `description` file (plain text, purely informational — never affects git behavior). `_run_repo_desc_get`/`_run_repo_desc_set` read/write it; `on_edit_desc` fetches the current text into a `QInputDialog.getMultiLineText` prefilled editor. Content is base64-transported in both directions to sidestep multi-line/quoting issues.
- "伺服器空間總覽" (`disk_usage` mode) runs `df -h` on `remote_root`'s filesystem plus `du -sh` totals and a top-10 largest-repo ranking — read-only, no state changes.
- "Telegram 通知設定…" (`NotifyConfigDialog`, `tg_conf_get`/`tg_conf_set` modes) edits `config/tg_bot.conf` (`BOT_TOKEN=`/`CHAT_ID=`), the same file `sync_github_mirrors.sh` and the CI engine both read for notifications — backs up the old file (`.bak-<timestamp>`) before overwriting, same convention as `SshKeysDialog`.

### Repo creation templates

`CreateRepoDialog` can optionally seed a brand-new bare repo with an initial `chore: 初始化 repository` commit (README.md with a title, and/or a Python-flavored `.gitignore` from the `GITIGNORE_TEMPLATE` constant). Since a bare repo has no working tree, this is done with git plumbing over SSH — `git hash-object`/`update-index`/`write-tree`/`commit-tree`/`update-ref` against a scratch `GIT_INDEX_FILE` (must come from `mktemp -u`, i.e. a path only, never a pre-created empty file — git's index reader treats a 0-byte file as a corrupt index, not an empty one) — with `GIT_AUTHOR_*`/`GIT_COMMITTER_*` explicitly set in the command since the server-side git user has no configured identity. This bypasses the pre-receive hook entirely (it's not a push), which is fine since template seeding happens before any CI policy could apply.

### Safety mechanisms baked into the code

- `CONTAINER_ROOTS` (`D:\git`, `D:\GIT`) and disk roots are hard-blocked from being connected as a "project" (`is_container_root`) — prevents accidentally git-initing an entire drive/container folder.
- `find_nested_repos` detects git repos nested inside the chosen folder and forces a "I understand the risk" checkbox before proceeding (they'd otherwise become gitlinks).
- `is_safe_name` whitelists repo/archive names via `^[^\W_][\w.-]*$` (Unicode-aware — first char must be alnum/CJK, not `_` or punctuation; rest can include `.`/`-`), rejecting `.`, `..`, `_archived` — every remote path built from user input goes through this before being interpolated into a shell command.
- Repo deletion defaults to "safe takedown" (move to `_archived/`) rather than `rm -rf`; hard delete requires typing the exact repo name to confirm.
- `ArchiveDialog` flags (but never auto-deletes) archived items older than `ARCHIVE_STALE_DAYS` (90 days), parsed client-side from the `<name>.YYYYMMDD-HHMMSS[.tar.gz]` timestamp suffix that `_run_delete` appends on archive. Batch cleanup (`on_bulk_purge`) requires each item to be individually checked in the list — there's no "select all and purge" in one click by design.
- SSH passwords are masked in the log output (`_mask`) and only persisted to the registry (`QSettings`) if the user explicitly opts in via "記住此身份的密碼".
- `SshKeysDialog` only ever touches `$HOME/.ssh/authorized_keys` for the *currently connected* SSH identity (never another user, never system-wide) and backs up the file (`.bak-<timestamp>`) before removing a key. Each listed key shows its SHA256 fingerprint (`ssh_fingerprint()`), computed entirely client-side from the already-fetched key line — no extra NAS round-trip.
- `audit_log()` appends a local, timestamped line to `~/.nas_git_connector/audit.log` (outside this repo) whenever a Worker mode in `DESTRUCTIVE_MODES` (`delete`, `rename_repo`, `repo_gc`, `tag_delete`, `ssh_keys_delete`, `archive_purge`) finishes successfully — the NAS side only records pushes, not admin actions taken through this GUI, so this is the only local trail of what got deleted/renamed/gc'd and when. Viewable via "本機操作稽核紀錄" in the Maintenance tab.
- Healthcheck's LFS section flags repos with any tracked file over `LFS_SUGGEST_BYTES` (5 MB) — advisory only, doesn't touch the repo.

### Persistence

Settings/profiles (SSH user/host/remote root, optional saved password, per-machine profile binding, last-used folder) are stored via `QSettings("TerryTools", "NasGitConnector")` — on Windows this is the registry, not a file in this repo. Multiple named "profiles" (e.g. 家中/公司) can each auto-select based on `socket.gethostname()`.
