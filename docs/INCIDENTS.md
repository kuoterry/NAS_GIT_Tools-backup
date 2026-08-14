# INCIDENTS.md

Full post-mortem narratives for this repo, moved out of `CLAUDE.md` so that file stays a description of *how the code works now* rather than a logbook.

`CLAUDE.md` keeps the durable outcome of each entry below — the rule, the invariant, or the code that exists because of it — and links here. Read this file when you need the *symptom → diagnosis → why it looked like something else* detail: several of these took multiple wrong theories to land, and the wrong theories are the useful part when the next unexplained failure shows up.

Chronological.

---

## 2026-07-11 — `git_devs` account creation broke on each of its first three real runs

This feature broke on its first three real-world runs, each a different bug, all found by actually running it against production:

1. **Silently wiped `kuoterry`/`Git_User1` out of `git_devs`** when adding `git_user2`. Root cause: the membership query used `getent group git_devs`, but this DSM's non-interactive SSH command environment doesn't have `getent` in `PATH` (confirmed — the same command fails "command not found" in an interactive login shell too). The query silently returned empty, so the generated `synogroup --member` line only listed the new user, and running it replaced the whole group. Fix: query `/etc/group` directly with `grep`/`cut` instead of `getent`, and the script now re-reads `/etc/group` right after `synogroup --member` and loudly warns (`‼️`) if any intended member is missing — turns a silent failure into an impossible-to-miss one.
2. **The DSM-user-creation step embedded a literal password placeholder** (`'<請設定密碼>'`) inside an executable line, and the user ran it verbatim (twice — once with the tool's own placeholder, once by copy-pasting example text typed in chat). First fix attempt made the script `read -s NEWPW` interactively instead — but that itself caused problem 3 below, so the final fix auto-generates the password instead of asking.
3. **Multiple separate `sudo` prompts appearing mid-paste corrupted execution** when adding `git_user3`: with ~9 separate `sudo`-prefixed lines and no cached credential, several of them independently prompted for a password while a large block was still being pasted, and lines arriving during a no-echo password read got eaten/misinterpreted — `git_user3`'s account was never created and several later lines silently didn't run. Fix: `sudo -v` as the very first line to cache credentials once, up front, before any other output exists to interfere with the prompt; combined with removing the interactive `read -s` from fix 2, the script now has exactly one interactive moment, at the start, so it can genuinely be pasted as a single block.
4. **`sudo sh -c 'cat > "$HOME_DIR/.ssh/authorized_keys"' <<'EOF'` failed with "No such file or directory"** (still on `git_user3`, after fixing #3): `$HOME_DIR` is inside the single-quoted string passed to `sh -c`, so it's expanded by the *inner* subshell that `sudo` spawns — but that subshell doesn't inherit `HOME_DIR` (never exported, and `sudo` resets the environment by default anyway), so it expands to empty and the path becomes `/.ssh/authorized_keys`. This bug existed since the very first version of this feature; it just took until the third account for anyone to reach that exact line. Fix: `sudo tee "$HOME_DIR/.ssh/authorized_keys" >/dev/null <<'EOF'` instead — the path is a plain argv to `tee`, expanded by the *outer* shell before `sudo` ever runs, so it never depends on what environment survives into the sudo'd process.

The three generalized lessons from this incident live in `CLAUDE.md` under "Creating new `git_devs` accounts" — they apply to every remote command and generated script in `nas_git_connector.py`, not just this feature.

## 2026-07-15 — a rotated Telegram bot token silently didn't reach the CI engine

`PATCHED_ENGINE_B64` used to have `BOT_TOKEN`/`CHAT_ID` hardcoded directly in the engine script, so a token rotated through the GUI's "Telegram 通知設定…" silently had no effect on CI violation notifications specifically — every *other* script on the server was already config-file-based, this one wasn't, which is exactly why it went unnoticed (the other notification paths kept working after a rotation). Fix: the engine now sources the shared config like everything else (`CONF="$BASE/config/tg_bot.conf"; [ -f "$CONF" ] && . "$CONF"`), and `send_telegram()` no-ops instead of curling with empty credentials if the config is missing/blank.

## 2026-07-15 — `authorized_keys` perfect, login still falls back to password (DSM home-dir ACL)

Adding a key to an existing account (`git_user2`, via `AddKeyForUserDialog`) ran clean — script executed with no errors, `authorized_keys` had the right content and `chmod`/`chown` — but key-based login still silently fell back to password auth. `ssh -v` on the client showed the key being offered and nothing rejecting it outright; the actual cause only showed up server-side:

```
debug1: Remote: Ignored authorized keys: bad ACL permission for file /volume1/homes/<user>
```

Root cause: DSM's sshd checks Synology's own ACL layer on the **home directory itself** — not just the classic Unix permission bits `chmod` sets, and not just `.ssh`/`authorized_keys`. If that ACL is non-trivial (as it commonly is for accounts whose home directory was left at DSM's default), sshd silently discards the entire `authorized_keys` file rather than rejecting just the offending part, so it looks exactly like "the key is wrong" even though the key setup is perfect.

Confirmed fix, verified against production: `sudo synoacltool -del "$HOME_DIR"` followed by `sudo chmod 700 "$HOME_DIR"`, run against `$HOME_DIR` itself before touching `.ssh`. The earlier incidents above only ever fixed permissions *inside* the home directory, never the home directory's own ACL, which is why this surfaced separately and later.

## 2026-07-16 — same symptom, second root cause: home directory owned by `root:root`

`git_user3` still couldn't log in with its key even after the ACL fix above was manually re-applied against production — `synoacltool -get`/`-del` reported "It's Linux mode" (no Synology ACL on this DSM's home volume at all, so that theory didn't apply here) and `authorized_keys` was confirmed present with correct content/permissions/ownership. `ssh -v` showed the server rejecting the offered key outright (never even getting to signature verification) and falling back to password.

Root cause, found by comparing a working account (`git_user2`) against the broken one directly on the NAS: **the home directory itself (`/var/services/homes/git_user3`) was owned by `root:root`**, while the working account's home directory was owned by the account itself (`git_user2:users`). `synouser --add` on this DSM leaves the newly-created home directory owned by root; nothing in the generated script ever chowned the home directory itself — every fix so far (`chmod 700 "$HOME_DIR"`, `synoacltool -del "$HOME_DIR"`, `chown -R ... "$HOME_DIR/.ssh"`) touched the directory's mode/ACL or its `.ssh` subtree, never its ownership.

Fix, verified against production: `sudo chown <user>:users "$HOME_DIR"` right after the existing `chmod 700 "$HOME_DIR"` line.

## 2026-07-16 (second one same day) — key accepted, then `Permission denied` for every command (`/sbin/nologin`)

`git_user4` — a completely different account, created separately from `git_user3` — also couldn't be used, but not a login-rejection symptom this time: `ssh -v` showed the key being **accepted** (`Entering interactive session`), then the remote side printed `Permission denied, please try again.` and the connection exited with status 1 for *any* command, including a plain `whoami`.

Root cause: `/etc/passwd` showed `git_user4`'s shell as `/sbin/nologin`, unlike every working account (`git_user2`, `git_user3`, `kuoterry` all `/bin/sh`) — `/sbin/nologin` unconditionally refuses to exec *anything* handed to it over SSH (interactive shell or a single command, same for `git-receive-pack` on a push), so it looks like a permission problem but is unrelated to keys, ACLs, or ownership entirely. Why some accounts get `/bin/sh` and others get `/sbin/nologin` from `synouser --add` is unknown — not controlled by any documented argument, and `usermod`/`chsh` don't exist on this DSM's BusyBox userland.

Fix, verified against production: force the shell directly via `sudo sed -i 's#^\(<user>:.*:\)/sbin/nologin$#\1/bin/sh#' /etc/passwd` — same "don't trust the DSM tool, edit the file directly" approach as the `getent` fix. Added right after `synouser --add` in `CreateGitDevsUserDialog._build_script`, and right before the ACL/ownership fix in `AddKeyForUserDialog._build_script` — the latter matters because an account created before this fix existed (like `git_user4`) needs the "補金鑰" flow to also be able to repair it, not just new accounts going forward.

Being the *third* distinct root cause behind the same user-visible symptom ("generated the script, ran it clean, key still doesn't work" — ACL → home ownership → login shell) is what motivated `_login_precondition_selfcheck()`; see `CLAUDE.md`.

## 2026-07-16 (code review, not a production incident) — unescaped free-text fields in the generated script

`CreateGitDevsUserDialog._build_script`'s `synouser --add` line embedded the free-text 描述/email fields (`desc`/`email`, both plain `QLineEdit.text().strip()`) directly inside double quotes with no escaping, unlike `username`/`pubkey`/`password` which were all already validated or generated safely. Since this whole script is designed to be pasted and run as one trusted block, a description containing `"`, `` ` ``, or `$(...)` would execute as shell commands under `sudo` the moment the admin pasted it. Both fields now go through `shq()`.

## 2026-07-16 (code review) — command injection in `_run_connect` and the branch field

`_run_connect` — the tool's most-used feature (串接專案) — was the one Worker mode that never called `is_safe_name()` on `repo_name`, and interpolated it unquoted into the hook-install command; the "branch" field (free-text, used by both `_run_connect` and `_run_create_repo`) was never validated or `shq()`-escaped at all, unlike every other ref-like value in the file. Both were real command-injection gaps on the NAS side, found by a full-file security review, not by an incident. `_run_connect` now validates `repo_name` the same way every other Worker mode does; both branch fields now go through `shq()` exactly like `_run_repo_log`/`_run_repo_diff`/`_run_tag_create` already did.

## 2026-07-16 (code review) — partial-failure batch `repo_gc` skipped its audit entry

`on_ci_done` used to only call `audit_log()` when `ok=True`. Batch `repo_gc` emits `done(nfail == 0, ...)`, so a batch of e.g. 5 repos where 1 fails set `ok=False` and silently skipped the audit entry — even though the other 4 repos actually had `git gc` run on them (a real destructive action with no other record).

First attempt at a fix made `on_ci_done` call `audit_log()` unconditionally for any `DESTRUCTIVE_MODES` mode regardless of `ok` — but a follow-up diff review caught that this over-widened the fix: it also started logging pure client-side validation failures and connection failures for the *other* five (atomic, single-item) destructive modes, where nothing ever ran on the NAS at all, polluting the audit trail with no-op attempts. Reverted `on_ci_done` to its original `if ok:` gating; the fix now lives narrowly in `_run_repo_gc` itself, which calls `audit_log()` directly when `nfail > 0 and nok > 0` (genuine partial success) before emitting `done` — full failure (`nok == 0`) still logs nothing, matching the original "only log what actually happened" intent.

## 2026-07-16 (code review) — `_run_grep_all` mis-split any path containing a colon

`_run_grep_all`'s remote `git grep` output (`tree:path:line:content`) was parsed with a blind `split(":", 3)`, which silently mis-splits any hit whose file path itself contains a colon (legal on POSIX). The remote awk step now strips the known `$base:` tree prefix by exact length rather than by colon-splitting, and the Python side finds the path/line boundary via `re.match(r"^(.*?):(\d+):(.*)$", grepline)` (line number is guaranteed all-digits, so a non-greedy path group correctly finds the real boundary in the overwhelming common case).

Known residual limitations, both accepted as-is rather than chased further — see `CLAUDE.md` for the short version:

- A path that itself contains a `:digits:` substring *before* the real line-number field (e.g. `notes:2024:report.py`) still mis-splits — the regex's leftmost match wins. Caught by a follow-up diff review of this exact fix. A fully robust fix would need NUL-delimited `git grep -z` output plumbed through `awk`/Python without relying on colons at all; not done since this DSM's BusyBox `awk` support for `-z`-style records is unverified, and the remaining failure mode is far rarer than the original bug (any colon anywhere in a path).
- Not introduced by this fix, not yet addressed: `git`'s default `core.quotePath=true` C-style-escapes any non-ASCII path in `grep` output, so a hit in a CJK-named file returns a quoted/octal-escaped `path` that `GrepResultsDialog`'s "開啟" can't resolve back to the real file on disk.

## 2026-07-22 — `build_exe.bat` silently stopped producing the versioned exe copy

The versioned copy (`NasGitConnector_v<version>.exe`) silently never got produced on a second machine, even after the `.bat` CRLF-risk fix had already been applied and the file confirmed CRLF on disk — so this was *not* a line-ending problem, despite looking like one at first (both the batch file and the CRLF healthcheck feature were being discussed in the same conversation, which is what made it easy to conflate the two).

Root cause, reproduced directly on the second machine, independent of line endings: the old inline form —

```
%PY% -c "import re;print(re.search(r'__version__ *= *\"([^\"]+)\"', open('nas_git_connector.py', encoding='utf-8').read()).group(1))"
```

— puts backslash-escaped double quotes (`\"`) inside the single-quoted `for /f ('...')` capture string. `cmd.exe` has no concept of `\"` as an escaped quote (batch has no such escape mechanism); each `\"` is just one more literal `"` character that still toggles cmd's quote-parity tracking, which is what `for /f` uses to figure out where the parenthesized command actually ends. The quote count comes out odd and the whole line fails to parse (`') do set "VERSION was unexpected at this time.`) — confirmed by reproducing the identical error on a minimal repro `.bat` with correct CRLF endings, ruling out encoding entirely.

The `if defined VERSION (...) else (...)` branch after it never sees a set `VERSION`, so it silently falls into the `[WARN] Could not read __version__` branch — the main PyInstaller build still succeeds, so the tool "works," just never produces the versioned filename, which is why this went unnoticed rather than erroring loudly.

Fix: moved the regex out of the batch line entirely into a standalone `get_version.py` — the `for /f` capture command is now just `%PY% "path\to\get_version.py"` with zero embedded double quotes.

## 2026-07-26 — CI engine skipped commit-message checks entirely on any new branch

Found by accident: pushing a brand-new branch of this repo printed one line from the remote —

```
remote: fatal: Invalid revision range 0000000000000000000000000000000000000000..6c7c20f...
```

— and then succeeded anyway.

Root cause: the engine's commit-message loop was `for c in $(git rev-list "$oldrev..$newrev")`. On a newly-created branch `$oldrev` is 40 zeros, so the range is invalid and `git rev-list` exits with that fatal, producing no output. The `for` body therefore never ran, and since the engine ends in `exit 0` regardless, the push went through with **none** of its commit messages checked — under `strict` too. The branch-name rule sits before the loop, so that half kept working, which is part of why nothing looked broken. A branch *deletion* (`$newrev` all zeros) hit the same fatal.

The failure mode is the same shape as the 2026-07-22 build one: a check that silently stops checking is indistinguishable from a check that passes.

Fix: `$newrev` all zeros → `continue` (nothing to check on a delete); `$oldrev` all zeros → `git rev-list "$newrev" --not --all`. The `--not --all` form is correct specifically because pre-receive runs *before* the new ref is created, so `--all` covers every pre-existing ref and the difference is exactly the commits this push is adding.

Verified before committing, in a throwaway local bare repo with the engine installed as its `pre-receive` (`POLICY_MODE=strict` exported into the push): old engine reproduced the fatal and accepted a deliberately non-compliant commit message on a new branch; new engine reported the violation and blocked it; a compliant new branch and a follow-up push to an existing branch both stayed clean. The engine's hardcoded `export PATH=/usr/sbin:/usr/bin:/sbin:/bin` has to be stripped from the *test copy* of the hook for this to run under Windows git-bash — it's needed on the NAS, so don't "fix" it in the source.

Note the fix only reaches production when someone clicks "升級 CI 引擎" in the GUI — committing it here changes what gets deployed, not what is currently running.

---

## 2026-08-13 — Key_Management 每個成功的封存/刪除/備份都回報「發生未預期錯誤」（1.4.0～1.5.0）

`eb4dbe2`（2026-08-13 稍早的「逐檔稽核」強化）讓每個破壞性動作照抄手足工具的慣例：`aud_ok = audit_log(...)` 之後把 `audit_failed_note(aud_ok)` 附在完成訊息尾端。問題是慣例只搬了呼叫端——`audit_failed_note()` 在 Key_Management 裡從未被定義，而它的 `audit_log()` 也沒有 `return`（手足版本回 `bool`）。動作本身（檔案已搬進封存區/已刪除/已備份）全部做完之後，成功路徑在組訊息時炸 `NameError`，被 `Worker.run()` 的 `except Exception` 吞成 `done(False, "發生未預期錯誤：name 'audit_failed_note' is not defined")`——**檔案真的被處理了，UI 卻報失敗**，且因 `ok=False` 不觸發重掃，報表繼續顯示已不存在的金鑰。1.5.0 的新功能（encrypt_key/rotate_key/convert_ppk/加密備份）照抄同一慣例，把受影響路徑從 5 條擴到 9 條。

為什麼活了兩個版本沒被抓到：`python -c "import key_management"` 的驗證抓不到執行期 `NameError`；1.5.0 新加的 unittest 只測純函數，而這隻蟲正好長在 Worker 的成功路徑上。由第三方細讀代理發現（grep「呼叫了但沒定義」），不是使用者回報。

修法（1.5.1）：`audit_log()` 回傳 `bool`、補上 `audit_failed_note()` 定義；`tests/test_key_management.py` 新增 `TestAuditPlumbing`，直接呼叫 `Worker._run_delete` 的封存成功路徑斷言 `done(True, …)`——教訓入庫：**純函數測試蓋不到「動作做完、回報路徑才炸」這種洞，關鍵 Worker 路徑要有煙霧測試**。

---

## 2026-08-13 — CI 引擎兩個「檢查早已停止檢查」：違規 log 從未有寫入者、profile 旋鈕從未被讀

第三方細讀代理發現、解碼 `PATCHED_ENGINE_B64` 證實的兩個同型缺陷：

1. **`logs/ci_violation.log` 全系統沒有任何寫入者。** 引擎的 `violate()` 只做 echo＋Telegram＋（strict 時）exit 1；90 行內沒有任何一行寫檔。下游 `ci_daily_violation_report.sh` 每天讀這個不存在的檔，讀不到就**主動發「🎉 今日沒有任何 CI 違規」**——不是沉默，是每天一封的假安心。Telegram 即時訊息又會被聊天室滾掉，違規歷史等於從未存在。修法：`violate()`/`hard_block()` 寫入 `date | repo | branch | reason | mode | user`（第 2 欄必須是 repo，日報的 `awk -F'|' '{print $2}'` 依賴它）。
2. **`ci_profiles/<policy>.conf` 是死旋鈕。** 引擎只讀 `ci_policies/<repo>.policy` 與 `tg_bot.conf`，`ci_profiles/` 出現 0 次——但 `_run_hooks` 的報表把 conf 的 `PROTECT_MASTER` 等欄位印成生效中設定，`CiProfileDialog`（2.9.0 新做的編輯器）的警語也說改了會生效。修法：引擎先設內建預設值再 source conf；`PROTECT_MASTER` 實作為 hard block（不分 soft/strict——soft 下只警告等於沒保護）；新增 `MAX_FILE_MB`、`CHECK_SECRETS` 兩個新旋鈕。

**部署當天的第三個坑（差點重演同一型）**：NAS 上其實一直存在舊的 conf 檔，用的是**另一套變數名與 yes/no 值**（`PROTECT_MASTER=yes`、`CHECK_COMMIT_FORMAT=`、`CHECK_BRANCH=`）——以前引擎不讀所以無所謂，新引擎一上線 source 進來，`"yes"` 過不了 `[ "$PROTECT_MASTER" = "1" ]`，master 保護在 soft repo 上**再次靜默失效**。當場抓到（部署後立刻 `cat` 全部 conf 檢查行尾與內容），修法雙管齊下：引擎加 `__flag()` 正規化（1/yes/true/on 都算開）、NAS 端 conf 改寫成正典旋鈕名（舊檔備份）。教訓：**啟用一個「一直存在但從未被讀」的設定檔之前，先看檔案裡實際寫了什麼**——它的內容從未被任何執行路徑驗證過。

驗證：拋棄式 bare repo 真 push 11 案例全過（合規放行、壞訊息 strict 擋/soft 放、master 兩種 policy 都擋、2MB 超限擋、BOT_TOKEN 樣式擋、新分支 `--not --all` 路徑、yes 值正規化、CHECK_COMMIT_MSG=no 停用生效、log 欄位對齊日報 awk）。新引擎已部署 NAS（舊引擎與舊 conf 均有 .bak）。

---

## 2026-08-14 — 跨機器金鑰名冊同步兩個月來每次都「成功」，實際上兩台機器互相覆蓋

症狀是從一個無關的問題查起的：`git_user2` 的 `authorized_keys` 有兩把查不到來源的 ❓ 金鑰。查證過程中發現本機 `registry.json` 的 6 筆條目 `seen_hosts` **全部只有 `ACER_NB`**——公司機自己。名冊設計上有 `seen_hosts`（這把鑰匙在哪幾台電腦出現過，聯集、只加不減）＋ `label_host()`（hostname 翻成家中/公司），也就是說「這把是公司機還是家機的」這個能力**早就做好了**，但從來沒有一次真的合併到對方的資料。

NAS 上一看就清楚：

```
-rw-------  1 git_user2  git_devs  4641  Aug 14 09:38  km_registry_sync.json
-rw-------  1 kuoterry   git_devs  8283  Aug 13 20:12  km_registry_sync.json.bak-20260813-201251
```

檔案是 **600**，而兩台機器用**不同 SSH 身份**同步（家機 `kuoterry`、公司機 `git_user2`）。誰推誰就把檔案鎖成只有自己讀得到。實測確認：

```
$ ssh kuoterry@... head -c 60 /volume1/Git_Server/config/km_registry_sync.json
head: cannot open '...' for reading: Permission denied
```

兩段程式合起來把這個權限錯誤變成靜默的資料破壞：

- push（`_run_sync_registry`）結尾是 `chmod 600 "$f"`——`mv "$f.new" "$f"` 之後檔案屬於推送者，chmod 成功，於是每次推送都重新把對方鎖在門外。
- pull 是 `if [ -f "$f" ]; then cat "$f"; else echo '{}'; fi` 後面接一行 `true`。`cat` 因權限失敗只往 stderr 噴，`true` 讓整段 rc=0，`_between(out)` 回空字串，`json.loads("" or "{}")` 得到 `{}`——**「檔案不存在」與「檔案讀不到」被壓成同一個結果**。

於是流程變成：拉不到（當成遠端是空的）→ 跟本機合併（等於沒合併）→ 把只有自己資料的版本推回去，蓋掉對方的 → 回報「已同步金鑰名冊，共 N 筆（涵蓋所有已同步過的電腦）」。訊息裡那句「涵蓋所有已同步過的電腦」尤其誤導，因為它從來就只涵蓋一台。

跟 `ci_violation.log` 沒有寫入者、`build_exe.bat` 版號複製靜默失敗是同一個形狀：**停止運作的檢查/同步與正常運作的檢查/同步，在畫面上長得一模一樣。**

修法（Key_Management 1.9.0）：

1. push 改 `chmod 660` ＋ `chgrp git_devs`（`config/` 本來就是 `drwxrwsr-x git_devs` setgid），失敗會回報 `___PERMFAIL___` 並在成功訊息後面附警告——不再靜默。
2. pull 用 `___MISSING___` / `___UNREADABLE___` / `___CATFAIL___` 三個標記把「不存在」「讀不到」「讀失敗」分開。讀不到就**中止同步**（附上該下的 `chmod`/`chgrp` 指令），絕不繼續推送——寧可不同步，也不能拿空的遠端去蓋掉別台的資料。JSON 解析失敗同樣中止（以前是靜靜當成空 dict）。
3. 成功訊息改成實際列出涵蓋了哪幾台機器（`seen_hosts` 聯集後跑 `label_host()`），而不是宣稱「所有已同步過的電腦」。一台機器名單就是同步沒生效的直接證據。

資料救回：NAS 端 `.bak-20260813-201251` 保有家機那份 8 筆（`seen_hosts` 全部 `Terry_ASUS`），與公司機的 6 筆合併成 14 筆推回 NAS，權限改 660，並實測 `kuoterry` 身份讀得到。順帶解掉原本那兩把 ❓ 之一：`SHA256:UGd6fB9FZDqric/…`（註解 `git_user2`）就在家機名冊裡，不能撤。

附帶收穫：`check_private_key_permissions()` 呼叫 `icacls` 時沒指定 `encoding`。繁中 Windows 的 `icacls` 輸出是 cp950，直譯器在 UTF-8 模式下（`PYTHONUTF8=1`，或未來 Python 改預設值）解碼會丟 `UnicodeDecodeError`，而該例外不在函式的 `except (OSError, TimeoutExpired)` 清單裡，會**炸穿整趟掃描**，不是只讓權限檢查回空字串。跑 `PYTHONUTF8=1 python -m unittest` 時 2 個測試炸出來才發現。改成明確指定 `locale.getpreferredencoding(False)` ＋ `errors="replace"`，兩種模式行為一致，並補了測試。
