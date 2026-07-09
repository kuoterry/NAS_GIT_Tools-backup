# -*- coding: utf-8 -*-
"""
NAS Git 專案串接工具 (PyQt6 GUI 版)
====================================
目的：用滑鼠瀏覽到「單一專案資料夾」，一鍵把它接上 DS418 的 Git Server
      (/volume1/Git_Server 大庫)。專案有沒有 git init 過都可以。

為什麼用 GUI：
  - 專案資料夾用「檔案選擇對話框」挑，不靠當前目錄猜 → 從根源消滅「站錯資料夾」。
  - 「大庫容器」(如 D:\\git)與磁碟根目錄一律硬擋，執行鈕直接反灰。
  - 底下有巢狀 git repo 時會列出來，要你勾「我了解風險」才放行。

前提：
  1. 本機已裝 git，且 PATH 找得到；已裝 OpenSSH client (Windows 內建 ssh)。
  2. 已對 NAS 設好 SSH 免密碼登入 (Public Key)。
  3. 已設 git 身分：git config --global user.name / user.email。
  4. pip install PyQt6

作者備註：NAS Git 根目錄固定 /volume1/Git_Server；遠端一律落在這裡。
"""

import os
import sys
import re
import socket
import shutil
import platform
import subprocess

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QGroupBox, QInputDialog, QTabWidget, QListWidget,
    QDialog, QRadioButton, QDialogButtonBox, QListWidgetItem
)

# ============================================================
# 設定：大庫容器（要硬擋、絕不可當專案推上去的路徑）
# 這些路徑本身是「裝很多 git 專案的容器」，不是單一專案。
# 比對時不分大小寫。可自行增修。
# ============================================================
CONTAINER_ROOTS = [
    r"D:\git",
    r"D:\GIT",
]

# ============================================================
# 預設身份(Profile)：第一次執行會自動建立。
# 每個身份各自記住自己的 SSH 使用者 / 主機 / 根目錄。
#   家中電腦 → kuoterry
#   公司電腦 → Git_Server1
# 之後在 UI 可自行「儲存 / 新增 / 刪除」身份。
# ============================================================
DEFAULT_PROFILES = {
    "家中 (kuoterry)": {
        "user": "kuoterry",
        "host": "kcc3713.synology.me",
        "remote_root": "/volume1/Git_Server",
    },
    "公司 (Git_User1)": {
        "user": "Git_User1",
        "host": "kcc3713.synology.me",
        "remote_root": "/volume1/Git_Server",
    },
}

# Windows 下讓子行程不要彈黑窗
if os.name == "nt":
    _NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW
else:
    _NO_WINDOW = 0

# 倉庫 / 封存項目名稱白名單：只允許英數與 . _ -，且須以英數開頭。
# 一次擋掉 / \ ' " $ ` 空白 中文 及 . .. _archived 等危險或保留名稱。
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def is_safe_name(name: str) -> bool:
    return bool(name) and bool(_SAFE_NAME_RE.match(name)) and name not in (".", "..", "_archived")

# 修補版 CI 引擎（pre-receive.ci）內容，base64 編碼。
# 一鍵升級時解碼寫入 NAS 的 /volume1/Git_Server/hooks_template/pre-receive.ci。
# 內容與隨附的 pre-receive.ci 檔一致（含 AUTO_POLICY_LOAD 自載入 policy）。
PATCHED_ENGINE_B64 = (
    "IyEvYmluL2Jhc2gKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQojIFNoYXJl"
    "ZCBDSSBFbmdpbmUgKHByZS1yZWNlaXZlLmNpKQojICArIEFVVE9fUE9MSUNZX0xPQUTvvJroh6rli5Xlvp4gY2lfcG9saWNpZXMv"
    "PHJlcG8+LnBvbGljeSDoroAgUE9MSUNZX01PREUKIyAgICDkvb/jgIzmr4/lgIsgcmVwbyDnjajnq4voqK0gQ0njgI3nnJ/mraPn"
    "lJ/mlYjjgIIKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQoKZXhwb3J0IFBB"
    "VEg9L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4KCkJBU0U9Ii92b2x1bWUxL0dpdF9TZXJ2ZXIiCgojIC0tLSBBVVRPX1BP"
    "TElDWV9MT0FEICjorpMgY2lfcG9saWNpZXMvPHJlcG8+LnBvbGljeSDnlJ/mlYgpIC0tLQojIGJhcmUgcmVwb++8mnB3ZCDljbMg"
    "cmVwbyDnm67pjITjgILoi6XlpJbpg6jlt7IgZXhwb3J0IFBPTElDWV9NT0RF77yI5aaCIGNpX3NlbGZfdGVzdO+8ieWJh+WwiumH"
    "jeS5i+OAggpbIC16ICIkUkVQT19OQU1FIiBdICYmIFJFUE9fTkFNRT0iJChiYXNlbmFtZSAiJChwd2QpIikiCmlmIFsgLXogIiRQ"
    "T0xJQ1lfTU9ERSIgXTsgdGhlbgogICAgX19QRj0iJEJBU0UvY2lfcG9saWNpZXMvJFJFUE9fTkFNRS5wb2xpY3kiCiAgICBbIC1m"
    "ICIkX19QRiIgXSAmJiBQT0xJQ1lfTU9ERT0iJChzZWQgLW4gJ3MvXltbOnNwYWNlOl1dKlBPTElDWT0vL3AnICIkX19QRiIgfCBo"
    "ZWFkIC0xKSIKZmkKWyAteiAiJFBPTElDWV9NT0RFIiBdICYmIFBPTElDWV9NT0RFPW5vbmUKIyBub25lIOaIlueEoSBwb2xpY3kg"
    "4oaSIOWujOWFqOeVpemBjiBDSe+8iOetieaWvOatpCByZXBvIOWBnOeUqCBDSe+8iQpbICIkUE9MSUNZX01PREUiID0gIm5vbmUi"
    "IF0gJiYgZXhpdCAwCiMgLS0tIEVORCBBVVRPX1BPTElDWV9MT0FEIC0tLQoKQk9UX1RPS0VOPSI3ODA1ODQxNDY4OkFBR3cxQzAt"
    "T1F4YUVqM1Q4UUVwbEhwU0RsRmhQNWM2b2x3IgpDSEFUX0lEPSI4NTc4OTg2MjQxIgoKTU9ERT0iJFBPTElDWV9NT0RFIiAgICAg"
    "IyBzb2Z0IC8gc3RyaWN0ClJFUE89IiRSRVBPX05BTUUiCgpzZW5kX3RlbGVncmFtKCkgewogICAgbG9jYWwgbXNnPSIkMSIKICAg"
    "IGN1cmwgLXMgLVggUE9TVCAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRCT1RfVE9LRU4vc2VuZE1lc3NhZ2UiIFwKICAg"
    "ICAgLS1kYXRhLXVybGVuY29kZSAiY2hhdF9pZD0kQ0hBVF9JRCIgXAogICAgICAtLWRhdGEtdXJsZW5jb2RlICJ0ZXh0PVtDSV1b"
    "JFJFUE9dICRtc2ciIFwKICAgICAgPi9kZXYvbnVsbAp9Cgp2aW9sYXRlKCkgewogICAgbG9jYWwgcmVhc29uPSIkMSIKCiAgICBl"
    "Y2hvICLimqDvuI8gQ0kgdmlvbGF0aW9uOiAkcmVhc29uIgogICAgc2VuZF90ZWxlZ3JhbSAiJHJlYXNvbiIKCiAgICBpZiBbICIk"
    "TU9ERSIgPSAic3RyaWN0IiBdOyB0aGVuCiAgICAgICAgZWNobyAi4p2MIENJIGJsb2NrZWQgcHVzaCIKICAgICAgICBleGl0IDEK"
    "ICAgIGZpCn0KCndoaWxlIHJlYWQgb2xkcmV2IG5ld3JldiByZWZuYW1lOyBkbwogICAgY2FzZSAiJHJlZm5hbWUiIGluCiAgICAg"
    "ICAgcmVmcy9oZWFkcy8qKSA7OwogICAgICAgICopIGNvbnRpbnVlIDs7CiAgICBlc2FjCgogICAgYnJhbmNoPSR7cmVmbmFtZSNy"
    "ZWZzL2hlYWRzL30KCiAgICAjIGJyYW5jaCDopo/liYcKICAgIGVjaG8gIiRicmFuY2giIHwgZ3JlcCAtRXEgJ14oZGV2ZWxvcCR8"
    "ZmVhdHVyZS98cmVsZWFzZS8pJyB8fCBcCiAgICAgICAgdmlvbGF0ZSAiYmFkIGJyYW5jaCBuYW1lOiAkYnJhbmNoIgoKICAgICMg"
    "Y29tbWl0IG1lc3NhZ2Ug6KaP5YmHCiAgICBmb3IgYyBpbiAkKGdpdCByZXYtbGlzdCAiJG9sZHJldi4uJG5ld3JldiIpOyBkbwog"
    "ICAgICAgIGdpdCBsb2cgLTEgLS1wcmV0dHk9JUIgIiRjIiB8IFwKICAgICAgICAgIGdyZXAgLUVxICdcWyhKSVJBfFRBU0spLVsw"
    "LTldK1xdfF4oZmVhdHxmaXh8Y2hvcmV8ZG9jcyk6JyB8fCBcCiAgICAgICAgICB2aW9sYXRlICJiYWQgY29tbWl0IG1lc3NhZ2Ug"
    "KCRjKSIKICAgIGRvbmUKZG9uZQoKZXhpdCAwCg=="
)

# 通用 .gitignore（Keil MDK / Python / ESP-IDF）
GITIGNORE_TEXT = """\
# ============================================
# .gitignore — 通用（Keil MDK / Python / ESP-IDF）
# ============================================

# ========== Keil MDK (ARMCLANG) ==========
*.uvguix.*
*.uvoptx
*.bak
*.dbgconf
*.scvd
JLinkSettings.ini
*.uvgui.*
*.__i
*._ia
*.__ii
Objects/
Listings/
Output/
DebugConfig/
RTE/_*/
RTE/
*.o
*.axf
*.elf
*.hex
*.bin
*.map
*.lst
*.crf
*.d
*.dep
*.lnp
*.htm
*.build_log.htm
*.iex
*.sct
*.tra
*.l1p
*.l2p
*.fed
*.cdb
*.ddb
*.i
*.reggroups

# ========== Python ==========
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
.eggs/
.pytest_cache/
.mypy_cache/
.venv/
venv/
env/
dist/
build/
*.exe
*.spec

# ========== ESP-IDF ==========
sdkconfig.old
managed_components/

# ========== 編輯器 / 工具 ==========
.vscode/
.idea/

# ========== Synology / Windows ==========
@eaDir/
Thumbs.db
Desktop.ini
~$*
*.tmp
"""


# ============================================================
# 小工具：路徑判斷
# ============================================================
def norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)).rstrip("\\/")


def is_container_root(path: str) -> bool:
    """是否為大庫容器根，或磁碟根目錄（如 D:\\）。這些一律禁止當專案。"""
    if not path:
        return False
    p = norm(path)
    blocked = {norm(r) for r in CONTAINER_ROOTS}
    if p in blocked:
        return True
    # 磁碟根目錄：splitdrive 之後尾巴只剩 '' 或 '\' '/'
    _, tail = os.path.splitdrive(os.path.abspath(path))
    if tail in ("", "\\", "/", os.sep):
        return True
    return False


def find_nested_repos(path: str):
    """列出 path 底下『本身已是 git repo』的子資料夾名稱。"""
    result = []
    try:
        for name in os.listdir(path):
            full = os.path.join(path, name)
            if os.path.isdir(full) and os.path.exists(os.path.join(full, ".git")):
                result.append(name)
    except OSError:
        pass
    return sorted(result)


def is_git_repo(path: str) -> bool:
    return os.path.exists(os.path.join(path, ".git"))


# ============================================================
# 背景工作執行緒
# 只發訊號，不碰任何 widget（避免 QThread 崩潰）。
# ============================================================
class Worker(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)  # (成功?, 結尾訊息)
    repos = pyqtSignal(list)      # 列出倉庫用：回傳 repo 名稱清單
    hooks = pyqtSignal(str)       # 讀 CI hook 用：回傳 hook 內容文字

    def __init__(self, cfg: dict, mode: str = "connect"):
        super().__init__()
        self.cfg = cfg
        self.mode = mode  # "connect" 串接 / "test" 測連線 / "list" 列出倉庫

    # --- 執行外部指令的統一入口 ---
    def _mask(self, a):
        """在 log 中把密碼遮成 ****，不外洩。"""
        pw = self.cfg.get("password", "")
        if pw and a == pw:
            return "****"
        return a

    def _run(self, args, cwd=None, input_bytes=None, env=None):
        self.log.emit("$ " + " ".join(self._mask(a) for a in args))
        try:
            cp = subprocess.run(
                args, cwd=cwd, capture_output=True, input=input_bytes,
                env=env, creationflags=_NO_WINDOW
            )
        except FileNotFoundError as e:
            self.log.emit(f"[錯誤] 找不到執行檔：{e}")
            return 127, "", str(e)
        out = cp.stdout.decode("utf-8", "replace").strip()
        err = cp.stderr.decode("utf-8", "replace").strip()
        if out:
            self.log.emit(out)
        if err:
            self.log.emit(err)
        return cp.returncode, out, err

    def _ssh(self, remote_cmd):
        """對 NAS 執行遠端指令。有密碼→用 plink -pw；無密碼→用內建 ssh（金鑰）。"""
        c = self.cfg
        ssh_host = f"{c['user']}@{c['host']}"
        pw = c.get("password", "")
        if pw:
            plink = shutil.which("plink")
            if not plink:
                self.log.emit(
                    "[錯誤] 有填密碼，但找不到 plink.exe（PuTTY）。"
                    "請安裝 PuTTY，或改用 SSH 金鑰（免密碼）。"
                )
                return 255, "", "plink-missing"
            # 餵 y\n 以在首次連線時自動接受主機金鑰（之後會被 PuTTY 快取）
            args = [plink, "-pw", pw, ssh_host, remote_cmd]
            return self._run(args, input_bytes=b"y\n")
        else:
            args = [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10",
                ssh_host, remote_cmd,
            ]
            return self._run(args)

    def _git_env(self):
        """本地 git 若要用密碼推送，透過 plink 當 GIT_SSH_COMMAND。無密碼回 None。"""
        pw = self.cfg.get("password", "")
        if not pw:
            return None
        plink = shutil.which("plink")
        if not plink:
            return None
        env = os.environ.copy()
        env["GIT_SSH_COMMAND"] = f'"{plink}" -pw {pw}'
        return env

    def run(self):
        if self.mode == "test":
            self._run_test()
        elif self.mode == "list":
            self._run_list()
        elif self.mode == "delete":
            self._run_delete()
        elif self.mode == "hooks":
            self._run_hooks()
        elif self.mode == "ci_status":
            self._run_ci_status()
        elif self.mode == "set_ci":
            self._run_set_ci()
        elif self.mode == "set_ci_batch":
            self._run_set_ci_batch()
        elif self.mode == "repo_detail":
            self._run_repo_detail()
        elif self.mode == "clone":
            self._run_clone()
        elif self.mode == "upgrade_engine":
            self._run_upgrade_engine()
        elif self.mode == "healthcheck":
            self._run_healthcheck()
        elif self.mode == "repair":
            self._run_repair()
        elif self.mode == "log":
            self._run_log()
        elif self.mode == "create_repo":
            self._run_create_repo()
        elif self.mode == "ci_selftest":
            self._run_ci_selftest()
        elif self.mode == "archive_list":
            self._run_archive_list()
        elif self.mode == "archive_restore":
            self._run_archive_restore()
        elif self.mode == "archive_purge":
            self._run_archive_purge()
        else:
            self._run_connect()

    @staticmethod
    def _between(out):
        """取 ___BEGIN___ / ___END___ 之間的內容，濾掉登入橫幅等雜訊。"""
        lines = out.splitlines()
        try:
            b = lines.index("___BEGIN___")
            e = lines.index("___END___")
            return "\n".join(lines[b + 1:e]).strip()
        except ValueError:
            return out.strip()

    # --- 只測 NAS 連線 ---
    def _run_test(self):
        rc, out, _ = self._ssh("echo NAS_OK")
        if rc == 0 and "NAS_OK" in out:
            self.done.emit(True, "NAS 連線正常。")
        else:
            self.done.emit(False, "無法連線 NAS（SSH 驗證或連線問題）。\n"
                                  "請確認已設 SSH 金鑰，或填密碼並安裝 PuTTY(plink)。在家可改用內網 IP。")

    # --- 列出 Git_Server 底下的倉庫（含空庫 / 最後 commit 資訊）---
    def _run_list(self):
        c = self.cfg
        root = c["remote_root"]
        self.log.emit(f"--- 列出 {root} 底下的倉庫 ---")
        # 每行輸出：name<TAB>status<TAB>policy。status=空庫或最後commit；policy=none/soft/strict
        cmd = "\n".join([
            "echo ___BEGIN___",
            f'for d in "{root}"/*/; do',
            "  [ -e \"$d/HEAD\" ] || continue",
            "  name=$(basename \"$d\")",
            "  info=$(git --git-dir=\"$d\" for-each-ref --sort=-committerdate "
            "--format='%(committerdate:short)|%(refname:short)' refs/heads 2>/dev/null | head -1)",
            f"  pf='{root}/ci_policies/'\"$name\"'.policy'; pol=none",
            "  [ -f \"$pf\" ] && pol=$(sed -n 's/^[[:space:]]*POLICY=//p' \"$pf\" | head -1)",
            "  [ -z \"$pol\" ] && pol=none",
            "  if [ -z \"$info\" ]; then",
            "    printf '%s\\t%s\\t%s\\n' \"$name\" \"空庫（無 commit）\" \"$pol\"",
            "  else",
            "    dt=${info%%|*}; br=${info#*|}",
            "    printf '%s\\t%s (%s)\\t%s\\n' \"$name\" \"$dt\" \"$br\" \"$pol\"",
            "  fi",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.repos.emit([])
            self.done.emit(False, "無法連線 NAS 或列出失敗。\n"
                                  "請確認已設 SSH 金鑰，或填密碼並安裝 PuTTY(plink)。在家可改用內網 IP。")
            return
        lines = out.splitlines()
        try:
            b = lines.index("___BEGIN___")
            e = lines.index("___END___")
            body = lines[b + 1:e]
        except ValueError:
            body = lines
        items = []
        for ln in body:
            ln = ln.rstrip("\n")
            if not ln.strip():
                continue
            parts = ln.split("\t")
            name = parts[0].strip() if parts else ""
            status = parts[1].strip() if len(parts) > 1 else ""
            pol = parts[2].strip() if len(parts) > 2 else "none"
            items.append((name, status, pol))
        items.sort(key=lambda t: t[0].lower())
        self.repos.emit(items)
        n_empty = sum(1 for t in items if t[1].startswith("空庫"))
        self.done.emit(True, f"找到 {len(items)} 個倉庫（其中 {n_empty} 個空庫）。")

    # --- 安全下庄 / 刪除倉庫 ---
    def _run_delete(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        mode = c.get("delete_mode", "archive")

        # 安全檢查：名稱不得含路徑分隔、上層、引號，或指到保留目錄
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許英數與 . _ -，須英數開頭）：{name!r}")
            return

        path = f"{root}/{name}"
        self.log.emit(f"--- 安全下庄：{name}（模式：{mode}）---")

        # 先確認確實是裸倉庫（有 HEAD），避免誤刪其他資料夾
        rc, out, _ = self._ssh(f"[ -e '{path}/HEAD' ] && echo ___ISREPO___ || echo NO")
        if rc != 0 or "___ISREPO___" not in out:
            self.done.emit(False, f"找不到、或不是有效的裸倉庫，已中止：{path}")
            return

        if mode == "archive":
            cmd = (
                f"ts=$(date +%Y%m%d-%H%M%S); mkdir -p '{root}/_archived' && "
                f"mv '{path}' '{root}/_archived/{name}.'$ts && echo ___OK___"
            )
            okmsg = f"已安全下庄：搬到封存區 {root}/_archived/（可還原）\n倉庫：{name}"
        elif mode == "backup_delete":
            cmd = (
                f"ts=$(date +%Y%m%d-%H%M%S); mkdir -p '{root}/_archived' && "
                f"tar -czf '{root}/_archived/{name}.'$ts'.tar.gz' -C '{root}' '{name}' && "
                f"rm -rf '{path}' && echo ___OK___"
            )
            okmsg = f"已打包備份到 {root}/_archived/ 後刪除\n倉庫：{name}"
        else:  # hard_delete
            cmd = f"rm -rf '{path}' && echo ___OK___"
            okmsg = f"已直接刪除（不可還原）\n倉庫：{name}"

        rc, out, _ = self._ssh(cmd)
        if rc == 0 and "___OK___" in out:
            self.done.emit(True, okmsg)
        else:
            self.done.emit(False, f"處理失敗（可能是權限或磁碟空間問題）：{name}")

    # --- 讀取該庫的 CI 規則（server-side hook 內容）---
    def _run_hooks(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許英數與 . _ -，須英數開頭）：{name!r}")
            return
        path = f"{root}/{name}"
        self.log.emit(f"--- 讀取 {name} 的 CI 規則報告 ---")
        # 組合報告：policy 開關 + profile(.conf，兩個目錄都找) + repo stub + CI 引擎
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'",
            f"name='{name}'",
            "repo=\"$BASE/$name\"",
            "echo \"==================== CI 規則報告 ====================\"",
            "echo \"倉庫：$name\"",
            "pf=\"$BASE/ci_policies/$name.policy\"",
            "POLICY=none; PROFILE=-",
            "if [ -f \"$pf\" ]; then",
            "  p=$(sed -n 's/^[[:space:]]*POLICY=//p' \"$pf\" | head -1)",
            "  pr=$(sed -n 's/^[[:space:]]*PROFILE=//p' \"$pf\" | head -1)",
            "  [ -n \"$p\" ] && POLICY=\"$p\"",
            "  [ -n \"$pr\" ] && PROFILE=\"$pr\"",
            "fi",
            "if [ \"$POLICY\" = none ]; then CIEN=\"否（無 policy 或 POLICY=none）\"; else CIEN=\"是\"; fi",
            "conf=\"\"",
            "for d in \"$BASE/ci_profiles\" \"$BASE/ci_policies\"; do",
            "  [ -f \"$d/$POLICY.conf\" ] && { conf=\"$d/$POLICY.conf\"; break; }",
            "done",
            "MODE=\"\"; PM=\"\"; CB=\"\"; CC=\"\"",
            "if [ -n \"$conf\" ]; then",
            "  MODE=$(sed -n 's/^[[:space:]]*MODE=//p' \"$conf\" | head -1)",
            "  PM=$(sed -n 's/^[[:space:]]*PROTECT_MASTER=//p' \"$conf\" | head -1)",
            "  CB=$(sed -n 's/^[[:space:]]*CHECK_BRANCH_NAME=//p' \"$conf\" | head -1)",
            "  CC=$(sed -n 's/^[[:space:]]*CHECK_COMMIT_MSG=//p' \"$conf\" | head -1)",
            "fi",
            "echo \"CI 啟用：$CIEN\"",
            "echo \"policy：$POLICY\"",
            "echo \"profile(.conf)：${conf:-（找不到 $POLICY.conf）}\"",
            "echo \"模式 MODE：${MODE:-?}\"",
            "echo \"檢查：保護master=${PM:-?}  分支名=${CB:-?}  commit格式=${CC:-?}\"",
            "echo",
            "echo \"---------- ci_policies/$name.policy ----------\"",
            "if [ -f \"$pf\" ]; then cat \"$pf\"; else echo \"（無此 policy 檔 → CI 未啟用）\"; fi",
            "echo",
            "echo \"---------- profile conf ----------\"",
            "if [ -n \"$conf\" ]; then echo \"# $conf\"; cat \"$conf\"; else echo \"（找不到 $POLICY.conf）\"; fi",
            "echo",
            "echo \"---------- repo pre-receive (stub) ----------\"",
            "if [ -f \"$repo/hooks/pre-receive\" ]; then cat \"$repo/hooks/pre-receive\"; else echo \"（無 pre-receive）\"; fi",
            "echo",
            "echo \"---------- CI 引擎 pre-receive.ci ----------\"",
            "eng=\"$BASE/hooks_template/pre-receive.ci\"",
            "if [ -f \"$eng\" ]; then cat \"$eng\"; else echo \"（找不到 $eng）\"; fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 CI 規則失敗（連線或權限問題）。")
            return
        lines = out.splitlines()
        try:
            b = lines.index("___BEGIN___")
            e = lines.index("___END___")
            body = "\n".join(lines[b + 1:e]).strip()
        except ValueError:
            body = out.strip()
        self.hooks.emit(body)
        self.done.emit(True, f"已讀取 {name} 的 CI 規則報告。")

    # --- CI 狀態總表（全庫 policy / mode / 啟用狀態）---
    def _run_ci_status(self):
        c = self.cfg
        root = c["remote_root"]
        self.log.emit("--- 讀取 CI 狀態總表 ---")
        # 遠端只吐原始欄位（Tab 分隔），對齊交給 Python，避免庫名超長把欄位擠歪。
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'",
            "eng=\"$BASE/hooks_template/pre-receive.ci\"",
            "if [ -f \"$eng\" ] && grep -q AUTO_POLICY_LOAD \"$eng\"; then",
            "  printf 'ENGINE\\t%s\\n' upgraded",
            "else",
            "  printf 'ENGINE\\t%s\\n' legacy",
            "fi",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  pf=\"$BASE/ci_policies/$name.policy\"",
            "  POLICY=none",
            "  if [ -f \"$pf\" ]; then",
            "    p=$(sed -n 's/^[[:space:]]*POLICY=//p' \"$pf\" | head -1)",
            "    [ -n \"$p\" ] && POLICY=\"$p\"",
            "  fi",
            "  case \"$POLICY\" in",
            "    strict) EN=block; ST=OK;;",
            "    soft)   EN=warn;  ST=OK;;",
            "    *)      POLICY=none; EN=-; ST=X;;",
            "  esac",
            "  printf 'ROW\\t%s\\t%s\\t%s\\t%s\\n' \"$name\" \"$POLICY\" \"$EN\" \"$ST\"",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 CI 狀態總表失敗（連線或權限問題）。")
            return
        lines = out.splitlines()
        try:
            b = lines.index("___BEGIN___")
            e = lines.index("___END___")
            body = lines[b + 1:e]
        except ValueError:
            body = lines
        self.hooks.emit(self._format_ci_status(body))
        self.done.emit(True, "已讀取 CI 狀態總表。")

    @staticmethod
    def _disp_width(s):
        """字串顯示寬度（東亞全形算 2），供等寬字型對齊。"""
        import unicodedata
        w = 0
        for ch in s:
            w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        return w

    def _pad(self, s, width):
        return s + " " * max(0, width - self._disp_width(s))

    def _format_ci_status(self, body):
        engine = "legacy"
        rows = []
        for ln in body:
            parts = ln.split("\t")
            if not parts:
                continue
            if parts[0] == "ENGINE" and len(parts) >= 2:
                engine = parts[1].strip()
            elif parts[0] == "ROW" and len(parts) >= 5:
                rows.append((parts[1], parts[2], parts[3], parts[4]))

        head = ("引擎狀態：已升級（policy 生效中）" if engine == "upgraded"
                else "引擎狀態：未升級（policy 尚未生效，請按「升級 CI 引擎」）")

        cols = ("REPO", "POLICY", "ENFORCE", "CI")
        w_repo = max([self._disp_width(cols[0])] + [self._disp_width(r[0]) for r in rows] + [4])
        w_pol = max([self._disp_width(cols[1])] + [self._disp_width(r[1]) for r in rows])
        w_enf = max([self._disp_width(cols[2])] + [self._disp_width(r[2]) for r in rows])

        def fmt(a, b_, c_, d_):
            return f"{self._pad(a, w_repo)}  {self._pad(b_, w_pol)}  {self._pad(c_, w_enf)}  {d_}"

        out = [head, "", fmt(*cols), "-" * (w_repo + w_pol + w_enf + 10)]
        for r in rows:
            out.append(fmt(*r))
        if not rows:
            out.append("（沒有任何 *.git 倉庫）")
        return "\n".join(out)

    # --- 設定某個 repo 的 CI（寫 policy 檔 + 確保 stub）---
    def _run_set_ci(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        pol = c.get("ci_policy", "none")
        if pol not in ("none", "soft", "strict"):
            self.done.emit(False, f"不支援的 policy：{pol!r}")
            return
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許英數與 . _ -，須英數開頭）：{name!r}")
            return
        self.log.emit(f"--- 設定 {name} 的 CI：POLICY={pol} ---")
        cmd = "\n".join([
            f"BASE='{root}'",
            f"name='{name}'",
            f"pol='{pol}'",
            "mkdir -p \"$BASE/ci_policies\"",
            "pf=\"$BASE/ci_policies/$name.policy\"",
            "if [ \"$pol\" = none ]; then",
            "  printf '# %s\\nPOLICY=none\\n' \"$name\" > \"$pf\"",
            "else",
            "  printf '# %s\\nPOLICY=%s\\nPROFILE=%s\\n' \"$name\" \"$pol\" \"$pol\" > \"$pf\"",
            "fi",
            "repo=\"$BASE/$name\"",
            "hook=\"$repo/hooks/pre-receive\"",
            "mkdir -p \"$repo/hooks\"",
            "if [ ! -f \"$hook\" ]; then",
            "  printf '#!/bin/bash\\nexec %s/hooks_template/pre-receive.ci\\n' \"$BASE\" > \"$hook\"",
            "  chmod 750 \"$hook\"",
            "fi",
            "chgrp git_devs \"$pf\" \"$hook\" 2>/dev/null",
            "echo ___OK___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc == 0 and "___OK___" in out:
            desc = {"none": "停用（不檢查）", "soft": "soft（只警告）", "strict": "strict（擋 push）"}[pol]
            self.done.emit(True, f"已設定 {name} 的 CI：{desc}")
        else:
            self.done.emit(False, f"設定失敗（權限問題？）：{name}")

    # --- 批次設定 CI（多個 repo 一次套用同一 policy）---
    def _run_set_ci_batch(self):
        c = self.cfg
        root = c["remote_root"]
        names = c.get("repo_names", [])
        pol = c.get("ci_policy", "none")
        if pol not in ("none", "soft", "strict"):
            self.done.emit(False, f"不支援的 policy：{pol!r}")
            return
        safe = [n for n in names if is_safe_name(n)]
        if not safe:
            self.done.emit(False, "沒有可套用的有效倉庫。")
            return
        self.log.emit(f"--- 批次設定 CI：{len(safe)} 個 repo → POLICY={pol} ---")
        quoted = " ".join("'" + n + "'" for n in safe)
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; pol='{pol}'",
            "mkdir -p \"$BASE/ci_policies\"",
            f"for name in {quoted}; do",
            "  pf=\"$BASE/ci_policies/$name.policy\"",
            "  if [ \"$pol\" = none ]; then",
            "    printf '# %s\\nPOLICY=none\\n' \"$name\" > \"$pf\"",
            "  else",
            "    printf '# %s\\nPOLICY=%s\\nPROFILE=%s\\n' \"$name\" \"$pol\" \"$pol\" > \"$pf\"",
            "  fi",
            "  repo=\"$BASE/$name\"; hook=\"$repo/hooks/pre-receive\"",
            "  mkdir -p \"$repo/hooks\"",
            "  [ -f \"$hook\" ] || { printf '#!/bin/bash\\nexec %s/hooks_template/pre-receive.ci\\n' \"$BASE\" > \"$hook\"; chmod 750 \"$hook\"; }",
            "  chgrp git_devs \"$pf\" \"$hook\" 2>/dev/null",
            "  echo \"[SET] $name → $pol\"",
            "done",
            "echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc == 0 and "___OK___" in out:
            self.hooks.emit(self._between(out))
            self.done.emit(True, f"已對 {len(safe)} 個 repo 套用 CI：{pol}")
        else:
            self.done.emit(False, "批次設定失敗（權限問題？）。")

    # --- repo 明細（分支 / 大小 / 各分支最後 commit）---
    def _run_repo_detail(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許英數與 . _ -）：{name!r}")
            return
        self.log.emit(f"--- repo 明細：{name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "echo \"== 倉庫明細：$name ==\"",
            "echo \"大小：$(du -sh \"$repo\" 2>/dev/null | cut -f1)\"",
            "echo \"預設分支(HEAD)：$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)\"",
            "pf=\"$BASE/ci_policies/$name.policy\"; pol=none; [ -f \"$pf\" ] && pol=$(sed -n 's/^[[:space:]]*POLICY=//p' \"$pf\" | head -1)",
            "echo \"CI policy：${pol:-none}\"",
            "echo",
            "nb=$(git --git-dir=\"$repo\" for-each-ref refs/heads 2>/dev/null | wc -l)",
            "echo \"分支數：$nb\"",
            "if [ \"$nb\" = 0 ]; then",
            "  echo \"（空庫，尚無任何分支/commit）\"",
            "else",
            "  echo \"分支（依最後提交由新到舊）：\"",
            "  git --git-dir=\"$repo\" for-each-ref --sort=-committerdate --format='  %(refname:short)  |  %(committerdate:short)  |  %(authorname)  |  %(subject)' refs/heads 2>/dev/null",
            "fi",
            "echo",
            "echo \"標籤數：$(git --git-dir=\"$repo\" tag 2>/dev/null | wc -l)\"",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取明細失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已讀取 {name} 明細。")

    # --- 從 NAS clone 到本地（本機執行 git clone，走金鑰/plink）---
    def _run_clone(self):
        c = self.cfg
        url = c.get("clone_url", "")
        parent = c.get("target_dir", "")
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規：{name!r}")
            return
        if not url or not parent:
            self.done.emit(False, "缺少 Clone URL 或目標資料夾。")
            return
        folder = name[:-4] if name.endswith(".git") else name
        target = os.path.join(parent, folder)
        if os.path.exists(target):
            self.done.emit(False, f"目標資料夾已存在，未動作：\n{target}")
            return
        self.log.emit(f"--- git clone → {target} ---")
        rc, out, err = self._run(["git", "clone", url, target], env=self._git_env())
        if rc == 0:
            self.done.emit(True, f"已 clone 到本地：\n{target}")
        else:
            msg = (err or out).strip()
            tail = msg.splitlines()[-1] if msg else "未知錯誤"
            self.done.emit(False, f"clone 失敗：{tail}")

    # --- 一鍵升級 NAS 上的 CI 引擎（自動備份 + 換檔）---
    def _run_upgrade_engine(self):
        c = self.cfg
        root = c["remote_root"]
        b64 = PATCHED_ENGINE_B64
        self.log.emit("--- 升級 CI 引擎 pre-receive.ci（自動備份 + 換檔）---")
        # 用 base64 傳輸避免引號/換行問題；先解碼到 .new，做健全性檢查，備份舊檔後再換上。
        cmd = "\n".join([
            f"BASE='{root}'",
            "eng=\"$BASE/hooks_template/pre-receive.ci\"",
            "mkdir -p \"$BASE/hooks_template\"",
            f"printf '%s' '{b64}' | base64 -d > \"$eng.new\" || {{ echo DECODE_FAIL; exit 0; }}",
            # 健全性：必須含 AUTO_POLICY_LOAD 且非空
            "if ! grep -q AUTO_POLICY_LOAD \"$eng.new\"; then echo BAD_CONTENT; rm -f \"$eng.new\"; exit 0; fi",
            "if [ ! -s \"$eng.new\" ]; then echo EMPTY; rm -f \"$eng.new\"; exit 0; fi",
            # 備份舊檔（若存在）",
            "if [ -f \"$eng\" ]; then cp \"$eng\" \"$eng.bak-$(date +%Y%m%d-%H%M%S)\"; echo \"BACKUP_DONE\"; fi",
            "mv \"$eng.new\" \"$eng\"",
            "chmod 755 \"$eng\"",
            "chgrp git_devs \"$eng\" 2>/dev/null",
            "echo ___OK___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0 or "___OK___" not in out:
            reason = ""
            for tag in ("DECODE_FAIL", "BAD_CONTENT", "EMPTY"):
                if tag in out:
                    reason = f"（{tag}）"
                    break
            self.done.emit(False, f"升級失敗{reason}。請檢查連線與 hooks_template 目錄權限。")
            return
        backed = "（已備份舊檔為 pre-receive.ci.bak-時間戳）" if "BACKUP_DONE" in out else "（原本無舊檔）"
        self.done.emit(True, "CI 引擎已升級為自載入 policy 版本。\n" + backed +
                             "\n之後各 repo 的 CI 會依 ci_policies/<repo>.policy 生效。")

    # --- Git Server 健康檢查（唯讀）---
    def _run_healthcheck(self):
        root = self.cfg["remote_root"]
        self.log.emit("--- Git Server 健康檢查 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'",
            "echo '== 模板 / 引擎 =='",
            "[ -f \"$BASE/hooks_template/pre-receive.ci\" ] && echo '[OK] CI 引擎存在' || echo '[!!] 缺 hooks_template/pre-receive.ci'",
            "[ -f \"$BASE/hooks_template/pre-receive.stub\" ] && echo '[OK] pre-receive.stub 存在' || echo '[!!] 缺 hooks_template/pre-receive.stub'",
            "[ -f \"$BASE/hooks_template/post-receive\" ] && echo '[OK] post-receive 模板存在' || echo '[!!] 缺 hooks_template/post-receive'",
            "if [ -f \"$BASE/hooks_template/pre-receive.ci\" ] && grep -q AUTO_POLICY_LOAD \"$BASE/hooks_template/pre-receive.ci\"; then echo '[OK] CI 引擎已升級（policy 生效）'; else echo '[  ] CI 引擎未升級（policy 尚未生效）'; fi",
            "echo",
            "echo '== 各 repo hook / 群組 =='",
            "bad=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  n=$(basename \"$repo\"); msg=''",
            "  [ -x \"$repo/hooks/post-receive\" ] || { msg=\"$msg 缺post-receive\"; bad=1; }",
            "  [ -f \"$repo/hooks/pre-receive\" ] || { msg=\"$msg 缺pre-receive\"; bad=1; }",
            "  g=$(stat -c %G \"$repo\" 2>/dev/null)",
            "  [ \"$g\" = git_devs ] || { msg=\"$msg group=$g\"; bad=1; }",
            "  [ -n \"$msg\" ] && echo \"[!!] $n:$msg\"",
            "done",
            "[ \"$bad\" = 0 ] && echo '[OK] 所有 repo 的 hook 與群組正常'",
            "echo",
            "echo '== 日誌 =='",
            "[ -d \"$BASE/logs\" ] && echo '[OK] logs 目錄存在' || echo '[  ] 無 logs 目錄'",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "健康檢查失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, "健康檢查完成。")

    # --- 一鍵修復（套用 template hook + 修群組權限）---
    def _run_repair(self):
        root = self.cfg["remote_root"]
        self.log.emit("--- 一鍵修復：套用 template hook + 修群組 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'",
            "PRE=\"$BASE/hooks_template/pre-receive.stub\"",
            "POST=\"$BASE/hooks_template/post-receive\"",
            "fixed=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  n=$(basename \"$repo\")",
            "  mkdir -p \"$repo/hooks\"",
            "  [ -f \"$PRE\" ] && { cp \"$PRE\" \"$repo/hooks/pre-receive\"; chmod 750 \"$repo/hooks/pre-receive\"; }",
            "  [ -f \"$POST\" ] && { cp \"$POST\" \"$repo/hooks/post-receive\"; chmod 750 \"$repo/hooks/post-receive\"; }",
            "  chgrp -R git_devs \"$repo\" 2>/dev/null; chmod -R g+rwX \"$repo\" 2>/dev/null",
            "  echo \"[FIX] $n\"",
            "  fixed=$((fixed+1))",
            "done",
            "echo \"共處理 $fixed 個 repo\"",
            "echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0 or "___OK___" not in out:
            self.done.emit(False, "修復失敗（權限問題？需以 git_devs 帳號執行）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, "一鍵修復完成。")

    # --- 日誌檢視（tail）---
    def _run_log(self):
        root = self.cfg["remote_root"]
        logfile = self.cfg.get("logfile", "")
        n = int(self.cfg.get("log_lines", 200))
        if logfile not in ("git_push.log", "ci_violation.log", "post_receive_debug.log"):
            self.done.emit(False, f"不支援的日誌：{logfile!r}")
            return
        self.log.emit(f"--- 讀取日誌 {logfile}（最後 {n} 筆）---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"f='{root}/logs/{logfile}'",
            f"if [ -f \"$f\" ]; then tail -n {n} \"$f\"; else echo \"（找不到 $f）\"; fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取日誌失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已讀取 {logfile}。")

    # --- 在 NAS 直接新建空倉庫（bare + hook + 權限 + 可選 CI）---
    def _run_create_repo(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        branch = c.get("branch", "develop") or "develop"
        pol = c.get("ci_policy", "none")
        if not name.endswith(".git"):
            name += ".git"
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許英數與 . _ -）：{name!r}")
            return
        if pol not in ("none", "soft", "strict"):
            pol = "none"
        self.log.emit(f"--- 在 NAS 新建空倉庫：{name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; branch='{branch}'; pol='{pol}'",
            "repo=\"$BASE/$name\"",
            "if [ -e \"$repo\" ]; then echo EXISTS; echo ___END___; exit 0; fi",
            "git init --bare \"$repo\" >/dev/null 2>&1 || { echo INIT_FAIL; echo ___END___; exit 0; }",
            "[ -f \"$BASE/hooks_template/pre-receive.stub\" ] && { cp \"$BASE/hooks_template/pre-receive.stub\" \"$repo/hooks/pre-receive\"; chmod 750 \"$repo/hooks/pre-receive\"; }",
            "[ -f \"$BASE/hooks_template/post-receive\" ] && { cp \"$BASE/hooks_template/post-receive\" \"$repo/hooks/post-receive\"; chmod 750 \"$repo/hooks/post-receive\"; }",
            "git --git-dir=\"$repo\" symbolic-ref HEAD \"refs/heads/$branch\" 2>/dev/null",
            "mkdir -p \"$BASE/ci_policies\"",
            "if [ \"$pol\" != none ]; then printf '# %s\\nPOLICY=%s\\nPROFILE=%s\\n' \"$name\" \"$pol\" \"$pol\" > \"$BASE/ci_policies/$name.policy\"; fi",
            "chgrp -R git_devs \"$repo\" 2>/dev/null; chmod -R g+rwX \"$repo\" 2>/dev/null",
            "echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if "EXISTS" in out:
            self.done.emit(False, f"倉庫已存在，未建立：{name}")
            return
        if rc != 0 or "___OK___" not in out:
            fail = "INIT_FAIL" in out
            self.done.emit(False, "建立失敗" + ("（git init --bare 失敗）" if fail else "（權限問題？）"))
            return
        url = f"{c['user']}@{c['host']}:{root}/{name}"
        self.done.emit(True, f"已建立空倉庫：{name}\n預設分支 HEAD → {branch}\nCI：{pol}\nClone URL：{url}")

    # --- CI 自我測試（不用 push；用假 push 跑引擎）---
    def _run_ci_selftest(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許英數與 . _ -）：{name!r}")
            return
        self.log.emit(f"--- CI 自我測試：{name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "pf=\"$BASE/ci_policies/$name.policy\"; pol=none",
            "[ -f \"$pf\" ] && pol=$(sed -n 's/^[[:space:]]*POLICY=//p' \"$pf\" | head -1)",
            "[ -z \"$pol\" ] && pol=none",
            "eng=\"$BASE/hooks_template/pre-receive.ci\"",
            "echo \"倉庫：$name\"",
            "echo \"目前 POLICY：$pol　(strict=擋 / soft=只警告 / none=略過)\"",
            "echo \"註：strict/soft 遇違規會實際發一則 Telegram（這是真的引擎測試）\"",
            "echo",
            "if [ ! -f \"$eng\" ]; then echo '缺 CI 引擎，無法測試'; echo ___END___; exit 0; fi",
            "cd \"$repo\" 2>/dev/null || { echo '找不到 repo 目錄'; echo ___END___; exit 0; }",
            "Z=0000000000000000000000000000000000000000",
            "N=1111111111111111111111111111111111111111",
            "echo '── 測試①：推 master（不合規分支）──'",
            "printf '%s %s refs/heads/master\\n' \"$Z\" \"$N\" | POLICY_MODE=\"$pol\" REPO_NAME=\"$name\" bash \"$eng\" 2>/dev/null",
            "echo \"→ 結束碼 $?　(1=擋下 / 0=放行或僅警告)\"",
            "echo",
            "echo '── 測試②：推 feature/test（合規分支）──'",
            "printf '%s %s refs/heads/feature/test\\n' \"$Z\" \"$N\" | POLICY_MODE=\"$pol\" REPO_NAME=\"$name\" bash \"$eng\" 2>/dev/null",
            "echo \"→ 結束碼 $?\"",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "自我測試失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已對 {name} 完成 CI 自我測試。")

    # --- 封存區：列出 ---
    def _run_archive_list(self):
        root = self.cfg["remote_root"]
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; A=\"$BASE/_archived\"",
            "if [ ! -d \"$A\" ]; then echo ___END___; exit 0; fi",
            "for e in \"$A\"/*; do",
            "  [ -e \"$e\" ] || continue",
            "  bn=$(basename \"$e\")",
            "  if [ -d \"$e\" ]; then t=dir; else t=file; fi",
            "  sz=$(du -sh \"$e\" 2>/dev/null | cut -f1)",
            "  printf 'ENTRY\\t%s\\t%s\\t%s\\n' \"$bn\" \"$t\" \"$sz\"",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取封存區失敗（連線或權限問題）。")
            return
        entries = []
        for ln in self._between(out).splitlines():
            p = ln.split("\t")
            if len(p) >= 4 and p[0] == "ENTRY":
                entries.append((p[1], p[2], p[3]))
        self.repos.emit(entries)
        self.done.emit(True, f"封存區有 {len(entries)} 個項目。")

    def _safe_arch(self, arch):
        return is_safe_name(arch)

    # --- 封存區：還原 ---
    def _run_archive_restore(self):
        root = self.cfg["remote_root"]
        arch = self.cfg.get("arch_name", "")
        if not self._safe_arch(arch):
            self.done.emit(False, f"名稱不安全：{arch!r}")
            return
        self.log.emit(f"--- 還原封存：{arch} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; A=\"$BASE/_archived\"; arch='{arch}'",
            "e=\"$A/$arch\"",
            "if [ ! -e \"$e\" ]; then echo NOTFOUND; echo ___END___; exit 0; fi",
            "if [ -d \"$e\" ]; then",
            "  orig=$(printf '%s' \"$arch\" | sed 's/\\.[0-9]\\{8\\}-[0-9]\\{6\\}$//')",
            "  tgt=\"$BASE/$orig\"",
            "  if [ -e \"$tgt\" ]; then echo \"TARGET_EXISTS $orig\"; echo ___END___; exit 0; fi",
            "  mv \"$e\" \"$tgt\" && echo \"RESTORED $orig\"",
            "else",
            "  case \"$arch\" in",
            "    *.tar.gz) tar -xzf \"$e\" -C \"$BASE\" && echo EXTRACTED ;;",
            "    *) echo UNKNOWN_FILE ;;",
            "  esac",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if rc == 0 and ("RESTORED" in body or "EXTRACTED" in body):
            self.done.emit(True, "已還原：" + body.replace("RESTORED", "→ ").replace("EXTRACTED", "（tarball 已解回）"))
        elif "TARGET_EXISTS" in body:
            self.done.emit(False, "還原失敗：目標倉庫已存在（同名衝突）。")
        elif "NOTFOUND" in body:
            self.done.emit(False, "找不到該封存項目。")
        else:
            self.done.emit(False, "還原失敗（權限或格式問題）。")

    # --- 封存區：永久刪除 ---
    def _run_archive_purge(self):
        root = self.cfg["remote_root"]
        arch = self.cfg.get("arch_name", "")
        if not self._safe_arch(arch):
            self.done.emit(False, f"名稱不安全：{arch!r}")
            return
        self.log.emit(f"--- 永久刪除封存：{arch} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; A=\"$BASE/_archived\"; arch='{arch}'",
            "e=\"$A/$arch\"",
            "if [ ! -e \"$e\" ]; then echo NOTFOUND; echo ___END___; exit 0; fi",
            "rm -rf \"$e\" && echo PURGED",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if rc == 0 and "PURGED" in body:
            self.done.emit(True, f"已永久刪除：{arch}")
        else:
            self.done.emit(False, "刪除失敗（權限問題？）。")

    # --- 完整串接 ---
    def _run_connect(self):
        c = self.cfg
        project_path = c["project_path"]
        repo_name = c["repo_name"]
        branch = c["branch"]
        user = c["user"]
        host = c["host"]
        root = c["remote_root"]

        if not repo_name.endswith(".git"):
            repo_name = repo_name + ".git"
        remote_repo_path = f"{root}/{repo_name}"
        remote_url = f"{user}@{host}:{remote_repo_path}"
        ssh_host = f"{user}@{host}"

        self.log.emit("=" * 52)
        self.log.emit(f"專案資料夾 : {project_path}")
        self.log.emit(f"NAS Repo   : {remote_repo_path}")
        self.log.emit(f"Remote URL : {remote_url}")
        self.log.emit(f"主分支     : {branch}")
        self.log.emit("=" * 52)

        # Step 0.5 檢查 git 身分
        rc, name_out, _ = self._run(["git", "config", "--global", "user.name"])
        rc2, email_out, _ = self._run(["git", "config", "--global", "user.email"])
        if not name_out.strip() or not email_out.strip():
            self.done.emit(
                False,
                "尚未設定 git 使用者身分，commit 會失敗。\n"
                "請先執行：\n"
                '  git config --global user.name "郭有庠"\n'
                '  git config --global user.email "kuoterry@kcc3713.synology.me"',
            )
            return
        self.log.emit(f"ℹ git 身分：{name_out} <{email_out}>")

        # Step 1 NAS 建庫
        self.log.emit("--- 步驟 1：在 NAS 建立裸倉庫 ---")
        rc, out, _ = self._ssh(f"[ -d '{remote_repo_path}' ] && echo YES || echo NO")
        if rc != 0:
            self.done.emit(False, "無法連線 NAS（SSH 驗證或連線問題）。\n"
                                  "請確認已設 SSH 金鑰，或填密碼並安裝 PuTTY(plink)。在家可改用內網 IP。")
            return

        if "YES" in out:
            self.log.emit(f"[INFO] NAS repo 已存在，跳過建立：{remote_repo_path}")
        else:
            rc, _, _ = self._ssh(f"git init --bare '{remote_repo_path}'")
            if rc != 0:
                self.done.emit(False, "NAS repo 建立失敗（git init --bare）。")
                return
            # 權限：sudo -n（免密碼）盡力而為，失敗不中斷
            perm_cmd = (
                f"sudo -n chown -R {user}:git_devs '{remote_repo_path}' 2>/dev/null && "
                f"sudo -n chmod g+s '{remote_repo_path}' 2>/dev/null && "
                f"sudo -n chmod -R g+rwX '{remote_repo_path}' 2>/dev/null"
            )
            rc, _, _ = self._ssh(perm_cmd)
            if rc == 0:
                self.log.emit(f"[OK] 已建立並設定權限：{remote_repo_path}")
            else:
                self.log.emit("⚠️ NAS repo 已建立，但權限需手動補完（sudo 未設 NOPASSWD）。")
                self.log.emit("   請另開視窗執行（會問 NAS 密碼）：")
                self.log.emit(
                    f'   ssh {ssh_host} "sudo chown -R {user}:git_devs '
                    f"'{remote_repo_path}'; sudo chmod g+s '{remote_repo_path}'; "
                    f"sudo chmod -R g+rwX '{remote_repo_path}'\""
                )

        # 安裝 hook（盡力而為）
        self.log.emit("👉 安裝 Git hook...")
        hook_cmd = (
            f"if [ -f {root}/install_and_monitor_git_hooks.sh ]; then "
            f"{root}/install_and_monitor_git_hooks.sh {repo_name}; "
            f"else echo '[WARN] 找不到 install_and_monitor_git_hooks.sh，略過'; fi"
        )
        self._ssh(hook_cmd)

        # Step 2 本地就地配置
        self.log.emit("--- 步驟 2：本地就地配置 ---")

        # 2-1 init
        if not is_git_repo(project_path):
            rc, _, _ = self._run(["git", "init"], cwd=project_path)
            self.log.emit("✔ 已 git init")
        else:
            self.log.emit("ℹ 已是 Git repo，跳過 init")

        # 2-2 .gitignore
        gi_path = os.path.join(project_path, ".gitignore")
        if not os.path.exists(gi_path):
            try:
                with open(gi_path, "w", encoding="utf-8") as f:
                    f.write(GITIGNORE_TEXT)
                self.log.emit("✔ 已建立通用 .gitignore")
            except OSError as e:
                self.log.emit(f"⚠️ 寫入 .gitignore 失敗：{e}")
        else:
            self.log.emit("ℹ .gitignore 已存在，保留原檔")

        # 2-3 remote origin
        rc, remotes, _ = self._run(["git", "remote"], cwd=project_path)
        if "origin" in remotes.split():
            self._run(["git", "remote", "set-url", "origin", remote_url], cwd=project_path)
            self.log.emit(f"✔ 已更新 origin -> {remote_url}")
        else:
            self._run(["git", "remote", "add", "origin", remote_url], cwd=project_path)
            self.log.emit(f"✔ 已新增 origin -> {remote_url}")

        # 2-4 是否已有 commit
        rc, _, _ = self._run(["git", "rev-parse", "--verify", "HEAD"], cwd=project_path)
        has_head = (rc == 0)

        if not has_head:
            nested = find_nested_repos(project_path)
            if nested:
                self.log.emit("⚠️ 以下子資料夾本身是 git repo，將被記成 gitlink 指標（非實際內容）：")
                for n in nested:
                    self.log.emit(f"      └─ {n}")
            self._run(["git", "add", "."], cwd=project_path)
            self._run(["git", "commit", "-m", "chore: initial project setup"], cwd=project_path)
            rc, _, _ = self._run(["git", "rev-parse", "--verify", "HEAD"], cwd=project_path)
            if rc != 0:
                self.done.emit(False, "首次 commit 沒有成功產生（多半是 git 身分未設）。")
                return
            self.log.emit("✔ 已建立首次 commit (chore: initial project setup)")
        else:
            self.log.emit("ℹ 已有 commit 歷史，跳過首次 commit")
            self._run(["git", "add", ".gitignore"], cwd=project_path)
            rc, _, _ = self._run(["git", "diff", "--cached", "--quiet"], cwd=project_path)
            if rc != 0:
                self._run(["git", "commit", "-m", "chore: add .gitignore"], cwd=project_path)
                self.log.emit("✔ 已提交新增的 .gitignore")

        # 2-5 分支
        self._run(["git", "branch", "-M", branch], cwd=project_path)
        rc, cur, _ = self._run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=project_path)
        if cur.strip() != branch:
            self.done.emit(False, f"分支設定異常（目前 '{cur}'，預期 '{branch}'）。")
            return
        self.log.emit(f"✔ 主分支已設為 {branch}")

        # 2-6 push（有密碼時透過 plink 當 GIT_SSH_COMMAND）
        self.log.emit(f"👉 推送到 NAS ({branch})...")
        rc, _, _ = self._run(
            ["git", "push", "-u", "origin", branch],
            cwd=project_path, env=self._git_env()
        )
        if rc != 0:
            self.done.emit(
                False,
                "推送失敗。請檢查 SSH 驗證與 NAS repo 權限。\n"
                "若 NAS 權限剛才未補完，補完後可重跑（或手動 git push -u origin " + branch + "）。",
            )
            return

        # 2-7 NAS HEAD 指向本分支
        rc, _, _ = self._ssh(
            f"git --git-dir='{remote_repo_path}' symbolic-ref HEAD refs/heads/{branch}"
        )
        if rc == 0:
            self.log.emit(f"✔ 已將 NAS 預設分支(HEAD)指向 {branch}")

        self.done.emit(True, f"完成！專案已就地接上 NAS。\nNAS 倉庫：{remote_repo_path}")


# ============================================================
# 安全下庄 / 刪除確認對話框
# 需打字輸入倉庫名稱才能執行；預設走「可還原」的封存模式。
# ============================================================
class DeleteRepoDialog(QDialog):
    def __init__(self, parent, repo_name, full_path):
        super().__init__(parent)
        self.setWindowTitle("安全下庄 / 刪除倉庫")
        self.repo_name = repo_name
        self.setMinimumWidth(480)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"倉庫：{repo_name}"))
        p = QLabel(f"NAS 路徑：{full_path}")
        p.setWordWrap(True)
        lay.addWidget(p)
        warn = QLabel("此操作會動到 NAS 上的倉庫，請謹慎確認。")
        warn.setStyleSheet("color:#b06f00;")
        lay.addWidget(warn)

        gb = QGroupBox("處理方式")
        gl = QVBoxLayout(gb)
        self.rb_archive = QRadioButton("安全下庄：搬到封存區 _archived/（可還原，推薦）")
        self.rb_backup = QRadioButton("打包備份後刪除：先產生 .tar.gz 再刪除")
        self.rb_hard = QRadioButton("直接刪除：rm -rf（不可還原）")
        self.rb_archive.setChecked(True)
        gl.addWidget(self.rb_archive)
        gl.addWidget(self.rb_backup)
        gl.addWidget(self.rb_hard)
        lay.addWidget(gb)

        lay.addWidget(QLabel(f"請輸入倉庫名稱「{repo_name}」以確認："))
        self.confirm_edit = QLineEdit()
        self.confirm_edit.textChanged.connect(self._update_ok)
        lay.addWidget(self.confirm_edit)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.ok_btn = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_btn.setText("執行")
        self.ok_btn.setEnabled(False)
        lay.addWidget(self.buttons)

    def _update_ok(self, text):
        self.ok_btn.setEnabled(text.strip() == self.repo_name)

    def delete_mode(self):
        if self.rb_backup.isChecked():
            return "backup_delete"
        if self.rb_hard.isChecked():
            return "hard_delete"
        return "archive"


# ============================================================
# 通用文字檢視對話框（用於顯示 CI hook 內容）
# ============================================================
class TextViewDialog(QDialog):
    def __init__(self, parent, title, text):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(720, 560)
        self._text = text

        lay = QVBoxLayout(self)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(QFont("Consolas", 10))
        view.setPlainText(text)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(view, stretch=1)

        row = QHBoxLayout()
        copy_btn = QPushButton("複製全部")
        copy_btn.clicked.connect(self._copy)
        close_btn = QPushButton("關閉")
        close_btn.clicked.connect(self.accept)
        row.addWidget(copy_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        lay.addLayout(row)

    def _copy(self):
        QApplication.clipboard().setText(self._text)


# ============================================================
# 設定 CI 對話框（每個 repo 獨立）
# ============================================================
class SetCiDialog(QDialog):
    def __init__(self, parent, repo_name, current="", batch_count=0):
        super().__init__(parent)
        self.setWindowTitle("設定 CI" + (f" — {repo_name}" if not batch_count else "（批次）"))
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        if batch_count:
            lay.addWidget(QLabel(f"將對選取的 {batch_count} 個倉庫一次套用同一 CI 規則。"))
        else:
            lay.addWidget(QLabel(f"倉庫：{repo_name}"))
        hint = QLabel("選這個 repo 要套用的 CI 規則（可隨時改）。")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#666;")
        lay.addWidget(hint)

        gb = QGroupBox("CI 規則")
        gl = QVBoxLayout(gb)
        self.rb_none = QRadioButton("停用：不檢查（POLICY=none）")
        self.rb_soft = QRadioButton("soft：違規只發 Telegram 警告，不擋 push")
        self.rb_strict = QRadioButton("strict：違規直接擋下 push")
        # 預選：批次時預設 soft；單庫時預選目前值
        cur = (current or "").strip()
        if cur == "strict":
            self.rb_strict.setChecked(True)
        elif cur == "none":
            self.rb_none.setChecked(True)
        else:
            self.rb_soft.setChecked(True)
        gl.addWidget(self.rb_none)
        gl.addWidget(self.rb_soft)
        gl.addWidget(self.rb_strict)
        lay.addWidget(gb)

        if current and not batch_count:
            curlbl = QLabel(f"目前設定：{cur or 'none'}")
            curlbl.setStyleSheet("color:#1a7f37;")
            lay.addWidget(curlbl)

        rule = QLabel("檢查內容：分支須為 develop / feature/* / release/*；"
                      "commit 須以 feat:/fix:/chore:/docs: 開頭，或含 [JIRA|TASK-數字]。")
        rule.setWordWrap(True)
        rule.setStyleSheet("color:#666;")
        lay.addWidget(rule)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("套用")
        lay.addWidget(bb)

    def policy(self):
        if self.rb_none.isChecked():
            return "none"
        if self.rb_strict.isChecked():
            return "strict"
        return "soft"


# ============================================================
# 在 NAS 新建空倉庫 對話框
# ============================================================
class CreateRepoDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("在 NAS 新建空倉庫")
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        g = QGridLayout()
        g.addWidget(QLabel("倉庫名稱："), 0, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如 MyProject（會自動補 .git，建議純英數 - _）")
        g.addWidget(self.name_edit, 0, 1)
        g.addWidget(QLabel("預設分支："), 1, 0)
        self.branch_edit = QLineEdit("develop")
        g.addWidget(self.branch_edit, 1, 1)
        lay.addLayout(g)

        gb = QGroupBox("CI 規則（可日後再改）")
        gl = QVBoxLayout(gb)
        self.rb_none = QRadioButton("停用（none）")
        self.rb_soft = QRadioButton("soft（只警告）")
        self.rb_strict = QRadioButton("strict（擋 push）")
        self.rb_none.setChecked(True)
        gl.addWidget(self.rb_none)
        gl.addWidget(self.rb_soft)
        gl.addWidget(self.rb_strict)
        lay.addWidget(gb)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("建立")
        lay.addWidget(bb)

    def _ok(self):
        if not self.name_edit.text().strip():
            QMessageBox.information(self, "缺名稱", "請輸入倉庫名稱。")
            return
        self.accept()

    def values(self):
        pol = "strict" if self.rb_strict.isChecked() else ("soft" if self.rb_soft.isChecked() else "none")
        return (self.name_edit.text().strip(),
                self.branch_edit.text().strip() or "develop", pol)


# ============================================================
# 封存區 _archived/ 管理 對話框
# ============================================================
class ArchiveDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.worker = None
        self.setWindowTitle("封存區 _archived/ 管理")
        self.resize(580, 440)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("「安全下庄」搬走或打包的倉庫放這裡，可還原或永久刪除。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.restore_b = QPushButton("還原")
        self.purge_b = QPushButton("永久刪除…")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.restore_b)
        row.addWidget(self.purge_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.restore_b.clicked.connect(self.on_restore)
        self.purge_b.clicked.connect(self.on_purge)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.restore_b, self.purge_b):
            x.setEnabled(not b)

    def _sel(self):
        it = self.list.selectedItems()
        return it[0].data(Qt.ItemDataRole.UserRole) if it else ""

    def _start(self, mode, extra=None):
        cfg = dict(self.cfg)
        if extra:
            cfg.update(extra)
        self._busy(True)
        self.status.setText("處理中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode=mode)
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def refresh(self):
        self.list.clear()
        self._start("archive_list")

    def on_entries(self, entries):
        self.list.clear()
        for name, typ, size in entries:
            kind = "tarball" if typ == "file" else "目錄"
            it = QListWidgetItem(f"{name}    [{kind}, {size}]")
            it.setData(Qt.ItemDataRole.UserRole, name)
            self.list.addItem(it)

    def on_restore(self):
        n = self._sel()
        if not n:
            self.status.setText("請先選一個項目。")
            return
        self._start("archive_restore", {"arch_name": n})

    def on_purge(self):
        n = self._sel()
        if not n:
            self.status.setText("請先選一個項目。")
            return
        r = QMessageBox.question(self, "永久刪除",
                                 f"確定永久刪除？此動作無法復原：\n{n}")
        if r != QMessageBox.StandardButton.Yes:
            return
        self._start("archive_purge", {"arch_name": n})

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok and self.worker and self.worker.mode in ("archive_restore", "archive_purge"):
            self.refresh()


# ============================================================
# 主視窗
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NAS Git 專案串接工具")
        self.resize(760, 640)
        self.settings = QSettings("TerryTools", "NasGitConnector")
        self._seed_default_profiles()
        self.worker = None

        self._all_repos = []  # 瀏覽分頁：完整倉庫清單（供篩選用）

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # ================= 共用：身份 / NAS 設定 =================
        nb = QGroupBox("身份 / NAS 設定（會依本機電腦名稱自動選身份；兩個分頁共用）")
        ng = QGridLayout(nb)

        ng.addWidget(QLabel("身份："), 0, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(self._profile_names())
        ng.addWidget(self.profile_combo, 0, 1)
        save_prof_btn = QPushButton("儲存此身份")
        add_prof_btn = QPushButton("新增")
        del_prof_btn = QPushButton("刪除")
        ng.addWidget(save_prof_btn, 0, 2)
        ng.addWidget(add_prof_btn, 0, 3)
        ng.addWidget(del_prof_btn, 0, 4)

        self.machine_label = QLabel("")
        self.machine_label.setWordWrap(True)
        ng.addWidget(self.machine_label, 1, 0, 1, 4)
        bind_btn = QPushButton("綁定此電腦")
        bind_btn.setToolTip("把目前這台電腦的名稱綁到上面選的身份；下次開啟會自動選它。")
        ng.addWidget(bind_btn, 1, 4)

        ng.addWidget(QLabel("SSH 使用者："), 2, 0)
        self.user_edit = QLineEdit()
        ng.addWidget(self.user_edit, 2, 1, 1, 4)

        ng.addWidget(QLabel("NAS 主機："), 3, 0)
        self.host_combo = QComboBox()
        self.host_combo.setEditable(True)
        self.host_combo.addItems(["kcc3713.synology.me", "192.168.1.101"])
        ng.addWidget(self.host_combo, 3, 1, 1, 4)

        ng.addWidget(QLabel("Git_Server 根："), 4, 0)
        self.root_edit = QLineEdit()
        ng.addWidget(self.root_edit, 4, 1, 1, 4)

        # SSH 密碼（選填）：留空 = 用金鑰免密碼；有填 = 用 PuTTY 的 plink -pw
        ng.addWidget(QLabel("SSH 密碼："), 5, 0)
        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setPlaceholderText("留空＝用 SSH 金鑰（推薦）；有填＝需安裝 PuTTY(plink)")
        ng.addWidget(self.pw_edit, 5, 1, 1, 3)
        self.show_pw_check = QCheckBox("顯示")
        self.show_pw_check.stateChanged.connect(self.toggle_pw_echo)
        ng.addWidget(self.show_pw_check, 5, 4)

        self.remember_pw_check = QCheckBox(
            "記住此身份的密碼（明碼存於本機登錄檔，較不安全；建議改用 SSH 金鑰）"
        )
        ng.addWidget(self.remember_pw_check, 6, 0, 1, 5)

        root.addWidget(nb)

        save_prof_btn.clicked.connect(self.save_current_profile)
        add_prof_btn.clicked.connect(self.add_profile)
        del_prof_btn.clicked.connect(self.delete_profile)
        bind_btn.clicked.connect(self.bind_current_machine)
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)

        # ================= 分頁 =================
        tabs = QTabWidget()
        root.addWidget(tabs, stretch=1)

        # ---------- 分頁 1：串接專案 ----------
        connect_page = QWidget()
        cp = QVBoxLayout(connect_page)

        proj_box = QGroupBox("專案資料夾（用瀏覽挑『單一專案』，不要挑 D:\\git 大庫）")
        proj_layout = QHBoxLayout(proj_box)
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("按右邊「瀏覽…」選擇專案資料夾")
        browse_btn = QPushButton("瀏覽…")
        browse_btn.clicked.connect(self.on_browse)
        proj_layout.addWidget(self.path_edit)
        proj_layout.addWidget(browse_btn)
        cp.addWidget(proj_box)

        self.status_label = QLabel("尚未選擇專案資料夾。")
        self.status_label.setWordWrap(True)
        cp.addWidget(self.status_label)

        self.ack_check = QCheckBox("我了解風險：底下的子專案會被記成 gitlink 指標，仍要繼續")
        self.ack_check.setVisible(False)
        self.ack_check.stateChanged.connect(self.update_run_enabled)
        cp.addWidget(self.ack_check)

        rb = QGroupBox("倉庫設定")
        grid = QGridLayout(rb)
        grid.addWidget(QLabel("Repo 名稱："), 0, 0)
        self.repo_edit = QLineEdit()
        self.repo_edit.setPlaceholderText("預設用資料夾名稱（可改，建議純英數 - _）")
        grid.addWidget(self.repo_edit, 0, 1)
        grid.addWidget(QLabel("主分支："), 0, 2)
        self.branch_edit = QLineEdit(self.settings.value("branch", "develop"))
        grid.addWidget(self.branch_edit, 0, 3)
        cp.addWidget(rb)

        btn_row = QHBoxLayout()
        self.test_btn = QPushButton("測試 NAS 連線")
        self.test_btn.clicked.connect(self.on_test)
        self.run_btn = QPushButton("開始串接")
        self.run_btn.setEnabled(False)
        self.run_btn.clicked.connect(self.on_run)
        btn_row.addWidget(self.test_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(self.run_btn)
        cp.addLayout(btn_row)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        cp.addWidget(self.log_view, stretch=1)

        tabs.addTab(connect_page, "串接專案")

        # ---------- 分頁 2：瀏覽倉庫 / Clone URL ----------
        browse_page = QWidget()
        bp = QVBoxLayout(browse_page)

        top_row = QHBoxLayout()
        self.refresh_btn = QPushButton("重新整理（列出 NAS 倉庫）")
        self.refresh_btn.clicked.connect(self.on_refresh)
        self.ci_status_btn = QPushButton("CI 狀態總表…")
        self.ci_status_btn.setToolTip("列出所有倉庫的 policy / MODE / 是否啟用 CI。")
        self.ci_status_btn.clicked.connect(self.on_ci_status)
        self.upgrade_btn = QPushButton("升級 CI 引擎…")
        self.upgrade_btn.setToolTip("把 NAS 上的 pre-receive.ci 換成自載入 policy 版本（自動備份），讓每 repo 的 CI 設定真正生效。")
        self.upgrade_btn.clicked.connect(self.on_upgrade_engine)
        self.create_btn = QPushButton("新建空倉庫…")
        self.create_btn.setToolTip("直接在 NAS 建立 bare repo（含 hook 與權限），不需先有本地資料夾。")
        self.create_btn.clicked.connect(self.on_create_repo)
        self.archive_btn = QPushButton("封存區…")
        self.archive_btn.setToolTip("管理『安全下庄』搬走或打包的倉庫：還原或永久刪除。")
        self.archive_btn.clicked.connect(self.on_archive)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("輸入關鍵字即時篩選…")
        self.filter_edit.textChanged.connect(self.apply_repo_filter)
        top_row.addWidget(self.refresh_btn)
        top_row.addWidget(self.ci_status_btn)
        top_row.addWidget(self.upgrade_btn)
        top_row.addWidget(self.create_btn)
        top_row.addWidget(self.archive_btn)
        top_row.addWidget(self.filter_edit, stretch=1)
        bp.addLayout(top_row)

        self.repo_list = QListWidget()
        self.repo_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.repo_list.itemSelectionChanged.connect(self.on_repo_selected)
        bp.addWidget(self.repo_list, stretch=1)

        # 動作列
        danger_row = QHBoxLayout()
        self.ci_btn = QPushButton("檢視此庫 CI 規則…")
        self.ci_btn.setEnabled(False)
        self.ci_btn.setToolTip("讀齊此倉庫的 policy + profile.conf + stub + CI 引擎，組成完整報告。")
        self.ci_btn.clicked.connect(self.on_view_ci)
        danger_row.addWidget(self.ci_btn)
        self.set_ci_btn = QPushButton("設定 CI…")
        self.set_ci_btn.setEnabled(False)
        self.set_ci_btn.setToolTip("為此倉庫獨立設定 CI：停用 / soft / strict。")
        self.set_ci_btn.clicked.connect(self.on_set_ci)
        danger_row.addWidget(self.set_ci_btn)
        self.selftest_btn = QPushButton("CI 自測…")
        self.selftest_btn.setEnabled(False)
        self.selftest_btn.setToolTip("不用 push，用假 push 跑引擎驗證此庫 CI 行為（strict/soft 會發一則 Telegram）。")
        self.selftest_btn.clicked.connect(self.on_ci_selftest)
        danger_row.addWidget(self.selftest_btn)
        self.detail_btn = QPushButton("明細…")
        self.detail_btn.setEnabled(False)
        self.detail_btn.setToolTip("看此庫的分支、各分支最後 commit、大小、標籤數。")
        self.detail_btn.clicked.connect(self.on_repo_detail)
        danger_row.addWidget(self.detail_btn)
        self.batch_ci_btn = QPushButton("批次設定 CI…")
        self.batch_ci_btn.setEnabled(False)
        self.batch_ci_btn.setToolTip("對『目前選取的多個』倉庫一次套用同一 CI 規則（可按住 Ctrl/Shift 多選）。")
        self.batch_ci_btn.clicked.connect(self.on_set_ci_batch)
        danger_row.addWidget(self.batch_ci_btn)
        danger_row.addStretch(1)
        self.delete_btn = QPushButton("安全下庄 / 刪除此倉庫…")
        self.delete_btn.setEnabled(False)
        self.delete_btn.setToolTip("先在清單選一個倉庫。預設會搬到封存區(可還原)。")
        self.delete_btn.clicked.connect(self.on_delete_repo)
        danger_row.addWidget(self.delete_btn)
        bp.addLayout(danger_row)

        url_box = QGroupBox("Clone URL（點上面的倉庫即產生）")
        ug = QGridLayout(url_box)
        ug.addWidget(QLabel("URL："), 0, 0)
        self.clone_edit = QLineEdit()
        self.clone_edit.setReadOnly(True)
        self.clone_edit.setPlaceholderText("在上方清單選一個倉庫")
        ug.addWidget(self.clone_edit, 0, 1)
        copy_url_btn = QPushButton("複製 URL")
        copy_url_btn.clicked.connect(self.copy_clone_url)
        ug.addWidget(copy_url_btn, 0, 2)
        copy_cmd_btn = QPushButton("複製 git clone 指令")
        copy_cmd_btn.clicked.connect(self.copy_clone_cmd)
        ug.addWidget(copy_cmd_btn, 1, 1)
        self.clone_btn = QPushButton("Clone 到本地…")
        self.clone_btn.setEnabled(False)
        self.clone_btn.setToolTip("把選取的倉庫從 NAS clone 到你指定的本地資料夾（走目前身份的金鑰/plink）。")
        self.clone_btn.clicked.connect(self.on_clone)
        ug.addWidget(self.clone_btn, 1, 2)
        bp.addWidget(url_box)

        self.browse_status = QLabel("按「重新整理」以列出 NAS 上 Git_Server 的倉庫。")
        self.browse_status.setWordWrap(True)
        bp.addWidget(self.browse_status)

        tabs.addTab(browse_page, "瀏覽倉庫 / Clone URL")

        # ---------- 分頁 3：維運 / 日誌 ----------
        maint_page = QWidget()
        mp = QVBoxLayout(maint_page)

        ops_box = QGroupBox("Git Server 維運")
        og = QGridLayout(ops_box)
        self.hc_btn = QPushButton("健康檢查")
        self.hc_btn.setToolTip("唯讀檢查：模板/引擎、各 repo 的 hook 與 git_devs 群組、logs 目錄。")
        self.hc_btn.clicked.connect(self.on_healthcheck)
        self.repair_btn = QPushButton("一鍵修復…")
        self.repair_btn.setToolTip("對所有 repo 套用 template hook（pre/post-receive）並修正 git_devs 群組與權限。")
        self.repair_btn.clicked.connect(self.on_repair)
        og.addWidget(self.hc_btn, 0, 0)
        og.addWidget(self.repair_btn, 0, 1)
        mp.addWidget(ops_box)

        log_box = QGroupBox("日誌檢視（最後 200 筆）")
        lg = QGridLayout(log_box)
        self.push_log_btn = QPushButton("推送日誌 git_push.log")
        self.push_log_btn.clicked.connect(lambda: self.on_view_log("git_push.log", "推送日誌"))
        self.viol_log_btn = QPushButton("CI 違規日誌 ci_violation.log")
        self.viol_log_btn.clicked.connect(lambda: self.on_view_log("ci_violation.log", "CI 違規日誌"))
        self.dbg_log_btn = QPushButton("post-receive 除錯日誌")
        self.dbg_log_btn.clicked.connect(lambda: self.on_view_log("post_receive_debug.log", "post-receive 除錯日誌"))
        lg.addWidget(self.push_log_btn, 0, 0)
        lg.addWidget(self.viol_log_btn, 0, 1)
        lg.addWidget(self.dbg_log_btn, 0, 2)
        mp.addWidget(log_box)

        self.maint_status = QLabel("維運動作都會走目前選定的身份（金鑰/plink）。")
        self.maint_status.setWordWrap(True)
        mp.addWidget(self.maint_status)
        mp.addStretch(1)

        tabs.addTab(maint_page, "維運 / 日誌")

        # ---- 開啟時自動選身份：本機綁定優先，其次上次使用 ----
        auto = self.detect_profile_for_machine()
        last = self.settings.value("last_profile", "")
        if auto:
            self.profile_combo.setCurrentText(auto)
        elif last in self._profile_names():
            self.profile_combo.setCurrentText(last)
        self.load_profile_into_fields(self.profile_combo.currentText())
        self.update_machine_label()

    # --- 選資料夾 ---
    def on_browse(self):
        start = self.settings.value("last_dir", "")
        d = QFileDialog.getExistingDirectory(self, "選擇專案資料夾", start)
        if not d:
            return
        d = os.path.abspath(d)
        self.path_edit.setText(d)
        self.settings.setValue("last_dir", os.path.dirname(d))
        # 自動帶入 repo 名 = 資料夾名
        self.repo_edit.setText(os.path.basename(d))
        self.precheck(d)

    # --- 本地預檢（即時、不連網）---
    def precheck(self, path: str):
        self.ack_check.setVisible(False)
        self.ack_check.setChecked(False)

        if is_container_root(path):
            self.status_label.setText(
                "❌ 這是『大庫容器 / 磁碟根目錄』，不能當單一專案串接。\n"
                "請往下挑一個實際的專案資料夾。"
            )
            self.status_label.setStyleSheet("color:#b00020;")
            self.run_btn.setEnabled(False)
            return

        nested = find_nested_repos(path)
        already = is_git_repo(path)

        lines = []
        lines.append("✔ 已 git 初始化過（會沿用歷史）" if already else "✔ 尚未 git 初始化（會做首次 commit）")

        if nested and not already:
            lines.append(f"⚠️ 偵測到 {len(nested)} 個子資料夾本身是 git repo：{'、'.join(nested)}")
            lines.append("   這通常代表選到了工作區頂層。若非本意，請改挑單一專案。")
            self.ack_check.setVisible(True)
            self.status_label.setStyleSheet("color:#b06f00;")
        else:
            self.status_label.setStyleSheet("color:#1a7f37;")

        self.status_label.setText("\n".join(lines))
        self.update_run_enabled()

    def update_run_enabled(self):
        path = self.path_edit.text().strip()
        if not path or is_container_root(path):
            self.run_btn.setEnabled(False)
            return
        if self.ack_check.isVisible() and not self.ack_check.isChecked():
            self.run_btn.setEnabled(False)
            return
        self.run_btn.setEnabled(True)

    # ---------- 身份(Profile) ----------
    def _profile_names(self):
        names = self.settings.value("profile_names", [])
        if isinstance(names, str):
            names = [names]
        return list(names) if names else []

    def _seed_default_profiles(self):
        if not self._profile_names():
            for name, vals in DEFAULT_PROFILES.items():
                self._write_profile(name, vals)
            self.settings.setValue("profile_names", list(DEFAULT_PROFILES.keys()))

    def _write_profile(self, name, vals):
        self.settings.setValue(f"profiles/{name}/user", vals.get("user", ""))
        self.settings.setValue(f"profiles/{name}/host", vals.get("host", ""))
        self.settings.setValue(f"profiles/{name}/remote_root", vals.get("remote_root", ""))

    def _read_profile(self, name):
        return {
            "user": self.settings.value(f"profiles/{name}/user", "kuoterry"),
            "host": self.settings.value(f"profiles/{name}/host", "kcc3713.synology.me"),
            "remote_root": self.settings.value(f"profiles/{name}/remote_root", "/volume1/Git_Server"),
        }

    def load_profile_into_fields(self, name):
        if not name:
            return
        vals = self._read_profile(name)
        self.user_edit.setText(vals["user"])
        self.host_combo.setCurrentText(vals["host"])
        self.root_edit.setText(vals["remote_root"])
        # 密碼：只有之前勾了「記住」才會有存；沒有就留空
        saved_pw = self.settings.value(f"profiles/{name}/password", "")
        self.pw_edit.setText(saved_pw)
        self.remember_pw_check.setChecked(bool(saved_pw))

    def on_profile_changed(self, name):
        if not name:
            return
        self.load_profile_into_fields(name)
        self.settings.setValue("last_profile", name)

    def save_current_profile(self, silent=False):
        name = self.profile_combo.currentText()
        if not name:
            return
        self._write_profile(name, {
            "user": self.user_edit.text().strip(),
            "host": self.host_combo.currentText().strip(),
            "remote_root": self.root_edit.text().strip(),
        })
        # 密碼：勾了「記住」才寫入登錄檔；沒勾就把之前存的清掉
        if self.remember_pw_check.isChecked():
            self.settings.setValue(f"profiles/{name}/password", self.pw_edit.text())
        else:
            self.settings.remove(f"profiles/{name}/password")
        if not silent:
            QMessageBox.information(self, "已儲存", f"身份「{name}」的設定已記住。")

    def add_profile(self):
        name, ok = QInputDialog.getText(self, "新增身份", "身份名稱（例如：公司筆電）：")
        name = (name or "").strip()
        if not ok or not name:
            return
        names = self._profile_names()
        if name in names:
            QMessageBox.information(self, "已存在", "同名身份已存在。")
            return
        self._write_profile(name, {
            "user": self.user_edit.text().strip() or "kuoterry",
            "host": self.host_combo.currentText().strip() or "kcc3713.synology.me",
            "remote_root": self.root_edit.text().strip() or "/volume1/Git_Server",
        })
        names.append(name)
        self.settings.setValue("profile_names", names)
        self.profile_combo.addItem(name)
        self.profile_combo.setCurrentText(name)

    def delete_profile(self):
        names = self._profile_names()
        if len(names) <= 1:
            QMessageBox.information(self, "無法刪除", "至少要保留一個身份。")
            return
        name = self.profile_combo.currentText()
        r = QMessageBox.question(self, "刪除身份", f"確定刪除身份「{name}」？")
        if r != QMessageBox.StandardButton.Yes:
            return
        self.settings.remove(f"profiles/{name}")
        names.remove(name)
        self.settings.setValue("profile_names", names)
        idx = self.profile_combo.currentIndex()
        self.profile_combo.removeItem(idx)

    # ---------- 本機辨識（自動選身份）----------
    def current_machine_id(self) -> str:
        """本機識別：以電腦名稱(hostname)為準。"""
        name = ""
        try:
            name = socket.gethostname()
        except Exception:
            pass
        if not name:
            name = platform.node()
        return (name or "UNKNOWN").strip()

    def _profile_machines(self, name):
        m = self.settings.value(f"profiles/{name}/machines", [])
        if isinstance(m, str):
            m = [m] if m else []
        return list(m) if m else []

    def _set_profile_machines(self, name, machines):
        self.settings.setValue(f"profiles/{name}/machines", machines)

    def detect_profile_for_machine(self):
        """看本機電腦名稱綁在哪個身份；找不到回 None。"""
        mid = self.current_machine_id().lower()
        for name in self._profile_names():
            for m in self._profile_machines(name):
                if m.strip().lower() == mid:
                    return name
        return None

    def update_machine_label(self):
        mid = self.current_machine_id()
        auto = self.detect_profile_for_machine()
        if auto:
            self.machine_label.setText(f"本機電腦名稱：{mid} → 自動對應身份「{auto}」")
            self.machine_label.setStyleSheet("color:#1a7f37;")
        else:
            self.machine_label.setText(
                f"本機電腦名稱：{mid}（尚未綁定；請選好上面的身份後按「綁定此電腦」）"
            )
            self.machine_label.setStyleSheet("color:#b06f00;")

    def bind_current_machine(self):
        name = self.profile_combo.currentText()
        if not name:
            return
        mid = self.current_machine_id()
        # 一台電腦只綁一個身份：先從其他身份移除這台，再綁到目前身份
        for other in self._profile_names():
            ms = self._profile_machines(other)
            ms2 = [x for x in ms if x.strip().lower() != mid.lower()]
            if ms2 != ms:
                self._set_profile_machines(other, ms2)
        ms = self._profile_machines(name)
        if mid.lower() not in [x.lower() for x in ms]:
            ms.append(mid)
        self._set_profile_machines(name, ms)
        self.update_machine_label()
        QMessageBox.information(
            self, "已綁定",
            f"這台電腦「{mid}」已綁定到身份「{name}」。\n下次開啟會自動選這個身份。"
        )

    # --- 收集設定 ---
    def collect_cfg(self) -> dict:
        return {
            "project_path": self.path_edit.text().strip(),
            "repo_name": self.repo_edit.text().strip() or os.path.basename(self.path_edit.text().strip()),
            "branch": self.branch_edit.text().strip() or "develop",
            "user": self.user_edit.text().strip() or "kuoterry",
            "host": self.host_combo.currentText().strip() or "kcc3713.synology.me",
            "remote_root": self.root_edit.text().strip() or "/volume1/Git_Server",
            "password": self.pw_edit.text(),
        }

    def save_settings(self, cfg):
        # branch 為全域預設；user/host/remote_root 存回「當前身份」
        self.settings.setValue("branch", cfg["branch"])
        self.save_current_profile(silent=True)

    def collect_identity_cfg(self) -> dict:
        """只取身份/NAS 欄位（供測試連線、列出倉庫用）。"""
        return {
            "user": self.user_edit.text().strip() or "kuoterry",
            "host": self.host_combo.currentText().strip() or "kcc3713.synology.me",
            "remote_root": self.root_edit.text().strip() or "/volume1/Git_Server",
            "password": self.pw_edit.text(),
        }

    def toggle_pw_echo(self):
        mode = (QLineEdit.EchoMode.Normal if self.show_pw_check.isChecked()
                else QLineEdit.EchoMode.Password)
        self.pw_edit.setEchoMode(mode)

    def append_log(self, text: str):
        self.log_view.appendPlainText(text)

    def set_busy(self, busy: bool):
        self.run_btn.setEnabled(not busy)
        self.test_btn.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self.ci_status_btn.setEnabled(not busy)
        self.upgrade_btn.setEnabled(not busy)
        self.create_btn.setEnabled(not busy)
        self.archive_btn.setEnabled(not busy)
        for b in (self.hc_btn, self.repair_btn, self.push_log_btn,
                  self.viol_log_btn, self.dbg_log_btn):
            b.setEnabled(not busy)
        has_sel = len(self.repo_list.selectedItems()) > 0
        self.delete_btn.setEnabled(not busy and has_sel)
        self.ci_btn.setEnabled(not busy and has_sel)
        self.set_ci_btn.setEnabled(not busy and has_sel)
        self.selftest_btn.setEnabled(not busy and has_sel)
        self.detail_btn.setEnabled(not busy and has_sel)
        self.batch_ci_btn.setEnabled(not busy and has_sel)
        self.clone_btn.setEnabled(not busy and has_sel)
        if busy:
            self.run_btn.setText("執行中…")
        else:
            self.run_btn.setText("開始串接")
            self.update_run_enabled()

    # --- 測試連線 ---
    def on_test(self):
        cfg = self.collect_cfg()
        self.save_settings(cfg)
        self.log_view.clear()
        self.set_busy(True)
        self.worker = Worker(cfg, mode="test")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    # --- 開始串接 ---
    def on_run(self):
        cfg = self.collect_cfg()
        if is_container_root(cfg["project_path"]):
            QMessageBox.critical(self, "禁止", "這是大庫容器 / 磁碟根目錄，不能當專案串接。")
            return
        # 名稱含中文/特殊字元提醒
        bad = any(not (ch.isalnum() or ch in "-_.") for ch in cfg["repo_name"])
        if bad:
            r = QMessageBox.question(
                self, "確認 repo 名稱",
                f"repo 名稱「{cfg['repo_name']}」含中文/空白/特殊字元。\n建議純英數與 - _。仍要繼續嗎？",
            )
            if r != QMessageBox.StandardButton.Yes:
                return
        self.save_settings(cfg)
        self.log_view.clear()
        self.set_busy(True)
        self.worker = Worker(cfg, mode="connect")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_done(self, ok: bool, msg: str):
        self.set_busy(False)
        self.append_log("")
        self.append_log(("🎉 " if ok else "❌ ") + msg.replace("\n", " "))
        if ok:
            QMessageBox.information(self, "完成", msg)
        else:
            QMessageBox.warning(self, "未完成", msg)

    # ---------- 瀏覽倉庫 / Clone URL ----------
    def on_refresh(self):
        cfg = self.collect_identity_cfg()
        self.save_current_profile(silent=True)
        self.repo_list.clear()
        self._all_repos = []
        self.clone_edit.clear()
        self.browse_status.setText("連線 NAS 列出倉庫中…")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="list")
        self.worker.repos.connect(self.on_repos)
        self.worker.done.connect(self.on_list_done)
        self.worker.start()

    def on_repos(self, items: list):
        # items: list of (name, status, policy)；容錯舊格式
        norm = []
        for it in items:
            if isinstance(it, (list, tuple)):
                name = str(it[0])
                status = str(it[1]) if len(it) > 1 else ""
                pol = str(it[2]) if len(it) > 2 else "none"
                norm.append((name, status, pol))
            else:
                norm.append((str(it), "", "none"))
        self._all_repos = norm
        self.apply_repo_filter(self.filter_edit.text())

    def on_list_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText(msg + "　（可多選；點一個產生 Clone URL）")
            self.browse_status.setStyleSheet("color:#1a7f37;")
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", " "))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "列出失敗", msg)

    def apply_repo_filter(self, text: str):
        text = (text or "").strip().lower()
        self.repo_list.clear()
        for name, status, pol in self._all_repos:
            if text and text not in name.lower():
                continue
            ci = {"soft": "CI:soft", "strict": "CI:strict"}.get(pol, "CI:—")
            label = f"{name}    ·    {status}    ·    {ci}" if status else f"{name}    ·    {ci}"
            it = QListWidgetItem(label)
            it.setData(Qt.ItemDataRole.UserRole, name)
            it.setData(Qt.ItemDataRole.UserRole + 1, pol)
            if status.startswith("空庫"):
                it.setForeground(Qt.GlobalColor.gray)
            self.repo_list.addItem(it)

    def _selected_repo_name(self) -> str:
        items = self.repo_list.selectedItems()
        if not items:
            return ""
        return items[0].data(Qt.ItemDataRole.UserRole) or items[0].text()

    def _selected_repo_policy(self) -> str:
        items = self.repo_list.selectedItems()
        if not items:
            return ""
        return items[0].data(Qt.ItemDataRole.UserRole + 1) or "none"

    def _selected_repo_names(self) -> list:
        return [it.data(Qt.ItemDataRole.UserRole) or it.text()
                for it in self.repo_list.selectedItems()]

    def _current_clone_url(self) -> str:
        name = self._selected_repo_name()
        if not name:
            return ""
        c = self.collect_identity_cfg()
        return f"{c['user']}@{c['host']}:{c['remote_root']}/{name}"

    def on_repo_selected(self):
        self.clone_edit.setText(self._current_clone_url())
        has = len(self.repo_list.selectedItems()) > 0
        self.delete_btn.setEnabled(has)
        self.ci_btn.setEnabled(has)
        self.set_ci_btn.setEnabled(has)
        self.selftest_btn.setEnabled(has)
        self.detail_btn.setEnabled(has)
        self.batch_ci_btn.setEnabled(len(self.repo_list.selectedItems()) >= 1)
        self.clone_btn.setEnabled(has)

    def copy_clone_url(self):
        url = self.clone_edit.text().strip()
        if not url:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        QApplication.clipboard().setText(url)
        self.browse_status.setText("已複製 Clone URL 到剪貼簿。")
        self.browse_status.setStyleSheet("color:#1a7f37;")

    def copy_clone_cmd(self):
        url = self.clone_edit.text().strip()
        if not url:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        QApplication.clipboard().setText(f"git clone {url}")
        self.browse_status.setText("已複製「git clone …」指令到剪貼簿。")
        self.browse_status.setStyleSheet("color:#1a7f37;")

    # ---------- 安全下庄 / 刪除 ----------
    def on_delete_repo(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        c = self.collect_identity_cfg()
        full = f"{c['remote_root']}/{name}"
        dlg = DeleteRepoDialog(self, name, full)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cfg = dict(c)
        cfg["repo_name"] = name
        cfg["delete_mode"] = dlg.delete_mode()
        self.save_current_profile(silent=True)
        self.browse_status.setText(f"處理「{name}」中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="delete")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_delete_done)
        self.worker.start()

    def on_delete_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            QMessageBox.information(self, "完成", msg)
            self.on_refresh()  # 重新列出，讓清單即時更新
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "未完成", msg)

    # ---------- 檢視 CI 規則 / Hook ----------
    def on_view_ci(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        self.save_current_profile(silent=True)
        self._ci_title = f"CI 規則報告 — {name}"
        self.browse_status.setText(f"讀取「{name}」的 CI 規則中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="hooks")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()

    def on_ci_status(self):
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        self._ci_title = "CI 狀態總表（全庫）"
        self.browse_status.setText("讀取 CI 狀態總表中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="ci_status")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()

    def on_ci_result(self, text: str):
        title = getattr(self, "_ci_title", "CI 規則")
        dlg = TextViewDialog(self, title, text or "（沒有內容）")
        dlg.exec()

    def on_ci_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "讀取失敗", msg)

    # ---------- 設定 CI（每 repo 獨立）----------
    def on_set_ci(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        dlg = SetCiDialog(self, name, current=self._selected_repo_policy())
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        cfg["ci_policy"] = dlg.policy()
        self.save_current_profile(silent=True)
        self.browse_status.setText(f"設定「{name}」的 CI 中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="set_ci")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_set_ci_done)
        self.worker.start()

    def on_set_ci_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            QMessageBox.information(self, "完成", msg)
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "設定失敗", msg)

    # ---------- 一鍵升級 CI 引擎 ----------
    def on_upgrade_engine(self):
        c = self.collect_identity_cfg()
        eng = f"{c['remote_root']}/hooks_template/pre-receive.ci"
        r = QMessageBox.question(
            self, "升級 CI 引擎",
            "將把 NAS 上的：\n"
            f"  {eng}\n"
            "換成「自載入 policy」版本（會先自動備份成 .bak-時間戳）。\n\n"
            "升級後，各 repo 的 CI 才會依 ci_policies/<repo>.policy 真正生效：\n"
            "strict→擋 push、soft→只警告、none/無→略過。\n\n"
            "確定要升級嗎？",
        )
        if r != QMessageBox.StandardButton.Yes:
            return
        self.save_current_profile(silent=True)
        self.browse_status.setText("升級 CI 引擎中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(dict(c), mode="upgrade_engine")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_upgrade_done)
        self.worker.start()

    def on_upgrade_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            QMessageBox.information(self, "完成", msg)
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "升級失敗", msg)

    # ---------- 維運 / 日誌 ----------
    def _start_maint(self, mode, title, extra=None):
        cfg = dict(self.collect_identity_cfg())
        if extra:
            cfg.update(extra)
        self.save_current_profile(silent=True)
        self._ci_title = title
        self.maint_status.setText(f"{title}中…")
        self.maint_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode=mode)
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_maint_done)
        self.worker.start()

    def on_healthcheck(self):
        self._start_maint("healthcheck", "健康檢查")

    def on_repair(self):
        r = QMessageBox.question(
            self, "一鍵修復",
            "將對所有 repo：\n"
            "・以 hooks_template 的 pre-receive.stub / post-receive 覆蓋各 repo 的 hook\n"
            "・chmod 750 hook、chgrp -R git_devs、chmod -R g+rwX\n\n"
            "這會統一全庫 hook 與權限。確定執行嗎？",
        )
        if r != QMessageBox.StandardButton.Yes:
            return
        self._start_maint("repair", "一鍵修復")

    def on_view_log(self, logfile, title):
        self._start_maint("log", title, extra={"logfile": logfile, "log_lines": 200})

    def on_maint_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.maint_status.setText("✔ " + msg.replace("\n", "　"))
            self.maint_status.setStyleSheet("color:#1a7f37;")
        else:
            self.maint_status.setText("❌ " + msg.replace("\n", "　"))
            self.maint_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "失敗", msg)

    # ---------- 新建空倉庫 ----------
    def on_create_repo(self):
        dlg = CreateRepoDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        name, branch, pol = dlg.values()
        cfg = dict(self.collect_identity_cfg())
        cfg.update({"repo_name": name, "branch": branch, "ci_policy": pol})
        self.save_current_profile(silent=True)
        self.browse_status.setText(f"建立倉庫「{name}」中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="create_repo")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_create_done)
        self.worker.start()

    def on_create_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            QMessageBox.information(self, "完成", msg)
            self.on_refresh()
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "建立失敗", msg)

    # ---------- 封存區 ----------
    def on_archive(self):
        dlg = ArchiveDialog(self, dict(self.collect_identity_cfg()))
        dlg.exec()
        self.on_refresh()  # 還原可能讓庫回到清單，關閉後重整

    # ---------- CI 自測 ----------
    def on_ci_selftest(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        self.save_current_profile(silent=True)
        self._ci_title = f"CI 自我測試 — {name}"
        self.browse_status.setText(f"對「{name}」做 CI 自測中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="ci_selftest")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()

    # ---------- 批次設定 CI ----------
    def on_set_ci_batch(self):
        names = self._selected_repo_names()
        if not names:
            self.browse_status.setText("請先在清單選取一個或多個倉庫。")
            return
        dlg = SetCiDialog(self, "", batch_count=len(names))
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_names"] = names
        cfg["ci_policy"] = dlg.policy()
        self.save_current_profile(silent=True)
        self._ci_title = f"批次設定 CI（{len(names)} 個）"
        self.browse_status.setText(f"批次設定 {len(names)} 個 repo 的 CI 中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="set_ci_batch")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_batch_done)
        self.worker.start()

    def on_batch_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            self.on_refresh()  # 重整讓清單 CI 欄更新
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "批次設定失敗", msg)

    # ---------- repo 明細 ----------
    def on_repo_detail(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        self.save_current_profile(silent=True)
        self._ci_title = f"倉庫明細 — {name}"
        self.browse_status.setText(f"讀取「{name}」明細中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="repo_detail")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()

    # ---------- 從 NAS clone 到本地 ----------
    def on_clone(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        url = self._current_clone_url()
        parent = QFileDialog.getExistingDirectory(
            self, "選擇要 clone 到哪個資料夾（會在其下建立子資料夾）",
            self.settings.value("last_clone_dir", ""))
        if not parent:
            return
        self.settings.setValue("last_clone_dir", parent)
        folder = name[:-4] if name.endswith(".git") else name
        target = os.path.join(parent, folder)
        if os.path.exists(target):
            QMessageBox.warning(self, "已存在", f"目標資料夾已存在，未動作：\n{target}")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg.update({"clone_url": url, "target_dir": parent, "repo_name": name})
        self.save_current_profile(silent=True)
        self.browse_status.setText(f"clone「{name}」到 {target} 中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="clone")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_clone_done)
        self.worker.start()

    def on_clone_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", " "))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            QMessageBox.information(self, "完成", msg)
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", " "))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "Clone 失敗", msg)


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
