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

__version__ = "1.0.0"

import os
import sys
import re
import socket
import shutil
import platform
import subprocess
import base64
import hashlib
import secrets
import string
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QGroupBox, QInputDialog, QTabWidget, QListWidget,
    QDialog, QRadioButton, QDialogButtonBox, QListWidgetItem, QSpinBox, QTextBrowser
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

# 封存區保留政策提醒：項目封存超過這麼多天，就在封存區清單上標記提醒（僅提醒，不自動清除）。
ARCHIVE_STALE_DAYS = 90

# 健康檢查用：單一檔案超過這個大小（bytes）就建議改用 Git LFS，僅提醒不自動處理。
LFS_SUGGEST_BYTES = 5 * 1024 * 1024

# 新建空倉庫可選套用的 .gitignore 模板（Python 專案常見規則）。
GITIGNORE_TEMPLATE = """__pycache__/
*.pyc
.venv/
venv/
build/
dist/
*.egg-info/
.DS_Store
"""

# 本機操作稽核 log：這套工具做的破壞性動作（刪 repo、砍 tag、砍 SSH 金鑰、批次清封存、GC 等）
# NAS 端只留得住 push 記錄，這裡額外留一份本機紀錄方便事後追查「我到底做過什麼」。
AUDIT_LOG_PATH = os.path.join(os.path.expanduser("~"), ".nas_git_connector", "audit.log")
DESTRUCTIVE_MODES = {"delete", "rename_repo", "repo_gc", "tag_delete", "ssh_keys_delete", "archive_purge"}

# 新增 git_devs 帳號時自動產生的 DSM 登入密碼留底檔——明碼存放，僅供應急查回密碼用；
# 這個檔案本身就是機密，請自行限制存取（例如搬到有加密的資料夾）並定期清理不再需要的紀錄。
GIT_DEVS_CRED_LOG_PATH = os.path.join(os.path.expanduser("~"), ".nas_git_connector", "git_devs_credentials.log")


def save_git_devs_credential(admin_user: str, host: str, new_username: str, password: str):
    try:
        os.makedirs(os.path.dirname(GIT_DEVS_CRED_LOG_PATH), exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(GIT_DEVS_CRED_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t建立者={admin_user}@{host}\t帳號={new_username}\t密碼={password}\n")
    except OSError:
        pass


def audit_log(user: str, host: str, action: str, detail: str):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{user}@{host}\t{action}\t{detail}\n")
    except OSError:
        pass

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

# 倉庫 / 封存項目名稱白名單：只允許「文字字元」（含中日韓文字/字母/數字，不含底線）開頭，
# 後面可接文字字元、底線、. -。名稱會用單引號整段包進 SSH shell 指令，
# 這裡擋的是會破壞 quoting 或有路徑意義的字元：/ \ ' " $ ` 空白 ; | & ( ) < > 等，
# 中日韓文字本身不構成 shell 注入風險，故放行。仍排除 . .. _archived 等保留名稱。
_SAFE_NAME_RE = re.compile(r"^[^\W_][\w.-]*$", re.UNICODE)


def is_safe_name(name: str) -> bool:
    return bool(name) and bool(_SAFE_NAME_RE.match(name)) and name not in (".", "..", "_archived")


def shq(value: str) -> str:
    """把任意字串包成單引號 POSIX shell 字面值，用於分支名、檔案路徑等非白名單值。"""
    return "'" + value.replace("'", "'\\''") + "'"


# Unix/DSM 帳號名稱白名單：小寫英文開頭，其餘可接小寫英數字、底線、連字號。
_SAFE_USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def is_safe_username(name: str) -> bool:
    return bool(name) and bool(_SAFE_USERNAME_RE.match(name)) and len(name) <= 32


_SSH_PUBKEY_RE = re.compile(
    r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|"
    r"ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|"
    r"sk-ecdsa-sha2-nistp256@openssh\.com) "
)


def is_ssh_pubkey(line: str) -> bool:
    return bool(_SSH_PUBKEY_RE.match(line))


def ssh_fingerprint(line: str) -> str:
    """算 authorized_keys 一行的 SHA256 指紋（同 ssh-keygen -lf 的格式），純本機計算不用連 NAS。"""
    parts = line.split(None, 2)
    if len(parts) < 2:
        return "?"
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception:
        return "?"
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fmt_size_kb(kb: int) -> str:
    """把 du -sk 回傳的 KB 數字格式化成人類可讀大小（K/M/G）。"""
    v = float(kb)
    for unit in ("K", "M", "G", "T"):
        if v < 1024 or unit == "T":
            return f"{v:.0f}{unit}" if unit == "K" else f"{v:.1f}{unit}"
        v /= 1024
    return f"{v:.1f}T"

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
        elif self.mode == "rename_repo":
            self._run_rename_repo()
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
        elif self.mode == "repo_desc_get":
            self._run_repo_desc_get()
        elif self.mode == "repo_desc_set":
            self._run_repo_desc_set()
        elif self.mode == "branch_protect_get":
            self._run_branch_protect_get()
        elif self.mode == "branch_protect_set":
            self._run_branch_protect_set()
        elif self.mode == "repo_files":
            self._run_repo_files()
        elif self.mode == "file_content":
            self._run_file_content()
        elif self.mode == "repo_gc":
            self._run_repo_gc()
        elif self.mode == "repo_log":
            self._run_repo_log()
        elif self.mode == "repo_branches":
            self._run_repo_branches()
        elif self.mode == "merged_branches":
            self._run_merged_branches()
        elif self.mode == "grep_all":
            self._run_grep_all()
        elif self.mode == "repo_diff":
            self._run_repo_diff()
        elif self.mode == "tag_list":
            self._run_tag_list()
        elif self.mode == "tag_create":
            self._run_tag_create()
        elif self.mode == "tag_delete":
            self._run_tag_delete()
        elif self.mode == "file_blame":
            self._run_file_blame()
        elif self.mode == "ssh_keys_list":
            self._run_ssh_keys_list()
        elif self.mode == "ssh_keys_add":
            self._run_ssh_keys_add()
        elif self.mode == "ssh_keys_delete":
            self._run_ssh_keys_delete()
        elif self.mode == "prep_new_user":
            self._run_prep_new_user()
        elif self.mode == "clone":
            self._run_clone()
        elif self.mode == "create_mirror":
            self._run_create_mirror()
        elif self.mode == "sync_mirrors":
            self._run_sync_mirrors()
        elif self.mode == "upgrade_engine":
            self._run_upgrade_engine()
        elif self.mode == "healthcheck":
            self._run_healthcheck()
        elif self.mode == "disk_usage":
            self._run_disk_usage()
        elif self.mode == "tg_conf_get":
            self._run_tg_conf_get()
        elif self.mode == "tg_conf_set":
            self._run_tg_conf_set()
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
        # 每行：name<TAB>status<TAB>policy<TAB>mirror_url（mirror_url 非空代表是 GitHub 鏡像）
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
            "  mu=''",
            "  [ \"$(git --git-dir=\"$d\" config --get remote.origin.mirror 2>/dev/null)\" = true ] && mu=$(git --git-dir=\"$d\" config --get remote.origin.url 2>/dev/null)",
            "  sz=$(du -sk \"$d\" 2>/dev/null | cut -f1); [ -z \"$sz\" ] && sz=0",
            "  if [ -z \"$info\" ]; then",
            "    printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$name\" \"空庫（無 commit）\" \"$pol\" \"$mu\" \"$sz\"",
            "  else",
            "    dt=${info%%|*}; br=${info#*|}",
            "    printf '%s\\t%s (%s)\\t%s\\t%s\\t%s\\n' \"$name\" \"$dt\" \"$br\" \"$pol\" \"$mu\" \"$sz\"",
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
            mirror = parts[3].strip() if len(parts) > 3 else ""
            try:
                size_kb = int(parts[4].strip()) if len(parts) > 4 else 0
            except ValueError:
                size_kb = 0
            items.append((name, status, pol, mirror, size_kb))
        items.sort(key=lambda t: t[0].lower())
        self.repos.emit(items)
        n_empty = sum(1 for t in items if t[1].startswith("空庫"))
        n_mir = sum(1 for t in items if len(t) > 3 and t[3])
        self.done.emit(True, f"找到 {len(items)} 個倉庫（空庫 {n_empty}、鏡像 {n_mir}）。")

    # --- 安全下庄 / 刪除倉庫 ---
    def _run_delete(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        mode = c.get("delete_mode", "archive")

        # 安全檢查：名稱不得含路徑分隔、上層、引號，或指到保留目錄
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -，須以中英數開頭）：{name!r}")
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

    # --- 重新命名倉庫（含同步改 ci_policies/<repo>.policy 檔名）---
    def _run_rename_repo(self):
        c = self.cfg
        root = c["remote_root"]
        old_name = c.get("repo_name", "")
        new_name = c.get("new_name", "")
        if not new_name.endswith(".git"):
            new_name += ".git"
        if not is_safe_name(old_name):
            self.done.emit(False, f"倉庫名稱不合規：{old_name!r}")
            return
        if not is_safe_name(new_name):
            self.done.emit(False, f"新名稱不合規（僅允許中英數字與 . _ -，須以中英數開頭）：{new_name!r}")
            return
        if old_name == new_name:
            self.done.emit(False, "新舊名稱相同，未執行。")
            return
        old_path = f"{root}/{old_name}"
        new_path = f"{root}/{new_name}"
        self.log.emit(f"--- 重新命名：{old_name} → {new_name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"old='{old_path}'; new='{new_path}'",
            "[ -e \"$old/HEAD\" ] || { echo NOTREPO; echo ___END___; exit 0; }",
            "[ -e \"$new\" ] && { echo TARGET_EXISTS; echo ___END___; exit 0; }",
            "mv \"$old\" \"$new\" && echo MOVED",
            f"oldpf='{root}/ci_policies/{old_name}.policy'; newpf='{root}/ci_policies/{new_name}.policy'",
            "[ -f \"$oldpf\" ] && mv \"$oldpf\" \"$newpf\"",
            "echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if rc == 0 and "___OK___" in body:
            self.done.emit(True, f"已重新命名：{old_name} → {new_name}")
        elif "TARGET_EXISTS" in body:
            self.done.emit(False, f"重新命名失敗：目標名稱已存在（{new_name}）。")
        elif "NOTREPO" in body:
            self.done.emit(False, f"找不到、或不是有效的裸倉庫：{old_name}")
        else:
            self.done.emit(False, "重新命名失敗（連線或權限問題）。")

    # --- 讀取該庫的 CI 規則（server-side hook 內容）---
    def _run_hooks(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -，須以中英數開頭）：{name!r}")
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
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -，須以中英數開頭）：{name!r}")
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
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        self.log.emit(f"--- repo 明細：{name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "echo \"== 倉庫明細：$name ==\"",
            "echo \"大小：$(du -sh \"$repo\" 2>/dev/null | cut -f1)\"",
            "echo \"預設分支(HEAD)：$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)\"",
            "desc=$(cat \"$repo/description\" 2>/dev/null)",
            "case \"$desc\" in Unnamed\\ repository*|'') desc='（未設定）';; esac",
            "echo \"描述：$desc\"",
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

    # --- 讀取 repo 描述（bare repo 的 description 檔）---
    def _run_repo_desc_get(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"f='{root}/{name}/description'",
            "if [ -f \"$f\" ]; then cat \"$f\"; fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取描述失敗（連線或權限問題）。")
            return
        text = self._between(out)
        if text.startswith("Unnamed repository"):
            text = ""
        self.hooks.emit(text)
        self.done.emit(True, "已讀取描述。")

    # --- 寫入 repo 描述（走 base64 避免多行/引號問題）---
    def _run_repo_desc_set(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        desc = c.get("repo_desc", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        self.log.emit(f"--- 更新描述：{name} ---")
        b64 = base64.b64encode(desc.encode("utf-8")).decode("ascii")
        cmd = "\n".join([
            f"f='{root}/{name}/description'",
            f"printf '%s' '{b64}' | base64 -d > \"$f\" && echo ___OK___",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc == 0 and "___OK___" in out:
            self.done.emit(True, f"已更新「{name}」的描述。")
        else:
            self.done.emit(False, "更新描述失敗（連線或權限問題）。")

    # --- 讀取分支保護設定（git 原生 receive.denyDeletes / denyNonFastForwards，與 CI 引擎彼此獨立）---
    def _run_branch_protect_get(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"repo='{root}/{name}'",
            "git --git-dir=\"$repo\" config --get receive.denyDeletes 2>/dev/null || echo false",
            "git --git-dir=\"$repo\" config --get receive.denyNonFastForwards 2>/dev/null || echo false",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取分支保護設定失敗（連線或權限問題）。")
            return
        lines = self._between(out).splitlines()
        deny_del = lines[0].strip() if len(lines) > 0 else "false"
        deny_ff = lines[1].strip() if len(lines) > 1 else "false"
        self.hooks.emit(f"denyDeletes={deny_del}\ndenyNonFastForwards={deny_ff}")
        self.done.emit(True, "已讀取分支保護設定。")

    # --- 設定分支保護（禁止刪除分支/tag、禁止強制推送）---
    def _run_branch_protect_set(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        deny_del = "true" if c.get("deny_deletes") else "false"
        deny_ff = "true" if c.get("deny_nonff") else "false"
        self.log.emit(f"--- 設定分支保護：{name}（denyDeletes={deny_del}, denyNonFastForwards={deny_ff}）---")
        cmd = "\n".join([
            f"repo='{root}/{name}'",
            f"git --git-dir=\"$repo\" config receive.denyDeletes {deny_del}",
            f"git --git-dir=\"$repo\" config receive.denyNonFastForwards {deny_ff}",
            "echo ___OK___",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0 or "___OK___" not in out:
            self.done.emit(False, "更新分支保護失敗（連線或權限問題）。")
            return
        state = []
        if deny_del == "true":
            state.append("禁止刪除分支/tag")
        if deny_ff == "true":
            state.append("禁止強制推送")
        summary = "、".join(state) if state else "已清除保護（恢復預設）"
        self.done.emit(True, f"已更新「{name}」分支保護：{summary}")

    # --- 列出 repo 在預設分支下所有檔案（不用 clone）---
    def _run_repo_files(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        self.log.emit(f"--- 檔案列表：{name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "branch=$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)",
            "if [ -z \"$branch\" ]; then",
            "  echo \"EMPTY\"",
            "else",
            "  echo \"BRANCH\t$branch\"",
            "  git --git-dir=\"$repo\" ls-tree -r -l \"$branch\" | "
            "awk -F'\\t' '{n=split($1,a,\" \"); size=a[n]; printf \"FILE\\t%s\\t%s\\n\", size, $2}'",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取檔案列表失敗（連線或權限問題）。")
            return
        body = self._between(out)
        branch = ""
        items = []
        for ln in body.splitlines():
            p = ln.split("\t")
            if p[0] == "BRANCH" and len(p) >= 2:
                branch = p[1]
            elif p[0] == "FILE" and len(p) >= 3:
                items.append((p[1], p[2]))
        self.repos.emit(items)
        if not branch:
            self.done.emit(True, f"{name} 是空庫，尚無任何分支/commit，無檔案可列。")
        else:
            self.done.emit(True, f"已讀取 {name} 檔案列表（分支：{branch}，共 {len(items)} 個檔案）。")

    # --- 顯示某檔案在 HEAD 版本下的內容（不用 clone）---
    def _run_file_content(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        path = c.get("file_path", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if not path:
            self.done.emit(False, "缺少檔案路徑。")
            return
        self.log.emit(f"--- 檔案內容：{name}:{path} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            f"git --git-dir=\"$repo\" show HEAD:{shq(path)} 2>&1",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取檔案內容失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已讀取 {path}。")

    # --- 對選取的倉庫執行 git gc（回收空間、整理 pack）---
    def _run_repo_gc(self):
        c = self.cfg
        root = c["remote_root"]
        names = [n for n in c.get("repo_names", []) if is_safe_name(n)]
        if not names:
            self.done.emit(False, "沒有選取任何倉庫。")
            return
        flt = "".join(" " + n + " " for n in names)
        self.log.emit(f"--- Git GC 維護（{len(names)} 個倉庫）---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; FILTER='{flt}'",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  case \"$FILTER\" in *\" $name \"*) ;; *) continue;; esac",
            "  before=$(du -sh \"$repo\" 2>/dev/null | cut -f1)",
            "  if git --git-dir=\"$repo\" gc --quiet >/dev/null 2>&1; then",
            "    after=$(du -sh \"$repo\" 2>/dev/null | cut -f1)",
            "    echo \"[OK]   $name  $before -> $after\"",
            "  else",
            "    echo \"[FAIL] $name\"",
            "  fi",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "GC 失敗（連線或權限問題）。")
            return
        body = self._between(out)
        self.hooks.emit(body)
        nfail = body.count("[FAIL]")
        nok = body.count("[OK]")
        self.done.emit(nfail == 0, f"GC 完成：成功 {nok}、失敗 {nfail}。")

    # --- 讀取某分支的完整 commit log（非只最後一筆）---
    def _run_repo_log(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        branch = c.get("branch", "")
        count = c.get("count", 50)
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if not branch:
            self.done.emit(False, "缺少分支名稱。")
            return
        self.log.emit(f"--- Commit Log：{name} ({branch}) ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            f"git --git-dir=\"$repo\" log {shq(branch)} -n {int(count)} "
            "--date=short --pretty=format:'%h  %ad  %an  %s' 2>&1",
            "echo",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 log 失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已讀取 {name}（{branch}）最近 {count} 筆 commit。")

    # --- 列出某倉庫所有分支名稱（供下拉選單用）---
    def _run_repo_branches(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.repos.emit([])
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "git --git-dir=\"$repo\" for-each-ref --sort=-committerdate "
            "--format='%(refname:short)' refs/heads 2>/dev/null",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.repos.emit([])
            self.done.emit(False, "讀取分支清單失敗（連線或權限問題）。")
            return
        names = [ln.strip() for ln in self._between(out).splitlines() if ln.strip()]
        self.repos.emit(names)
        self.done.emit(True, f"共 {len(names)} 個分支。")

    # --- 已完全合併進預設分支的分支清單（僅列出，不自動刪除）---
    def _run_merged_branches(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        self.log.emit(f"--- 已合併分支：{name} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "base=$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)",
            "if [ -z \"$base\" ]; then",
            "  echo \"（空庫，無法判斷已合併分支）\"",
            "else",
            "  echo \"== 已合併進 $base 的分支（可考慮清理，本工具不會自動刪除）==\"",
            "  git --git-dir=\"$repo\" for-each-ref --merged \"$base\" --sort=-committerdate "
            "--format='%(refname:short)|%(committerdate:short)|%(authorname)|%(subject)' refs/heads 2>/dev/null | "
            "while IFS='|' read -r rn cd an su; do",
            "    [ \"$rn\" = \"$base\" ] && continue",
            "    printf '  %s  |  %s  |  %s  |  %s\\n' \"$rn\" \"$cd\" \"$an\" \"$su\"",
            "  done",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取已合併分支失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已讀取 {name} 的已合併分支清單。")

    # --- 跨所有倉庫全文搜尋（各庫預設分支下）---
    def _run_grep_all(self):
        root = self.cfg["remote_root"]
        pattern = self.cfg.get("pattern", "")
        if not pattern:
            self.repos.emit([])
            self.done.emit(False, "請輸入搜尋字串。")
            return
        self.log.emit(f"--- 跨庫搜尋：{pattern} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; PATTERN={shq(pattern)}",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  base=$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)",
            "  [ -z \"$base\" ] && continue",
            "  git --git-dir=\"$repo\" grep -n -I -e \"$PATTERN\" \"$base\" 2>/dev/null | "
            "sed \"s/^/HIT\\t$name\\t/\"",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.repos.emit([])
            self.done.emit(False, "搜尋失敗（連線或權限問題）。")
            return
        hits = []
        for ln in self._between(out).splitlines():
            if not ln.startswith("HIT\t"):
                continue
            parts = ln[4:].split("\t", 1)
            if len(parts) != 2:
                continue
            repo_name, grepline = parts
            gparts = grepline.split(":", 3)
            if len(gparts) < 4:
                continue
            _tree, path, lineno, content = gparts
            hits.append((repo_name, path, lineno, content))
        self.repos.emit(hits)
        self.done.emit(True, f"搜尋「{pattern}」完成，共 {len(hits)} 筆符合。")

    # --- 比較同倉庫內兩個分支/commit ---
    def _run_repo_diff(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        ref_a = c.get("ref_a", "")
        ref_b = c.get("ref_b", "")
        stat_only = c.get("stat_only", True)
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if not ref_a or not ref_b:
            self.done.emit(False, "請指定要比較的兩個分支/commit。")
            return
        self.log.emit(f"--- Diff：{name}  {ref_a}..{ref_b} ---")
        opt = "--stat" if stat_only else ""
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            f"git --git-dir=\"$repo\" diff {opt} {shq(ref_a)} {shq(ref_b)} 2>&1",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "比較失敗（連線或權限問題）。")
            return
        body = self._between(out)
        self.hooks.emit(body or "（沒有差異）")
        self.done.emit(True, f"已比較 {ref_a}..{ref_b}。")

    # --- 列出此庫的所有 tag（annotated tag 當簡易 Release 標記）---
    def _run_tag_list(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.repos.emit([])
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            "git --git-dir=\"$repo\" for-each-ref --sort=-creatordate "
            "--format='%(refname:short)|%(creatordate:short)|%(taggername)|%(contents:subject)' "
            "refs/tags 2>/dev/null",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.repos.emit([])
            self.done.emit(False, "讀取 tag 清單失敗（連線或權限問題）。")
            return
        items = []
        for ln in self._between(out).splitlines():
            p = ln.split("|")
            if p and p[0].strip():
                items.append((p[0].strip(),
                              p[1].strip() if len(p) > 1 else "",
                              p[2].strip() if len(p) > 2 else "",
                              p[3].strip() if len(p) > 3 else ""))
        self.repos.emit(items)
        self.done.emit(True, f"共 {len(items)} 個 tag。")

    # --- 新增 annotated tag（當作簡易 Release 標記）---
    def _run_tag_create(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        tag = c.get("tag_name", "")
        ref = c.get("tag_ref", "")
        message = c.get("tag_message", "") or tag
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if not tag or not ref:
            self.done.emit(False, "請指定 tag 名稱與要標記的分支/commit。")
            return
        self.log.emit(f"--- 新增 tag：{name} {tag} @ {ref} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            f"git --git-dir=\"$repo\" tag -a {shq(tag)} {shq(ref)} -m {shq(message)} 2>&1 && echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if rc == 0 and "___OK___" in body:
            self.done.emit(True, f"已建立 tag：{tag} @ {ref}")
        else:
            self.done.emit(False, f"建立 tag 失敗：{body.replace('___OK___', '').strip() or '未知錯誤'}")

    # --- 刪除 tag ---
    def _run_tag_delete(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        tag = c.get("tag_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if not tag:
            self.done.emit(False, "缺少 tag 名稱。")
            return
        self.log.emit(f"--- 刪除 tag：{name} {tag} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            f"git --git-dir=\"$repo\" tag -d {shq(tag)} 2>&1 && echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if rc == 0 and "___OK___" in body:
            self.done.emit(True, f"已刪除 tag：{tag}")
        else:
            self.done.emit(False, f"刪除 tag 失敗：{body.replace('___OK___', '').strip() or '未知錯誤'}")

    # --- git blame 某檔案（HEAD 版本）---
    def _run_file_blame(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        path = c.get("file_path", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if not path:
            self.done.emit(False, "缺少檔案路徑。")
            return
        self.log.emit(f"--- Blame：{name}:{path} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; repo=\"$BASE/$name\"",
            f"git --git-dir=\"$repo\" blame --date=short HEAD -- {shq(path)} 2>&1",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 blame 失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, f"已讀取 {path} 的 blame。")

    # --- 列出目前 profile 帳號自己的 authorized_keys ---
    def _run_ssh_keys_list(self):
        self.log.emit("--- 讀取 SSH 授權金鑰（authorized_keys）---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            "f=\"$HOME/.ssh/authorized_keys\"",
            "if [ -f \"$f\" ]; then",
            "  while IFS= read -r line || [ -n \"$line\" ]; do",
            "    [ -z \"$line\" ] && continue",
            "    case \"$line\" in \"#\"*) continue;; esac",
            "    printf 'KEY\\t%s\\n' \"$line\"",
            "  done < \"$f\"",
            "else",
            "  echo NOFILE",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.repos.emit([])
            self.done.emit(False, "讀取 authorized_keys 失敗（連線或權限問題）。")
            return
        body = self._between(out)
        keys = [ln[4:] for ln in body.splitlines() if ln.startswith("KEY\t")]
        self.repos.emit(keys)
        self.done.emit(True, f"共 {len(keys)} 把已授權的金鑰。")

    # --- 新增一把公鑰到 authorized_keys ---
    def _run_ssh_keys_add(self):
        key_line = " ".join(self.cfg.get("key_line", "").split())
        if not is_ssh_pubkey(key_line):
            self.done.emit(False, "看起來不是合法的 SSH 公鑰格式（應以 ssh-rsa / ssh-ed25519 等開頭）。")
            return
        self.log.emit("--- 新增 SSH 授權金鑰 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            "mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\"",
            "f=\"$HOME/.ssh/authorized_keys\"",
            "touch \"$f\" && chmod 600 \"$f\"",
            f"line={shq(key_line)}",
            "if grep -qxF \"$line\" \"$f\" 2>/dev/null; then",
            "  echo DUP",
            "else",
            "  printf '%s\\n' \"$line\" >> \"$f\" && echo ___OK___",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if "DUP" in body:
            self.done.emit(False, "這把金鑰已經在 authorized_keys 裡了。")
        elif rc == 0 and "___OK___" in body:
            self.done.emit(True, "已新增授權金鑰。")
        else:
            self.done.emit(False, "新增失敗（連線或權限問題）。")

    # --- 從 authorized_keys 移除一把公鑰（先備份原檔）---
    def _run_ssh_keys_delete(self):
        key_line = self.cfg.get("key_line", "")
        if not key_line:
            self.done.emit(False, "缺少要刪除的金鑰內容。")
            return
        self.log.emit("--- 刪除 SSH 授權金鑰 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            "f=\"$HOME/.ssh/authorized_keys\"",
            "if [ ! -f \"$f\" ]; then echo NOFILE; echo ___END___; exit 0; fi",
            f"line={shq(key_line)}",
            "cp \"$f\" \"$f.bak-$(date +%Y%m%d-%H%M%S)\"",
            "grep -vxF \"$line\" \"$f\" > \"$f.tmp\" && mv \"$f.tmp\" \"$f\" && chmod 600 \"$f\" && echo ___OK___",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        body = self._between(out)
        if rc == 0 and "___OK___" in body:
            self.done.emit(True, "已刪除該授權金鑰（原檔已備份 .bak-時間戳）。")
        else:
            self.done.emit(False, "刪除失敗（連線或權限問題，或找不到 authorized_keys）。")

    # --- 查詢 git_devs 現況（帳號是否已存在、目前成員名單），供產生新增帳號指令用 ---
    # 唯讀查詢，不會建立帳號、不會改群組——實際建帳號指令由使用者自行以特權身份執行。
    def _run_prep_new_user(self):
        name = self.cfg.get("new_user", "")
        if not is_safe_username(name):
            self.done.emit(False, f"帳號名稱不合規（僅允許小寫英文開頭、接小寫英數字/底線/連字號）：{name!r}")
            return
        self.log.emit(f"--- 查詢 git_devs 現況（供新增帳號 {name} 用）---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"name={shq(name)}",
            "id \"$name\" >/dev/null 2>&1 && echo EXISTS:YES || echo EXISTS:NO",
            # 這裡故意不用 getent：部分 DSM 的 SSH 遠端指令環境 PATH 沒收錄 getent，
            # 會靜默查到空字串，讓後面產生的 synogroup --member 誤把其他人踢出群組。
            # 直接讀 /etc/group 比較可靠，跟工具其他地方一樣走 grep/cut。
            "echo \"MEMBERS:$(grep '^git_devs:' /etc/group | cut -d: -f4)\"",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "查詢失敗（連線或權限問題）。")
            return
        body = self._between(out)
        exists = "EXISTS:YES" in body
        members = ""
        for ln in body.splitlines():
            if ln.startswith("MEMBERS:"):
                members = ln[len("MEMBERS:"):].strip()
                break
        self.hooks.emit(f"EXISTS={'1' if exists else '0'}\nMEMBERS={members}")
        self.done.emit(True, "查詢完成。")

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

    # --- 在 NAS 建立 GitHub 鏡像庫（git clone --mirror，NAS 直接對 GitHub 拉）---
    def _run_create_mirror(self):
        c = self.cfg
        root = c["remote_root"]
        url = (c.get("mirror_url", "") or "").strip()
        name = c.get("repo_name", "")
        if not name.endswith(".git"):
            name += ".git"
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        # URL 白名單：只允許常見 git 遠端格式，且不得含引號/空白/反引號/$
        if not re.match(r"^(https://|http://|git@|ssh://|file://)[A-Za-z0-9@._:/~?=&%+\-]+$", url):
            self.done.emit(False, "GitHub URL 格式不合規（僅允許 https:// / git@ / ssh:// / file:// 開頭的正常網址）。")
            return
        self.log.emit(f"--- 建立 GitHub 鏡像：{name} ← {url} ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; url='{url}'",
            "repo=\"$BASE/$name\"",
            "if [ -e \"$repo\" ]; then echo EXISTS; echo ___END___; exit 0; fi",
            "if git clone --mirror \"$url\" \"$repo\" >/dev/null 2>&1; then",
            "  chgrp -R git_devs \"$repo\" 2>/dev/null; chmod -R g+rwX \"$repo\" 2>/dev/null",
            "  echo ___OK___",
            "else",
            "  rm -rf \"$repo\"; echo CLONE_FAIL",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if "EXISTS" in out:
            self.done.emit(False, f"倉庫已存在，未建立：{name}")
        elif rc == 0 and "___OK___" in out:
            clone_url = f"{c['user']}@{c['host']}:{root}/{name}"
            self.done.emit(True, f"已建立鏡像：{name}\n上游：{url}\n本地 Clone URL：{clone_url}\n（日後用『同步鏡像』或排程更新）")
        else:
            self.done.emit(False, "建立鏡像失敗（NAS 連不到 GitHub？私有庫需在 NAS 設金鑰/token？）。")

    # --- 同步鏡像（remote update --prune）；names 空則同步全部鏡像 ---
    def _run_sync_mirrors(self):
        root = self.cfg["remote_root"]
        names = [n for n in self.cfg.get("mirror_names", []) if is_safe_name(n)]
        flt = ("".join(" " + n + " " for n in names)) if names else ""
        self.log.emit(f"--- 同步鏡像（{'選取 ' + str(len(names)) + ' 個' if names else '全部'}）---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; FILTER='{flt}'",
            "n=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  [ \"$(git --git-dir=\"$repo\" config --get remote.origin.mirror 2>/dev/null)\" = true ] || continue",
            "  if [ -n \"$FILTER\" ]; then case \"$FILTER\" in *\" $name \"*) ;; *) continue;; esac; fi",
            "  n=$((n+1))",
            "  if git --git-dir=\"$repo\" remote update --prune >/dev/null 2>&1; then",
            "    echo \"[OK]   $name\"",
            "  else",
            "    echo \"[FAIL] $name\"",
            "  fi",
            "done",
            "[ \"$n\" = 0 ] && echo '（沒有符合的鏡像庫）'",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "同步失敗（連線或權限問題）。")
            return
        body = self._between(out)
        self.hooks.emit(body)
        nfail = body.count("[FAIL]")
        nok = body.count("[OK]")
        self.done.emit(nfail == 0, f"鏡像同步完成：成功 {nok}、失敗 {nfail}。")

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
            "  sr=$(git --git-dir=\"$repo\" config --get core.sharedRepository 2>/dev/null)",
            "  [ \"$sr\" = group ] || { msg=\"$msg 未設core.sharedRepository=group（多身份交錯 push 可能卡權限，跑一鍵修復或手動 chmod -R g+rwX 排除）\"; bad=1; }",
            "  [ -n \"$msg\" ] && echo \"[!!] $n:$msg\"",
            "done",
            "[ \"$bad\" = 0 ] && echo '[OK] 所有 repo 的 hook 與群組正常'",
            "echo",
            "echo '== LFS 使用建議 =='",
            "lfs_hits=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  n=$(basename \"$repo\")",
            "  base=$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)",
            "  [ -z \"$base\" ] && continue",
            f"  big=$(git --git-dir=\"$repo\" ls-tree -r -l \"$base\" 2>/dev/null | awk '$4+0 > {LFS_SUGGEST_BYTES} {{c++}} END{{print c+0}}')",
            "  if [ \"${big:-0}\" -gt 0 ] 2>/dev/null; then",
            f"    echo \"[  ] $n：有 $big 個檔案超過 {LFS_SUGGEST_BYTES // (1024*1024)}MB，考慮改用 Git LFS 存放大型二進位檔\"",
            "    lfs_hits=$((lfs_hits+1))",
            "  fi",
            "done",
            "[ \"$lfs_hits\" = 0 ] && echo '[OK] 沒有偵測到明顯需要上 LFS 的大型檔案'",
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

    # --- 伺服器總儲存空間總覽（檔案系統可用空間 + 總用量 + 最大的幾個 repo）---
    def _run_disk_usage(self):
        root = self.cfg["remote_root"]
        self.log.emit("--- 伺服器空間總覽 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'",
            "echo '== 檔案系統可用空間 (df -h) =='",
            "df -h \"$BASE\" 2>/dev/null",
            "echo",
            "echo '== Git_Server 總用量 =='",
            "du -sh \"$BASE\" 2>/dev/null",
            "echo",
            "echo '== 各倉庫大小排行（前 10 大）=='",
            "for d in \"$BASE\"/*.git; do [ -d \"$d\" ] || continue; du -sh \"$d\" 2>/dev/null; done | sort -rh | head -10",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取伺服器空間資訊失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, "已讀取伺服器空間總覽。")

    # --- 讀取 Telegram 通知設定（CI 引擎與鏡像同步腳本共用的 config/tg_bot.conf）---
    def _run_tg_conf_get(self):
        root = self.cfg["remote_root"]
        self.log.emit("--- 讀取 Telegram 通知設定 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"f='{root}/config/tg_bot.conf'",
            "if [ -f \"$f\" ]; then",
            "  echo \"TOKEN=$(sed -n 's/^[[:space:]]*BOT_TOKEN=//p' \"$f\" | head -1)\"",
            "  echo \"CHAT=$(sed -n 's/^[[:space:]]*CHAT_ID=//p' \"$f\" | head -1)\"",
            "else",
            "  echo 'TOKEN='",
            "  echo 'CHAT='",
            "fi",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 Telegram 通知設定失敗（連線或權限問題）。")
            return
        self.hooks.emit(self._between(out))
        self.done.emit(True, "已讀取 Telegram 通知設定。")

    # --- 寫入 Telegram 通知設定（寫前先備份舊檔）---
    def _run_tg_conf_set(self):
        root = self.cfg["remote_root"]
        token = self.cfg.get("tg_token", "").strip()
        chat = self.cfg.get("tg_chat", "").strip()
        self.log.emit("--- 更新 Telegram 通知設定 ---")
        cmd = "\n".join([
            f"d='{root}/config'; f=\"$d/tg_bot.conf\"",
            "mkdir -p \"$d\"",
            "[ -f \"$f\" ] && cp \"$f\" \"$f.bak-$(date +%Y%m%d-%H%M%S)\"",
            f"printf 'BOT_TOKEN=%s\\nCHAT_ID=%s\\n' {shq(token)} {shq(chat)} > \"$f\"",
            "chmod 600 \"$f\"",
            "echo ___OK___",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc == 0 and "___OK___" in out:
            self.done.emit(True, "已更新 Telegram 通知設定（舊檔已備份）。")
        else:
            self.done.emit(False, "更新 Telegram 通知設定失敗（連線或權限問題）。")

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
            "  git --git-dir=\"$repo\" config core.sharedRepository group 2>/dev/null",
            "  chgrp -R git_devs \"$repo\" 2>/dev/null; chmod -R g+rwX \"$repo\" 2>/dev/null; chmod g+s \"$repo\" 2>/dev/null",
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
        add_readme = bool(c.get("add_readme"))
        add_gitignore = bool(c.get("add_gitignore"))
        if not name.endswith(".git"):
            name += ".git"
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
            return
        if pol not in ("none", "soft", "strict"):
            pol = "none"
        self.log.emit(f"--- 在 NAS 新建空倉庫：{name} ---")
        title = name[:-4] if name.endswith(".git") else name
        readme_b64 = base64.b64encode(f"# {title}\n".encode("utf-8")).decode("ascii")
        gitignore_b64 = base64.b64encode(GITIGNORE_TEMPLATE.encode("utf-8")).decode("ascii")
        seed_lines = []
        if add_readme or add_gitignore:
            seed_lines = [
                "idx=$(mktemp -u)",  # 只要路徑、不要預先建立空檔——空檔會被 git 當成損壞的 index
                "export GIT_INDEX_FILE=\"$idx\" GIT_DIR=\"$repo\"",
            ]
            if add_readme:
                seed_lines.append(
                    f"printf '%s' '{readme_b64}' | base64 -d | git hash-object -w --stdin | "
                    "xargs -I{} git update-index --add --cacheinfo 100644,{},README.md")
            if add_gitignore:
                seed_lines.append(
                    f"printf '%s' '{gitignore_b64}' | base64 -d | git hash-object -w --stdin | "
                    "xargs -I{} git update-index --add --cacheinfo 100644,{},.gitignore")
            seed_lines += [
                "tree=$(git write-tree)",
                "seed_commit=$(GIT_AUTHOR_NAME='NAS Git Connector' GIT_AUTHOR_EMAIL='nas-git-connector@local' "
                "GIT_COMMITTER_NAME='NAS Git Connector' GIT_COMMITTER_EMAIL='nas-git-connector@local' "
                "git commit-tree \"$tree\" -m 'chore: 初始化 repository')",
                "git update-ref \"refs/heads/$branch\" \"$seed_commit\"",
                "rm -f \"$idx\"",
                "unset GIT_INDEX_FILE GIT_DIR",
            ]
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'; branch='{branch}'; pol='{pol}'",
            "repo=\"$BASE/$name\"",
            "if [ -e \"$repo\" ]; then echo EXISTS; echo ___END___; exit 0; fi",
            "git init --bare \"$repo\" >/dev/null 2>&1 || { echo INIT_FAIL; echo ___END___; exit 0; }",
            "git --git-dir=\"$repo\" config core.sharedRepository group",
            "[ -f \"$BASE/hooks_template/pre-receive.stub\" ] && { cp \"$BASE/hooks_template/pre-receive.stub\" \"$repo/hooks/pre-receive\"; chmod 750 \"$repo/hooks/pre-receive\"; }",
            "[ -f \"$BASE/hooks_template/post-receive\" ] && { cp \"$BASE/hooks_template/post-receive\" \"$repo/hooks/post-receive\"; chmod 750 \"$repo/hooks/post-receive\"; }",
            "git --git-dir=\"$repo\" symbolic-ref HEAD \"refs/heads/$branch\" 2>/dev/null",
            *seed_lines,
            "mkdir -p \"$BASE/ci_policies\"",
            "if [ \"$pol\" != none ]; then printf '# %s\\nPOLICY=%s\\nPROFILE=%s\\n' \"$name\" \"$pol\" \"$pol\" > \"$BASE/ci_policies/$name.policy\"; fi",
            "chgrp -R git_devs \"$repo\" 2>/dev/null; chmod -R g+rwX \"$repo\" 2>/dev/null; chmod g+s \"$repo\" 2>/dev/null",
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
        seed_note = "\n初始內容：" + "、".join(
            n for n, on in (("README.md", add_readme), (".gitignore", add_gitignore)) if on
        ) if (add_readme or add_gitignore) else ""
        self.done.emit(True, f"已建立空倉庫：{name}\n預設分支 HEAD → {branch}\nCI：{pol}{seed_note}\nClone URL：{url}")

    # --- CI 自我測試（不用 push；用假 push 跑引擎）---
    def _run_ci_selftest(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{name!r}")
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
            # 讓 git 之後自己建立的物件檔就是群組可寫，避免不同身份交錯 push 時互卡權限
            self._ssh(f"git --git-dir='{remote_repo_path}' config core.sharedRepository group")
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
    def __init__(self, parent, title, text, markdown=False, goto_line=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(720, 560)
        self._text = text

        lay = QVBoxLayout(self)
        if markdown:
            view = QTextBrowser()
            view.setReadOnly(True)
            view.setOpenExternalLinks(True)
            view.setMarkdown(text)
        else:
            view = QPlainTextEdit()
            view.setReadOnly(True)
            view.setFont(QFont("NSimSun", 10))
            view.setPlainText(text)
            view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            if goto_line:
                try:
                    n = int(goto_line)
                    block = view.document().findBlockByNumber(max(0, n - 1))
                    cur = view.textCursor()
                    cur.setPosition(block.position())
                    view.setTextCursor(cur)
                    view.centerCursor()
                except (ValueError, TypeError):
                    pass
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
# 檔案列表對話框（不用 clone，瀏覽 HEAD 下的檔案並可預覽內容）
# ============================================================
class RepoFilesDialog(QDialog):
    def __init__(self, parent, cfg, repo_name):
        super().__init__(parent)
        self.cfg = cfg
        self.repo_name = repo_name
        self.worker = None
        self.content_worker = None
        self.setWindowTitle(f"檔案列表 — {repo_name}")
        self.resize(560, 480)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("此庫在預設分支（HEAD）下的所有檔案；雙擊或按「檢視內容」可直接預覽，不用 clone。"))
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self.on_view)
        lay.addWidget(self.list, stretch=1)

        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.view_b = QPushButton("檢視內容")
        self.blame_b = QPushButton("Blame")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.view_b)
        row.addWidget(self.blame_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.view_b.clicked.connect(self.on_view)
        self.blame_b.clicked.connect(self.on_blame)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.view_b, self.blame_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
        self.status.setText("讀取中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        self.worker = Worker(cfg, mode="repo_files")
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_list_done)
        self.worker.start()

    def on_entries(self, entries):
        self.list.clear()
        for size, path in entries:
            it = QListWidgetItem(f"{size:>10}  {path}")
            it.setData(Qt.ItemDataRole.UserRole, path)
            self.list.addItem(it)

    def on_list_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_view(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先選一個檔案。")
            return
        path = it.data(Qt.ItemDataRole.UserRole)
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        cfg["file_path"] = path
        self._busy(True)
        self.status.setText(f"讀取「{path}」中…")
        self.status.setStyleSheet("")
        self.content_worker = Worker(cfg, mode="file_content")
        self.content_worker.hooks.connect(lambda text, p=path: self._show_content(p, text))
        self.content_worker.done.connect(self.on_view_done)
        self.content_worker.start()

    def _show_content(self, path, text):
        is_md = path.lower().endswith((".md", ".markdown"))
        dlg = TextViewDialog(self, f"{self.repo_name}:{path}", text or "（空檔案）", markdown=is_md)
        dlg.exec()

    def on_view_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_blame(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先選一個檔案。")
            return
        path = it.data(Qt.ItemDataRole.UserRole)
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        cfg["file_path"] = path
        self._busy(True)
        self.status.setText(f"讀取「{path}」blame 中…")
        self.status.setStyleSheet("")
        self.content_worker = Worker(cfg, mode="file_blame")
        self.content_worker.hooks.connect(lambda text, p=path: self._show_blame(p, text))
        self.content_worker.done.connect(self.on_view_done)
        self.content_worker.start()

    def _show_blame(self, path, text):
        dlg = TextViewDialog(self, f"Blame — {self.repo_name}:{path}", text or "（空檔案）")
        dlg.exec()


# ============================================================
# Commit Log 瀏覽對話框（某分支的完整歷史，不只最後一筆）
# ============================================================
class RepoLogDialog(QDialog):
    def __init__(self, parent, cfg, repo_name):
        super().__init__(parent)
        self.cfg = cfg
        self.repo_name = repo_name
        self.worker = None
        self.branch_worker = None
        self.setWindowTitle(f"Commit Log — {repo_name}")
        self.resize(720, 560)

        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("分支："))
        self.branch_combo = QComboBox()
        row.addWidget(self.branch_combo, stretch=1)
        row.addWidget(QLabel("筆數："))
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 1000)
        self.count_spin.setValue(50)
        row.addWidget(self.count_spin)
        self.query_b = QPushButton("查詢")
        self.query_b.clicked.connect(self.on_query)
        row.addWidget(self.query_b)
        lay.addLayout(row)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setFont(QFont("Consolas", 10))
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(self.view, stretch=1)

        brow = QHBoxLayout()
        copy_b = QPushButton("複製全部")
        copy_b.clicked.connect(lambda: QApplication.clipboard().setText(self.view.toPlainText()))
        close_b = QPushButton("關閉")
        close_b.clicked.connect(self.accept)
        brow.addWidget(copy_b)
        brow.addStretch(1)
        brow.addWidget(close_b)
        lay.addLayout(brow)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self._load_branches()

    def _busy(self, b):
        self.query_b.setEnabled(not b)

    def _load_branches(self):
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        self.branch_worker = Worker(cfg, mode="repo_branches")
        self.branch_worker.repos.connect(self._on_branches)
        self.branch_worker.done.connect(self._on_branches_done)
        self.branch_worker.start()

    def _on_branches(self, names):
        self.branch_combo.clear()
        self.branch_combo.addItems(names)

    def _on_branches_done(self, ok, msg):
        if ok and self.branch_combo.count() > 0:
            self.on_query()
        elif not ok:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")

    def on_query(self):
        branch = self.branch_combo.currentText().strip()
        if not branch:
            self.status.setText("此庫沒有可用分支。")
            return
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        cfg["branch"] = branch
        cfg["count"] = self.count_spin.value()
        self._busy(True)
        self.status.setText(f"讀取「{branch}」log 中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode="repo_log")
        self.worker.hooks.connect(self.view.setPlainText)
        self.worker.done.connect(self.on_query_done)
        self.worker.start()

    def on_query_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")


# ============================================================
# Diff 比較對話框（同倉庫內任兩個分支/commit）
# ============================================================
class RepoDiffDialog(QDialog):
    def __init__(self, parent, cfg, repo_name):
        super().__init__(parent)
        self.cfg = cfg
        self.repo_name = repo_name
        self.worker = None
        self.branch_worker = None
        self.setWindowTitle(f"Diff 比較 — {repo_name}")
        self.resize(760, 580)

        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("A："))
        self.combo_a = QComboBox()
        self.combo_a.setEditable(True)
        row.addWidget(self.combo_a, stretch=1)
        row.addWidget(QLabel("B："))
        self.combo_b = QComboBox()
        self.combo_b.setEditable(True)
        row.addWidget(self.combo_b, stretch=1)
        lay.addLayout(row)

        row2 = QHBoxLayout()
        self.stat_chk = QCheckBox("只顯示統計（--stat，不看完整內容差異）")
        self.stat_chk.setChecked(True)
        row2.addWidget(self.stat_chk)
        row2.addStretch(1)
        self.diff_b = QPushButton("比較")
        self.diff_b.clicked.connect(self.on_diff)
        row2.addWidget(self.diff_b)
        lay.addLayout(row2)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setFont(QFont("Consolas", 10))
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(self.view, stretch=1)

        brow = QHBoxLayout()
        copy_b = QPushButton("複製全部")
        copy_b.clicked.connect(lambda: QApplication.clipboard().setText(self.view.toPlainText()))
        close_b = QPushButton("關閉")
        close_b.clicked.connect(self.accept)
        brow.addWidget(copy_b)
        brow.addStretch(1)
        brow.addWidget(close_b)
        lay.addLayout(brow)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self._load_branches()

    def _busy(self, b):
        self.diff_b.setEnabled(not b)

    def _load_branches(self):
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        self.branch_worker = Worker(cfg, mode="repo_branches")
        self.branch_worker.repos.connect(self._on_branches)
        self.branch_worker.done.connect(self._on_branches_done)
        self.branch_worker.start()

    def _on_branches(self, names):
        self.combo_a.clear()
        self.combo_b.clear()
        self.combo_a.addItems(names)
        self.combo_b.addItems(names)
        if len(names) >= 2:
            self.combo_b.setCurrentIndex(1)

    def _on_branches_done(self, ok, msg):
        if not ok:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")

    def on_diff(self):
        ref_a = self.combo_a.currentText().strip()
        ref_b = self.combo_b.currentText().strip()
        if not ref_a or not ref_b:
            self.status.setText("請指定 A 與 B 兩個分支/commit。")
            return
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        cfg["ref_a"] = ref_a
        cfg["ref_b"] = ref_b
        cfg["stat_only"] = self.stat_chk.isChecked()
        self._busy(True)
        self.status.setText(f"比較 {ref_a}..{ref_b} 中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode="repo_diff")
        self.worker.hooks.connect(self.view.setPlainText)
        self.worker.done.connect(self.on_diff_done)
        self.worker.start()

    def on_diff_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")


# ============================================================
# 新增 Tag / Release 子對話框
# ============================================================
class CreateTagDialog(QDialog):
    def __init__(self, parent, branches):
        super().__init__(parent)
        self.setWindowTitle("新增 Tag / Release")
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        g = QGridLayout()
        g.addWidget(QLabel("Tag 名稱："), 0, 0)
        self.tag_edit = QLineEdit()
        self.tag_edit.setPlaceholderText("例如 v1.2.0")
        g.addWidget(self.tag_edit, 0, 1)
        g.addWidget(QLabel("標記於（分支/commit）："), 1, 0)
        self.ref_combo = QComboBox()
        self.ref_combo.setEditable(True)
        self.ref_combo.addItems(branches)
        g.addWidget(self.ref_combo, 1, 1)
        lay.addLayout(g)
        lay.addWidget(QLabel("Release 說明（tag message，可留空）："))
        self.msg_edit = QPlainTextEdit()
        self.msg_edit.setFixedHeight(100)
        lay.addWidget(self.msg_edit)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("建立")
        lay.addWidget(bb)

    def _ok(self):
        if not self.tag_edit.text().strip() or not self.ref_combo.currentText().strip():
            QMessageBox.information(self, "缺欄位", "請輸入 tag 名稱與要標記的分支/commit。")
            return
        self.accept()

    def values(self):
        return (self.tag_edit.text().strip(),
                self.ref_combo.currentText().strip(),
                self.msg_edit.toPlainText().strip())


# ============================================================
# Tag / Release 管理對話框（annotated tag 當簡易 Release）
# ============================================================
class TagDialog(QDialog):
    def __init__(self, parent, cfg, repo_name):
        super().__init__(parent)
        self.cfg = cfg
        self.repo_name = repo_name
        self.worker = None
        self.branch_worker = None
        self._branches = []
        self.setWindowTitle(f"Tag / Release — {repo_name}")
        self.resize(640, 460)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("此庫的 annotated tag（可當作簡易 Release 標記；不含檔案下載/HTML 頁面）。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)

        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.create_b = QPushButton("新增 Tag…")
        self.delete_b = QPushButton("刪除")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.create_b)
        row.addWidget(self.delete_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.create_b.clicked.connect(self.on_create)
        self.delete_b.clicked.connect(self.on_delete)
        self.close_b.clicked.connect(self.accept)

        self._load_branches()
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.create_b, self.delete_b):
            x.setEnabled(not b)

    def _load_branches(self):
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        self.branch_worker = Worker(cfg, mode="repo_branches")
        self.branch_worker.repos.connect(self._on_branches)
        self.branch_worker.start()

    def _on_branches(self, names):
        self._branches = names

    def refresh(self):
        self.list.clear()
        self._busy(True)
        self.status.setText("讀取中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.repo_name
        self.worker = Worker(cfg, mode="tag_list")
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, entries):
        self.list.clear()
        for tag, date, tagger, subject in entries:
            label = f"{tag}    {date}"
            if tagger:
                label += f"  by {tagger}"
            if subject:
                label += f"  — {subject}"
            it = QListWidgetItem(label)
            it.setData(Qt.ItemDataRole.UserRole, tag)
            self.list.addItem(it)

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_create(self):
        dlg = CreateTagDialog(self, self._branches)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        tag, ref, msg = dlg.values()
        cfg = dict(self.cfg)
        cfg.update({"repo_name": self.repo_name, "tag_name": tag, "tag_ref": ref, "tag_message": msg})
        self._busy(True)
        self.status.setText(f"建立 tag「{tag}」中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode="tag_create")
        self.worker.done.connect(self._on_create_done)
        self.worker.start()

    def _on_create_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            self.refresh()

    def on_delete(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先選一個 tag。")
            return
        tag = it.data(Qt.ItemDataRole.UserRole)
        r = QMessageBox.question(self, "刪除 tag", f"確定刪除 tag「{tag}」？此動作無法復原。")
        if r != QMessageBox.StandardButton.Yes:
            return
        cfg = dict(self.cfg)
        cfg.update({"repo_name": self.repo_name, "tag_name": tag})
        self._busy(True)
        self.status.setText(f"刪除 tag「{tag}」中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode="tag_delete")
        self.worker.done.connect(self._on_delete_done)
        self.worker.start()

    def _on_delete_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "tag_delete",
                      f"{self.repo_name}: {msg}".replace("\n", " "))
            self.refresh()


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

        tb = QGroupBox("初始內容模板（可選，會建立第一筆 commit）")
        tl = QVBoxLayout(tb)
        self.cb_readme = QCheckBox("加入 README.md（標題帶倉庫名）")
        self.cb_gitignore = QCheckBox("加入 .gitignore（Python 常見規則）")
        tl.addWidget(self.cb_readme)
        tl.addWidget(self.cb_gitignore)
        lay.addWidget(tb)

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
                self.branch_edit.text().strip() or "develop", pol,
                self.cb_readme.isChecked(), self.cb_gitignore.isChecked())


# ============================================================
# 分支保護對話框（git 原生 receive.denyDeletes / denyNonFastForwards）
# ============================================================
class BranchProtectDialog(QDialog):
    def __init__(self, parent, cfg, name):
        super().__init__(parent)
        self.cfg = cfg
        self.name = name
        self.worker = None
        self.setWindowTitle(f"分支保護 — {name}")
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "以 git 原生設定保護此倉庫，push 端會直接被擋（與 CI policy 引擎彼此獨立、互不影響）。"))
        self.cb_del = QCheckBox("禁止刪除分支/tag（receive.denyDeletes）")
        self.cb_ff = QCheckBox("禁止強制推送 / 非快轉更新（receive.denyNonFastForwards）")
        lay.addWidget(self.cb_del)
        lay.addWidget(self.cb_ff)
        self.status = QLabel("讀取目前設定中…")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.bb.accepted.connect(self.on_save)
        self.bb.rejected.connect(self.reject)
        self.bb.setEnabled(False)
        lay.addWidget(self.bb)
        self._load()

    def _load(self):
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.name
        self.worker = Worker(cfg, mode="branch_protect_get")
        self.worker.hooks.connect(self._on_loaded)
        self.worker.done.connect(self._on_load_done)
        self.worker.start()

    def _on_loaded(self, text):
        vals = {}
        for ln in text.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                vals[k.strip()] = v.strip()
        self.cb_del.setChecked(vals.get("denyDeletes", "false") == "true")
        self.cb_ff.setChecked(vals.get("denyNonFastForwards", "false") == "true")

    def _on_load_done(self, ok, msg):
        self.bb.setEnabled(True)
        self.status.setText("" if ok else ("❌ " + msg))
        self.status.setStyleSheet("" if ok else "color:#b00020;")

    def on_save(self):
        self.bb.setEnabled(False)
        self.status.setText("儲存中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.name
        cfg["deny_deletes"] = self.cb_del.isChecked()
        cfg["deny_nonff"] = self.cb_ff.isChecked()
        self.worker = Worker(cfg, mode="branch_protect_set")
        self.worker.done.connect(self._on_saved)
        self.worker.start()

    def _on_saved(self, ok, msg):
        self.bb.setEnabled(True)
        if ok:
            QMessageBox.information(self, "完成", msg)
            self.accept()
        else:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")


# ============================================================
# Telegram 通知設定對話框（config/tg_bot.conf，CI 引擎與鏡像同步腳本共用）
# ============================================================
class NotifyConfigDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.worker = None
        self.setWindowTitle("Telegram 通知設定")
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "CI 引擎（soft/strict 警告）與 GitHub 鏡像同步腳本共用這份設定（NAS 上 config/tg_bot.conf）。留空即停用通知。"))
        g = QGridLayout()
        g.addWidget(QLabel("Bot Token："), 0, 0)
        self.token_edit = QLineEdit()
        g.addWidget(self.token_edit, 0, 1)
        g.addWidget(QLabel("Chat ID："), 1, 0)
        self.chat_edit = QLineEdit()
        g.addWidget(self.chat_edit, 1, 1)
        lay.addLayout(g)
        self.status = QLabel("讀取中…")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.bb.accepted.connect(self.on_save)
        self.bb.rejected.connect(self.reject)
        self.bb.setEnabled(False)
        lay.addWidget(self.bb)
        self._load()

    def _load(self):
        self.worker = Worker(dict(self.cfg), mode="tg_conf_get")
        self.worker.hooks.connect(self._on_loaded)
        self.worker.done.connect(self._on_load_done)
        self.worker.start()

    def _on_loaded(self, text):
        for ln in text.splitlines():
            if ln.startswith("TOKEN="):
                self.token_edit.setText(ln[len("TOKEN="):])
            elif ln.startswith("CHAT="):
                self.chat_edit.setText(ln[len("CHAT="):])

    def _on_load_done(self, ok, msg):
        self.bb.setEnabled(True)
        self.status.setText("" if ok else ("❌ " + msg))
        self.status.setStyleSheet("" if ok else "color:#b00020;")

    def on_save(self):
        self.bb.setEnabled(False)
        self.status.setText("儲存中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["tg_token"] = self.token_edit.text().strip()
        cfg["tg_chat"] = self.chat_edit.text().strip()
        self.worker = Worker(cfg, mode="tg_conf_set")
        self.worker.done.connect(self._on_saved)
        self.worker.start()

    def _on_saved(self, ok, msg):
        self.bb.setEnabled(True)
        if ok:
            QMessageBox.information(self, "完成", msg)
            self.accept()
        else:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")


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
        lay.addWidget(QLabel("「安全下庄」搬走或打包的倉庫放這裡，可還原或永久刪除。每一項前面有勾選框，可多選後批次清理。"))
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

        row2 = QHBoxLayout()
        self.check_stale_b = QPushButton(f"勾選超過 {ARCHIVE_STALE_DAYS} 天的項目")
        self.bulk_purge_b = QPushButton("清理已勾選…")
        row2.addWidget(self.check_stale_b)
        row2.addWidget(self.bulk_purge_b)
        row2.addStretch(1)
        lay.addLayout(row2)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.restore_b.clicked.connect(self.on_restore)
        self.purge_b.clicked.connect(self.on_purge)
        self.check_stale_b.clicked.connect(self.on_check_stale)
        self.bulk_purge_b.clicked.connect(self.on_bulk_purge)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.restore_b, self.purge_b, self.check_stale_b, self.bulk_purge_b):
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
        self._n_stale = 0
        for name, typ, size in entries:
            kind = "tarball" if typ == "file" else "目錄"
            age = self._archived_age_days(name)
            if age is not None and age >= ARCHIVE_STALE_DAYS:
                self._n_stale += 1
                label = f"⚠ {name}    [{kind}, {size}] — 已封存 {age} 天，建議檢查是否可清理"
            else:
                label = f"{name}    [{kind}, {size}]"
            it = QListWidgetItem(label)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Unchecked)
            it.setData(Qt.ItemDataRole.UserRole, name)
            self.list.addItem(it)

    @staticmethod
    def _archived_age_days(name: str):
        """從封存名稱（*.YYYYMMDD-HHMMSS 或 *.YYYYMMDD-HHMMSS.tar.gz）解析封存天數，解析不出來回傳 None。"""
        m = re.search(r"\.(\d{8})-(\d{6})(?:\.tar\.gz)?$", name)
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
        except ValueError:
            return None
        return (datetime.now() - ts).days

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
        n_stale = getattr(self, "_n_stale", 0)
        if ok and self.worker and self.worker.mode == "archive_list" and n_stale:
            msg += f"\n其中 {n_stale} 個已封存超過 {ARCHIVE_STALE_DAYS} 天（見 ⚠ 標記），建議檢查是否可清理。"
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#b06000;" if (ok and n_stale) else ("color:#1a7f37;" if ok else "color:#b00020;"))
        if ok and self.worker and self.worker.mode == "archive_purge":
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "archive_purge", msg.replace("\n", " "))
        if ok and self.worker and self.worker.mode in ("archive_restore", "archive_purge"):
            self.refresh()

    def on_check_stale(self):
        for i in range(self.list.count()):
            it = self.list.item(i)
            name = it.data(Qt.ItemDataRole.UserRole)
            age = self._archived_age_days(name) if name else None
            if age is not None and age >= ARCHIVE_STALE_DAYS:
                it.setCheckState(Qt.CheckState.Checked)

    def _checked_names(self):
        names = []
        for i in range(self.list.count()):
            it = self.list.item(i)
            if it.checkState() == Qt.CheckState.Checked:
                n = it.data(Qt.ItemDataRole.UserRole)
                if n:
                    names.append(n)
        return names

    def on_bulk_purge(self):
        names = self._checked_names()
        if not names:
            self.status.setText("請先勾選要清理的項目。")
            return
        r = QMessageBox.question(
            self, "批次永久刪除",
            f"確定永久刪除以下 {len(names)} 個封存項目？此動作無法復原：\n" + "\n".join(names))
        if r != QMessageBox.StandardButton.Yes:
            return
        self._purge_queue = list(names)
        self._purge_ok = 0
        self._purge_fail = 0
        self._busy(True)
        self._run_next_purge()

    def _run_next_purge(self):
        if not self._purge_queue:
            self._busy(False)
            msg = f"批次清理完成：成功 {self._purge_ok}、失敗 {self._purge_fail}。"
            self.status.setText(("✔ " if self._purge_fail == 0 else "⚠ ") + msg)
            self.status.setStyleSheet("color:#1a7f37;" if self._purge_fail == 0 else "color:#b06000;")
            self.refresh()
            return
        name = self._purge_queue.pop(0)
        self._purging_name = name
        self.status.setText(f"刪除中… {name}（剩 {len(self._purge_queue) + 1} 個）")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["arch_name"] = name
        self.worker = Worker(cfg, mode="archive_purge")
        self.worker.done.connect(self._on_bulk_purge_one_done)
        self.worker.start()

    def _on_bulk_purge_one_done(self, ok, msg):
        if ok:
            self._purge_ok += 1
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "archive_purge",
                      getattr(self, "_purging_name", "").replace("\n", " ") + " (批次清理)")
        else:
            self._purge_fail += 1
        self._run_next_purge()


# ============================================================
# 活動總覽對話框（所有倉庫依最後 commit 時間排序）
# ============================================================
class ActivityDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.worker = None
        self.setWindowTitle("活動總覽 — 依最近 push 排序")
        self.resize(620, 480)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("所有倉庫依最後一次 commit 時間排序（新到舊），空庫排最後。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def refresh(self):
        self.list.clear()
        self.refresh_b.setEnabled(False)
        self.status.setText("讀取中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        self.worker = Worker(cfg, mode="list")
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, entries):
        self.list.clear()
        dated = []
        empty = []
        for item in entries:
            name = item[0]
            status = item[1] if len(item) > 1 else ""
            m = re.match(r"^(\d{4}-\d{2}-\d{2})\s*\((.+)\)$", status)
            if m:
                dated.append((m.group(1), m.group(2), name))
            else:
                empty.append(name)
        dated.sort(key=lambda t: t[0], reverse=True)
        for date, branch, name in dated:
            self.list.addItem(QListWidgetItem(f"{date}  {name}  ({branch})"))
        for name in empty:
            self.list.addItem(QListWidgetItem(f"—           {name}  （空庫）"))

    def on_done(self, ok, msg):
        self.refresh_b.setEnabled(True)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")


# ============================================================
# SSH 授權金鑰管理對話框（僅限目前身份自己這個帳號的 authorized_keys）
# ============================================================
class SshKeysDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.worker = None
        self.setWindowTitle(f"SSH 金鑰管理 — {cfg.get('user', '')}@{cfg.get('host', '')}")
        self.resize(680, 440)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("目前身份這個 SSH 帳號自己的 authorized_keys（只影響這一個帳號，不動其他人）。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.add_b = QPushButton("新增金鑰…")
        self.delete_b = QPushButton("刪除")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.add_b)
        row.addWidget(self.delete_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.add_b.clicked.connect(self.on_add)
        self.delete_b.clicked.connect(self.on_delete)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.add_b, self.delete_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
        self.status.setText("讀取中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        self.worker = Worker(cfg, mode="ssh_keys_list")
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, keys):
        self.list.clear()
        for line in keys:
            parts = line.split(None, 2)
            ktype = parts[0] if len(parts) > 0 else "?"
            comment = parts[2] if len(parts) > 2 else "(無註解)"
            fp = ssh_fingerprint(line)
            it = QListWidgetItem(f"{ktype}  {comment}\n    {fp}")
            it.setData(Qt.ItemDataRole.UserRole, line)
            self.list.addItem(it)

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_add(self):
        text, ok = QInputDialog.getMultiLineText(
            self, "新增授權金鑰", "貼上公鑰內容（例如 id_ed25519.pub 的內容，單行）：")
        text = text.strip()
        if not ok or not text:
            return
        cfg = dict(self.cfg)
        cfg["key_line"] = text
        self._busy(True)
        self.status.setText("新增中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode="ssh_keys_add")
        self.worker.done.connect(self._on_add_done)
        self.worker.start()

    def _on_add_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            self.refresh()

    def on_delete(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先選一把金鑰。")
            return
        line = it.data(Qt.ItemDataRole.UserRole)
        r = QMessageBox.question(self, "刪除授權金鑰", "確定移除這把金鑰？原檔會先備份。\n\n" + it.text())
        if r != QMessageBox.StandardButton.Yes:
            return
        cfg = dict(self.cfg)
        cfg["key_line"] = line
        self._deleting_line = line
        self._busy(True)
        self.status.setText("刪除中…")
        self.status.setStyleSheet("")
        self.worker = Worker(cfg, mode="ssh_keys_delete")
        self.worker.done.connect(self._on_delete_done)
        self.worker.start()

    def _on_delete_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "ssh_keys_delete",
                      getattr(self, "_deleting_line", "").replace("\n", " "))
            self.refresh()


# ============================================================
# 新增 git_devs 帳號：查詢現況 + 產生指令（工具本身不執行，需使用者自行以特權身份貼上跑）
# ============================================================
class CreateGitDevsUserDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.worker = None
        self.setWindowTitle("新增 git_devs 帳號")
        self.setMinimumWidth(520)

        lay = QVBoxLayout(self)
        note = QLabel(
            "這個工具沒有免密碼 sudo，沒辦法自己在 NAS 上建帳號。填好欄位按「產生設定指令」，"
            "把產生出來的整段指令複製、貼到一個有 sudo 權限的 SSH 視窗，一次執行到底就好——"
            "全程只有一開始的 sudo 密碼要你手動輸入，其餘都自動處理、自動核對。"
            f"新帳號密碼會自動產生並留底到本機 {GIT_DEVS_CRED_LOG_PATH}（明碼檔案，請自行妥善保護）。"
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#666;")
        lay.addWidget(note)

        g = QGridLayout()
        g.addWidget(QLabel("帳號名稱："), 0, 0)
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("小寫英文開頭，例如 alice（將加入 git_devs 群組）")
        g.addWidget(self.user_edit, 0, 1)
        g.addWidget(QLabel("描述（可留空）："), 1, 0)
        self.desc_edit = QLineEdit()
        g.addWidget(self.desc_edit, 1, 1)
        g.addWidget(QLabel("Email（可留空）："), 2, 0)
        self.email_edit = QLineEdit()
        g.addWidget(self.email_edit, 2, 1)
        lay.addLayout(g)

        lay.addWidget(QLabel("該帳號要用來 push 的 SSH 公鑰（.pub 檔內容，由申請人自己產生、只給公鑰）："))
        self.pubkey_edit = QPlainTextEdit()
        self.pubkey_edit.setPlaceholderText("ssh-ed25519 AAAA... comment")
        self.pubkey_edit.setFixedHeight(80)
        lay.addWidget(self.pubkey_edit)

        row = QHBoxLayout()
        self.gen_b = QPushButton("產生設定指令")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.gen_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.gen_b.clicked.connect(self.on_generate)
        self.close_b.clicked.connect(self.accept)

    def on_generate(self):
        username = self.user_edit.text().strip()
        if not is_safe_username(username):
            self.status.setText("帳號名稱不合規：僅允許小寫英文開頭，接小寫英數字/底線/連字號。")
            self.status.setStyleSheet("color:#b00020;")
            return
        pubkey = " ".join(self.pubkey_edit.toPlainText().split())
        if not is_ssh_pubkey(pubkey):
            self.status.setText("公鑰格式看起來不對，應以 ssh-rsa / ssh-ed25519 等開頭。")
            self.status.setStyleSheet("color:#b00020;")
            return
        self.gen_b.setEnabled(False)
        self.status.setText("查詢 git_devs 現況中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["new_user"] = username
        self.worker = Worker(cfg, mode="prep_new_user")
        self.worker.hooks.connect(lambda text: self._on_queried(username, pubkey, text))
        self.worker.done.connect(self.on_query_done)
        self.worker.start()

    def on_query_done(self, ok, msg):
        self.gen_b.setEnabled(True)
        if not ok:
            self.status.setText("❌ " + msg.replace("\n", "　"))
            self.status.setStyleSheet("color:#b00020;")

    def _on_queried(self, username, pubkey, text):
        exists = False
        members = ""
        for ln in text.splitlines():
            if ln.startswith("EXISTS="):
                exists = ln[len("EXISTS="):].strip() == "1"
            elif ln.startswith("MEMBERS="):
                members = ln[len("MEMBERS="):].strip()
        if exists:
            self.status.setText(f"⚠ 帳號「{username}」已經存在，以下指令仍會產生，但建帳號那段請自行判斷是否跳過。")
            self.status.setStyleSheet("color:#b06000;")
        else:
            self.status.setText(f"✔ 查詢完成，「{username}」目前不存在，可以建立。")
            self.status.setStyleSheet("color:#1a7f37;")
        member_list = [m for m in members.split(",") if m]
        alphabet = string.ascii_letters + string.digits
        password = "".join(secrets.choice(alphabet) for _ in range(16))
        save_git_devs_credential(self.cfg.get("user", ""), self.cfg.get("host", ""), username, password)
        QMessageBox.information(
            self, "密碼已留底",
            f"「{username}」的登入密碼已寫入本機檔案：\n{GIT_DEVS_CRED_LOG_PATH}\n\n"
            "這是明碼檔案，請自行妥善保護（例如搬到有加密的資料夾），不需要的紀錄記得定期清理。")
        script = self._build_script(username, pubkey, member_list, exists, password)
        dlg = TextViewDialog(self, f"新增 git_devs 帳號 — 待執行指令（{username}）", script)
        dlg.exec()

    def _build_script(self, username, pubkey, member_list, exists, password):
        desc = self.desc_edit.text().strip() or username
        email = self.email_edit.text().strip()
        root = self.cfg.get("remote_root", "/volume1/Git_Server")
        all_members = member_list + [username]
        new_members = " ".join(all_members)
        lines = [
            "# ============================================================",
            f"# 新增 git_devs 帳號：{username}",
            "# 由 NasGitConnector 產生，這段指令不會自動執行。",
            "# 整段複製、貼到有 sudo 權限的 SSH 視窗、一次執行到底即可。",
            "# 全程唯一會問你的是最開頭的 sudo -v（問你自己的登入密碼），其餘全自動，不用手動改任何一行。",
            "# synouser 的參數順序可能因 DSM 版本略有不同，若第 1 步報錯，先跑 `synouser --help` 核對。",
            "# ============================================================",
            "",
            "# 0) 先讓 sudo 記住密碼，避免整段貼下去時中途又跳密碼提示、把後面指令吃掉／打斷",
            "sudo -v",
            "",
            f"# 1) 建立 DSM 使用者（密碼已由 NasGitConnector 產生並存到本機 {GIT_DEVS_CRED_LOG_PATH}）",
        ]
        if exists:
            lines.append(f"#    帳號 {username} 已存在，這段可能不需要，請自行判斷是否跳過：")
        lines += [
            f"sudo synouser --add {username} '{password}' \"{desc}\" \"{email}\" 0 0",
            "",
            "# 2) 加入 git_devs 群組",
            "#    注意：synogroup --member 是「整批覆蓋」不是「附加」！",
            f"#    以下已經把產生指令當下查到的既有成員（{', '.join(member_list) or '（查不到既有成員——如果你知道應該有人，先手動核對 /etc/group 再繼續，不要照跑下一行）'}）都列進去。",
            f"sudo synogroup --member git_devs {new_members}",
            "#    執行完立刻回讀名單自我檢查，任何一個原本該在的人不見了就大聲警告：",
            "AFTER_MEMBERS=$(grep '^git_devs:' /etc/group | cut -d: -f4)",
            f"for m in {new_members}; do",
            '  case ",$AFTER_MEMBERS," in',
            '    *",$m,"*) ;;',
            '    *) echo "‼️  警告：$m 不在更新後的 git_devs 名單裡（目前：$AFTER_MEMBERS），可能被踢出，請立刻人工確認並補回！" ;;',
            "  esac",
            "done",
            'echo "目前 git_devs 成員：$AFTER_MEMBERS"',
            "",
            "# 3) 確認實際 home 目錄（不同 DSM 設定可能不是 /var/services/homes/<帳號>）",
            f"HOME_DIR=$(grep \"^{username}:\" /etc/passwd | cut -d: -f6)",
            f'[ -z "$HOME_DIR" ] && HOME_DIR=/var/services/homes/{username}',
            'echo "偵測到的 home 目錄：$HOME_DIR"',
            "",
            "# 4) 設定 SSH 金鑰登入",
            'sudo mkdir -p "$HOME_DIR/.ssh"',
            "sudo tee \"$HOME_DIR/.ssh/authorized_keys\" >/dev/null <<'EOF'",
            pubkey,
            "EOF",
            'sudo chmod 700 "$HOME_DIR/.ssh"',
            'sudo chmod 600 "$HOME_DIR/.ssh/authorized_keys"',
            f'sudo chown -R {username}:users "$HOME_DIR/.ssh"',
            "",
            "# 5) 同步既有倉庫權限，讓新帳號一開始就能直接 push（跟修 kuoterry/Git_User1 那次同一件事）",
            f"sudo chmod -R g+rwX {root}",
            f"sudo find {root} -maxdepth 1 -type d -name '*.git' -exec chmod g+s {{}} \\;",
            "",
            "# 6) 完成後回這套工具按「一鍵修復…」，把 core.sharedRepository=group 補到每個既有倉庫。",
        ]
        return "\n".join(lines)


# ============================================================
# 跨庫搜尋結果對話框（雙擊直接開啟檔案並跳到該行）
# ============================================================
class GrepResultsDialog(QDialog):
    def __init__(self, parent, cfg, pattern):
        super().__init__(parent)
        self.cfg = cfg
        self.pattern = pattern
        self.worker = None
        self.content_worker = None
        self.setWindowTitle(f"跨庫搜尋結果 — {pattern}")
        self.resize(780, 540)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"搜尋「{pattern}」（各庫預設分支）。雙擊或按「開啟檔案」可直接預覽並跳到該行。"))
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self.on_open)
        lay.addWidget(self.list, stretch=1)

        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新搜尋")
        self.open_b = QPushButton("開啟檔案")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.open_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.open_b.clicked.connect(self.on_open)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.open_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
        self.status.setText("搜尋中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["pattern"] = self.pattern
        self.worker = Worker(cfg, mode="grep_all")
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, hits):
        self.list.clear()
        for repo, path, lineno, content in hits:
            it = QListWidgetItem(f"{repo}  {path}:{lineno}   {content.strip()}")
            it.setData(Qt.ItemDataRole.UserRole, (repo, path, lineno))
            self.list.addItem(it)
        if not hits:
            self.list.addItem(QListWidgetItem("（沒有找到符合的內容）"))

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_open(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先選一筆結果。")
            return
        data = it.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        repo, path, lineno = data
        cfg = dict(self.cfg)
        cfg["repo_name"] = repo
        cfg["file_path"] = path
        self._busy(True)
        self.status.setText(f"讀取「{repo}:{path}」中…")
        self.status.setStyleSheet("")
        self.content_worker = Worker(cfg, mode="file_content")
        self.content_worker.hooks.connect(lambda text, r=repo, p=path, ln=lineno: self._show(r, p, ln, text))
        self.content_worker.done.connect(self.on_open_done)
        self.content_worker.start()

    def _show(self, repo, path, lineno, text):
        is_md = path.lower().endswith((".md", ".markdown"))
        dlg = TextViewDialog(self, f"{repo}:{path}", text or "（空檔案）",
                              markdown=is_md, goto_line=None if is_md else lineno)
        dlg.exec()

    def on_open_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")


# ============================================================
# 註冊 GitHub 鏡像 對話框
# ============================================================
class MirrorDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("註冊 GitHub 鏡像庫")
        self.setMinimumWidth(500)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("讓 NAS 直接對應一個 GitHub 倉庫（NAS 會去 GitHub 拉，之後可同步/排程）。"))
        g = QGridLayout()
        g.addWidget(QLabel("GitHub URL："), 0, 0)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://github.com/作者/repo.git")
        self.url_edit.textChanged.connect(self._suggest_name)
        g.addWidget(self.url_edit, 0, 1)
        g.addWidget(QLabel("NAS 庫名："), 1, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("自動由 URL 帶入，可改（會自動補 .git）")
        g.addWidget(self.name_edit, 1, 1)
        lay.addLayout(g)
        note = QLabel("提醒：鏡像庫是唯讀對應上游，別把自己的 commit 推進去。私有庫需在 NAS 端設好 GitHub 金鑰/token。")
        note.setWordWrap(True)
        note.setStyleSheet("color:#666;")
        lay.addWidget(note)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("建立鏡像")
        lay.addWidget(bb)

    def _suggest_name(self, url):
        if self.name_edit.text().strip() and self.name_edit.property("edited"):
            return
        seg = url.rstrip("/").split("/")[-1] if url else ""
        if seg.endswith(".git"):
            seg = seg[:-4]
        self.name_edit.setText(seg)

    def _ok(self):
        if not self.url_edit.text().strip():
            QMessageBox.information(self, "缺 URL", "請輸入 GitHub URL。")
            return
        if not self.name_edit.text().strip():
            QMessageBox.information(self, "缺庫名", "請輸入 NAS 庫名。")
            return
        self.accept()

    def values(self):
        return self.url_edit.text().strip(), self.name_edit.text().strip()


# ============================================================
# 主視窗
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NAS Git 專案串接工具 v{__version__}")
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
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["排序：名稱", "排序：大小（大到小）", "排序：最近活動"])
        self.sort_combo.currentIndexChanged.connect(lambda _=None: self.apply_repo_filter(self.filter_edit.text()))
        self.mirror_reg_btn = QPushButton("註冊鏡像…")
        self.mirror_reg_btn.setToolTip("讓 NAS 直接對應一個 GitHub 倉庫（git clone --mirror）。")
        self.mirror_reg_btn.clicked.connect(self.on_create_mirror)
        self.mirror_sync_btn = QPushButton("同步鏡像")
        self.mirror_sync_btn.setToolTip("對選取的鏡像庫執行 remote update；沒選就同步全部鏡像。")
        self.mirror_sync_btn.clicked.connect(self.on_sync_mirrors)

        top_row.addWidget(self.refresh_btn)
        top_row.addWidget(self.ci_status_btn)
        top_row.addWidget(self.upgrade_btn)
        top_row.addWidget(self.filter_edit, stretch=1)
        top_row.addWidget(self.sort_combo)
        bp.addLayout(top_row)

        top_row2 = QHBoxLayout()
        top_row2.addWidget(self.create_btn)
        top_row2.addWidget(self.archive_btn)
        top_row2.addWidget(self.mirror_reg_btn)
        top_row2.addWidget(self.mirror_sync_btn)
        top_row2.addStretch(1)
        bp.addLayout(top_row2)

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
        self.files_btn = QPushButton("檔案列表…")
        self.files_btn.setEnabled(False)
        self.files_btn.setToolTip("不用 clone，直接列出此庫在預設分支下的所有檔案與大小。")
        self.files_btn.clicked.connect(self.on_repo_files)
        danger_row.addWidget(self.files_btn)
        self.desc_btn = QPushButton("編輯描述…")
        self.desc_btn.setEnabled(False)
        self.desc_btn.setToolTip("讀寫此庫的 description 檔（bare repo 原生機制），用來標註這個倉庫是幹嘛的。")
        self.desc_btn.clicked.connect(self.on_edit_desc)
        danger_row.addWidget(self.desc_btn)
        self.branch_protect_btn = QPushButton("分支保護…")
        self.branch_protect_btn.setEnabled(False)
        self.branch_protect_btn.setToolTip("設定 git 原生 receive.denyDeletes / denyNonFastForwards，與 CI 引擎彼此獨立。")
        self.branch_protect_btn.clicked.connect(self.on_branch_protect)
        danger_row.addWidget(self.branch_protect_btn)
        self.batch_ci_btn = QPushButton("批次設定 CI…")
        self.batch_ci_btn.setEnabled(False)
        self.batch_ci_btn.setToolTip("對『目前選取的多個』倉庫一次套用同一 CI 規則（可按住 Ctrl/Shift 多選）。")
        self.batch_ci_btn.clicked.connect(self.on_set_ci_batch)
        danger_row.addWidget(self.batch_ci_btn)
        self.rename_btn = QPushButton("重新命名…")
        self.rename_btn.setEnabled(False)
        self.rename_btn.setToolTip("真正 rename 這個倉庫（含同步改 ci_policies/<repo>.policy 檔名），不是封存再重建。")
        self.rename_btn.clicked.connect(self.on_rename_repo)
        danger_row.addWidget(self.rename_btn)
        danger_row.addStretch(1)
        self.delete_btn = QPushButton("安全下庄 / 刪除此倉庫…")
        self.delete_btn.setEnabled(False)
        self.delete_btn.setToolTip("先在清單選一個倉庫。預設會搬到封存區(可還原)。")
        self.delete_btn.clicked.connect(self.on_delete_repo)
        danger_row.addWidget(self.delete_btn)

        tools_row = QHBoxLayout()
        self.log_btn = QPushButton("Commit Log…")
        self.log_btn.setEnabled(False)
        self.log_btn.setToolTip("瀏覽此庫某分支的完整 commit 歷史（不只最後一筆）。")
        self.log_btn.clicked.connect(self.on_repo_log)
        tools_row.addWidget(self.log_btn)
        self.merged_btn = QPushButton("已合併分支…")
        self.merged_btn.setEnabled(False)
        self.merged_btn.setToolTip("列出已完全合併進預設分支、可考慮清理的分支（僅列出，不會自動刪除）。")
        self.merged_btn.clicked.connect(self.on_merged_branches)
        tools_row.addWidget(self.merged_btn)
        self.diff_btn = QPushButton("Diff 比較…")
        self.diff_btn.setEnabled(False)
        self.diff_btn.setToolTip("比較此庫任兩個分支/commit 的差異，不用 clone。")
        self.diff_btn.clicked.connect(self.on_repo_diff)
        tools_row.addWidget(self.diff_btn)
        self.gc_btn = QPushButton("GC 維護…")
        self.gc_btn.setEnabled(False)
        self.gc_btn.setToolTip("對選取的倉庫執行 git gc，回收空間、整理 pack（可多選）。")
        self.gc_btn.clicked.connect(self.on_repo_gc)
        tools_row.addWidget(self.gc_btn)
        self.tag_btn = QPushButton("Tag / Release…")
        self.tag_btn.setEnabled(False)
        self.tag_btn.setToolTip("列出/新增/刪除此庫的 annotated tag（可當簡易 Release 標記）。")
        self.tag_btn.clicked.connect(self.on_tag_dialog)
        tools_row.addWidget(self.tag_btn)
        self.search_all_btn = QPushButton("搜尋所有倉庫…")
        self.search_all_btn.setToolTip("在所有倉庫的預設分支下做全文搜尋（git grep），不用逐一 clone。")
        self.search_all_btn.clicked.connect(self.on_grep_all)
        tools_row.addWidget(self.search_all_btn)
        self.activity_btn = QPushButton("活動總覽…")
        self.activity_btn.setToolTip("依最後 push 時間排序，一次看所有倉庫最近有沒有動靜。")
        self.activity_btn.clicked.connect(self.on_activity_dashboard)
        tools_row.addWidget(self.activity_btn)
        self.ssh_keys_btn = QPushButton("SSH 金鑰管理…")
        self.ssh_keys_btn.setToolTip("管理目前身份這個 SSH 帳號自己的 authorized_keys（新增/刪除授權金鑰）。")
        self.ssh_keys_btn.clicked.connect(self.on_ssh_keys)
        tools_row.addWidget(self.ssh_keys_btn)
        tools_row.addStretch(1)
        bp.addLayout(danger_row)
        bp.addLayout(tools_row)

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
        self.new_user_btn = QPushButton("新增 git_devs 帳號…")
        self.new_user_btn.setToolTip("查詢 git_devs 現況並產生新增帳號的完整指令，需自行貼到有 sudo 權限的 SSH 視窗執行。")
        self.new_user_btn.clicked.connect(self.on_create_git_devs_user)
        self.disk_btn = QPushButton("伺服器空間總覽")
        self.disk_btn.setToolTip("df 可用空間、Git_Server 總用量、各倉庫大小排行前 10 大。")
        self.disk_btn.clicked.connect(self.on_disk_usage)
        self.notify_btn = QPushButton("Telegram 通知設定…")
        self.notify_btn.setToolTip("CI 引擎與 GitHub 鏡像同步腳本共用的 config/tg_bot.conf。")
        self.notify_btn.clicked.connect(self.on_notify_config)
        og.addWidget(self.hc_btn, 0, 0)
        og.addWidget(self.repair_btn, 0, 1)
        og.addWidget(self.new_user_btn, 0, 2)
        og.addWidget(self.disk_btn, 1, 0)
        og.addWidget(self.notify_btn, 1, 1)
        mp.addWidget(ops_box)

        log_box = QGroupBox("日誌檢視（最後 200 筆）")
        lg = QGridLayout(log_box)
        self.push_log_btn = QPushButton("推送日誌 git_push.log")
        self.push_log_btn.clicked.connect(lambda: self.on_view_log("git_push.log", "推送日誌"))
        self.viol_log_btn = QPushButton("CI 違規日誌 ci_violation.log")
        self.viol_log_btn.clicked.connect(lambda: self.on_view_log("ci_violation.log", "CI 違規日誌"))
        self.dbg_log_btn = QPushButton("post-receive 除錯日誌")
        self.dbg_log_btn.clicked.connect(lambda: self.on_view_log("post_receive_debug.log", "post-receive 除錯日誌"))
        self.audit_log_btn = QPushButton("本機操作稽核紀錄")
        self.audit_log_btn.setToolTip("這套工具在本機做過的刪除/砍 tag/砍金鑰/GC/批次清封存等破壞性動作紀錄。")
        self.audit_log_btn.clicked.connect(self.on_view_audit_log)
        lg.addWidget(self.push_log_btn, 0, 0)
        lg.addWidget(self.viol_log_btn, 0, 1)
        lg.addWidget(self.dbg_log_btn, 0, 2)
        lg.addWidget(self.audit_log_btn, 1, 0)
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
        self.mirror_reg_btn.setEnabled(not busy)
        self.mirror_sync_btn.setEnabled(not busy)
        self.search_all_btn.setEnabled(not busy)
        self.activity_btn.setEnabled(not busy)
        self.ssh_keys_btn.setEnabled(not busy)
        for b in (self.hc_btn, self.repair_btn, self.new_user_btn, self.disk_btn, self.notify_btn,
                  self.push_log_btn, self.viol_log_btn, self.dbg_log_btn):
            b.setEnabled(not busy)
        has_sel = len(self.repo_list.selectedItems()) > 0
        self.delete_btn.setEnabled(not busy and has_sel)
        self.ci_btn.setEnabled(not busy and has_sel)
        self.set_ci_btn.setEnabled(not busy and has_sel)
        self.selftest_btn.setEnabled(not busy and has_sel)
        self.detail_btn.setEnabled(not busy and has_sel)
        self.files_btn.setEnabled(not busy and has_sel)
        self.batch_ci_btn.setEnabled(not busy and has_sel)
        self.rename_btn.setEnabled(not busy and has_sel)
        self.clone_btn.setEnabled(not busy and has_sel)
        self.log_btn.setEnabled(not busy and has_sel)
        self.merged_btn.setEnabled(not busy and has_sel)
        self.diff_btn.setEnabled(not busy and has_sel)
        self.gc_btn.setEnabled(not busy and has_sel)
        self.tag_btn.setEnabled(not busy and has_sel)
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
        # items: (name, status, policy, mirror_url, size_kb)；容錯舊格式
        norm = []
        for it in items:
            if isinstance(it, (list, tuple)):
                name = str(it[0])
                status = str(it[1]) if len(it) > 1 else ""
                pol = str(it[2]) if len(it) > 2 else "none"
                mirror = str(it[3]) if len(it) > 3 else ""
                try:
                    size_kb = int(it[4]) if len(it) > 4 else 0
                except (TypeError, ValueError):
                    size_kb = 0
                norm.append((name, status, pol, mirror, size_kb))
            else:
                norm.append((str(it), "", "none", "", 0))
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
        rows = [r for r in self._all_repos if not text or text in r[0].lower()]
        sort_idx = self.sort_combo.currentIndex() if hasattr(self, "sort_combo") else 0
        if sort_idx == 1:  # 大小（大到小）
            rows.sort(key=lambda r: r[4], reverse=True)
        elif sort_idx == 2:  # 最近活動（依 status 裡的日期，新到舊；空庫排最後）
            def activity_key(r):
                m = re.match(r"^(\d{4}-\d{2}-\d{2})", r[1])
                return (0, m.group(1)) if m else (1, "")
            rows.sort(key=activity_key, reverse=True)
        else:  # 名稱
            rows.sort(key=lambda r: r[0].lower())
        self.repo_list.clear()
        for name, status, pol, mirror, size_kb in rows:
            ci = {"soft": "CI:soft", "strict": "CI:strict"}.get(pol, "CI:—")
            parts = [name]
            if status:
                parts.append(status)
            parts.append(ci)
            parts.append(fmt_size_kb(size_kb))
            if mirror:
                parts.append("↺鏡像")
            it = QListWidgetItem("    ·    ".join(parts))
            it.setData(Qt.ItemDataRole.UserRole, name)
            it.setData(Qt.ItemDataRole.UserRole + 1, pol)
            it.setData(Qt.ItemDataRole.UserRole + 2, mirror)
            if mirror:
                it.setToolTip(f"GitHub 鏡像 ← {mirror}")
            if status.startswith("空庫"):
                it.setForeground(Qt.GlobalColor.gray)
            self.repo_list.addItem(it)

    def _selected_mirror_names(self):
        out = []
        for it in self.repo_list.selectedItems():
            if it.data(Qt.ItemDataRole.UserRole + 2):
                out.append(it.data(Qt.ItemDataRole.UserRole) or it.text())
        return out

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
        self.files_btn.setEnabled(has)
        self.desc_btn.setEnabled(has)
        self.branch_protect_btn.setEnabled(has)
        self.batch_ci_btn.setEnabled(len(self.repo_list.selectedItems()) >= 1)
        self.rename_btn.setEnabled(has)
        self.clone_btn.setEnabled(has)
        self.log_btn.setEnabled(has)
        self.merged_btn.setEnabled(has)
        self.diff_btn.setEnabled(has)
        self.gc_btn.setEnabled(has)
        self.tag_btn.setEnabled(has)

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
            c = self.collect_identity_cfg()
            audit_log(c.get("user", ""), c.get("host", ""), "delete", msg.replace("\n", " "))
            QMessageBox.information(self, "完成", msg)
            self.on_refresh()  # 重新列出，讓清單即時更新
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "未完成", msg)

    # ---------- 重新命名倉庫 ----------
    def on_rename_repo(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        current = name[:-4] if name.endswith(".git") else name
        new_name, ok = QInputDialog.getText(self, "重新命名倉庫", f"「{current}」的新名稱：", text=current)
        new_name = new_name.strip()
        if not ok or not new_name or new_name == current:
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        cfg["new_name"] = new_name
        self.save_current_profile(silent=True)
        self.browse_status.setText(f"重新命名「{name}」中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="rename_repo")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_rename_done)
        self.worker.start()

    def on_rename_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            c = self.collect_identity_cfg()
            audit_log(c.get("user", ""), c.get("host", ""), "rename_repo", msg.replace("\n", " "))
            self.on_refresh()
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "重新命名失敗", msg)

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
            if self.worker and self.worker.mode in DESTRUCTIVE_MODES:
                c = self.collect_identity_cfg()
                audit_log(c.get("user", ""), c.get("host", ""), self.worker.mode, msg.replace("\n", " "))
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

    def on_disk_usage(self):
        self._start_maint("disk_usage", "伺服器空間總覽")

    def on_notify_config(self):
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = NotifyConfigDialog(self, cfg)
        dlg.exec()

    def on_create_git_devs_user(self):
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = CreateGitDevsUserDialog(self, cfg)
        dlg.exec()

    def on_view_log(self, logfile, title):
        self._start_maint("log", title, extra={"logfile": logfile, "log_lines": 200})

    def on_view_audit_log(self):
        try:
            with open(AUDIT_LOG_PATH, encoding="utf-8") as f:
                text = f.read().strip()
        except OSError:
            text = ""
        dlg = TextViewDialog(self, "本機操作稽核紀錄",
                              text or f"（目前沒有紀錄，檔案：{AUDIT_LOG_PATH}）")
        dlg.exec()

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
        name, branch, pol, add_readme, add_gitignore = dlg.values()
        cfg = dict(self.collect_identity_cfg())
        cfg.update({"repo_name": name, "branch": branch, "ci_policy": pol,
                    "add_readme": add_readme, "add_gitignore": add_gitignore})
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

    def on_edit_desc(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        self.save_current_profile(silent=True)
        self._desc_repo_name = name
        self.browse_status.setText(f"讀取「{name}」描述中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="repo_desc_get")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self._on_desc_fetched)
        self.worker.done.connect(self._on_desc_get_done)
        self.worker.start()

    def _on_desc_get_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("")
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "讀取失敗", msg)

    def _on_desc_fetched(self, text: str):
        name = getattr(self, "_desc_repo_name", "")
        new_text, ok = QInputDialog.getMultiLineText(
            self, f"編輯描述 — {name}",
            "此倉庫的描述（寫入 bare repo 的 description 檔，僅供人閱讀，不影響 git 行為）：", text)
        if not ok:
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        cfg["repo_desc"] = new_text
        self.browse_status.setText(f"更新「{name}」描述中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="repo_desc_set")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_desc_set_done)
        self.worker.start()

    def on_desc_set_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "更新失敗", msg)

    def on_branch_protect(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = BranchProtectDialog(self, cfg, name)
        dlg.exec()

    def on_repo_files(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = RepoFilesDialog(self, cfg, name)
        dlg.exec()

    def on_repo_log(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = RepoLogDialog(self, cfg, name)
        dlg.exec()

    def on_repo_diff(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = RepoDiffDialog(self, cfg, name)
        dlg.exec()

    def on_tag_dialog(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = TagDialog(self, cfg, name)
        dlg.exec()

    def on_activity_dashboard(self):
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = ActivityDialog(self, cfg)
        dlg.exec()

    def on_ssh_keys(self):
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = SshKeysDialog(self, cfg)
        dlg.exec()

    def on_merged_branches(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_name"] = name
        self.save_current_profile(silent=True)
        self._ci_title = f"已合併分支 — {name}"
        self.browse_status.setText(f"讀取「{name}」已合併分支中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="merged_branches")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()

    def on_repo_gc(self):
        names = self._selected_repo_names()
        if not names:
            self.browse_status.setText("請先在清單選一個或多個倉庫。")
            return
        r = QMessageBox.question(
            self, "GC 維護",
            f"確定對以下 {len(names)} 個倉庫執行 git gc？此動作會整理 pack、回收空間，過程可能需要一些時間：\n"
            + "、".join(names))
        if r != QMessageBox.StandardButton.Yes:
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_names"] = names
        self.save_current_profile(silent=True)
        self._ci_title = "GC 維護結果"
        self.browse_status.setText(f"對 {len(names)} 個倉庫執行 GC 中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="repo_gc")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()

    def on_grep_all(self):
        term, ok = QInputDialog.getText(self, "搜尋所有倉庫", "輸入要搜尋的字串（在各庫預設分支下搜尋）：")
        term = term.strip()
        if not ok or not term:
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = GrepResultsDialog(self, cfg, term)
        dlg.exec()

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

    # ---------- GitHub 鏡像 ----------
    def on_create_mirror(self):
        dlg = MirrorDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        url, name = dlg.values()
        cfg = dict(self.collect_identity_cfg())
        cfg.update({"mirror_url": url, "repo_name": name})
        self.save_current_profile(silent=True)
        self.browse_status.setText(f"建立鏡像「{name}」中…（clone --mirror 可能較久）")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="create_mirror")
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_mirror_create_done)
        self.worker.start()

    def on_mirror_create_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            QMessageBox.information(self, "完成", msg)
            self.on_refresh()
        else:
            self.browse_status.setText("❌ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#b00020;")
            QMessageBox.warning(self, "建立鏡像失敗", msg)

    def on_sync_mirrors(self):
        names = self._selected_mirror_names()  # 選取中的鏡像；空=全部
        cfg = dict(self.collect_identity_cfg())
        cfg["mirror_names"] = names
        self.save_current_profile(silent=True)
        scope = f"選取的 {len(names)} 個鏡像" if names else "全部鏡像"
        self._ci_title = "鏡像同步結果"
        self.browse_status.setText(f"同步{scope}中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="sync_mirrors")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
