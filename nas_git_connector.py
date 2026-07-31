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

__version__ = "2.6.1"

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
import json
import urllib.request
import urllib.error
import traceback
import threading
import time
import tempfile
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QGroupBox, QInputDialog, QTabWidget, QTabBar, QListWidget,
    QDialog, QRadioButton, QDialogButtonBox, QListWidgetItem, QSpinBox, QTextBrowser,
    QTableWidget, QTableWidgetItem, QHeaderView
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

# 新建空倉庫可選套用的 .gitignore 模板：直接沿用下方 GITIGNORE_TEXT（單一真相來源，
# 過去這裡另有一份精簡 Python 版，兩份同用途模板遲早 drift）。定義在 GITIGNORE_TEXT 之後。

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


def audit_log(user: str, host: str, action: str, detail: str) -> bool:
    """把一筆破壞性操作寫進本機稽核 log；寫入失敗回傳 False 並跳一次性警告。

    這個檔案是刪 repo / 砍 tag 等動作唯一的本機紀錄，寫不進去不能靜默吞掉——
    每個 session 至少要讓使用者知道一次稽核已中斷（之後同 session 不重複跳窗）。
    """
    global _AUDIT_LOG_WARNED
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{user}@{host}\t{action}\t{detail}\n")
        return True
    except OSError as e:
        if not _AUDIT_LOG_WARNED:
            _AUDIT_LOG_WARNED = True
            try:
                app = QApplication.instance()
                # audit_log 也會從 Worker 執行緒被呼叫（如 _run_repo_gc），
                # QMessageBox 只能在 UI 執行緒跳，其餘情況退回 stderr。
                if app is not None and QThread.currentThread() is app.thread():
                    QMessageBox.warning(
                        None, "稽核紀錄寫入失敗",
                        f"無法寫入本機稽核紀錄：\n{AUDIT_LOG_PATH}\n\n{e}\n\n"
                        "破壞性操作將不會留下本機紀錄（本次啟動期間只提醒這一次）。")
                else:
                    print(f"[WARN] 稽核紀錄寫入失敗：{AUDIT_LOG_PATH}：{e}", file=sys.stderr)
            except Exception:
                pass
        return False


_AUDIT_LOG_WARNED = False

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


def append_ssh_config_match_block(hostname: str, user: str, identity_path: str):
    """在本機 ~/.ssh/config 附加一段 `Match originalhost <hostname> user <user>` 區塊，
    讓之後不管是這個工具的 _ssh()、還是終端機直接打 `ssh user@hostname`/`git push`，
    都不用手動帶 -i 就會自動用到剛產生的這把私鑰。

    只有「同一台 NAS、多個帳號各自不同金鑰」這種情境才需要——因為 ssh 只認預設檔名
    （id_rsa/id_ed25519/id_ecdsa），本機產生金鑰時若檔名帶了帳號後綴（例如
    id_ed25519_git_user3），沒有這段設定的話 ssh 根本不會主動去試這把私鑰。
    區塊已存在就不重寫，避免覆蓋既有設定；與 Key_Management 專案 `key_management.py`
    的 `append_ssh_config_host()` 是各自獨立的實作，寫法故意保持一致（同樣格式，
    同一支 SSH config 可以互相讀懂），但這兩個工具彼此不 import、不共用程式碼。
    """
    ssh_config_path = os.path.join(os.path.expanduser("~"), ".ssh", "config")
    try:
        if os.path.exists(ssh_config_path):
            with open(ssh_config_path, "r", encoding="utf-8", errors="ignore") as f:
                existing = f.read()
        else:
            existing = ""
    except OSError as e:
        return False, f"讀取 SSH config 失敗：{e}"
    match_re = re.compile(
        r"^match\s+originalhost\s+" + re.escape(hostname) + r"\s+user\s+" + re.escape(user) + r"\s*$",
        re.IGNORECASE)
    for line in existing.splitlines():
        if match_re.match(line.strip()):
            return False, (f"SSH config 裡已經有「{hostname}」+「{user}」的 Match 區塊，"
                            "為避免衝突不會自動改寫，請自行手動編輯。")
    block = f'\nMatch originalhost {hostname} user {user}\n    IdentityFile "{identity_path}"\n'
    try:
        os.makedirs(os.path.dirname(ssh_config_path), exist_ok=True)
        with open(ssh_config_path, "a", encoding="utf-8") as f:
            f.write(block)
    except OSError as e:
        return False, f"寫入 SSH config 失敗：{e}"
    return True, f"已加入 SSH config：Match originalhost {hostname} user {user}"


def offer_write_local_ssh_config(parent, hostname: str, user: str, key_path: str):
    """本機產生金鑰成功後，問一次「這把金鑰要不要也在這台機器直接用」；
    要的話寫入 append_ssh_config_match_block()，不用每次都手動編輯 SSH config。
    只問一次、預設不寫（No），因為這幾個對話框（CreateGitDevsUserDialog／
    AddKeyForUserDialog／RotateKeyDialog）原本的預設情境是「產生給別人用、
    私鑰要交接出去」，不是每次都要在本機直接登入。"""
    r = QMessageBox.question(
        parent, "本機也要用這個帳號登入嗎？",
        f"這把金鑰要不要順便設定成：以後這台機器直接 ssh/git 用「{user}@{hostname}」"
        "登入時，自動用這把私鑰（不用再手動加 -i）？\n\n"
        "如果這把金鑰是要交給別人用、不會在這台機器登入，選「否」即可。",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No)
    if r != QMessageBox.StandardButton.Yes:
        return
    ok, msg = append_ssh_config_match_block(hostname, user, key_path)
    if ok:
        QMessageBox.information(parent, "已寫入 SSH config", msg)
    else:
        QMessageBox.warning(parent, "未寫入 SSH config", msg)


def open_admin_terminal(cfg: dict):
    """開一個新終端機視窗，直接 SSH 進 NAS（用目前連線設定的身份：kuoterry／Git_User1 等
    有 sudo 權限的身份），免得使用者還要自己另開終端機貼待執行腳本。

    判斷邏輯跟 Worker._ssh() 一致：有填密碼→plink -pw；沒填→內建 ssh（有指定私鑰檔就明確
    帶 -i／IdentitiesOnly=yes，理由同 _ssh()：非預設檔名的金鑰，ssh 不會自動去試）。
    只在 Windows 上支援（這個工具本來就是 Windows 專用 GUI）。"""
    if os.name != "nt":
        return False, "目前只支援 Windows 開啟終端機。"
    host = cfg.get("host", "")
    user = cfg.get("user", "")
    if not host or not user:
        return False, "目前身份設定缺少帳號或主機，無法開啟終端機。"
    password = cfg.get("password", "")
    identity_file = cfg.get("identity_file", "")
    try:
        if password:
            plink = shutil.which("plink")
            if not plink:
                return False, "有填密碼，但找不到 plink.exe（PuTTY），無法開啟終端機登入。"
            args = [plink, "-pw", password, f"{user}@{host}"]
        else:
            args = ["ssh"]
            if identity_file:
                args += ["-i", identity_file, "-o", "IdentitiesOnly=yes"]
            args += [f"{user}@{host}"]
        subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True, ""
    except OSError as e:
        return False, f"開啟終端機失敗：{e}"


def _login_precondition_selfcheck(username: str) -> list:
    """回傳一段 shell 片段（字串 list），一次檢查「SSH 金鑰登入某 git_devs 帳號」目前已知
    會踩到的每一個前置條件，跑完印出 ✅/‼️ 摘要——不是每次踩到新坑才補一條檢查，而是
    把目前已知的坑（shell、home 擁有者、home ACL、authorized_keys）一次列成清單，讓下一個
    帳號在「建立/補金鑰當下」就能看到問題，不用等事後登入失敗才回頭排查。

    只檢查、印警告，不重覆做已經在腳本前面做過的修正動作（shell 強制設定、
    chown/chmod/synoacltool 都已經在前面步驟做過），這裡純粹是跑完後的總結。
    CreateGitDevsUserDialog（新帳號）、AddKeyForUserDialog（補金鑰）、RotateKeyDialog（輪替）
    都呼叫這個共用片段，確保三邊的檢查清單不會慢慢長歪、各自遺漏。"""
    return [
        "# ---- 登入前置條件自我檢查（已知會擋 SSH 金鑰登入的項目，一次列出）----",
        f'SHELL_NOW=$(grep "^{username}:" /etc/passwd | cut -d: -f7)',
        'case "$SHELL_NOW" in',
        '  */nologin|*/false)',
        f'    echo "‼️  shell 是 $SHELL_NOW，SSH 執行的所有指令（含 git push）都會被擋，需要人工排查" ;;',
        "  *)",
        '    echo "✅ shell：$SHELL_NOW" ;;',
        "esac",
        f'OWNER_NOW=$(stat -c "%U" "$HOME_DIR" 2>/dev/null)',
        f'if [ "$OWNER_NOW" = "{username}" ]; then',
        '  echo "✅ home 目錄擁有者：$OWNER_NOW"',
        "else",
        f'  echo "‼️  home 目錄擁有者是 $OWNER_NOW，不是 {username}，sshd 會拒絕金鑰登入"',
        "fi",
        '# authorized_keys 在對方 700 的 .ssh 目錄底下，非 root 連 stat 都進不去，必須用 sudo 才問得到真相：',
        'if sudo test -s "$HOME_DIR/.ssh/authorized_keys" 2>/dev/null; then',
        '  echo "✅ authorized_keys 有內容"',
        "else",
        '  echo "‼️  authorized_keys 是空的或不存在，這個帳號還沒有能用的金鑰"',
        "fi",
    ]


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


# Key_Management（同倉庫的獨立姊妹工具）本機金鑰名冊路徑。兩工具原則上完全獨立、
# 不共用程式碼，這裡是唯一的例外：唯讀讀取這個 JSON 檔案，省去手動複製貼上公鑰，
# 僅止於此，不反向寫入、不 import 對方模組。
KEY_MANAGEMENT_REGISTRY_PATH = os.path.join(os.path.expanduser("~"), ".key_management", "registry.json")


def key_management_registry_pubkeys():
    """唯讀掃 Key_Management 的 registry.json，回傳 [(顯示用標籤, 公鑰單行內容), ...]。
    只收目前狀態 active、且對應 .pub 檔存在並看得懂（單行 OpenSSH 格式）的項目；
    .ppk 或多行 RFC4716 格式的公鑰不在這裡處理，讀不到就跳過。"""
    try:
        with open(KEY_MANAGEMENT_REGISTRY_PATH, "r", encoding="utf-8") as f:
            reg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    items = []
    for entry in reg.values():
        if entry.get("status") != "active":
            continue
        pub_path = entry.get("pub_path")
        if not pub_path or not os.path.isfile(pub_path):
            continue
        try:
            with open(pub_path, "r", encoding="utf-8") as f:
                line = f.readline().strip()
        except OSError:
            continue
        if not is_ssh_pubkey(line):
            continue
        comment = entry.get("comment") or "(無 comment)"
        fp = entry.get("fingerprint") or ssh_fingerprint(line)
        label = f"{comment}  [{entry.get('type', '?')}]  {fp}"
        items.append((label, line))
    return items


def pick_key_management_pubkey(parent):
    """跳出清單讓使用者從 Key_Management 名冊挑一把公鑰，回傳公鑰單行內容或 None（取消/沒東西可選）。"""
    items = key_management_registry_pubkeys()
    if not items:
        QMessageBox.information(
            parent, "從 Key_Management 匯入",
            "找不到可用的公鑰——Key_Management 可能還沒產生過金鑰，或現有的都是 .ppk／多行格式，"
            "請自行開檔複製內容。")
        return None
    labels = [it[0] for it in items]
    label, ok = QInputDialog.getItem(
        parent, "從 Key_Management 匯入公鑰", "選一把公鑰：", labels, editable=False)
    if not ok:
        return None
    return dict(items)[label]


# 倉庫來源分類：mirror 由 remote.origin.mirror 決定，優先於 nasgit.kind（見 CLAUDE.md）。
REPO_KIND_TABS = [
    ("all", "全部"),
    ("own", "自己的"),
    ("fork", "我 fork 的"),
    ("clone", "clone 別人的"),
    ("mirror", "鏡像"),
    ("", "未分類"),
]
REPO_KIND_MARK = {"own": "🏠自己", "fork": "🍴fork", "clone": "📥clone", "mirror": "↺鏡像"}


def effective_repo_kind(mirror: str, kind: str) -> str:
    """回傳這個倉庫實際歸屬的分類：mirror 一律優先，其次是 nasgit.kind，都沒有就是未分類（空字串）。"""
    if mirror:
        return "mirror"
    return kind or ""


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
    "IF0gJiYgZXhpdCAwCiMgLS0tIEVORCBBVVRPX1BPTElDWV9MT0FEIC0tLQoKQ09ORj0iJEJBU0UvY29uZmlnL3RnX2JvdC5jb25m"
    "IiAgICMg6IiH5YW25LuW6IWz5pys5YWx55So5ZCM5LiA5Lu9IFRlbGVncmFtIOioreWumu+8jEdVSSDmj5sgdG9rZW4g6YCZ6KOh"
    "5omN5pyD6Lef6JGX5o+bCkJPVF9UT0tFTj0iIjsgQ0hBVF9JRD0iIgpbIC1mICIkQ09ORiIgXSAmJiAuICIkQ09ORiIKCk1PREU9"
    "IiRQT0xJQ1lfTU9ERSIgICAgICMgc29mdCAvIHN0cmljdApSRVBPPSIkUkVQT19OQU1FIgoKWkVSTz0iMDAwMDAwMDAwMDAwMDAw"
    "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIKCnNlbmRfdGVsZWdyYW0oKSB7CiAgICBsb2NhbCBtc2c9IiQxIgogICAgWyAteiAi"
    "JEJPVF9UT0tFTiIgXSAmJiByZXR1cm4gMAogICAgWyAteiAiJENIQVRfSUQiIF0gJiYgcmV0dXJuIDAKICAgIGN1cmwgLXMgLVgg"
    "UE9TVCAiaHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdCRCT1RfVE9LRU4vc2VuZE1lc3NhZ2UiIFwKICAgICAgLS1kYXRhLXVy"
    "bGVuY29kZSAiY2hhdF9pZD0kQ0hBVF9JRCIgXAogICAgICAtLWRhdGEtdXJsZW5jb2RlICJ0ZXh0PVtDSV1bJFJFUE9dICRtc2ci"
    "IFwKICAgICAgPi9kZXYvbnVsbAp9Cgp2aW9sYXRlKCkgewogICAgbG9jYWwgcmVhc29uPSIkMSIKCiAgICBlY2hvICLimqDvuI8g"
    "Q0kgdmlvbGF0aW9uOiAkcmVhc29uIgogICAgc2VuZF90ZWxlZ3JhbSAiJHJlYXNvbiIKCiAgICBpZiBbICIkTU9ERSIgPSAic3Ry"
    "aWN0IiBdOyB0aGVuCiAgICAgICAgZWNobyAi4p2MIENJIGJsb2NrZWQgcHVzaCIKICAgICAgICBleGl0IDEKICAgIGZpCn0KCndo"
    "aWxlIHJlYWQgb2xkcmV2IG5ld3JldiByZWZuYW1lOyBkbwogICAgY2FzZSAiJHJlZm5hbWUiIGluCiAgICAgICAgcmVmcy9oZWFk"
    "cy8qKSA7OwogICAgICAgICopIGNvbnRpbnVlIDs7CiAgICBlc2FjCgogICAgYnJhbmNoPSR7cmVmbmFtZSNyZWZzL2hlYWRzL30K"
    "CiAgICAjIOWIqumZpOWIhuaUr++8iG5ld3JldiDlhaggMO+8ie+8muaykuacieaWsCBjb21taXQg5Y+v5qqi5p+l77yM55u05o6l"
    "55Wl6YGO44CCCiAgICAjIOS4jeeVpemBjueahOipsSByZXYtbGlzdCAiJG9sZHJldi4uMDAwMC4uLiIg5pyDIGZhdGFs77yM6Lef"
    "5paw5YiG5pSv5ZCM5LiA5YCL5Z2R44CCCiAgICBbICIkbmV3cmV2IiA9ICIkWkVSTyIgXSAmJiBjb250aW51ZQoKICAgICMgYnJh"
    "bmNoIOimj+WJhwogICAgZWNobyAiJGJyYW5jaCIgfCBncmVwIC1FcSAnXihkZXZlbG9wJHxmZWF0dXJlL3xyZWxlYXNlLyknIHx8"
    "IFwKICAgICAgICB2aW9sYXRlICJiYWQgYnJhbmNoIG5hbWU6ICRicmFuY2giCgogICAgIyBjb21taXQgbWVzc2FnZSDopo/liYcK"
    "ICAgICMg5paw5YiG5pSv5pmCIG9sZHJldiDmmK8gNDAg5YCLIDDvvIwiJG9sZHJldi4uJG5ld3JldiIg5pyD6K6TIGdpdCDnm7Tm"
    "jqUKICAgICMgZmF0YWw6IEludmFsaWQgcmV2aXNpb24gcmFuZ2XvvIzmlbTlgIsgZm9yIOi/tOWciOS4jeacg+i3ke+8neipsuas"
    "oeaOqOmAgeeahAogICAgIyDoqIrmga/mqqLmn6XnrYnmlrzmspLlgZrvvIjogIzkuJQgcHJlLXJlY2VpdmUg5LuNIGV4aXQgMO+8"
    "jOS4jeacg+acieS6uueZvOePvu+8ieOAggogICAgIyDmlrDliIbmlK/mlLnliJfjgIzlsJrmnKrooqvlhbbku5YgcmVmIOa2teiT"
    "i+OAjeeahCBjb21taXTvvJpwcmUtcmVjZWl2ZSDpmo7mrrXmlrAgcmVmCiAgICAjIOmChOaykuW7uueri++8jOaJgOS7pSAtLWFs"
    "bCDkuI3lkKvlroPvvIzmraPlpb3lj6rlianpgJnmrKHnnJ/mraPmlrDlop7nmoQgY29tbWl044CCCiAgICBpZiBbICIkb2xkcmV2"
    "IiA9ICIkWkVSTyIgXTsgdGhlbgogICAgICAgIFJFVl9SQU5HRT0iJG5ld3JldiAtLW5vdCAtLWFsbCIKICAgIGVsc2UKICAgICAg"
    "ICBSRVZfUkFOR0U9IiRvbGRyZXYuLiRuZXdyZXYiCiAgICBmaQoKICAgIGZvciBjIGluICQoZ2l0IHJldi1saXN0ICRSRVZfUkFO"
    "R0UpOyBkbwogICAgICAgIGdpdCBsb2cgLTEgLS1wcmV0dHk9JUIgIiRjIiB8IFwKICAgICAgICAgIGdyZXAgLUVxICdcWyhKSVJB"
    "fFRBU0spLVswLTldK1xdfF4oZmVhdHxmaXh8Y2hvcmV8ZG9jcyk6JyB8fCBcCiAgICAgICAgICB2aW9sYXRlICJiYWQgY29tbWl0"
    "IG1lc3NhZ2UgKCRjKSIKICAgIGRvbmUKZG9uZQoKZXhpdCAwCg=="
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

# 新建空倉庫的模板與串接流程共用同一份內容（單一真相來源）
GITIGNORE_TEMPLATE = GITIGNORE_TEXT


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

    # plink 是否支援 -pwfile（PuTTY 0.77+）。None=未知（先試 -pwfile），False=確定不支援。
    _plink_pwfile_ok = None

    def __init__(self, cfg: dict, mode: str = "connect"):
        super().__init__()
        self.cfg = cfg
        self.mode = mode  # "connect" 串接 / "test" 測連線 / "list" 列出倉庫
        self._cancel_requested = False
        self._pw_file = None  # plink -pwfile 用的暫存密碼檔，run() 結束時刪除

    def cancel(self):
        """要求中止目前操作：正在跑的子程序會被砍掉，_run 回傳 rc=125。"""
        self._cancel_requested = True

    # --- 執行外部指令的統一入口 ---
    def _mask(self, a):
        """在 log 中把密碼遮成 ****，不外洩。"""
        pw = self.cfg.get("password", "")
        if pw and a == pw:
            return "****"
        return a

    def _run(self, args, cwd=None, input_bytes=None, env=None, timeout=None):
        """執行子程序：輸出逐行即時 emit（長操作不再整段黑箱等待）、支援逾時與取消。

        回傳 (rc, out, err)。特殊 rc：124=逾時強制結束、125=使用者取消。
        timeout=None 表示不設限（僅留給本機互動性極低的操作；遠端一律給逾時）。
        """
        self.log.emit("$ " + " ".join(self._mask(a) for a in args))
        try:
            proc = subprocess.Popen(
                args, cwd=cwd, env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=_NO_WINDOW,
            )
        except FileNotFoundError as e:
            self.log.emit(f"[錯誤] 找不到執行檔：{e}")
            return 127, "", str(e)
        try:
            if input_bytes:
                proc.stdin.write(input_bytes)
                proc.stdin.flush()
            proc.stdin.close()
        except OSError:
            pass

        out_lines, err_lines = [], []

        def _reader(stream, sink):
            """把子程序的一條輸出流逐行收進 sink 並即時丟到 log 視窗。"""
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                sink.append(line)
                if line:
                    self.log.emit(line)
            stream.close()

        t_out = threading.Thread(target=_reader, args=(proc.stdout, out_lines), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc.stderr, err_lines), daemon=True)
        t_out.start()
        t_err.start()

        deadline = None if timeout is None else time.monotonic() + timeout
        killed_reason = None
        while proc.poll() is None:
            if self._cancel_requested:
                killed_reason = "cancel"
                break
            if deadline is not None and time.monotonic() > deadline:
                killed_reason = "timeout"
                break
            time.sleep(0.1)
        if killed_reason:
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
        t_out.join(timeout=5)
        t_err.join(timeout=5)
        out = "\n".join(out_lines).strip()
        err = "\n".join(err_lines).strip()
        if killed_reason == "cancel":
            self.log.emit("[中止] 使用者取消，已強制結束子程序")
            return 125, out, "cancelled"
        if killed_reason == "timeout":
            self.log.emit(f"[錯誤] 執行逾時（超過 {timeout} 秒），已強制結束")
            return 124, out, err or "timeout"
        return proc.returncode, out, err

    # 遠端指令預設逾時：一般操作 10 分鐘該夠；gc/fsck/同步鏡像等長操作各自傳更大的值。
    SSH_DEFAULT_TIMEOUT = 600

    def _plink_pw_args(self, pw):
        """回傳 plink 的密碼參數。優先用 -pwfile（密碼不進命令列，避免同機任何
        程序用 Win32_Process.CommandLine 直接讀到明碼）；偵測到舊版 plink 不支援
        時退回 -pw。密碼檔放使用者暫存目錄，run() 結束時刪除。"""
        if Worker._plink_pwfile_ok is False:
            return ["-pw", pw]
        if self._pw_file is None:
            fd, path = tempfile.mkstemp(prefix="nasgit_pw_")
            with os.fdopen(fd, "w", encoding="ascii", errors="replace") as f:
                f.write(pw)
            self._pw_file = path
        return ["-pwfile", self._pw_file]

    def _cleanup_pw_file(self):
        if self._pw_file:
            try:
                os.remove(self._pw_file)
            except OSError:
                pass
            self._pw_file = None

    def _ssh(self, remote_cmd, timeout=SSH_DEFAULT_TIMEOUT):
        """對 NAS 執行遠端指令。有密碼→用 plink；無密碼→用內建 ssh（金鑰，若這個身份
        指定了私鑰檔就明確帶 -i，避免 SSH 只憑預設檔名/agent 猜不到非預設命名的金鑰）。"""
        c = self.cfg
        ssh_host = f"{c['user']}@{c['host']}"
        pw = c.get("password", "")
        identity_file = c.get("identity_file", "")
        if pw:
            plink = shutil.which("plink")
            if not plink:
                self.log.emit(
                    "[錯誤] 有填密碼，但找不到 plink.exe（PuTTY）。"
                    "請安裝 PuTTY，或改用 SSH 金鑰（免密碼）。"
                )
                return 255, "", "plink-missing"
            # 餵 y\n 以在首次連線時自動接受主機金鑰（之後會被 PuTTY 快取）
            args = [plink] + self._plink_pw_args(pw) + [ssh_host, remote_cmd]
            rc, out, err = self._run(args, input_bytes=b"y\n", timeout=timeout)
            if rc != 0 and Worker._plink_pwfile_ok is None and "-pwfile" in (err or ""):
                # 舊版 plink 不認得 -pwfile：記住這件事，這次直接用 -pw 重跑一遍。
                Worker._plink_pwfile_ok = False
                self.log.emit("[提示] 此版 plink 不支援 -pwfile，退回 -pw（建議升級 PuTTY ≥ 0.77）")
                args = [plink, "-pw", pw, ssh_host, remote_cmd]
                rc, out, err = self._run(args, input_bytes=b"y\n", timeout=timeout)
            elif rc == 0 and Worker._plink_pwfile_ok is None:
                Worker._plink_pwfile_ok = True
            return rc, out, err
        else:
            args = [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10",
                # 連線後對端死掉（NAS 睡死/斷網）約 60 秒內偵測到，而不是永遠掛住。
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=4",
            ]
            if identity_file:
                args += ["-i", identity_file, "-o", "IdentitiesOnly=yes"]
            args += [ssh_host, remote_cmd]
            return self._run(args, timeout=timeout)

    def _git_env(self):
        """本地 git 若要用密碼推送，透過 plink 當 GIT_SSH_COMMAND；若無密碼但這個身份指定了
        私鑰檔，改用內建 ssh 明確帶 -i。兩者都沒設就回 None，讓 git 用系統預設解析。"""
        pw = self.cfg.get("password", "")
        identity_file = self.cfg.get("identity_file", "")
        if pw:
            plink = shutil.which("plink")
            if not plink:
                return None
            env = os.environ.copy()
            pw_args = self._plink_pw_args(pw)
            if pw_args[0] == "-pwfile":
                env["GIT_SSH_COMMAND"] = f'"{plink}" -pwfile "{pw_args[1]}"'
            else:
                env["GIT_SSH_COMMAND"] = f'"{plink}" -pw {pw}'
            return env
        if identity_file:
            env = os.environ.copy()
            env["GIT_SSH_COMMAND"] = f'ssh -i "{identity_file}" -o IdentitiesOnly=yes'
            return env
        return None

    def run(self):
        # 任何 _run_* 冒出的例外都必須轉成 done(False)：QThread 若無聲死掉，
        # done 永遠不發射、set_busy(False) 永遠不執行，整個 UI 會鎖死到砍程式為止。
        try:
            self._dispatch()
        except Exception as e:
            self.log.emit("[錯誤] 內部例外：\n" + traceback.format_exc().strip())
            self.done.emit(False, f"內部錯誤：{e}")
        finally:
            self._cleanup_pw_file()

    def _dispatch(self):
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
        elif self.mode == "repo_fsck":
            self._run_repo_fsck()
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
        elif self.mode == "local_gen_ssh_key":
            self._run_local_gen_ssh_key()
        elif self.mode == "list_git_devs_users":
            self._run_list_git_devs_users()
        elif self.mode == "clone":
            self._run_clone()
        elif self.mode == "create_mirror":
            self._run_create_mirror()
        elif self.mode == "sync_mirrors":
            self._run_sync_mirrors()
        elif self.mode == "get_backup_remote":
            self._run_get_backup_remote()
        elif self.mode == "set_backup_remote":
            self._run_set_backup_remote()
        elif self.mode == "backup_sync":
            self._run_backup_sync()
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
        elif self.mode == "profile_sync_pull":
            self._run_profile_sync_pull()
        elif self.mode == "profile_sync_push":
            self._run_profile_sync_push()
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
        elif self.mode == "set_repo_kind":
            self._run_set_repo_kind()
        elif self.mode == "github_scan":
            self._run_github_scan()
        elif self.mode == "local_scan":
            self._run_local_scan()
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

    @staticmethod
    def _err_hint(err, rc):
        """把一次失敗的 (stderr, rc) 擠成一句能直接放進使用者訊息的原因。"""
        if rc == 124:
            return "逾時無回應"
        if rc == 125:
            return "已被使用者中止"
        tail = (err or "").strip().splitlines()
        return tail[-1] if tail else f"連線或權限問題（rc={rc}）"

    def _ssh_block(self, lines, timeout=SSH_DEFAULT_TIMEOUT):
        """執行一段 ___BEGIN___/___END___ 包裝的遠端腳本，回 (ok, body, err_hint)。

        集中三件每個站點都在手工重複的事：包裝標記、_between 濾 banner、
        失敗時擠出一句可以直接附進使用者訊息的原因（stderr 末行／逾時／中止），
        讓「連線或權限問題」這種猜謎式錯誤訊息有東西可以附。
        新寫的 Worker mode 一律用這個，不要再手刻 echo ___BEGIN___。
        """
        cmd = "\n".join(["echo ___BEGIN___"] + list(lines) + ["echo ___END___", "true"])
        rc, out, err = self._ssh(cmd, timeout=timeout)
        body = self._between(out)
        if rc == 0:
            return True, body, ""
        if rc == 124:
            hint = f"逾時（超過 {timeout} 秒無回應）"
        elif rc == 125:
            hint = "已被使用者中止"
        else:
            tail = (err or "").strip().splitlines()
            hint = tail[-1] if tail else f"rc={rc}"
        return False, body, hint

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
        # 每行：name<TAB>status<TAB>policy<TAB>mirror_url<TAB>size_kb<TAB>kind<TAB>upstream
        # mirror_url 非空代表是 GitHub 鏡像；kind 為 own/fork/clone/空（未分類），鏡像庫一律不讀 kind
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
            "  kind=''; upstream=''",
            "  if [ -z \"$mu\" ]; then",
            "    kind=$(git --git-dir=\"$d\" config --get nasgit.kind 2>/dev/null)",
            "    upstream=$(git --git-dir=\"$d\" config --get nasgit.upstream 2>/dev/null)",
            "  fi",
            "  sz=$(du -sk \"$d\" 2>/dev/null | cut -f1); [ -z \"$sz\" ] && sz=0",
            "  if [ -z \"$info\" ]; then",
            "    printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$name\" \"空庫（無 commit）\" \"$pol\" \"$mu\" \"$sz\" \"$kind\" \"$upstream\"",
            "  else",
            "    dt=${info%%|*}; br=${info#*|}",
            "    printf '%s\\t%s (%s)\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$name\" \"$dt\" \"$br\" \"$pol\" \"$mu\" \"$sz\" \"$kind\" \"$upstream\"",
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
            kind = parts[5].strip() if len(parts) > 5 else ""
            upstream = parts[6].strip() if len(parts) > 6 else ""
            items.append((name, status, pol, mirror, size_kb, kind, upstream))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 CI 規則失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 CI 狀態總表失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取明細失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取描述失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取分支保護設定失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取檔案列表失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取檔案內容失敗：" + self._err_hint(err, rc))
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
            "  if err=$(git --git-dir=\"$repo\" gc --quiet 2>&1 >/dev/null); then",
            "    after=$(du -sh \"$repo\" 2>/dev/null | cut -f1)",
            "    echo \"[OK]   $name  $before -> $after\"",
            "  else",
            "    echo \"[FAIL] $name\"",
            "    echo \"$err\" | tail -n 3 | sed 's/^/       /'",
            "  fi",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, err = self._ssh(cmd, timeout=3600)
        if rc != 0:
            tail = (err or "").strip().splitlines()
            self.done.emit(False, "GC 失敗：" + (tail[-1] if tail else f"rc={rc}"))
            return
        body = self._between(out)
        self.hooks.emit(body)
        nfail = body.count("[FAIL]")
        nok = body.count("[OK]")
        msg = f"GC 完成：成功 {nok}、失敗 {nfail}。"
        if nfail > 0 and nok > 0:
            # 部分成功部分失敗時 done(ok=False) 不會走到 on_ci_done 的成功分支，
            # 但已成功的那幾個 repo 仍真的執行了 git gc，這裡直接補記，避免漏記。
            # 全部失敗（nok==0）則沒有任何破壞性動作發生，維持原本不記錄的行為。
            audit_log(c.get("user", ""), c.get("host", ""), "repo_gc", msg)
        self.done.emit(nfail == 0, msg)

    # --- 完整性檢查（git fsck，唯讀）---
    def _run_repo_fsck(self):
        c = self.cfg
        root = c["remote_root"]
        names = [n for n in c.get("repo_names", []) if is_safe_name(n)]
        if not names:
            self.done.emit(False, "沒有選取任何倉庫。")
            return
        flt = "".join(" " + n + " " for n in names)
        self.log.emit(f"--- 完整性檢查 git fsck（{len(names)} 個倉庫）---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; FILTER='{flt}'",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  case \"$FILTER\" in *\" $name \"*) ;; *) continue;; esac",
            "  out=$(git --git-dir=\"$repo\" fsck --full 2>&1)",
            "  if echo \"$out\" | grep -Eiq 'error|missing|corrupt|fatal'; then",
            "    echo \"[FAIL] $name：發現損毀/遺失物件\"",
            "    echo \"$out\" | sed 's/^/       /'",
            "  elif [ -n \"$out\" ]; then",
            "    n=$(echo \"$out\" | wc -l)",
            "    echo \"[OK]   $name（$n 筆 dangling/unreachable 物件，屬正常現象非損毀）\"",
            "  else",
            "    echo \"[OK]   $name（完全乾淨）\"",
            "  fi",
            "done",
            "echo ___END___",
            "true",
        ])
        rc, out, err = self._ssh(cmd, timeout=3600)
        if rc != 0:
            self.done.emit(False, "完整性檢查失敗：" + self._err_hint(err, rc))
            return
        body = self._between(out)
        self.hooks.emit(body)
        nfail = body.count("[FAIL]")
        nok = body.count("[OK]")
        self.done.emit(nfail == 0, f"完整性檢查完成：正常 {nok}、發現問題 {nfail}。")

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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 log 失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取已合併分支失敗：" + self._err_hint(err, rc))
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
            "awk -v b=\"$base\" -v n=\"$name\" "
            "'{ print \"HIT\\t\" n \"\\t\" substr($0, length(b) + 2) }'",
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
            # 檔名本身可能含冒號，不能盲目 split(":", n)；改抓「第一個 :數字: 分界」
            # 當作 path/lineno 的界線（line number 保證是純數字，path/content 則否）。
            m = re.match(r"^(.*?):(\d+):(.*)$", grepline)
            if not m:
                continue
            path, lineno, content = m.groups()
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "比較失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 blame 失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "查詢失敗：" + self._err_hint(err, rc))
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

    # --- 本機產生新的 SSH 金鑰對（給新申請的 git_devs 帳號用）---
    # 私鑰只留在這台機器，不會被讀出來或傳到 NAS；只把公鑰內容透過 hooks 訊號回傳給對話框。
    def _run_local_gen_ssh_key(self):
        path = self.cfg.get("key_path", "")
        comment = self.cfg.get("key_comment", "")
        if not path:
            self.done.emit(False, "缺少金鑰儲存路徑。")
            return
        if os.path.exists(path) or os.path.exists(path + ".pub"):
            self.done.emit(False, f"檔案已存在，未覆蓋：{path}（或 .pub），請換一個檔名。")
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.log.emit(f"--- 本機產生 SSH 金鑰對：{path} ---")
        rc, out, err = self._run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", path])
        if rc != 0:
            self.done.emit(False, "產生金鑰失敗：" + (err or out).strip())
            return
        pub_path = path + ".pub"
        try:
            with open(pub_path, encoding="utf-8") as f:
                pubkey = f.read().strip()
        except OSError as e:
            self.done.emit(False, f"金鑰已產生，但讀取公鑰檔失敗：{e}")
            return
        self.hooks.emit(pubkey)
        self.done.emit(True, f"已產生金鑰對：\n私鑰：{path}\n公鑰：{pub_path}")

    # --- 列出 git_devs 群組目前所有成員（含 uid/home/金鑰數，唯讀）---
    def _run_list_git_devs_users(self):
        self.log.emit("--- 查詢 git_devs 帳號清單 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            "members=$(grep '^git_devs:' /etc/group | cut -d: -f4)",
            "old_ifs=$IFS; IFS=','",
            "for u in $members; do",
            "  [ -z \"$u\" ] && continue",
            "  line=$(grep \"^$u:\" /etc/passwd)",
            "  uid=$(echo \"$line\" | cut -d: -f3)",
            "  home=$(echo \"$line\" | cut -d: -f6)",
            "  nkeys=$( [ -f \"$home/.ssh/authorized_keys\" ] && grep -vE '^#|^$' \"$home/.ssh/authorized_keys\" 2>/dev/null | wc -l )",
            "  printf '%s\\t%s\\t%s\\t%s\\n' \"$u\" \"${uid:-?}\" \"${home:-?}\" \"${nkeys:-0}\"",
            "done",
            "IFS=$old_ifs",
            "echo ___END___",
            "true",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc != 0:
            self.repos.emit([])
            self.done.emit(False, "查詢失敗（連線或權限問題）。")
            return
        body = self._between(out)
        items = []
        for ln in body.splitlines():
            parts = ln.split("\t")
            if len(parts) >= 4:
                items.append((parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()))
        self.repos.emit(items)
        self.done.emit(True, f"共 {len(items)} 個 git_devs 帳號。")

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
        rc, out, err = self._run(["git", "clone", url, target], env=self._git_env(), timeout=3600)
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
        ok, body, hint = self._ssh_block([
            f"BASE='{root}'; name='{name}'; url='{url}'",
            "repo=\"$BASE/$name\"",
            "if [ -e \"$repo\" ]; then echo EXISTS; echo ___END___; exit 0; fi",
            # 保留 clone 的 stderr：失敗時使用者才知道是 DNS、認證還是私有庫問題，不用猜。
            "if err=$(git clone --mirror \"$url\" \"$repo\" 2>&1 >/dev/null); then",
            "  chgrp -R git_devs \"$repo\" 2>/dev/null; chmod -R g+rwX \"$repo\" 2>/dev/null",
            "  echo ___OK___",
            "else",
            "  rm -rf \"$repo\"; echo CLONE_FAIL",
            "  echo \"$err\" | tail -n 5",
            "fi",
        ], timeout=3600)
        if "EXISTS" in body:
            self.done.emit(False, f"倉庫已存在，未建立：{name}")
        elif ok and "___OK___" in body:
            clone_url = f"{c['user']}@{c['host']}:{root}/{name}"
            self.done.emit(True, f"已建立鏡像：{name}\n上游：{url}\n本地 Clone URL：{clone_url}\n（日後用『同步鏡像』或排程更新）")
        else:
            detail = "\n".join(body.splitlines()[1:]) if "CLONE_FAIL" in body else hint
            self.done.emit(False, "建立鏡像失敗。" + (f"\n原因：\n{detail}" if detail else ""))

    # --- 同步鏡像（remote update --prune）；names 空則同步全部鏡像 ---
    def _run_sync_mirrors(self):
        root = self.cfg["remote_root"]
        names = [n for n in self.cfg.get("mirror_names", []) if is_safe_name(n)]
        flt = ("".join(" " + n + " " for n in names)) if names else ""
        self.log.emit(f"--- 同步鏡像（{'選取 ' + str(len(names)) + ' 個' if names else '全部'}）---")
        ok, body, hint = self._ssh_block([
            f"BASE='{root}'; FILTER='{flt}'",
            "n=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  [ \"$(git --git-dir=\"$repo\" config --get remote.origin.mirror 2>/dev/null)\" = true ] || continue",
            "  if [ -n \"$FILTER\" ]; then case \"$FILTER\" in *\" $name \"*) ;; *) continue;; esac; fi",
            "  n=$((n+1))",
            # 保留每庫的 stderr 末幾行：失敗清單才有可診斷的原因，不再只有 [FAIL] 三個字。
            "  if err=$(git --git-dir=\"$repo\" remote update --prune 2>&1 >/dev/null); then",
            "    echo \"[OK]   $name\"",
            "  else",
            "    echo \"[FAIL] $name\"",
            "    echo \"$err\" | tail -n 3 | sed 's/^/       /'",
            "  fi",
            "done",
            "[ \"$n\" = 0 ] && echo '（沒有符合的鏡像庫）'",
        ], timeout=3600)
        if not ok:
            self.done.emit(False, f"同步失敗：{hint}")
            return
        self.hooks.emit(body)
        nfail = body.count("[FAIL]")
        nok = body.count("[OK]")
        self.done.emit(nfail == 0, f"鏡像同步完成：成功 {nok}、失敗 {nfail}。")

    # --- 讀取離站備份目的地 URL（唯讀）---
    def _run_get_backup_remote(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規：{name!r}")
            return
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"BASE='{root}'; name='{name}'",
            "git --git-dir=\"$BASE/$name\" config --get remote.offsite-backup.url 2>/dev/null",
            "echo ___END___",
            "true",
        ])
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取失敗：" + self._err_hint(err, rc))
            return
        body = self._between(out).strip()
        self.hooks.emit(body)
        self.done.emit(True, "已讀取離站備份設定。" if body else "尚未設定離站備份。")

    # --- 設定/移除離站備份目的地（git remote add/remove offsite-backup）---
    def _run_set_backup_remote(self):
        c = self.cfg
        root = c["remote_root"]
        name = c.get("repo_name", "")
        url = (c.get("backup_url", "") or "").strip()
        if not is_safe_name(name):
            self.done.emit(False, f"倉庫名稱不合規：{name!r}")
            return
        if url and not re.match(r"^(https://|http://|git@|ssh://|file://)[A-Za-z0-9@._:/~?=&%+\-]+$", url):
            self.done.emit(False, "備份目的地 URL 格式不合規（僅允許 https:// / git@ / ssh:// / file:// 開頭的正常網址）。")
            return
        self.log.emit(f"--- 設定離站備份：{name} → {url or '(移除設定)'} ---")
        steps = [
            f"BASE='{root}'; name='{name}'",
            "repo=\"$BASE/$name\"",
            "git --git-dir=\"$repo\" remote remove offsite-backup >/dev/null 2>&1",
        ]
        if url:
            steps.append(f"url='{url}'")
            steps.append("git --git-dir=\"$repo\" remote add offsite-backup \"$url\" 2>&1")
        steps.append("echo ___OK___")
        steps.append("true")
        rc, out, _ = self._ssh("\n".join(steps))
        if rc != 0 or "___OK___" not in out:
            self.done.emit(False, "設定失敗（連線或權限問題）。")
            return
        if url:
            self.done.emit(True, f"已設定「{name}」的離站備份目的地：\n{url}")
        else:
            self.done.emit(True, f"已移除「{name}」的離站備份設定。")

    # --- 同步離站備份（git push --mirror offsite-backup）；names 空則同步全部已設定的 ---
    def _run_backup_sync(self):
        root = self.cfg["remote_root"]
        names = [n for n in self.cfg.get("backup_repo_names", []) if is_safe_name(n)]
        flt = ("".join(" " + n + " " for n in names)) if names else ""
        self.log.emit(f"--- 同步離站備份（{'選取 ' + str(len(names)) + ' 個' if names else '全部已設定'}）---")
        script = [
            f"BASE='{root}'; FILTER='{flt}'",
            "n=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  name=$(basename \"$repo\")",
            "  url=$(git --git-dir=\"$repo\" config --get remote.offsite-backup.url 2>/dev/null)",
            "  [ -n \"$url\" ] || continue",
            "  if [ -n \"$FILTER\" ]; then case \"$FILTER\" in *\" $name \"*) ;; *) continue;; esac; fi",
            "  n=$((n+1))",
            "  if err=$(git --git-dir=\"$repo\" push --mirror offsite-backup 2>&1 >/dev/null); then",
            "    echo \"[OK]   $name\"",
            # 成功才蓋時戳：健檢用它找「設了備份卻從沒推成功過」的倉庫。
            "    git --git-dir=\"$repo\" config nasgit.lastbackup \"$(date +%s)\" 2>/dev/null",
            "  else",
            "    echo \"[FAIL] $name\"",
            "    echo \"$err\" | tail -n 3 | sed 's/^/       /'",
            "  fi",
            "done",
            "[ \"$n\" = 0 ] && echo '（沒有設定離站備份的倉庫）'",
        ]
        ok, body, hint = self._ssh_block(script, timeout=3600)
        if not ok:
            self.done.emit(False, f"同步失敗：{hint}")
            return
        self.hooks.emit(body)
        nfail = body.count("[FAIL]")
        nok = body.count("[OK]")
        self.done.emit(nfail == 0, f"離站備份同步完成：成功 {nok}、失敗 {nfail}。")

    # --- 設定/批次設定倉庫來源分類（nasgit.kind / nasgit.upstream / nasgit.kindsrc）---
    # 鏡像庫（remote.origin.mirror=true）一律拒寫：mirror 這個分類只認 git 原生的
    # mirror flag，不能被 nasgit.kind 蓋過去，避免兩個真相來源打架。
    def _run_set_repo_kind(self):
        c = self.cfg
        root = c["remote_root"]
        items = c.get("kind_items", [])
        src = c.get("kind_src", "manual")
        if src not in ("manual", "auto-connect", "auto-github", "auto-local"):
            src = "manual"
        valid = [
            (name, kind, upstream or "")
            for name, kind, upstream in items
            if is_safe_name(name) and kind in ("own", "fork", "clone", "")
        ]
        if not valid:
            self.done.emit(False, "沒有可套用的有效倉庫。")
            return
        self.log.emit(f"--- 設定來源分類：{len(valid)} 個 repo ---")
        steps = ["echo ___BEGIN___", f"BASE='{root}'"]
        for name, kind, upstream in valid:
            steps.append(f"repo=\"$BASE/{name}\"")
            steps.append(
                "if [ \"$(git --git-dir=\"$repo\" config --get remote.origin.mirror "
                "2>/dev/null)\" = true ]; then"
            )
            steps.append(f"  echo '[SKIP] {name}（鏡像庫，不可設分類）'")
            steps.append("else")
            if kind:
                steps.append(f"  git --git-dir=\"$repo\" config nasgit.kind {shq(kind)}")
                steps.append(f"  git --git-dir=\"$repo\" config nasgit.kindsrc {shq(src)}")
                if upstream:
                    steps.append(f"  git --git-dir=\"$repo\" config nasgit.upstream {shq(upstream)}")
                else:
                    steps.append("  git --git-dir=\"$repo\" config --unset nasgit.upstream 2>/dev/null")
            else:
                steps.append("  git --git-dir=\"$repo\" config --unset nasgit.kind 2>/dev/null")
                steps.append("  git --git-dir=\"$repo\" config --unset nasgit.upstream 2>/dev/null")
                steps.append("  git --git-dir=\"$repo\" config --unset nasgit.kindsrc 2>/dev/null")
            kind_label = kind or "未分類"
            steps.append(f"  echo '[SET] {name} -> {kind_label}'")
            steps.append("fi")
        steps += ["echo ___OK___", "echo ___END___", "true"]
        rc, out, _ = self._ssh("\n".join(steps))
        if rc != 0 or "___OK___" not in out:
            self.done.emit(False, "設定失敗（連線或權限問題）。")
            return
        self.log.emit(self._between(out))
        self.done.emit(True, f"已設定 {len(valid)} 個倉庫的來源分類。")

    # --- 掃描 GitHub 帳號的倉庫列表，比對 fork 狀態（唯一會碰外部網路的模式）---
    # 只對「有機會對到目前 NAS 清單」的 fork 才多打一次 API 拿 parent 來源，避免大帳號逐一查爆額度。
    def _run_github_scan(self):
        c = self.cfg
        login = (c.get("github_login", "") or "").strip()
        token = (c.get("github_token", "") or "").strip()
        match_names = {n.lower() for n in (c.get("match_names", []) or [])}
        if not login:
            self.done.emit(False, "尚未填 GitHub 帳號。")
            return

        def _get(url):
            req = urllib.request.Request(url, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "NasGitConnector",
            })
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))

        self.log.emit(f"--- 掃描 GitHub 帳號 {login} 的倉庫（{'已帶 token' if token else '未帶 token，60 次/小時上限'}）---")
        repos = []
        page = 1
        try:
            while True:
                batch = _get(f"https://api.github.com/users/{login}/repos?per_page=100&page={page}&type=owner")
                if not batch:
                    break
                repos.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
        except urllib.error.HTTPError as e:
            if e.code == 403:
                self.done.emit(False, "GitHub API 額度超過限制（403）。填 token 可拉高額度，或稍後再試。")
            elif e.code == 404:
                self.done.emit(False, f"GitHub 帳號不存在或無法讀取：{login}")
            else:
                self.done.emit(False, f"GitHub API 失敗（HTTP {e.code}）。")
            return
        except urllib.error.URLError as e:
            self.done.emit(False, f"連不到 GitHub（{e.reason}）。")
            return

        result = {}
        for r in repos:
            name = r.get("name", "")
            if not name:
                continue
            entry = {"is_fork": bool(r.get("fork")), "owner": login, "parent": ""}
            if entry["is_fork"] and (not match_names or name.lower() in match_names):
                try:
                    detail = _get(f"https://api.github.com/repos/{login}/{name}")
                    entry["parent"] = (detail.get("parent") or {}).get("clone_url", "")
                except (urllib.error.HTTPError, urllib.error.URLError):
                    pass
            result[name] = entry
        self.hooks.emit(json.dumps(result, ensure_ascii=False))
        self.done.emit(True, f"已讀取 GitHub 帳號 {login} 的 {len(result)} 個倉庫。")

    # --- 掃描本機專案根目錄，挑出還留著非 NAS 來源 URL 的殘留 remote（fork 慣例的 upstream 等）---
    def _run_local_scan(self):
        c = self.cfg
        root_paths = c.get("scan_roots", []) or []
        nas_host_frag = c.get("host", "") or ""
        self.log.emit(f"--- 掃描本機 {len(root_paths)} 個資料夾 ---")
        found = {}
        for base in root_paths:
            if not base or not os.path.isdir(base):
                continue
            try:
                subdirs = [os.path.join(base, d) for d in os.listdir(base)
                           if os.path.isdir(os.path.join(base, d))]
            except OSError:
                continue
            for proj in subdirs:
                if not is_git_repo(proj):
                    continue
                rc, out, _ = self._run(
                    ["git", "config", "--get-regexp", r"^remote\..*\.url"], cwd=proj
                )
                if rc != 0 or not out:
                    continue
                name = os.path.basename(proj)
                for line in out.splitlines():
                    parts = line.split(" ", 1)
                    if len(parts) != 2:
                        continue
                    key, url = parts
                    if nas_host_frag and nas_host_frag in url:
                        continue
                    remote_name = key.split(".")[1] if key.count(".") >= 2 else key
                    found.setdefault(name, []).append({"remote": remote_name, "url": url})
        self.hooks.emit(json.dumps(found, ensure_ascii=False))
        self.done.emit(True, f"本機掃描完成，{len(found)} 個資料夾有殘留來源 URL。")

    # --- 一鍵升級 NAS 上的 CI 引擎（自動備份 + 換檔）---
    def _run_upgrade_engine(self):
        c = self.cfg
        root = c["remote_root"]
        # 引擎腳本內寫死 BASE="/volume1/Git_Server"；若目前 remote_root 不同，
        # 部署前先改寫，否則引擎會讀不到 ci_policies/<repo>.policy → POLICY 空
        # → 靜默放行所有 push（跟沒裝一樣，且完全看不出來）。
        eng_src = base64.b64decode(PATCHED_ENGINE_B64).decode("utf-8")
        eng_src, n_sub = re.subn(r"(?m)^BASE=.*$", f'BASE="{root}"', eng_src, count=1)
        if n_sub != 1:
            self.done.emit(False, "內建 CI 引擎內容異常（找不到 BASE= 行），已中止升級。")
            return
        b64 = base64.b64encode(eng_src.encode("utf-8")).decode("ascii")
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
            "echo '== .bat 換行風險掃描（缺 .gitattributes CRLF 保護）=='",
            "#    純 LF 或依賴簽出機器 core.autocrlf 的 .bat，換一台設定不同的機器",
            "#    clone/pull 下來後，cmd.exe 解析跨行 if(...)/for /f(...) 區塊可能整段",
            "#    錯亂（NAS_GIT_Tools 自己的 build_exe.bat 已實際發生過）。",
            "bat_hits=0",
            "for repo in \"$BASE\"/*.git; do",
            "  [ -d \"$repo\" ] || continue",
            "  n=$(basename \"$repo\")",
            "  base=$(git --git-dir=\"$repo\" symbolic-ref --short HEAD 2>/dev/null)",
            "  [ -z \"$base\" ] && continue",
            "  bats=$(git --git-dir=\"$repo\" ls-tree -r --name-only \"$base\" 2>/dev/null | grep -i '\\.bat$')",
            "  [ -z \"$bats\" ] && continue",
            "  ga_ok=0",
            "  if git --git-dir=\"$repo\" cat-file -e \"$base:.gitattributes\" 2>/dev/null; then",
            "    if git --git-dir=\"$repo\" show \"$base:.gitattributes\" 2>/dev/null | grep -Eq '^\\*\\.bat[[:space:]]+.*eol=crlf'; then",
            "      ga_ok=1",
            "    fi",
            "  fi",
            "  if [ \"$ga_ok\" = 0 ]; then",
            "    cnt=$(echo \"$bats\" | grep -c .)",
            "    echo \"[  ] $n：有 $cnt 個 .bat 檔，但沒有 .gitattributes 的 *.bat eol=crlf 保護，換機器 clone 可能因 core.autocrlf 設定不同讓 .bat 內多行 if/for 區塊解析錯亂\"",
            "    bat_hits=$((bat_hits+1))",
            "  fi",
            "done",
            "[ \"$bat_hits\" = 0 ] && echo '[OK] 沒有偵測到缺 CRLF 保護的 .bat 檔'",
            "echo",
            "echo '== git_devs 帳號 SSH 金鑰登入 ACL 檢查 =='",
            "#    DSM 的 sshd 會檢查 home 目錄本身的 Synology ACL，ACL 不乾淨的話會整段無聲",
            "#    忽略 authorized_keys、退回密碼登入，不會報任何錯誤，很難察覺（2026-07-15 實際事故）。",
            "acl_bad=0; acl_skip=0",
            "gd_members=$(grep '^git_devs:' /etc/group | cut -d: -f4)",
            "old_ifs=$IFS; IFS=','",
            "for u in $gd_members; do",
            "  [ -z \"$u\" ] && continue",
            "  home=$(grep \"^$u:\" /etc/passwd | cut -d: -f6)",
            "  [ -z \"$home\" ] && continue",
            "  acl_line=$(synoacltool -get \"$home\" 2>/dev/null | head -1)",
            "  if [ -z \"$acl_line\" ]; then",
            "    echo \"[  ] $u：無法讀取 $home 的 ACL 狀態（權限不足或指令不存在），略過\"",
            "    acl_skip=$((acl_skip+1))",
            "  elif echo \"$acl_line\" | grep -q 'No ACL'; then",
            "    :",
            "  else",
            "    echo \"[!!] $u：home 目錄（$home）還有 Synology ACL，SSH 金鑰登入可能被無聲忽略、退回密碼登入。修法：sudo synoacltool -del \\\"$home\\\" && sudo chmod 700 \\\"$home\\\"\"",
            "    acl_bad=$((acl_bad+1))",
            "  fi",
            "done",
            "IFS=$old_ifs",
            "if [ \"$acl_bad\" = 0 ] && [ \"$acl_skip\" = 0 ]; then",
            "  echo '[OK] 所有 git_devs 帳號的 home 目錄 ACL 正常'",
            "elif [ \"$acl_bad\" = 0 ]; then",
            "  echo \"[  ] 有 $acl_skip 個帳號的 home ACL 因權限不足無法確認（非 root 讀不到別人 home 的 ACL，這台 NAS 對這個身份沒開免密碼 sudo，此處無法補 sudo 問到真相），其餘沒發現異常，不代表全部正常\"",
            "fi",
            "echo",
            "echo '== 日誌 =='",
            "[ -d \"$BASE/logs\" ] && echo '[OK] logs 目錄存在' || echo '[  ] 無 logs 目錄'",
            "echo ___END___",
            "true",
        ])
        rc, out, err = self._ssh(cmd, timeout=3600)
        if rc != 0:
            self.done.emit(False, "健康檢查失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取伺服器空間資訊失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取 Telegram 通知設定失敗：" + self._err_hint(err, rc))
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

    # --- 讀取跨機器共享的身份設定（config/profiles_sync.json；只含 user/host/remote_root/
    #     updated_at/machines，絕不含密碼或 identity_file——那兩者是機器本地的東西）---
    def _run_profile_sync_pull(self):
        root = self.cfg["remote_root"]
        self.log.emit("--- 拉取跨機器身份設定 ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            f"f='{root}/config/profiles_sync.json'",
            "if [ -f \"$f\" ]; then cat \"$f\"; else echo '{}'; fi",
            "echo ___END___",
            "true",
        ])
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取跨機器身份設定失敗：" + self._err_hint(err, rc))
            return
        self.hooks.emit(self._between(out).strip() or "{}")
        self.done.emit(True, "已讀取跨機器身份設定。")

    # --- 寫回合併後的跨機器身份設定（走 base64，寫前先備份舊檔）---
    def _run_profile_sync_push(self):
        root = self.cfg["remote_root"]
        payload = self.cfg.get("sync_payload", "{}")
        self.log.emit("--- 推送跨機器身份設定 ---")
        b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        cmd = "\n".join([
            f"d='{root}/config'; f=\"$d/profiles_sync.json\"",
            "mkdir -p \"$d\"",
            "[ -f \"$f\" ] && cp \"$f\" \"$f.bak-$(date +%Y%m%d-%H%M%S)\"",
            f"printf '%s' '{b64}' | base64 -d > \"$f\"",
            "chmod 600 \"$f\"",
            "echo ___OK___",
        ])
        rc, out, _ = self._ssh(cmd)
        if rc == 0 and "___OK___" in out:
            self.done.emit(True, "已同步身份設定到 NAS（舊檔已備份）。")
        else:
            self.done.emit(False, "推送跨機器身份設定失敗（連線或權限問題）。")

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
        rc, out, _ = self._ssh(cmd, timeout=3600)
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取日誌失敗：" + self._err_hint(err, rc))
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
            f"BASE='{root}'; name='{name}'; branch={shq(branch)}; pol='{pol}'",
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "自我測試失敗：" + self._err_hint(err, rc))
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
        rc, out, err = self._ssh(cmd)
        if rc != 0:
            self.done.emit(False, "讀取封存區失敗：" + self._err_hint(err, rc))
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
        """永久刪除封存項目。支援單筆（arch_name）與批次（arch_names）——批次在
        同一條 SSH 連線內迴圈刪除，不再每個項目各開一條連線（20 項省下 ~30 秒握手）。"""
        root = self.cfg["remote_root"]
        names = self.cfg.get("arch_names") or (
            [self.cfg["arch_name"]] if self.cfg.get("arch_name") else [])
        bad = [a for a in names if not self._safe_arch(a)]
        if bad:
            self.done.emit(False, f"名稱不安全：{bad[0]!r}")
            return
        if not names:
            self.done.emit(False, "沒有要刪除的封存項目。")
            return
        self.log.emit(f"--- 永久刪除封存（{len(names)} 個）---")
        lines = [f"BASE='{root}'; A=\"$BASE/_archived\""]
        for a in names:
            lines += [
                f"e=\"$A/{a}\"",
                f"if [ ! -e \"$e\" ]; then echo '[NOTFOUND] {a}'",
                f"elif rm -rf \"$e\"; then echo '[OK] {a}'",
                f"else echo '[FAIL] {a}'; fi",
            ]
        ok, body, hint = self._ssh_block(lines)
        if not ok:
            self.done.emit(False, f"刪除失敗：{hint}")
            return
        self.hooks.emit(body)
        nok = body.count("[OK] ")
        nbad = body.count("[FAIL] ") + body.count("[NOTFOUND] ")
        if len(names) == 1:
            self.done.emit(nok == 1, f"已永久刪除：{names[0]}" if nok == 1
                           else f"刪除失敗（{body.strip() or '權限問題？'}）。")
        else:
            self.done.emit(nbad == 0, f"批次清理完成：成功 {nok}、失敗 {nbad}。")

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
        if not is_safe_name(repo_name):
            self.done.emit(False, f"倉庫名稱不合規（僅允許中英數字與 . _ -）：{repo_name!r}")
            return
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

        # Step 1 NAS 建庫（存在檢查＋建庫＋權限＋hook＋讀既有分類，合併成一條 SSH——
        # 過去這段拆成 5 條連線，每條 1-2 秒握手，串接一次要白等近十秒）
        self.log.emit("--- 步驟 1：在 NAS 建立裸倉庫 ---")
        ok, body, hint = self._ssh_block([
            f"REPO='{remote_repo_path}'; ROOT='{root}'; NAME='{repo_name}'",
            "if [ -d \"$REPO\" ]; then",
            "  echo EXISTS",
            "else",
            "  if git init --bare \"$REPO\" >/dev/null 2>&1; then",
            "    echo CREATED",
            # 讓 git 之後自己建立的物件檔就是群組可寫，避免不同身份交錯 push 時互卡權限
            "    git --git-dir=\"$REPO\" config core.sharedRepository group",
            # 權限：sudo -n（免密碼）盡力而為，失敗不中斷
            f"    if sudo -n chown -R {user}:git_devs \"$REPO\" 2>/dev/null && "
            f"sudo -n chmod g+s \"$REPO\" 2>/dev/null && sudo -n chmod -R g+rwX \"$REPO\" 2>/dev/null; then",
            "      echo PERM_OK",
            "    else",
            "      echo PERM_MANUAL",
            "    fi",
            "  else",
            "    echo INIT_FAIL",
            "  fi",
            "fi",
            "if [ -d \"$REPO\" ]; then",
            "  if [ -f \"$ROOT/install_and_monitor_git_hooks.sh\" ]; then",
            "    \"$ROOT/install_and_monitor_git_hooks.sh\" \"$NAME\"",
            "  else",
            "    echo '[WARN] 找不到 install_and_monitor_git_hooks.sh，略過'",
            "  fi",
            "  echo \"KIND=$(git --git-dir=\"$REPO\" config --get nasgit.kind 2>/dev/null)\"",
            "fi",
        ])
        if not ok:
            self.done.emit(False, "無法連線 NAS（SSH 驗證或連線問題）。\n"
                                  f"原因：{hint}\n"
                                  "請確認已設 SSH 金鑰，或填密碼並安裝 PuTTY(plink)。在家可改用內網 IP。")
            return
        if "INIT_FAIL" in body:
            self.done.emit(False, "NAS repo 建立失敗（git init --bare）。")
            return
        if "EXISTS" in body:
            self.log.emit(f"[INFO] NAS repo 已存在，跳過建立：{remote_repo_path}")
        elif "PERM_OK" in body:
            self.log.emit(f"[OK] 已建立並設定權限：{remote_repo_path}")
        elif "PERM_MANUAL" in body:
            self.log.emit("⚠️ NAS repo 已建立，但權限需手動補完（sudo 未設 NOPASSWD）。")
            self.log.emit("   請另開視窗執行（會問 NAS 密碼）：")
            self.log.emit(
                f'   ssh {ssh_host} "sudo chown -R {user}:git_devs '
                f"'{remote_repo_path}'; sudo chmod g+s '{remote_repo_path}'; "
                f"sudo chmod -R g+rwX '{remote_repo_path}'\""
            )
        existing_kind = ""
        for bl in body.splitlines():
            if bl.startswith("KIND="):
                existing_kind = bl[len("KIND="):].strip()

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
        prev_origin = ""
        if "origin" in remotes.split():
            # 覆蓋前先留一份，串接完會用它判斷這個專案的來源分類（自己的/clone/fork）
            _, prev_origin, _ = self._run(["git", "remote", "get-url", "origin"], cwd=project_path)
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

        # 2-7 NAS HEAD 指向本分支＋記錄來源分類（合併成一條 SSH；
        # NAS 上已有 nasgit.kind 就不覆蓋，見 CLAUDE.md）
        post_lines = [
            f"repo='{remote_repo_path}'",
            f"git --git-dir=\"$repo\" symbolic-ref HEAD refs/heads/{shq(branch)} && echo HEAD_OK",
        ]
        kind_label = ""
        if not existing_kind:
            kind_lines, kind_label = self._repo_kind_config_lines(prev_origin)
            post_lines += kind_lines
        ok, body, _hint = self._ssh_block(post_lines)
        if ok and "HEAD_OK" in body:
            self.log.emit(f"✔ 已將 NAS 預設分支(HEAD)指向 {branch}")
        if kind_label:
            self.log.emit(f"ℹ 來源分類：{kind_label}")

        self.done.emit(True, f"完成！專案已就地接上 NAS。\nNAS 倉庫：{remote_repo_path}")

    # --- 串接當下依 prev_origin 判斷來源分類，回傳要併進遠端腳本的 config 行與顯示文字。
    # 不自己開 SSH 連線：呼叫端（_run_connect）把這些行併進既有的 post-push 腳本一次送出；
    # 「NAS 已有 nasgit.kind 就不覆蓋」的檢查也由呼叫端用第一條腳本讀回的值把關（見 CLAUDE.md）---
    def _repo_kind_config_lines(self, prev_origin):
        prev_origin = (prev_origin or "").strip()
        if not prev_origin:
            kind, upstream, src = "own", "", "auto-connect"
        else:
            kind, upstream, src = "clone", prev_origin, "auto-connect"
            m = re.match(
                r"^(?:https://|git@|ssh://[^/]*/)github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$",
                prev_origin,
            )
            if m:
                owner, gh_repo = m.group(1), m.group(2)
                login = (self.cfg.get("github_login", "") or "").strip()
                if login and login.lower() == owner.lower():
                    try:
                        req = urllib.request.Request(
                            f"https://api.github.com/repos/{owner}/{gh_repo}",
                            headers={"Accept": "application/vnd.github+json", "User-Agent": "NasGitConnector"},
                        )
                        token = (self.cfg.get("github_token", "") or "").strip()
                        if token:
                            req.add_header("Authorization", f"Bearer {token}")
                        with urllib.request.urlopen(req, timeout=10) as resp:
                            detail = json.loads(resp.read().decode("utf-8"))
                        if detail.get("fork"):
                            kind, src = "fork", "auto-github"
                        else:
                            kind, upstream, src = "own", "", "auto-github"
                    except (urllib.error.HTTPError, urllib.error.URLError):
                        self.log.emit(
                            "ℹ 無法連線 GitHub API 判斷 fork 狀態，先記成「clone 別人的」，"
                            "之後可用「來源批次比對…」重新判定。"
                        )

        steps = [
            f"git --git-dir=\"$repo\" config nasgit.kind {shq(kind)}",
            f"git --git-dir=\"$repo\" config nasgit.kindsrc {shq(src)}",
        ]
        if upstream:
            steps.append(f"git --git-dir=\"$repo\" config nasgit.upstream {shq(upstream)}")
        label = {"own": "自己的", "fork": "我 fork 的", "clone": "clone 別人的"}[kind]
        return steps, label + (f"（來源 {upstream}）" if upstream else "")


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
    def __init__(self, parent, title, text, markdown=False, goto_line=None, terminal_cfg=None):
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
        row.addWidget(copy_btn)
        if terminal_cfg is not None:
            self._terminal_cfg = terminal_cfg
            term_btn = QPushButton(f"開啟終端機（{terminal_cfg.get('user', '')}@{terminal_cfg.get('host', '')}）…")
            term_btn.clicked.connect(self._open_terminal)
            row.addWidget(term_btn)
        close_btn = QPushButton("關閉")
        close_btn.clicked.connect(self.accept)
        row.addStretch(1)
        row.addWidget(close_btn)
        lay.addLayout(row)

    def _copy(self):
        QApplication.clipboard().setText(self._text)

    def _open_terminal(self):
        ok, msg = open_admin_terminal(self._terminal_cfg)
        if not ok:
            QMessageBox.warning(self, "開啟終端機失敗", msg)


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
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "branch_protect_set",
                      f"repo={self.name} denyDeletes={self.cb_del.isChecked()} denyNonFastForwards={self.cb_ff.isChecked()}")
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
            # 不記錄 token 內容本身，只記錄「有沒有設定」，避免密鑰進本機稽核紀錄
            detail = f"token={'(已設定)' if self.token_edit.text().strip() else '(空)'} chat_id={'(已設定)' if self.chat_edit.text().strip() else '(空)'}"
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "tg_conf_set", detail)
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
        # 一條 SSH 連線內批次刪除（過去每項各開一條連線、由 _run_next_purge 佇列驅動）
        self._busy(True)
        self.status.setText(f"批次刪除中…（{len(names)} 個）")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["arch_names"] = list(names)
        self.worker = Worker(cfg, mode="archive_purge")
        self.worker.hooks.connect(self._on_bulk_purge_body)
        self.worker.done.connect(self._on_bulk_purge_done)
        self.worker.start()

    def _on_bulk_purge_body(self, body: str):
        # 逐項補稽核：只記真的刪掉的那些
        for line in body.splitlines():
            if line.startswith("[OK] "):
                audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "archive_purge",
                          line[len("[OK] "):].strip() + " (批次清理)")

    def _on_bulk_purge_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "⚠ ") + msg)
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b06000;")
        self.refresh()


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
        self.import_b = QPushButton("從 Key_Management 匯入…")
        self.delete_b = QPushButton("刪除")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.add_b)
        row.addWidget(self.import_b)
        row.addWidget(self.delete_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.add_b.clicked.connect(self.on_add)
        self.import_b.clicked.connect(self.on_import)
        self.delete_b.clicked.connect(self.on_delete)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.add_b, self.import_b, self.delete_b):
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
        self._add_key_line(text)

    def on_import(self):
        pubkey = pick_key_management_pubkey(self)
        if pubkey:
            self._add_key_line(pubkey)

    def _add_key_line(self, text):
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

        pubkey_row = QHBoxLayout()
        pubkey_row.addWidget(QLabel("該帳號要用來 push 的 SSH 公鑰（.pub 檔內容，由申請人自己產生、只給公鑰）："), stretch=1)
        self.gen_key_b = QPushButton("本機產生新金鑰…")
        self.gen_key_b.setToolTip(
            "在這台機器上跑 ssh-keygen 產生一組新的金鑰對，私鑰留在本機、只把公鑰內容帶進下面欄位。\n"
            "如果這個帳號是要給別人用，記得把私鑰檔安全地交給對方，不要用明碼管道傳送。")
        self.gen_key_b.clicked.connect(self.on_gen_key)
        pubkey_row.addWidget(self.gen_key_b)
        self.import_key_b = QPushButton("從 Key_Management 匯入…")
        self.import_key_b.setToolTip("從姊妹工具 Key_Management 的本機金鑰名冊挑一把已產生好的公鑰，唯讀讀取，不會改動對方的檔案。")
        self.import_key_b.clicked.connect(self.on_import_key)
        pubkey_row.addWidget(self.import_key_b)
        lay.addLayout(pubkey_row)
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

    def on_gen_key(self):
        username = self.user_edit.text().strip()
        if not is_safe_username(username):
            self.status.setText("請先填好帳號名稱（會拿來當金鑰檔名與 comment）。")
            self.status.setStyleSheet("color:#b00020;")
            return
        default_name = f"id_ed25519_{username}"
        name, ok = QInputDialog.getText(
            self, "本機產生新金鑰",
            "金鑰檔名（存到 ~/.ssh/ 底下，私鑰留在這台機器，只有公鑰內容會被帶進上面欄位）：",
            text=default_name)
        name = name.strip()
        if not ok or not name:
            return
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        path = os.path.join(ssh_dir, name)
        if os.path.exists(path) or os.path.exists(path + ".pub"):
            QMessageBox.warning(self, "檔案已存在", f"{path}（或 .pub）已經存在，請換一個檔名，避免覆蓋既有金鑰。")
            return
        self.gen_key_b.setEnabled(False)
        self.status.setText("本機產生金鑰中…")
        self.status.setStyleSheet("")
        self._last_gen_key_path = path
        self._last_gen_key_username = username
        cfg = dict(self.cfg)
        cfg["key_path"] = path
        cfg["key_comment"] = username
        self.worker = Worker(cfg, mode="local_gen_ssh_key")
        self.worker.hooks.connect(self._on_key_generated)
        self.worker.done.connect(self._on_gen_key_done)
        self.worker.start()

    def _on_key_generated(self, pubkey):
        self.pubkey_edit.setPlainText(pubkey)

    def _on_gen_key_done(self, ok, msg):
        self.gen_key_b.setEnabled(True)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok:
            QMessageBox.information(
                self, "金鑰已產生",
                msg + "\n\n如果這個帳號要給別人用，請把私鑰檔安全地交給對方（不要用 email/聊天軟體明碼傳），"
                      "交接完成後可考慮從這台機器上刪除私鑰。")
            offer_write_local_ssh_config(
                self, self.cfg.get("host", ""), self._last_gen_key_username, self._last_gen_key_path)

    def on_import_key(self):
        pubkey = pick_key_management_pubkey(self)
        if pubkey:
            self.pubkey_edit.setPlainText(pubkey)

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
        dlg = TextViewDialog(self, f"新增 git_devs 帳號 — 待執行指令（{username}）", script,
                             terminal_cfg=self.cfg)
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
            f"sudo synouser --add {username} '{password}' {shq(desc)} {shq(email)} 0 0",
            "",
            "# 2) 強制設定登入 shell（不依賴 synouser --add 的預設值）",
            "#    DSM 建帳號時偶爾給 /sbin/nologin（觸發條件不明，synouser 沒有可靠參數能指定），",
            "#    /sbin/nologin 會擋掉「所有」透過 SSH 執行的指令，不只是互動登入——git push 用的",
            "#    git-receive-pack 一樣被擋，金鑰再對也沒用（git_user4 就是栽在這裡）。直接改",
            "#    /etc/passwd 那一行最保險，不依賴任何 synouser 子指令（版本不明、不可靠）。",
            f"sudo sed -i 's#^\\({username}:.*:\\)/sbin/nologin$#\\1/bin/sh#' /etc/passwd",
            "",
            "# 3) 加入 git_devs 群組",
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
            "# 4) 確認實際 home 目錄（不同 DSM 設定可能不是 /var/services/homes/<帳號>）",
            f"HOME_DIR=$(grep \"^{username}:\" /etc/passwd | cut -d: -f6)",
            f'[ -z "$HOME_DIR" ] && HOME_DIR=/var/services/homes/{username}',
            'echo "偵測到的 home 目錄：$HOME_DIR"',
            "",
            "# 5) 設定 SSH 金鑰登入",
            "#    先清掉 home 目錄本身的 Synology ACL：DSM 的 sshd 會額外檢查 home 目錄的 ACL，",
            "#    ACL 不乾淨的話會整個無聲忽略 authorized_keys、直接退回密碼登入（不報錯，很難察覺）。",
            "#    synouser --add 建出來的 home 目錄擁有者常常還是 root，不 chown 回本人的話，",
            "#    sshd 一樣會拒絕金鑰登入、退回密碼（git_user3 就是栽在這裡，只補了 .ssh 沒補 home 本身）。",
            'sudo synoacltool -del "$HOME_DIR"',
            'sudo chmod 700 "$HOME_DIR"',
            f'sudo chown {username}:users "$HOME_DIR"',
            'sudo mkdir -p "$HOME_DIR/.ssh"',
            "sudo tee \"$HOME_DIR/.ssh/authorized_keys\" >/dev/null <<'EOF'",
            pubkey,
            "EOF",
            'sudo chmod 700 "$HOME_DIR/.ssh"',
            'sudo chmod 600 "$HOME_DIR/.ssh/authorized_keys"',
            f'sudo chown -R {username}:users "$HOME_DIR/.ssh"',
            "",
            "# 6) 同步既有倉庫權限，讓新帳號一開始就能直接 push（跟修 kuoterry/Git_User1 那次同一件事）",
            f"sudo chmod -R g+rwX {root}",
            f"sudo find {root} -maxdepth 1 -type d -name '*.git' -exec chmod g+s {{}} \\;",
            "",
            "# 7) 完成後回這套工具按「一鍵修復…」，把 core.sharedRepository=group 補到每個既有倉庫。",
            "",
        ] + _login_precondition_selfcheck(username) + [
            "",
            "# 完成。上面「登入前置條件自我檢查」若全部 ✅，這個帳號應該就能直接用金鑰登入。",
        ]
        return "\n".join(lines)


# ============================================================
# git_devs 帳號清單檢視（唯讀）+ 移除帳號入口
# ============================================================
class GitDevsUsersDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.worker = None
        self.setWindowTitle("git_devs 帳號清單")
        self.resize(580, 420)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("目前 git_devs 群組的所有成員（含 home 目錄與 authorized_keys 金鑰數）。選一個可以移除、加金鑰或輪替金鑰。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.add_key_b = QPushButton("幫選取帳號新增金鑰…")
        self.rotate_b = QPushButton("金鑰輪替…")
        self.remove_b = QPushButton("移除選取帳號…")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.add_key_b)
        row.addWidget(self.rotate_b)
        row.addWidget(self.remove_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.add_key_b.clicked.connect(self.on_add_key)
        self.rotate_b.clicked.connect(self.on_rotate)
        self.remove_b.clicked.connect(self.on_remove)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def _busy(self, b):
        for x in (self.refresh_b, self.add_key_b, self.rotate_b, self.remove_b):
            x.setEnabled(not b)

    def _selected_username(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先在清單選一個帳號。")
            return None
        return it.data(Qt.ItemDataRole.UserRole)

    def refresh(self):
        self.list.clear()
        self._busy(True)
        self.status.setText("讀取中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        self.worker = Worker(cfg, mode="list_git_devs_users")
        self.worker.repos.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, entries):
        self.list.clear()
        for username, uid, home, nkeys in entries:
            it = QListWidgetItem(f"{username}    uid={uid}    home={home}    金鑰數={nkeys}")
            it.setData(Qt.ItemDataRole.UserRole, username)
            self.list.addItem(it)

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_add_key(self):
        username = self._selected_username()
        if not username:
            return
        dlg = AddKeyForUserDialog(self, self.cfg, username)
        dlg.exec()
        self.refresh()

    def on_rotate(self):
        username = self._selected_username()
        if not username:
            return
        dlg = RotateKeyDialog(self, self.cfg, username)
        dlg.exec()
        self.refresh()

    def on_remove(self):
        username = self._selected_username()
        if not username:
            return
        dlg = RemoveGitDevsUserDialog(self, self.cfg, username)
        dlg.exec()
        self.refresh()


# ============================================================
# 移除 git_devs 帳號：查詢現況 + 產生指令（做法比照新增，工具本身不執行）
# ============================================================
class RemoveGitDevsUserDialog(QDialog):
    def __init__(self, parent, cfg, username):
        super().__init__(parent)
        self.cfg = cfg
        self.username = username
        self.worker = None
        self.setWindowTitle(f"移除 git_devs 帳號 — {username}")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "跟新增帳號一樣，這套工具不會自動執行——會先唯讀查詢目前 git_devs 名單，"
            "組出移除指令給你複製，貼到有 sudo 權限的 SSH 視窗一次執行到底。\n"
            "注意：移除 git_devs 只會收回這個帳號 push 倉庫的權限，帳號本身如果沒勾下面選項，"
            "還是可以用同一把 SSH 金鑰登入 NAS shell——真的要徹底切斷存取，要連帳號一起刪。"))
        self.cb_delete_account = QCheckBox("同時刪除 DSM 帳號本身（synouser --del，不可逆）")
        self.cb_delete_account.setToolTip("不勾的話只是把帳號踢出 git_devs、收回 push 權限，帳號本身還在，比較容易復原。")
        lay.addWidget(self.cb_delete_account)
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
        if self.username in ("kuoterry", "Git_User1"):
            r = QMessageBox.question(
                self, "確認",
                f"「{self.username}」是這套工具預設身份使用的帳號之一，移除後這個身份會失去 push 權限。"
                "確定要繼續嗎？")
            if r != QMessageBox.StandardButton.Yes:
                return
        self.gen_b.setEnabled(False)
        self.status.setText("查詢 git_devs 現況中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["new_user"] = self.username
        self.worker = Worker(cfg, mode="prep_new_user")
        self.worker.hooks.connect(self._on_queried)
        self.worker.done.connect(self.on_query_done)
        self.worker.start()

    def on_query_done(self, ok, msg):
        self.gen_b.setEnabled(True)
        if not ok:
            self.status.setText("❌ " + msg.replace("\n", "　"))
            self.status.setStyleSheet("color:#b00020;")

    def _on_queried(self, text):
        exists = False
        members = ""
        for ln in text.splitlines():
            if ln.startswith("EXISTS="):
                exists = ln[len("EXISTS="):].strip() == "1"
            elif ln.startswith("MEMBERS="):
                members = ln[len("MEMBERS="):].strip()
        member_list = [m for m in members.split(",") if m]
        if self.username not in member_list:
            self.status.setText(f"⚠ 「{self.username}」目前不在 git_devs 名單裡，可能已經被移除了。")
            self.status.setStyleSheet("color:#b06000;")
        else:
            self.status.setText("✔ 查詢完成。")
            self.status.setStyleSheet("color:#1a7f37;")
        remaining = [m for m in member_list if m != self.username]
        if not remaining:
            QMessageBox.warning(
                self, "無法產生",
                "移除後 git_devs 會變成空群組，這風險太大，工具不會自動產生這種指令，請先確認清單，必要時手動處理。")
            return
        script = self._build_script(remaining, exists)
        dlg = TextViewDialog(self, f"移除 git_devs 帳號 — 待執行指令（{self.username}）", script)
        dlg.exec()

    def _build_script(self, remaining, exists):
        delete_account = self.cb_delete_account.isChecked()
        new_members = " ".join(remaining)
        lines = [
            "# ============================================================",
            f"# 移除 git_devs 帳號：{self.username}",
            "# 由 NasGitConnector 產生，這段指令不會自動執行。",
            "# 整段複製、貼到有 sudo 權限的 SSH 視窗、一次執行到底即可。",
            "# 全程唯一會問你的是最開頭的 sudo -v（問你自己的登入密碼），其餘全自動，不用手動改任何一行。",
            "# ============================================================",
            "",
            "# 0) 先讓 sudo 記住密碼，避免整段貼下去時中途又跳密碼提示、把後面指令吃掉／打斷",
            "sudo -v",
            "",
            f"# 1) 把 {self.username} 從 git_devs 移除",
            "#    注意：synogroup --member 是「整批覆蓋」不是「移除單一個」，這裡刻意不包含要移除的帳號。",
            f"sudo synogroup --member git_devs {new_members}",
            "#    執行完立刻回讀名單自我檢查：剩下的人都還在、要移除的人真的不見了，異常就大聲警告",
            "AFTER_MEMBERS=$(grep '^git_devs:' /etc/group | cut -d: -f4)",
            f"for m in {new_members}; do",
            '  case ",$AFTER_MEMBERS," in',
            '    *",$m,"*) ;;',
            '    *) echo "‼️  警告：$m 不在更新後的 git_devs 名單裡（目前：$AFTER_MEMBERS），可能被誤刪，請立刻人工確認並補回！" ;;',
            "  esac",
            "done",
            f'case ",$AFTER_MEMBERS," in',
            f'  *",{self.username},"*) echo "‼️  警告：{self.username} 還在名單裡，移除沒有成功！" ;;',
            f'  *) echo "✔ {self.username} 已從 git_devs 移除" ;;',
            "esac",
            'echo "目前 git_devs 成員：$AFTER_MEMBERS"',
            "",
        ]
        if delete_account:
            lines += [
                "# 2) 同時刪除 DSM 帳號本身（不可逆！執行前請確認真的要刪帳號，而不只是收回 git 權限）",
                f"sudo synouser --del {self.username}",
            ]
        else:
            lines += [
                f"# 2) 沒有勾選刪除 DSM 帳號，{self.username} 帳號本身還在（只是已經不在 git_devs、無法再 push 任何 repo，",
                "#    但仍可用同一把 SSH 金鑰登入 NAS shell）。之後若要徹底刪除，可自行執行：",
                f"#    sudo synouser --del {self.username}",
            ]
        return "\n".join(lines)


# ============================================================
# 幫既有 git_devs 帳號新增一把 SSH 金鑰：產生指令（做法比照新增/移除帳號，工具本身不執行）
# 跟 SshKeysDialog 的差異：SshKeysDialog 只能改「目前登入身份自己」的 authorized_keys，
# 這裡透過 sudo 腳本，即使連不上目標帳號本人，也能由有 sudo 權限的管理者代為加鑰匙。
# ============================================================
class AddKeyForUserDialog(QDialog):
    def __init__(self, parent, cfg, username):
        super().__init__(parent)
        self.cfg = cfg
        self.username = username
        self.worker = None
        self.setWindowTitle(f"幫既有帳號新增金鑰 — {username}")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"幫「{username}」這個既有 git_devs 帳號多加一把 SSH 公鑰。跟建立新帳號一樣，"
            "這套工具不會自動執行——按「產生設定指令」後把整段複製，貼到有 sudo 權限的 SSH 視窗一次執行到底。\n"
            "適用情境：你自己連不上這個帳號（沒有它原本的金鑰/密碼），但有 sudo 權限，要代為加鑰匙。"))
        pubkey_row = QHBoxLayout()
        pubkey_row.addWidget(QLabel("新公鑰內容："), stretch=1)
        self.gen_key_b = QPushButton("本機產生新金鑰…")
        self.gen_key_b.setToolTip("在這台機器上跑 ssh-keygen 產生一組新的金鑰對，私鑰留在本機，只把公鑰內容帶進下面欄位。")
        self.gen_key_b.clicked.connect(self.on_gen_key)
        pubkey_row.addWidget(self.gen_key_b)
        self.import_key_b = QPushButton("從 Key_Management 匯入…")
        self.import_key_b.clicked.connect(self.on_import_key)
        pubkey_row.addWidget(self.import_key_b)
        lay.addLayout(pubkey_row)
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

    def on_gen_key(self):
        default_name = f"id_ed25519_{self.username}"
        name, ok = QInputDialog.getText(
            self, "本機產生新金鑰",
            "金鑰檔名（存到 ~/.ssh/ 底下，私鑰留在這台機器，只有公鑰內容會被帶進上面欄位）：",
            text=default_name)
        name = name.strip()
        if not ok or not name:
            return
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        path = os.path.join(ssh_dir, name)
        if os.path.exists(path) or os.path.exists(path + ".pub"):
            QMessageBox.warning(self, "檔案已存在", f"{path}（或 .pub）已經存在，請換一個檔名，避免覆蓋既有金鑰。")
            return
        self.gen_key_b.setEnabled(False)
        self.status.setText("本機產生金鑰中…")
        self.status.setStyleSheet("")
        self._last_gen_key_path = path
        cfg = dict(self.cfg)
        cfg["key_path"] = path
        cfg["key_comment"] = self.username
        self.worker = Worker(cfg, mode="local_gen_ssh_key")
        self.worker.hooks.connect(lambda pubkey: self.pubkey_edit.setPlainText(pubkey))
        self.worker.done.connect(self._on_gen_key_done)
        self.worker.start()

    def _on_gen_key_done(self, ok, msg):
        self.gen_key_b.setEnabled(True)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok:
            QMessageBox.information(
                self, "金鑰已產生",
                msg + "\n\n請把私鑰檔安全地交給實際使用這個帳號的人（不要用 email/聊天軟體明碼傳）。")
            offer_write_local_ssh_config(self, self.cfg.get("host", ""), self.username, self._last_gen_key_path)

    def on_import_key(self):
        pubkey = pick_key_management_pubkey(self)
        if pubkey:
            self.pubkey_edit.setPlainText(pubkey)

    def on_generate(self):
        pubkey = " ".join(self.pubkey_edit.toPlainText().split())
        if not is_ssh_pubkey(pubkey):
            self.status.setText("公鑰格式看起來不對，應以 ssh-rsa / ssh-ed25519 等開頭。")
            self.status.setStyleSheet("color:#b00020;")
            return
        script = self._build_script(pubkey)
        dlg = TextViewDialog(self, f"幫既有帳號新增金鑰 — 待執行指令（{self.username}）", script,
                             terminal_cfg=self.cfg)
        dlg.exec()
        self.status.setText("✔ 指令已產生，請複製貼到有 sudo 權限的 SSH 視窗執行。")
        self.status.setStyleSheet("color:#1a7f37;")

    def _build_script(self, pubkey):
        lines = [
            "# ============================================================",
            f"# 幫既有 git_devs 帳號新增金鑰：{self.username}",
            "# 由 NasGitConnector 產生，這段指令不會自動執行。",
            "# 整段複製、貼到有 sudo 權限的 SSH 視窗、一次執行到底即可。",
            "# 全程唯一會問你的是最開頭的 sudo -v（問你自己的登入密碼），其餘全自動，不用手動改任何一行。",
            "# ============================================================",
            "",
            "# 0) 先讓 sudo 記住密碼，避免整段貼下去時中途又跳密碼提示、把後面指令吃掉／打斷",
            "sudo -v",
            "",
            "# 1) 確認實際 home 目錄（不同 DSM 設定可能不是 /var/services/homes/<帳號>）",
            f"HOME_DIR=$(grep \"^{self.username}:\" /etc/passwd | cut -d: -f6)",
            f'[ -z "$HOME_DIR" ] && HOME_DIR=/var/services/homes/{self.username}',
            'echo "偵測到的 home 目錄：$HOME_DIR"',
            "",
            "# 2) 強制設定登入 shell（既有帳號也可能被 DSM 設成 /sbin/nologin）",
            "#    /sbin/nologin 會擋掉「所有」透過 SSH 執行的指令，不只是互動登入——git push 用的",
            "#    git-receive-pack 一樣被擋，金鑰再對也沒用（git_user4 就是栽在這裡）。這個帳號",
            "#    可能是很久以前建的、也可能不是這套工具建的，不確定當初 shell 設對了沒，",
            "#    每次補金鑰都順手檢查/修正一次，比等下次登入失敗才回頭查划算。",
            f"sudo sed -i 's#^\\({self.username}:.*:\\)/sbin/nologin$#\\1/bin/sh#' /etc/passwd",
            "",
            "# 3) 新增金鑰（若這把已經存在則跳過，不重複加入，不動原本其他金鑰）",
            "#    先清掉 home 目錄本身的 Synology ACL：DSM 的 sshd 會額外檢查 home 目錄的 ACL，",
            "#    ACL 不乾淨的話會整個無聲忽略 authorized_keys、直接退回密碼登入（不報錯，很難察覺）。",
            "#    同時確保 home 目錄擁有者是本人（不是 root）——擁有者不對，sshd 一樣拒絕金鑰登入。",
            'sudo synoacltool -del "$HOME_DIR"',
            'sudo chmod 700 "$HOME_DIR"',
            f'sudo chown {self.username}:users "$HOME_DIR"',
            'sudo mkdir -p "$HOME_DIR/.ssh"',
            'sudo touch "$HOME_DIR/.ssh/authorized_keys"',
            "NEWKEY=$(cat <<'EOF'",
            pubkey,
            "EOF",
            ")",
            'if sudo grep -qxF "$NEWKEY" "$HOME_DIR/.ssh/authorized_keys" 2>/dev/null; then',
            '  echo "這把公鑰已經存在，不重複加入。"',
            "else",
            '  echo "$NEWKEY" | sudo tee -a "$HOME_DIR/.ssh/authorized_keys" >/dev/null',
            '  echo "已新增。"',
            "fi",
            'sudo chmod 700 "$HOME_DIR/.ssh"',
            'sudo chmod 600 "$HOME_DIR/.ssh/authorized_keys"',
            f'sudo chown -R {self.username}:users "$HOME_DIR/.ssh"',
            "",
        ] + _login_precondition_selfcheck(self.username) + [
            "",
            "# 完成。上面「登入前置條件自我檢查」若全部 ✅，這個帳號應該就能直接用金鑰登入。",
        ]
        return "\n".join(lines)


# ============================================================
# git_devs 既有帳號金鑰輪替：新公鑰＋撤銷舊公鑰一次做完（做法比照新增/移除帳號，工具本身不執行）
# 刻意只做這一件事：不碰 Key_Management 的名冊狀態，也不做排程／自動化，
# 舊鑰匙要不要在 Key_Management 那邊標記封存，交回使用者自行判斷。
# ============================================================
class RotateKeyDialog(QDialog):
    def __init__(self, parent, cfg, username):
        super().__init__(parent)
        self.cfg = cfg
        self.username = username
        self.worker = None
        self.setWindowTitle(f"金鑰輪替 — {username}")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"幫「{username}」把舊金鑰換成新金鑰：新公鑰加入、舊公鑰撤銷，一段腳本做完。\n"
            "跟其他帳號管理功能一樣，這套工具不會自動執行——產生指令後自行複製貼到有 sudo 權限的 SSH 視窗執行。\n"
            "注意：這裡只處理 NAS 端的 authorized_keys，Key_Management 本機名冊裡舊金鑰要不要標記封存，"
            "請自行到 Key_Management 那邊處理，這裡不會幫你動。"))

        lay.addWidget(QLabel("舊公鑰（要撤銷，貼上完整那一行；留空則只加新的，不撤銷）："))
        self.old_pubkey_edit = QPlainTextEdit()
        self.old_pubkey_edit.setPlaceholderText("ssh-ed25519 AAAA... old-comment（可留空）")
        self.old_pubkey_edit.setFixedHeight(60)
        lay.addWidget(self.old_pubkey_edit)

        new_row = QHBoxLayout()
        new_row.addWidget(QLabel("新公鑰："), stretch=1)
        self.gen_key_b = QPushButton("本機產生新金鑰…")
        self.gen_key_b.clicked.connect(self.on_gen_key)
        new_row.addWidget(self.gen_key_b)
        self.import_key_b = QPushButton("從 Key_Management 匯入…")
        self.import_key_b.clicked.connect(self.on_import_key)
        new_row.addWidget(self.import_key_b)
        lay.addLayout(new_row)
        self.new_pubkey_edit = QPlainTextEdit()
        self.new_pubkey_edit.setPlaceholderText("ssh-ed25519 AAAA... new-comment")
        self.new_pubkey_edit.setFixedHeight(60)
        lay.addWidget(self.new_pubkey_edit)

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

    def on_gen_key(self):
        default_name = f"id_ed25519_{self.username}_new"
        name, ok = QInputDialog.getText(
            self, "本機產生新金鑰",
            "金鑰檔名（存到 ~/.ssh/ 底下，私鑰留在這台機器，只有公鑰內容會被帶進下面欄位）：",
            text=default_name)
        name = name.strip()
        if not ok or not name:
            return
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        path = os.path.join(ssh_dir, name)
        if os.path.exists(path) or os.path.exists(path + ".pub"):
            QMessageBox.warning(self, "檔案已存在", f"{path}（或 .pub）已經存在，請換一個檔名，避免覆蓋既有金鑰。")
            return
        self.gen_key_b.setEnabled(False)
        self.status.setText("本機產生金鑰中…")
        self.status.setStyleSheet("")
        self._last_gen_key_path = path
        cfg = dict(self.cfg)
        cfg["key_path"] = path
        cfg["key_comment"] = f"{self.username}-rotated"
        self.worker = Worker(cfg, mode="local_gen_ssh_key")
        self.worker.hooks.connect(lambda pubkey: self.new_pubkey_edit.setPlainText(pubkey))
        self.worker.done.connect(self._on_gen_key_done)
        self.worker.start()

    def _on_gen_key_done(self, ok, msg):
        self.gen_key_b.setEnabled(True)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok:
            QMessageBox.information(
                self, "金鑰已產生",
                msg + "\n\n請把新私鑰檔安全地交給實際使用這個帳號的人，確認新鑰匙能登入後，再把舊私鑰刪除、作廢。")
            offer_write_local_ssh_config(self, self.cfg.get("host", ""), self.username, self._last_gen_key_path)

    def on_import_key(self):
        pubkey = pick_key_management_pubkey(self)
        if pubkey:
            self.new_pubkey_edit.setPlainText(pubkey)

    def on_generate(self):
        new_pubkey = " ".join(self.new_pubkey_edit.toPlainText().split())
        if not is_ssh_pubkey(new_pubkey):
            self.status.setText("新公鑰格式看起來不對，應以 ssh-rsa / ssh-ed25519 等開頭。")
            self.status.setStyleSheet("color:#b00020;")
            return
        old_pubkey = " ".join(self.old_pubkey_edit.toPlainText().split())
        if old_pubkey and not is_ssh_pubkey(old_pubkey):
            self.status.setText("舊公鑰格式看起來不對，應以 ssh-rsa / ssh-ed25519 等開頭（或留空跳過撤銷）。")
            self.status.setStyleSheet("color:#b00020;")
            return
        script = self._build_script(new_pubkey, old_pubkey)
        dlg = TextViewDialog(self, f"金鑰輪替 — 待執行指令（{self.username}）", script)
        dlg.exec()
        self.status.setText("✔ 指令已產生，請複製貼到有 sudo 權限的 SSH 視窗執行。")
        self.status.setStyleSheet("color:#1a7f37;")

    def _build_script(self, new_pubkey, old_pubkey):
        lines = [
            "# ============================================================",
            f"# 金鑰輪替：{self.username}",
            "# 由 NasGitConnector 產生，這段指令不會自動執行。",
            "# 整段複製、貼到有 sudo 權限的 SSH 視窗、一次執行到底即可。",
            "# 全程唯一會問你的是最開頭的 sudo -v（問你自己的登入密碼），其餘全自動，不用手動改任何一行。",
            "# ============================================================",
            "",
            "# 0) 先讓 sudo 記住密碼，避免整段貼下去時中途又跳密碼提示、把後面指令吃掉／打斷",
            "sudo -v",
            "",
            "# 1) 確認實際 home 目錄（不同 DSM 設定可能不是 /var/services/homes/<帳號>）",
            f"HOME_DIR=$(grep \"^{self.username}:\" /etc/passwd | cut -d: -f6)",
            f'[ -z "$HOME_DIR" ] && HOME_DIR=/var/services/homes/{self.username}',
            'echo "偵測到的 home 目錄：$HOME_DIR"',
            'AK="$HOME_DIR/.ssh/authorized_keys"',
            "",
            "# 2) 登入前置條件修正（與建帳號/補金鑰腳本同一套；輪替完才發現新鑰匙登不進去最冤枉）",
            "#    /sbin/nologin 會擋掉所有透過 SSH 執行的指令（含 git push）；home 目錄的 Synology ACL",
            "#    不乾淨、或擁有者不是本人，sshd 會整個無聲忽略 authorized_keys、退回密碼登入（不報錯）。",
            f"sudo sed -i 's#^\\({self.username}:.*:\\)/sbin/nologin$#\\1/bin/sh#' /etc/passwd",
            'sudo synoacltool -del "$HOME_DIR"',
            'sudo chmod 700 "$HOME_DIR"',
            f'sudo chown {self.username}:users "$HOME_DIR"',
            "",
            "# 3) 動手前先備份原檔",
            'sudo mkdir -p "$HOME_DIR/.ssh"',
            'sudo touch "$AK"',
            'sudo cp "$AK" "$AK.bak-$(date +%Y%m%d-%H%M%S)"',
            "",
            "# 4) 加入新公鑰（若已存在則跳過，不重複加入）",
            "NEWKEY=$(cat <<'EOF'",
            new_pubkey,
            "EOF",
            ")",
            'if sudo grep -qxF "$NEWKEY" "$AK" 2>/dev/null; then',
            '  echo "新公鑰已經存在，不重複加入。"',
            "else",
            '  echo "$NEWKEY" | sudo tee -a "$AK" >/dev/null',
            '  echo "已加入新公鑰。"',
            "fi",
        ]
        if old_pubkey:
            lines += [
                "",
                "# 5) 撤銷舊公鑰（找不到也不會報錯，就當作本來就不在）",
                "OLDKEY=$(cat <<'EOF'",
                old_pubkey,
                "EOF",
                ")",
                'sudo grep -vxF "$OLDKEY" "$AK" | sudo tee "$AK.tmp" >/dev/null',
                'sudo mv "$AK.tmp" "$AK"',
                'echo "已撤銷舊公鑰（原檔已備份在上面第 2 步印出的 .bak 檔名）。"',
            ]
        else:
            lines += [
                "",
                "# 5) 沒有填舊公鑰，跳過撤銷這步（只新增，不撤銷任何既有金鑰）",
            ]
        lines += [
            "",
            'sudo chmod 700 "$HOME_DIR/.ssh"',
            'sudo chmod 600 "$AK"',
            f'sudo chown -R {self.username}:users "$HOME_DIR/.ssh"',
            "",
        ] + _login_precondition_selfcheck(self.username) + [
            "",
            "# 完成後記得：確認新鑰匙能登入、舊鑰匙不能登入，再回 Key_Management 把舊金鑰標記封存/刪除。",
        ]
        return "\n".join(lines)


# ============================================================
# git_devs 密碼留底紀錄檢視（本機明碼檔案，可清除）
# ============================================================
class GitDevsCredLogDialog(QDialog):
    def __init__(self, parent, cfg):
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("git_devs 密碼留底紀錄")
        self.resize(640, 420)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"本機明碼紀錄檔：{GIT_DEVS_CRED_LOG_PATH}\n"
            "每次用「新增 git_devs 帳號」產生密碼都會留一筆在這裡，請自行妥善保護、不需要的紀錄記得清理。"))
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(QFont("Consolas", 10))
        lay.addWidget(self.text, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.clear_b = QPushButton("清除全部紀錄…")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.clear_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.refresh_b.clicked.connect(self.refresh)
        self.clear_b.clicked.connect(self.on_clear)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def refresh(self):
        try:
            with open(GIT_DEVS_CRED_LOG_PATH, encoding="utf-8") as f:
                text = f.read()
        except OSError:
            text = ""
        self.text.setPlainText(text or f"（目前沒有紀錄，檔案：{GIT_DEVS_CRED_LOG_PATH}）")

    def on_clear(self):
        r = QMessageBox.question(
            self, "清除全部紀錄",
            "確定清除本機所有 git_devs 密碼留底紀錄？此動作無法復原（清掉的只是這份本機檔案紀錄，"
            "不會影響 NAS 上帳號本身的密碼）。")
        if r != QMessageBox.StandardButton.Yes:
            return
        try:
            os.remove(GIT_DEVS_CRED_LOG_PATH)
        except OSError:
            pass
        audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""),
                  "clear_git_devs_creds", "清除本機 git_devs 密碼留底紀錄")
        self.refresh()


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
# 離站備份設定 對話框（此庫 → 外部 Git 端點，例如 GitHub 私有庫，作為 disaster recovery）
# ============================================================
class BackupDialog(QDialog):
    def __init__(self, parent, cfg, name):
        super().__init__(parent)
        self.cfg = cfg
        self.name = name
        self.worker = None
        self.setWindowTitle(f"離站備份設定 — {name}")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "設定後，可用「同步離站備份」把這個庫整份推到外部 Git 端點（例如 GitHub 私有庫），"
            "作為 NAS 本機以外的備份，避免 NAS 硬碟損壞時連封存區一起沒了。"))
        g = QGridLayout()
        g.addWidget(QLabel("備份目的地 URL："), 0, 0)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://github.com/作者/repo-backup.git（留空並儲存 = 移除備份設定）")
        g.addWidget(self.url_edit, 0, 1)
        lay.addLayout(g)
        note = QLabel(
            "注意：同步時執行的是 git push --mirror，會讓目的地完全比照這個庫，"
            "包含刪除目的地上、這個庫沒有的分支/tag。請指向一個專用的空白備份倉庫，"
            "不要指向還在使用中的其他倉庫。私有庫需先在 NAS 端設好 GitHub 金鑰/token。")
        note.setWordWrap(True)
        note.setStyleSheet("color:#666;")
        lay.addWidget(note)
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
        cfg = dict(self.cfg)
        cfg["repo_name"] = self.name
        self.worker = Worker(cfg, mode="get_backup_remote")
        self.worker.hooks.connect(self._on_loaded)
        self.worker.done.connect(self._on_load_done)
        self.worker.start()

    def _on_loaded(self, text):
        self.url_edit.setText(text.strip())

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
        cfg["backup_url"] = self.url_edit.text().strip()
        self.worker = Worker(cfg, mode="set_backup_remote")
        self.worker.done.connect(self._on_saved)
        self.worker.start()

    def _on_saved(self, ok, msg):
        self.bb.setEnabled(True)
        if ok:
            QMessageBox.information(self, "完成", msg)
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "set_backup_remote",
                      f"repo={self.name} url={self.url_edit.text().strip() or '(移除)'}")
            self.accept()
        else:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")


# ============================================================
# 單一倉庫來源分類對話框
# 分類值取自清單當下已載入的資料（不用額外連線讀取）；只有「儲存」會打 NAS。
# 鏡像庫的分類由 remote.origin.mirror 決定，此對話框對鏡像庫唯讀。
# ============================================================
class RepoKindDialog(QDialog):
    def __init__(self, parent, cfg, name, mirror_url, kind, upstream):
        super().__init__(parent)
        self.cfg = cfg
        self.name = name
        self.is_mirror = bool(mirror_url)
        self.worker = None
        self.setWindowTitle(f"來源分類 — {name}")
        self.setMinimumWidth(480)

        lay = QVBoxLayout(self)
        if self.is_mirror:
            note = QLabel(f"這是鏡像庫（← {mirror_url}），分類固定為「鏡像」，不能在此更改。")
            note.setWordWrap(True)
            lay.addWidget(note)
        else:
            lay.addWidget(QLabel("這個倉庫的來源是？"))

        gb = QGroupBox()
        gl = QVBoxLayout(gb)
        self.rb_own = QRadioButton("自己的（原創專案）")
        self.rb_fork = QRadioButton("我 fork 的")
        self.rb_clone = QRadioButton("clone 別人的（沒有 fork 關係）")
        self.rb_none = QRadioButton("未分類")
        for rb in (self.rb_own, self.rb_fork, self.rb_clone, self.rb_none):
            gl.addWidget(rb)
        lay.addWidget(gb)

        g = QGridLayout()
        g.addWidget(QLabel("來源 URL（fork/clone 才需要）："), 0, 0)
        self.upstream_edit = QLineEdit(upstream or "")
        g.addWidget(self.upstream_edit, 0, 1)
        lay.addLayout(g)

        {"own": self.rb_own, "fork": self.rb_fork, "clone": self.rb_clone,
         "": self.rb_none}.get(kind, self.rb_none).setChecked(True)

        if self.is_mirror:
            for rb in (self.rb_own, self.rb_fork, self.rb_clone, self.rb_none):
                rb.setEnabled(False)
            self.upstream_edit.setEnabled(False)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.bb.accepted.connect(self.on_save)
        self.bb.rejected.connect(self.reject)
        self.bb.button(QDialogButtonBox.StandardButton.Save).setEnabled(not self.is_mirror)
        lay.addWidget(self.bb)

    def _selected_kind(self) -> str:
        if self.rb_own.isChecked():
            return "own"
        if self.rb_fork.isChecked():
            return "fork"
        if self.rb_clone.isChecked():
            return "clone"
        return ""

    def on_save(self):
        kind = self._selected_kind()
        upstream = self.upstream_edit.text().strip() if kind in ("fork", "clone") else ""
        self.bb.setEnabled(False)
        self.status.setText("儲存中…")
        self.status.setStyleSheet("")
        cfg = dict(self.cfg)
        cfg["kind_items"] = [(self.name, kind, upstream)]
        cfg["kind_src"] = "manual"
        self.worker = Worker(cfg, mode="set_repo_kind")
        self.worker.done.connect(self._on_saved)
        self.worker.start()

    def _on_saved(self, ok, msg):
        self.bb.setEnabled(True)
        if ok:
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "set_repo_kind",
                      f"repo={self.name} kind={self._selected_kind() or '(未分類)'}")
            self.accept()
        else:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")


# ============================================================
# 批次比對倉庫來源分類對話框
# 兩個獨立證據來源合併給建議：GitHub 帳號的 fork 狀態（github_scan）、
# 本機專案殘留的非 NAS remote URL（local_scan，覆蓋 fork 慣例常見的 upstream remote 殘留）。
# 只給建議，不自動套用；逐列確認/可改分類，按「套用勾選」才真的寫回 NAS。
# ============================================================
class RepoKindScanDialog(QDialog):
    def __init__(self, parent, cfg, all_repos):
        super().__init__(parent)
        self.cfg = cfg
        self.all_repos = all_repos  # (name, status, pol, mirror, size_kb, kind, upstream)
        self.gh_worker = None
        self.local_worker = None
        self.apply_worker = None
        self.gh_result = {}
        self.local_result = {}
        self.settings = QSettings("TerryTools", "NasGitConnector")
        self.setWindowTitle("來源批次比對")
        self.resize(780, 560)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "用 GitHub 帳號的 fork 狀態、加上本機專案殘留的來源 remote，幫還沒分類的倉庫給建議。\n"
            "只是建議，逐列確認/可改分類後按「套用勾選」才會真的寫回 NAS。已是鏡像庫的不會列出。"))

        g = QGridLayout()
        g.addWidget(QLabel("GitHub 帳號："), 0, 0)
        self.login_edit = QLineEdit(self.settings.value("github_login", "", type=str))
        g.addWidget(self.login_edit, 0, 1)
        g.addWidget(QLabel("Token（選填，拉高額度/讀私有庫）："), 1, 0)
        self.token_edit = QLineEdit(self.settings.value("github_token", "", type=str))
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        g.addWidget(self.token_edit, 1, 1)
        self.remember_check = QCheckBox("記住帳號/token（存在本機設定）")
        self.remember_check.setChecked(bool(self.settings.value("github_login", "", type=str)))
        g.addWidget(self.remember_check, 2, 1)
        g.addWidget(QLabel("本機掃描資料夾（分號分隔）："), 3, 0)
        self.roots_edit = QLineEdit(";".join(CONTAINER_ROOTS))
        g.addWidget(self.roots_edit, 3, 1)
        self.browse_btn = QPushButton("瀏覽加入…")
        self.browse_btn.clicked.connect(self.on_browse_root)
        g.addWidget(self.browse_btn, 3, 2)
        lay.addLayout(g)

        row = QHBoxLayout()
        self.scan_btn = QPushButton("開始比對")
        self.scan_btn.clicked.connect(self.on_scan)
        row.addWidget(self.scan_btn)
        row.addStretch(1)
        lay.addLayout(row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["套用", "倉庫", "現況", "建議分類", "證據"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table, stretch=1)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.apply_btn = QPushButton("套用勾選")
        self.apply_btn.clicked.connect(self.on_apply)
        self.bb.addButton(self.apply_btn, QDialogButtonBox.ButtonRole.ActionRole)
        self.bb.rejected.connect(self.reject)
        lay.addWidget(self.bb)

    def on_browse_root(self):
        path = QFileDialog.getExistingDirectory(self, "選擇要掃描的資料夾")
        if path:
            cur = [p for p in self.roots_edit.text().split(";") if p.strip()]
            cur.append(path)
            self.roots_edit.setText(";".join(cur))

    def on_scan(self):
        login = self.login_edit.text().strip()
        if not login:
            self.status.setText("請先填 GitHub 帳號。")
            return
        if self.remember_check.isChecked():
            self.settings.setValue("github_login", login)
            self.settings.setValue("github_token", self.token_edit.text().strip())
        else:
            self.settings.remove("github_login")
            self.settings.remove("github_token")

        self.scan_btn.setEnabled(False)
        self.status.setText("掃描 GitHub 中…")
        self.status.setStyleSheet("")
        match_names = [r[0][:-4] if r[0].endswith(".git") else r[0] for r in self.all_repos]
        cfg = dict(self.cfg)
        cfg["github_login"] = login
        cfg["github_token"] = self.token_edit.text().strip()
        cfg["match_names"] = match_names
        self.gh_worker = Worker(cfg, mode="github_scan")
        self.gh_worker.hooks.connect(self._on_gh_result)
        self.gh_worker.done.connect(self._on_gh_done)
        self.gh_worker.start()

    def _on_gh_result(self, text):
        try:
            self.gh_result = json.loads(text) if text else {}
        except json.JSONDecodeError:
            self.gh_result = {}

    def _on_gh_done(self, ok, msg):
        if not ok:
            self.scan_btn.setEnabled(True)
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")
            return
        self.status.setText("掃描本機資料夾中…")
        roots = [p.strip() for p in self.roots_edit.text().split(";") if p.strip()]
        cfg = dict(self.cfg)
        cfg["scan_roots"] = roots
        self.local_worker = Worker(cfg, mode="local_scan")
        self.local_worker.hooks.connect(self._on_local_result)
        self.local_worker.done.connect(self._on_local_done)
        self.local_worker.start()

    def _on_local_result(self, text):
        try:
            self.local_result = json.loads(text) if text else {}
        except json.JSONDecodeError:
            self.local_result = {}

    def _on_local_done(self, ok, msg):
        self.scan_btn.setEnabled(True)
        if not ok:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")
            return
        self.status.setText("比對完成，逐列確認後按「套用勾選」寫回。")
        self.status.setStyleSheet("color:#1a7f37;")
        self._build_table()

    def _build_table(self):
        login = self.login_edit.text().strip().lower()
        # repo 名比對統一忽略大小寫：本機資料夾名稱/GitHub repo 名跟 NAS 上的 bare repo 名
        # 可能大小寫不完全一致（例如手動改過資料夾名）。
        gh_ci = {k.lower(): v for k, v in self.gh_result.items()}
        local_ci = {k.lower(): v for k, v in self.local_result.items()}
        self.table.setRowCount(0)
        for name, status, pol, mirror, size_kb, kind, upstream in self.all_repos:
            if mirror:
                continue  # 鏡像庫分類固定由 remote.origin.mirror 決定，不列入建議
            bare = name[:-4] if name.endswith(".git") else name
            suggest_kind, suggest_upstream, evidence = "", "", ""
            gh = gh_ci.get(bare.lower())
            if gh:
                if gh.get("is_fork"):
                    suggest_kind = "fork"
                    suggest_upstream = gh.get("parent") or ""
                    evidence = f"GitHub: fork ← {suggest_upstream or '(未知 parent)'}"
                else:
                    suggest_kind = "own"
                    evidence = f"GitHub: {login}/{bare}（非 fork）"
            else:
                local_hits = local_ci.get(bare.lower()) or []
                if local_hits:
                    h = local_hits[0]
                    suggest_kind = "clone"
                    suggest_upstream = h["url"]
                    evidence = f"本機 {h['remote']} ← {h['url']}"
            row = self.table.rowCount()
            self.table.insertRow(row)
            chk = QCheckBox()
            chk.setChecked(bool(suggest_kind) and not kind)
            self.table.setCellWidget(row, 0, chk)
            name_item = QTableWidgetItem(bare)
            name_item.setData(Qt.ItemDataRole.UserRole, name)
            self.table.setItem(row, 1, name_item)
            cur_label = {"own": "自己的", "fork": "fork", "clone": "clone", "": "未分類"}[kind or ""]
            self.table.setItem(row, 2, QTableWidgetItem(cur_label))
            combo = QComboBox()
            combo.addItems(["未分類", "自己的", "我 fork 的", "clone 別人的"])
            combo.setCurrentIndex({"": 0, "own": 1, "fork": 2, "clone": 3}[suggest_kind])
            self.table.setCellWidget(row, 3, combo)
            ev_item = QTableWidgetItem(evidence)
            ev_item.setData(Qt.ItemDataRole.UserRole, suggest_upstream)
            self.table.setItem(row, 4, ev_item)

    def on_apply(self):
        kind_map = {0: "", 1: "own", 2: "fork", 3: "clone"}
        items = []
        for row in range(self.table.rowCount()):
            chk = self.table.cellWidget(row, 0)
            if not chk.isChecked():
                continue
            name = self.table.item(row, 1).data(Qt.ItemDataRole.UserRole)
            combo = self.table.cellWidget(row, 3)
            kind = kind_map[combo.currentIndex()]
            upstream = self.table.item(row, 4).data(Qt.ItemDataRole.UserRole) or ""
            items.append((name, kind, upstream))
        if not items:
            self.status.setText("沒有勾選任何列。")
            return
        self.apply_btn.setEnabled(False)
        self.status.setText("寫回中…")
        cfg = dict(self.cfg)
        cfg["kind_items"] = items
        cfg["kind_src"] = "auto-github"
        self.apply_worker = Worker(cfg, mode="set_repo_kind")
        self.apply_worker.done.connect(self._on_applied)
        self.apply_worker.start()

    def _on_applied(self, ok, msg):
        self.apply_btn.setEnabled(True)
        if ok:
            audit_log(self.cfg.get("user", ""), self.cfg.get("host", ""), "set_repo_kind",
                      f"批次比對套用：{msg}")
            self.status.setText("✔ " + msg)
            self.status.setStyleSheet("color:#1a7f37;")
        else:
            self.status.setText("❌ " + msg)
            self.status.setStyleSheet("color:#b00020;")


# ============================================================
# 主視窗
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NAS Git 專案串接工具 v{__version__}")
        self.setMinimumSize(760, 640)
        self.settings = QSettings("TerryTools", "NasGitConnector")
        self._seed_default_profiles()
        self.worker = None

        self._all_repos = []  # 瀏覽分頁：完整倉庫清單（供篩選用）

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # ================= 共用：身份 / NAS 設定 =================
        # 可摺疊：這塊平常填好就不太需要再看，摺起來讓下面分頁（倉庫清單等）可視範圍變大。
        # 摺疊狀態記在 QSettings，跟其他 UI 偏好一樣重開機記得住；預設展開，不影響第一次使用的體驗。
        nb = QGroupBox("身份 / NAS 設定（會依本機電腦名稱自動選身份；兩個分頁共用）")
        nb.setCheckable(True)
        nb.setToolTip("取消勾選可摺疊此區塊，讓下面的分頁內容有更大可視範圍。")
        nb_outer = QVBoxLayout(nb)
        nb_outer.setContentsMargins(0, 0, 0, 0)
        nb_content = QWidget()
        ng = QGridLayout(nb_content)
        nb_outer.addWidget(nb_content)

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
        sync_prof_btn = QPushButton("☁ 同步跨機器設定")
        sync_prof_btn.setToolTip(
            "把身份設定（不含密碼、不含私鑰檔路徑）跟 NAS 上其他電腦同步："
            "拉回其他電腦新增/更新過的身份，再把這台的更新推上去。")
        ng.addWidget(sync_prof_btn, 0, 5)

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

        # 私鑰檔案（選填）：留空＝交給 SSH 預設解析（agent／~/.ssh/config／預設檔名）；
        # 有填＝這個身份的每次連線都明確帶 -i 指定這把，適合非預設檔名的金鑰（例如 git_devs 各帳號）。
        ng.addWidget(QLabel("私鑰檔案："), 7, 0)
        id_file_row = QHBoxLayout()
        self.identity_file_edit = QLineEdit()
        self.identity_file_edit.setPlaceholderText("留空＝用 SSH 預設解析（agent／~/.ssh/config／預設檔名）")
        id_file_row.addWidget(self.identity_file_edit)
        id_file_browse_btn = QPushButton("瀏覽…")
        id_file_browse_btn.clicked.connect(self.on_browse_identity_file)
        id_file_row.addWidget(id_file_browse_btn)
        ng.addLayout(id_file_row, 7, 1, 1, 4)

        root.addWidget(nb)

        nb_expanded = self.settings.value("identity_panel_expanded", True, type=bool)
        nb.setChecked(nb_expanded)
        nb_content.setVisible(nb_expanded)
        nb.toggled.connect(nb_content.setVisible)
        nb.toggled.connect(lambda checked: self.settings.setValue("identity_panel_expanded", checked))

        save_prof_btn.clicked.connect(self.save_current_profile)
        add_prof_btn.clicked.connect(self.add_profile)
        del_prof_btn.clicked.connect(self.delete_profile)
        bind_btn.clicked.connect(self.bind_current_machine)
        sync_prof_btn.clicked.connect(self.on_sync_profiles)
        self.sync_prof_btn = sync_prof_btn
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)

        # ================= 分頁 =================
        tabs = QTabWidget()
        root.addWidget(tabs, stretch=1)
        # 全域中止鈕：放在分頁列右上角，任何分頁都看得到；只有操作進行中才可按。
        self.cancel_btn = QPushButton("⛔ 中止")
        self.cancel_btn.setToolTip("強制中止目前執行中的操作（砍掉子程序）。遠端動作可能做一半，之後請重新整理確認狀態。")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.on_cancel_worker)
        tabs.setCornerWidget(self.cancel_btn, Qt.Corner.TopRightCorner)

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
        self.backup_sync_btn = QPushButton("同步離站備份")
        self.backup_sync_btn.setToolTip("對選取的倉庫執行 push --mirror 到其離站備份目的地；沒選就同步全部已設定備份的倉庫。")
        self.backup_sync_btn.clicked.connect(self.on_backup_sync)
        self.kind_scan_btn = QPushButton("來源批次比對…")
        self.kind_scan_btn.setToolTip("用 GitHub 帳號 fork 狀態＋本機殘留 remote，幫還沒分類的倉庫批次建議來源分類。")
        self.kind_scan_btn.clicked.connect(self.on_repo_kind_scan)

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
        top_row2.addWidget(self.backup_sync_btn)
        top_row2.addWidget(self.kind_scan_btn)
        top_row2.addStretch(1)
        bp.addLayout(top_row2)

        self.kind_tabbar = QTabBar()
        for _, label in REPO_KIND_TABS:
            self.kind_tabbar.addTab(label)
        self.kind_tabbar.currentChanged.connect(lambda _=None: self.apply_repo_filter(self.filter_edit.text()))
        bp.addWidget(self.kind_tabbar)

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
        self.backup_btn = QPushButton("離站備份…")
        self.backup_btn.setEnabled(False)
        self.backup_btn.setToolTip("設定此庫的離站備份目的地（外部 Git 端點，例如 GitHub 私有庫）。")
        self.backup_btn.clicked.connect(self.on_backup_dialog)
        danger_row.addWidget(self.backup_btn)
        self.kind_btn = QPushButton("來源分類…")
        self.kind_btn.setEnabled(False)
        self.kind_btn.setToolTip("標記這個倉庫是自己的原創專案、fork 的、還是單純 clone 別人的（鏡像庫唯讀）。")
        self.kind_btn.clicked.connect(self.on_repo_kind)
        danger_row.addWidget(self.kind_btn)
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
        self.fsck_btn = QPushButton("完整性檢查…")
        self.fsck_btn.setEnabled(False)
        self.fsck_btn.setToolTip("對選取的倉庫執行 git fsck --full，檢查是否有損毀/遺失物件（可多選，唯讀不修改）。")
        self.fsck_btn.clicked.connect(self.on_repo_fsck)
        tools_row.addWidget(self.fsck_btn)
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
        self.git_devs_list_btn = QPushButton("git_devs 帳號清單…")
        self.git_devs_list_btn.setToolTip("唯讀列出 git_devs 群組所有成員，可從清單直接產生移除某帳號的指令。")
        self.git_devs_list_btn.clicked.connect(self.on_git_devs_users)
        self.git_devs_cred_btn = QPushButton("git_devs 密碼留底紀錄…")
        self.git_devs_cred_btn.setToolTip("查看/清除本機留底的 git_devs 新帳號密碼紀錄（明碼檔案）。")
        self.git_devs_cred_btn.clicked.connect(self.on_view_git_devs_creds)
        og.addWidget(self.hc_btn, 0, 0)
        og.addWidget(self.repair_btn, 0, 1)
        og.addWidget(self.new_user_btn, 0, 2)
        og.addWidget(self.disk_btn, 1, 0)
        og.addWidget(self.notify_btn, 1, 1)
        og.addWidget(self.git_devs_list_btn, 1, 2)
        og.addWidget(self.git_devs_cred_btn, 2, 0)
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

    def _write_profile(self, name, vals, stamp=True):
        """寫入單一身份設定。stamp=True（預設）會順便蓋 updated_at，供跨機器同步比對新舊；
        同步流程套用遠端已經算好的值時要傳 stamp=False，避免自己剛拉回來的資料又被當成「本機更新」。"""
        self.settings.setValue(f"profiles/{name}/user", vals.get("user", ""))
        self.settings.setValue(f"profiles/{name}/host", vals.get("host", ""))
        self.settings.setValue(f"profiles/{name}/remote_root", vals.get("remote_root", ""))
        self.settings.setValue(f"profiles/{name}/identity_file", vals.get("identity_file", ""))
        if stamp:
            self.settings.setValue(f"profiles/{name}/updated_at", datetime.now(timezone.utc).isoformat())
        elif "updated_at" in vals:
            self.settings.setValue(f"profiles/{name}/updated_at", vals["updated_at"])

    def _read_profile(self, name):
        return {
            "user": self.settings.value(f"profiles/{name}/user", "kuoterry"),
            "host": self.settings.value(f"profiles/{name}/host", "kcc3713.synology.me"),
            "remote_root": self.settings.value(f"profiles/{name}/remote_root", "/volume1/Git_Server"),
            "identity_file": self.settings.value(f"profiles/{name}/identity_file", ""),
            "updated_at": self.settings.value(f"profiles/{name}/updated_at", ""),
        }

    def load_profile_into_fields(self, name):
        if not name:
            return
        vals = self._read_profile(name)
        self.user_edit.setText(vals["user"])
        self.host_combo.setCurrentText(vals["host"])
        self.root_edit.setText(vals["remote_root"])
        self.identity_file_edit.setText(vals["identity_file"])
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
            "identity_file": self.identity_file_edit.text().strip(),
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
            "identity_file": self.identity_file_edit.text().strip(),
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

    # ---------- 跨機器同步身份設定（config/profiles_sync.json，不含密碼/identity_file）----------
    def on_sync_profiles(self):
        self.sync_prof_btn.setEnabled(False)
        self.maint_status.setText("同步身份設定中（拉取）…")
        self.maint_status.setStyleSheet("")
        self.save_current_profile(silent=True)
        cfg = self.collect_identity_cfg()
        self._pulled_profiles_text = "{}"
        self._sync_worker = Worker(cfg, mode="profile_sync_pull")
        self._sync_worker.log.connect(self.append_log)
        self._sync_worker.hooks.connect(self._on_profile_sync_pulled)
        self._sync_worker.done.connect(self._on_profile_sync_pull_done)
        self._sync_worker.start()

    def _on_profile_sync_pulled(self, text):
        self._pulled_profiles_text = text

    @staticmethod
    def _merge_profiles(local: dict, remote: dict):
        """單人多機器情境：每筆帶 updated_at，較新的贏；machines（電腦名稱綁定）一律聯集、
        只加不減，避免一台機器同步時洗掉另一台機器登記的綁定。回傳 (merged, added, updated)。"""
        merged = {}
        added = updated = 0
        for name in set(local) | set(remote):
            l, r = local.get(name), remote.get(name)
            if l and not r:
                merged[name] = l
            elif r and not l:
                merged[name] = dict(r)
                added += 1
            else:
                lu, ru = l.get("updated_at") or "", r.get("updated_at") or ""
                winner = r if ru > lu else l
                l_machines = sorted(l.get("machines") or [])
                machines = sorted(set(l.get("machines") or []) | set(r.get("machines") or []))
                if ru > lu or machines != l_machines:
                    updated += 1
                merged[name] = {
                    "user": winner.get("user", ""),
                    "host": winner.get("host", ""),
                    "remote_root": winner.get("remote_root", ""),
                    "identity_file": l.get("identity_file", ""),  # 機器本地路徑，永遠沿用本機，不被遠端覆蓋
                    "updated_at": max(lu, ru),
                    "machines": machines,
                }
        return merged, added, updated

    def _on_profile_sync_pull_done(self, ok, msg):
        if not ok:
            self.sync_prof_btn.setEnabled(True)
            self.maint_status.setText("")
            QMessageBox.warning(self, "同步失敗", msg)
            return
        try:
            remote = json.loads(self._pulled_profiles_text or "{}")
        except (json.JSONDecodeError, TypeError):
            remote = {}
        local = {name: {**self._read_profile(name), "machines": self._profile_machines(name)}
                  for name in self._profile_names()}
        merged, added, updated = self._merge_profiles(local, remote)

        for name, vals in merged.items():
            if name not in self._profile_names():
                self.settings.setValue("profile_names", self._profile_names() + [name])
            self._write_profile(name, vals, stamp=False)
            self._set_profile_machines(name, vals.get("machines", []))

        cur = self.profile_combo.currentText()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItems(self._profile_names())
        if cur in self._profile_names():
            self.profile_combo.setCurrentText(cur)
        self.profile_combo.blockSignals(False)
        self.load_profile_into_fields(self.profile_combo.currentText())
        self.update_machine_label()

        self.maint_status.setText("同步身份設定中（推送）…")
        self._sync_added, self._sync_updated = added, updated
        cfg = self.collect_identity_cfg()
        cfg["sync_payload"] = json.dumps(merged, ensure_ascii=False)
        self._sync_worker = Worker(cfg, mode="profile_sync_push")
        self._sync_worker.log.connect(self.append_log)
        self._sync_worker.done.connect(self._on_profile_sync_push_done)
        self._sync_worker.start()

    def _on_profile_sync_push_done(self, ok, msg):
        self.sync_prof_btn.setEnabled(True)
        self.maint_status.setText("")
        if ok:
            QMessageBox.information(
                self, "同步完成",
                f"已同步跨機器身份設定：新增 {self._sync_added} 個、更新 {self._sync_updated} 個身份。")
        else:
            QMessageBox.warning(self, "同步失敗", msg)

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
            "identity_file": self.identity_file_edit.text().strip(),
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
            "identity_file": self.identity_file_edit.text().strip(),
            # 只有在「來源批次比對…」勾過「記住」才會有值；沒填就代表串接當下無法判斷
            # fork/own，只能先記成「clone 別人的」，之後仍可用批次比對補判斷。
            "github_login": self.settings.value("github_login", "", type=str),
            "github_token": self.settings.value("github_token", "", type=str),
        }

    def toggle_pw_echo(self):
        mode = (QLineEdit.EchoMode.Normal if self.show_pw_check.isChecked()
                else QLineEdit.EchoMode.Password)
        self.pw_edit.setEchoMode(mode)

    def on_browse_identity_file(self):
        start = self.identity_file_edit.text().strip() or os.path.join(os.path.expanduser("~"), ".ssh")
        path, _ = QFileDialog.getOpenFileName(self, "選擇這個身份要用的私鑰檔案", start)
        if path:
            self.identity_file_edit.setText(path)

    def append_log(self, text: str):
        self.log_view.appendPlainText(text)

    def set_busy(self, busy: bool):
        self.cancel_btn.setEnabled(busy)
        self.run_btn.setEnabled(not busy)
        self.test_btn.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self.kind_scan_btn.setEnabled(not busy)
        self.ci_status_btn.setEnabled(not busy)
        self.upgrade_btn.setEnabled(not busy)
        self.create_btn.setEnabled(not busy)
        self.archive_btn.setEnabled(not busy)
        self.mirror_reg_btn.setEnabled(not busy)
        self.mirror_sync_btn.setEnabled(not busy)
        self.backup_sync_btn.setEnabled(not busy)
        self.search_all_btn.setEnabled(not busy)
        self.activity_btn.setEnabled(not busy)
        self.ssh_keys_btn.setEnabled(not busy)
        for b in (self.hc_btn, self.repair_btn, self.new_user_btn, self.disk_btn, self.notify_btn,
                  self.git_devs_list_btn, self.git_devs_cred_btn,
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
        self.fsck_btn.setEnabled(not busy and has_sel)
        self.tag_btn.setEnabled(not busy and has_sel)
        # 這四顆過去只在 on_repo_selected 管，busy 時仍可按 → 併發 worker 互踩（稽核記錯 mode）。
        self.desc_btn.setEnabled(not busy and has_sel)
        self.branch_protect_btn.setEnabled(not busy and has_sel)
        self.backup_btn.setEnabled(not busy and has_sel)
        self.kind_btn.setEnabled(not busy and has_sel)
        if busy:
            self.run_btn.setText("執行中…")
        else:
            self.run_btn.setText("開始串接")
            self.update_run_enabled()

    def on_cancel_worker(self):
        w = self.worker
        if not (w and w.isRunning()):
            self.cancel_btn.setEnabled(False)
            return
        r = QMessageBox.question(
            self, "中止操作",
            "確定要強制中止目前操作？\n遠端動作可能做一半（例如同步、修復跑到一半），中止後建議重新整理確認狀態。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.Yes:
            w.cancel()

    def closeEvent(self, event):
        """跑到一半直接關窗會硬殺 QThread（遠端動作做一半、稽核沒記錄）——先確認、再收尾。"""
        w = self.worker
        if w and w.isRunning():
            r = QMessageBox.question(
                self, "操作進行中",
                "還有操作在執行中，現在關閉會中止它（遠端動作可能做一半）。\n確定要中止並離開嗎？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            w.cancel()
            w.wait(8000)
        event.accept()

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
        # items: (name, status, policy, mirror_url, size_kb, kind, upstream)；容錯舊格式
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
                kind = str(it[5]) if len(it) > 5 else ""
                upstream = str(it[6]) if len(it) > 6 else ""
                norm.append((name, status, pol, mirror, size_kb, kind, upstream))
            else:
                norm.append((str(it), "", "none", "", 0, "", ""))
        self._all_repos = norm
        self._update_kind_tab_counts()
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
        tab_kind = self._current_kind_tab()
        rows = [r for r in self._all_repos if not text or text in r[0].lower()]
        if tab_kind != "all":
            rows = [r for r in rows if effective_repo_kind(r[3], r[5] if len(r) > 5 else "") == tab_kind]
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
        # 重建前記住目前選取；否則打字篩選/重新整理都會把選取（含批次 CI 的多選）清掉
        selected_names = {i.data(Qt.ItemDataRole.UserRole) for i in self.repo_list.selectedItems()}
        self.repo_list.clear()
        for row in rows:
            name, status, pol, mirror, size_kb = row[0], row[1], row[2], row[3], row[4]
            kind = row[5] if len(row) > 5 else ""
            upstream = row[6] if len(row) > 6 else ""
            eff_kind = effective_repo_kind(mirror, kind)
            ci = {"soft": "CI:soft", "strict": "CI:strict"}.get(pol, "CI:—")
            parts = [name]
            if status:
                parts.append(status)
            parts.append(ci)
            parts.append(fmt_size_kb(size_kb))
            if eff_kind in REPO_KIND_MARK:
                parts.append(REPO_KIND_MARK[eff_kind])
            it = QListWidgetItem("    ·    ".join(parts))
            it.setData(Qt.ItemDataRole.UserRole, name)
            it.setData(Qt.ItemDataRole.UserRole + 1, pol)
            it.setData(Qt.ItemDataRole.UserRole + 2, mirror)
            it.setData(Qt.ItemDataRole.UserRole + 3, kind)
            it.setData(Qt.ItemDataRole.UserRole + 4, upstream)
            if mirror:
                it.setToolTip(f"GitHub 鏡像 ← {mirror}")
            elif upstream:
                it.setToolTip(f"來源 ← {upstream}")
            if status.startswith("空庫"):
                it.setForeground(Qt.GlobalColor.gray)
            self.repo_list.addItem(it)
            if name in selected_names:
                it.setSelected(True)

    def _current_kind_tab(self) -> str:
        if not hasattr(self, "kind_tabbar"):
            return "all"
        idx = self.kind_tabbar.currentIndex()
        if idx < 0 or idx >= len(REPO_KIND_TABS):
            return "all"
        return REPO_KIND_TABS[idx][0]

    def _update_kind_tab_counts(self):
        if not hasattr(self, "kind_tabbar"):
            return
        counts = {k: 0 for k, _ in REPO_KIND_TABS}
        for r in self._all_repos:
            eff = effective_repo_kind(r[3], r[5] if len(r) > 5 else "")
            counts["all"] += 1
            counts[eff] += 1
        for i, (kind_key, label) in enumerate(REPO_KIND_TABS):
            if kind_key == "all":
                self.kind_tabbar.setTabText(i, f"{label} ({counts['all']})")
            else:
                self.kind_tabbar.setTabText(i, f"{label} ({counts.get(kind_key, 0)})")

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
        self.backup_btn.setEnabled(has)
        self.kind_btn.setEnabled(has)
        self.batch_ci_btn.setEnabled(len(self.repo_list.selectedItems()) >= 1)
        self.rename_btn.setEnabled(has)
        self.clone_btn.setEnabled(has)
        self.log_btn.setEnabled(has)
        self.merged_btn.setEnabled(has)
        self.diff_btn.setEnabled(has)
        self.gc_btn.setEnabled(has)
        self.fsck_btn.setEnabled(has)
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

    def _patch_repo_row(self, name, new_name=None, policy=None):
        """rename/set_ci 完成後直接改本地清單資料並重畫，不再整包 re-list——
        _run_list 會對每個 repo 跑 du -sk，全量重整是這個畫面最貴的操作。"""
        for i, r in enumerate(self._all_repos):
            if r[0] == name:
                r = list(r)
                if new_name:
                    r[0] = new_name
                if policy is not None:
                    r[2] = policy
                self._all_repos[i] = tuple(r)
                break
        self._update_kind_tab_counts()
        self.apply_repo_filter(self.filter_edit.text())

    def on_rename_done(self, ok: bool, msg: str):
        self.set_busy(False)
        if ok:
            self.browse_status.setText("✔ " + msg.replace("\n", "　"))
            self.browse_status.setStyleSheet("color:#1a7f37;")
            c = self.collect_identity_cfg()
            audit_log(c.get("user", ""), c.get("host", ""), "rename_repo", msg.replace("\n", " "))
            w = self.sender()
            old = w.cfg.get("repo_name", "") if w else ""
            new = w.cfg.get("new_name", "") if w else ""
            if new and not new.endswith(".git"):
                new += ".git"
            if old and new:
                self._patch_repo_row(old, new_name=new)
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
            # 用發訊號的那個 Worker 判斷 mode，而不是 self.worker——
            # self.worker 是共用屬性，途中被重新指派會讓稽核記到錯的 mode。
            sender = self.sender()
            sender_mode = getattr(sender, "mode", None)
            if sender_mode in DESTRUCTIVE_MODES:
                c = self.collect_identity_cfg()
                audit_log(c.get("user", ""), c.get("host", ""), sender_mode, msg.replace("\n", " "))
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
            w = self.sender()
            if w:
                c = self.collect_identity_cfg()
                detail = f"repo={w.cfg.get('repo_name', '')} policy={w.cfg.get('ci_policy', '')}"
                audit_log(c.get("user", ""), c.get("host", ""), "set_ci", detail)
                self._patch_repo_row(w.cfg.get("repo_name", ""), policy=w.cfg.get("ci_policy", "none"))
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

    def on_git_devs_users(self):
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = GitDevsUsersDialog(self, cfg)
        dlg.exec()

    def on_view_git_devs_creds(self):
        cfg = dict(self.collect_identity_cfg())
        dlg = GitDevsCredLogDialog(self, cfg)
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
            w = self.sender()
            if w:
                c = self.collect_identity_cfg()
                repo_names = w.cfg.get("repo_names", [])
                pol = w.cfg.get("ci_policy", "none")
                detail = f"repos={','.join(repo_names)} policy={pol}"
                audit_log(c.get("user", ""), c.get("host", ""), "set_ci_batch", detail)
                for rn in repo_names:  # 原地更新 CI 欄，不整包 re-list
                    self._patch_repo_row(rn, policy=pol)
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
            if self.worker:
                c = self.collect_identity_cfg()
                audit_log(c.get("user", ""), c.get("host", ""), "repo_desc_set",
                          f"repo={self.worker.cfg.get('repo_name', '')}")
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

    def on_repo_fsck(self):
        names = self._selected_repo_names()
        if not names:
            self.browse_status.setText("請先在清單選一個或多個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        cfg["repo_names"] = names
        self.save_current_profile(silent=True)
        self._ci_title = "完整性檢查結果"
        self.browse_status.setText(f"對 {len(names)} 個倉庫執行完整性檢查中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="repo_fsck")
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

    # ---------- 離站備份 ----------
    def on_backup_dialog(self):
        name = self._selected_repo_name()
        if not name:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = BackupDialog(self, cfg, name)
        dlg.exec()

    # ---------- 來源分類 ----------
    def on_repo_kind(self):
        items = self.repo_list.selectedItems()
        if not items:
            self.browse_status.setText("請先在清單選一個倉庫。")
            return
        it = items[0]
        name = it.data(Qt.ItemDataRole.UserRole) or it.text()
        mirror = it.data(Qt.ItemDataRole.UserRole + 2) or ""
        kind = it.data(Qt.ItemDataRole.UserRole + 3) or ""
        upstream = it.data(Qt.ItemDataRole.UserRole + 4) or ""
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = RepoKindDialog(self, cfg, name, mirror, kind, upstream)
        if dlg.exec():
            self.on_refresh()

    def on_repo_kind_scan(self):
        if not self._all_repos:
            self.browse_status.setText("請先「重新整理」列出倉庫，再開批次比對。")
            return
        cfg = dict(self.collect_identity_cfg())
        self.save_current_profile(silent=True)
        dlg = RepoKindScanDialog(self, cfg, self._all_repos)
        dlg.exec()
        self.on_refresh()

    def on_backup_sync(self):
        names = self._selected_repo_names()  # 選取中的倉庫；空=同步全部已設定備份的倉庫
        cfg = dict(self.collect_identity_cfg())
        cfg["backup_repo_names"] = names
        self.save_current_profile(silent=True)
        scope = f"選取的 {len(names)} 個倉庫" if names else "全部已設定備份的倉庫"
        self._ci_title = "離站備份同步結果"
        self.browse_status.setText(f"同步{scope}中…")
        self.browse_status.setStyleSheet("")
        self.set_busy(True)
        self.worker = Worker(cfg, mode="backup_sync")
        self.worker.log.connect(self.append_log)
        self.worker.hooks.connect(self.on_ci_result)
        self.worker.done.connect(self.on_ci_done)
        self.worker.start()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.showMaximized()  # 自動貼合目前螢幕可用區域，不用每次自己按最大化
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
