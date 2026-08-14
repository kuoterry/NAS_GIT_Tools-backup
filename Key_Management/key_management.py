# -*- coding: utf-8 -*-
"""
金鑰管理工具 (PyQt6 GUI 版)
====================================
目的：掃描本機的 SSH 金鑰（OpenSSH 格式 + PuTTY .ppk 格式），整理成報表，
      並提供產生、封存刪除、永久刪除、備份、還原等管理功能，所有異動動作
      都會留下本機稽核紀錄。

安全原則：
  - 私鑰檔案「內容」絕不會出現在報表匯出裡，除非使用者在匯出當下主動勾選。
  - 私鑰的解析只讀取檔頭中繼資料（格式／是否加密），不需要密碼、不解密。
  - 唯一會讀取私鑰完整原始內容的地方是「檢視私鑰原始內容…」，且會先跳確認、
    並記錄到稽核紀錄。
  - 與 NAS_GIT_Tools 專案的 nas_git_connector.py 各自獨立運作、不 import、不共用程式碼。
    唯一例外是「跨電腦同步」功能（見下方「跨機器同步」）：(1) 可以唯讀取用
    NasGitConnector 的 QSettings 身份設定方便帶入連線資訊，不寫回、不強制依賴；
    (2) 同步只會把金鑰名冊的中繼資料（指紋／備註／類型／時間戳／看過它的電腦名稱）
    上傳到 NAS 共享檔案，私鑰檔案內容本身永遠不會被讀取、不會離開本機。

跨機器同步（選用，預設不啟用，需先在「⚙ 雲端同步設定…」填好連線資訊才會用到網路）：
  - 只支援 SSH 金鑰登入，不支援密碼登入（避免把單純本機工具的複雜度拉高不成比例）。
  - 共享檔案：NAS 上 <remote_root>/config/km_registry_sync.json，寫入前會先備份舊檔。
  - 合併規則：以指紋（或路徑後備）為 key；last_seen 較新的欄位為準；history 串接去重；
    seen_hosts（記錄「這把鑰匙在哪些電腦出現過」）一律聯集、只加不減。

作者備註：本機資料（金鑰名冊、稽核紀錄、封存區、同步連線設定）都放在 ~/.key_management/。
"""

import os
import sys
import re
import csv
import json
import base64
import hashlib
import locale
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QGroupBox, QInputDialog, QListWidget, QListWidgetItem,
    QDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QSpinBox,
)

# 備份加密（AES zip）是選用功能：pyzipper 沒裝時按鈕流程會退回明文複製並講明原因，
# 不把它列成硬依賴——這工具的其他功能全部不需要它。
try:
    import pyzipper
except ImportError:
    pyzipper = None

__version__ = "1.9.1"

# Windows 下讓子行程不要彈黑窗
if os.name == "nt":
    _NO_WINDOW = 0x08000000
else:
    _NO_WINDOW = 0

# ============================================================
# 本機資料存放位置：金鑰名冊（歷史紀錄）、稽核 log、封存區
# ============================================================
APP_DIR = os.path.join(os.path.expanduser("~"), ".key_management")
REGISTRY_PATH = os.path.join(APP_DIR, "registry.json")
AUDIT_LOG_PATH = os.path.join(APP_DIR, "audit.log")
ARCHIVE_DIR = os.path.join(APP_DIR, "archive")
SYNC_CONFIG_PATH = os.path.join(APP_DIR, "sync_config.json")

# 掃描時明確跳過的檔名：這些是「金鑰集合／設定檔」，不是單一身份金鑰本身。
SKIP_FILENAMES = {"known_hosts", "known_hosts.old", "authorized_keys", "config"}

_PUBKEY_PREFIXES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)

_PEM_HEADERS = {
    "-----BEGIN OPENSSH PRIVATE KEY-----": "openssh",
    "-----BEGIN RSA PRIVATE KEY-----": "pem-rsa",
    "-----BEGIN DSA PRIVATE KEY-----": "pem-dsa",
    "-----BEGIN EC PRIVATE KEY-----": "pem-ec",
    "-----BEGIN PRIVATE KEY-----": "pkcs8",
}


def audit_log(action: str, detail: str) -> bool:
    """所有管理動作（產生/封存/刪除/備份/還原/檢視私鑰原始內容）都留一筆本機紀錄。

    回傳寫入是否成功——呼叫端用 audit_failed_note() 把失敗附註進完成訊息。
    （1.4.0～1.5.0 的呼叫端已經在用這個回傳值，函式卻沒 return、
    audit_failed_note 也從未定義：動作本身做完，成功訊息卻被 NameError
    吞成「發生未預期錯誤」。修於 1.5.1。）"""
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{action}\t{detail}\n")
        return True
    except OSError:
        return False


def audit_failed_note(aud_ok: bool) -> str:
    """稽核寫入失敗時要附加在完成訊息尾端的警語；成功時回空字串。"""
    if aud_ok:
        return ""
    return f"\n⚠ 稽核紀錄寫入失敗（{AUDIT_LOG_PATH}），這筆動作沒有留下本機紀錄。"


# ============================================================
# 純函式：公鑰／私鑰解析（不依賴 Qt，方便獨立測試）
# ============================================================

def _read_ssh_string(data: bytes, offset: int):
    """讀取 SSH wire format 的 length-prefixed 字串欄位。"""
    if offset + 4 > len(data):
        raise ValueError("truncated")
    length = int.from_bytes(data[offset:offset + 4], "big")
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ValueError("truncated")
    return data[start:end], end


def is_pubkey_line(line: str) -> bool:
    line = line.strip()
    return any(line.startswith(p + " ") for p in _PUBKEY_PREFIXES)


def parse_pubkey_line(line: str):
    """解析一行 authorized_keys 格式的公鑰，回傳 {type, blob, comment} 或 None。"""
    parts = line.strip().split(None, 2)
    if len(parts) < 2 or not is_pubkey_line(line):
        return None
    key_type, b64 = parts[0], parts[1]
    comment = parts[2] if len(parts) > 2 else ""
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    return {"type": key_type, "blob": blob, "comment": comment}


def parse_rfc4716_pubkey(content: str):
    """解析 RFC 4716／SSH2 格式公鑰（PuTTYgen「Export OpenSSH key」某些版本會產生這種多行格式，
    跟單行 ssh-rsa AAAA... 格式不同，但一樣是純公開內容）。"""
    lines = content.splitlines()
    if not lines or not lines[0].strip().startswith("---- BEGIN SSH2 PUBLIC KEY"):
        return None
    comment = ""
    b64_lines = []
    for ln in lines[1:]:
        ln = ln.strip()
        if ln.startswith("---- END"):
            break
        if ":" in ln:
            if ln.startswith("Comment:"):
                comment = ln.split(":", 1)[1].strip().strip('"')
            continue
        b64_lines.append(ln)
    try:
        blob = base64.b64decode("".join(b64_lines))
        key_type, _off = _read_ssh_string(blob, 0)
        return {"type": key_type.decode("ascii"), "blob": blob, "comment": comment}
    except Exception:
        return None


def parse_pubkey_file(path: str):
    """讀一個 .pub 檔案，自動判斷是單行 OpenSSH 格式還是多行 RFC4716/SSH2 格式。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return None
    stripped = content.strip()
    if stripped.startswith("---- BEGIN SSH2 PUBLIC KEY"):
        return parse_rfc4716_pubkey(content)
    # 跳過開頭空行/註解行，不能只看第一行——編輯器多存一個換行就整個檔案默默解析失敗
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return parse_pubkey_line(line)
    return None


def ssh_fingerprint(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def describe_key_strength(key_type: str, blob: bytes) -> str:
    """只解析公鑰 blob 取得強度描述（RSA 位元數等），不涉及私鑰。"""
    try:
        if key_type == "ssh-rsa":
            _type_str, off = _read_ssh_string(blob, 0)
            _e, off = _read_ssh_string(blob, off)
            n, _off = _read_ssh_string(blob, off)
            bits = len(n.lstrip(b"\x00")) * 8
            return f"RSA {bits} 位元"
        if key_type == "ssh-dss":
            return "DSA 1024 位元（已淘汰）"
        if key_type == "ssh-ed25519":
            return "Ed25519（256 位元）"
        if key_type.startswith("ecdsa-sha2-"):
            curve = key_type.split("ecdsa-sha2-", 1)[1]
            return f"ECDSA {curve}"
        if key_type.startswith("sk-"):
            return f"{key_type}（FIDO2 安全金鑰）"
        return key_type
    except Exception:
        return key_type


def _is_openssh_v1_encrypted(raw: bytes):
    """判斷新版 OpenSSH 私鑰格式是否加密，只看 cipher name 欄位，不涉及金鑰本體。"""
    try:
        text = raw.decode("ascii", errors="ignore")
        b64_lines = [ln for ln in text.splitlines() if ln and not ln.startswith("-----")]
        joined = "".join(b64_lines)
        # magic(15 bytes) + cipher name 的 4-byte 長度前綴 + 名稱本身，128 個 base64 字元
        # （解碼後約 96 bytes）綽綽有餘；只解這一小段前綴，不把整段私鑰本體解碼進記憶體。
        prefix = joined[:128]
        prefix = prefix[: len(prefix) - len(prefix) % 4]
        blob = base64.b64decode(prefix)
        magic = b"openssh-key-v1\x00"
        if not blob.startswith(magic):
            return None
        ciphername, _off = _read_ssh_string(blob, len(magic))
        return ciphername != b"none"
    except Exception:
        return None


def classify_private_key_file(path: str):
    """回傳 {format, encrypted}；只讀檔頭中繼資料，絕不解析或外洩私鑰本體內容。"""
    try:
        with open(path, "rb") as f:
            raw = f.read(16384)
    except OSError:
        return None
    text = raw.decode("utf-8", errors="ignore")
    lines = text.splitlines()
    if not lines:
        return None
    first_line = lines[0].strip()

    if first_line.startswith("PuTTY-User-Key-File-"):
        enc = None
        for ln in lines:
            if ln.startswith("Encryption:"):
                enc = ln.split(":", 1)[1].strip()
                break
        return {"format": "ppk", "encrypted": (enc is not None and enc != "none")}

    if first_line == "-----BEGIN ENCRYPTED PRIVATE KEY-----":
        return {"format": "pkcs8", "encrypted": True}

    if first_line in _PEM_HEADERS:
        fmt = _PEM_HEADERS[first_line]
        if fmt == "openssh":
            return {"format": "openssh", "encrypted": _is_openssh_v1_encrypted(raw)}
        if fmt == "pkcs8":
            return {"format": "pkcs8", "encrypted": False}
        # 舊式 PEM（RSA/DSA/EC）：加密會在 BEGIN 之後緊接 Proc-Type: 4,ENCRYPTED
        return {"format": fmt, "encrypted": "Proc-Type: 4,ENCRYPTED" in text}

    return None


def parse_ppk_pubkey(path: str):
    """從 .ppk 檔案取出內嵌的公鑰（Public-Lines 區塊，PuTTY 格式裡永遠是明碼）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    key_type = None
    comment = ""
    pub_b64_lines = []
    try:
        # 整段解析都在 try 裡：一個被截斷/手改壞的 .ppk 只該讓「這個檔」解析失敗，
        # 不能讓 int()/IndexError 炸穿 build_records 導致整次掃描零筆結果。
        for i, ln in enumerate(lines):
            if ln.startswith("PuTTY-User-Key-File-"):
                key_type = ln.split(":", 1)[1].strip()
            elif ln.startswith("Comment:"):
                comment = ln.split(":", 1)[1].strip()
            elif ln.startswith("Public-Lines:"):
                count = int(ln.split(":", 1)[1].strip())
                pub_b64_lines = lines[i + 1:i + 1 + count]
                break
    except (ValueError, IndexError):
        return None
    if not key_type or not pub_b64_lines:
        return None
    try:
        blob = base64.b64decode("".join(pub_b64_lines))
    except Exception:
        return None
    return {"type": key_type, "blob": blob, "comment": comment}


def derive_pubkey_via_sshkeygen(path: str):
    """只對「已確認未加密」的私鑰呼叫，純本機執行，不會把檔案內容傳到任何地方。

    回傳 (公鑰行或 None, 失敗原因字串)——「沒裝 ssh-keygen」「逾時」「金鑰壞了」是
    三種不同的問題，全部折成同一句「無法自動推導」會讓使用者無從下手。"""
    if not shutil.which("ssh-keygen"):
        return None, "找不到 ssh-keygen（未安裝 OpenSSH 用戶端）"
    try:
        cp = subprocess.run(
            ["ssh-keygen", "-y", "-f", path],
            capture_output=True, text=True, timeout=5, input="",
            creationflags=_NO_WINDOW,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return cp.stdout.strip(), ""
        return None, (cp.stderr or "").strip().splitlines()[-1] if (cp.stderr or "").strip() else f"rc={cp.returncode}"
    except subprocess.TimeoutExpired:
        return None, "ssh-keygen 逾時（可能在等 passphrase？）"
    except OSError as e:
        return None, str(e)


# --- 私鑰檔權限檢查：Windows OpenSSH 遇到 ACL 過寬會「靜默忽略金鑰、退回密碼登入」，
# 不報任何錯（NasGitConnector 那邊 2026-07-15 的真實事故就是這一型）——本機端之前零可見度 ---

# icacls 輸出裡代表「過寬」的授權主體短名（去掉網域前綴後比對；群組名在中文
# Windows 通常仍是英文，中英兩種都認）。用「完整短名」比對而不是子字串——
# 帳號名剛好含 user（如 Git_User1）不能被誤中。
_BROAD_PRINCIPAL_NAMES = {
    "everyone", "users", "authenticated users", "每個人", "使用者", "已驗證的使用者",
}


def parse_icacls_broad_principals(icacls_output: str):
    """從 icacls 輸出行挑出「過寬」的授權主體，回傳主體字串清單（找不到＝權限乾淨）。

    每行格式（首行前綴檔名）：[檔名 ]DOMAIN\\Principal:(旗標)。取 ":(" 前的主體、
    去掉最後一個反斜線前的網域，再跟過寬名單比對完整短名。
    拆成純函數是為了可測：真實輸出長相用樣本釘在測試裡，不用真的動檔案 ACL。"""
    hits = []
    for ln in icacls_output.splitlines():
        s = ln.strip()
        if ":(" not in s:
            continue
        principal = s.split(":(", 1)[0]
        short = principal.rsplit("\\", 1)[-1].strip().lower()
        # 首行主體前面黏著檔名（無反斜線分隔，如 "C:\k Everyone"）——
        # 再用最後一/兩個空白詞比對一次（"authenticated users" 是兩個詞）
        words = short.split()
        candidates = {short}
        if words:
            candidates.add(words[-1])
            candidates.add(" ".join(words[-2:]))
        if candidates & _BROAD_PRINCIPAL_NAMES:
            hits.append(s)
    return hits


def check_private_key_permissions(path: str):
    """檢查私鑰檔權限是否過寬。回傳過寬描述字串；乾淨或無法判斷回 ""。

    POSIX：st_mode 的 group/other 位元非零即過寬。
    Windows：shell out 到 icacls 解析授權主體（僅讀取 ACL，不碰檔案內容）。
    讀不到/工具缺失一律回 ""——這是 advisory，不確定時寧可安靜也不誤報。"""
    try:
        if os.name != "nt":
            mode = os.stat(path).st_mode & 0o077
            return f"group/other 可存取（mode …{oct(os.stat(path).st_mode)[-3:]}）" if mode else ""
        # icacls 是唯一輸出「系統語系編碼」而非 UTF-8 的 subprocess（繁中 Windows
        # 上是 cp950）。這裡不指定 encoding 的話，直譯器在 UTF-8 模式下
        # （PYTHONUTF8=1，或未來 Python 預設值改掉）會丟 UnicodeDecodeError——
        # 那個例外不在下面的 except 清單裡，會一路炸穿整趟掃描，不是只讓這個
        # 權限檢查回空字串。明確指定系統語系＋errors="replace"，兩種模式行為一致。
        cp = subprocess.run(["icacls", path], capture_output=True, text=True,
                            encoding=locale.getpreferredencoding(False), errors="replace",
                            timeout=10, input="", creationflags=_NO_WINDOW)
        if cp.returncode != 0:
            return ""
        hits = parse_icacls_broad_principals(cp.stdout)
        return ("、".join(h.split(":")[0].split("\\")[-1] or h for h in hits[:3]) + " 可存取") if hits else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


# 掃描時直接跳過的大型雜訊目錄（加大資料夾如 Documents 時不用每檔讀 16KB）
SKIP_DIRNAMES = {".git", "node_modules", "__pycache__", ".venv", "venv", "$RECYCLE.BIN"}


def scan_folder(folder: str, errors: list = None):
    """遞迴掃描資料夾，依副檔名/內容判斷分成公鑰／私鑰／ppk 三類。

    回傳 (pub_files, priv_files, ppk_files, priv_info)：priv_info 是
    {path: classify_private_key_file() 結果}，讓 build_records 不用對同一個
    私鑰檔再讀第二次。讀不進去的子目錄記到 errors（不再無聲跳過）。"""
    pub_files, priv_files, ppk_files = [], [], []
    priv_info = {}

    def _on_walk_error(err):
        if errors is not None:
            errors.append(f"{getattr(err, 'filename', '?')}：{getattr(err, 'strerror', err)}")

    for root, dirs, files in os.walk(folder, onerror=_on_walk_error):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRNAMES]
        for name in files:
            if name in SKIP_FILENAMES:
                continue
            path = os.path.join(root, name)
            if name.endswith(".pub"):
                pub_files.append(path)
            elif name.endswith(".ppk"):
                ppk_files.append(path)
            else:
                info = classify_private_key_file(path)
                if info:
                    priv_files.append(path)
                    priv_info[path] = info
    return pub_files, priv_files, ppk_files, priv_info


# 金鑰年齡提醒的預設門檻（天）；MainWindow 有 QSpinBox 可調（存 QSettings），
# build_advisories 收 age_days 參數而不是直接讀設定——保持純函數、可測。
DEFAULT_KEY_AGE_DAYS = 730


def build_advisories(rec: dict, fingerprints_seen: dict, seen_hosts_by_fp: dict = None, this_host: str = "",
                     age_days: int = DEFAULT_KEY_AGE_DAYS, host_labels: dict = None) -> str:
    notes = []
    strength = rec.get("strength", "") or ""
    if strength.startswith("RSA"):
        try:
            bits = int(strength.split()[1])
            if bits < 2048:
                notes.append("⚠ RSA 位元數過低，建議更換")
        except (IndexError, ValueError):
            pass
    if rec.get("type") == "ssh-dss":
        notes.append("⚠ DSA 已淘汰，建議更換為 Ed25519")
    if rec.get("priv_path") and rec.get("priv_encrypted") is False:
        # 裸私鑰=落地即明文。非 .ppk 的可以直接用本工具補密碼（ssh-keygen -p）
        if rec.get("priv_format") == "ppk":
            notes.append("⚠ 私鑰未加密（.ppk 請用 PuTTYgen 加密，或先轉成 OpenSSH 再加）")
        else:
            notes.append("⚠ 私鑰未加密（可用「加上密碼保護…」補上）")
    if rec.get("pair_mismatch"):
        notes.append("⚠ .pub 與私鑰不是同一把（.pub 可能過期——指紋/強度是照 .pub 算的，"
                     "可用「重建 .pub」修復）")
    if rec.get("perm_loose"):
        notes.append(f"⚠ 私鑰檔權限過寬（{rec['perm_loose']}）——Windows OpenSSH 會靜默忽略"
                     "這種金鑰退回密碼登入（icacls <檔案> /inheritance:r /grant:r <你>:F 可收緊）")
    if rec.get("pub_path") and not rec.get("priv_path"):
        notes.append("ℹ 找不到對應私鑰（可能已刪除或不在掃描範圍）")
    if rec.get("priv_path") and not rec.get("pub_path") and not rec.get("blob"):
        if rec.get("priv_encrypted"):
            notes.append("ℹ 私鑰已加密且找不到公鑰，需密碼才能取得指紋")
        else:
            reason = rec.get("derive_error", "")
            notes.append("⚠ 找不到公鑰且無法自動推導" + (f"（{reason}）" if reason else ""))
    if rec.get("derived"):
        notes.append("✔ 已自動從私鑰推導出公鑰")
    mtime = rec.get("mtime")
    if mtime:
        age = (time.time() - mtime) / 86400
        if age > age_days:
            notes.append(f"ℹ 已 {int(age)} 天未變更，可考慮輪替")
    fp = rec.get("fingerprint")
    if fp and len(fingerprints_seen.get(fp, [])) > 1:
        notes.append("⚠ 與其他檔案指紋相同，可能是重複複製的金鑰")
    if fp and seen_hosts_by_fp:
        others = sorted(h for h in seen_hosts_by_fp.get(fp, {}) if h and h != this_host)
        if others:
            # hostname 翻成綁定標籤（家中/公司）——標籤才是給人看的
            shown = "、".join(label_host(h, host_labels) for h in others)
            notes.append(f"⚠ 這把金鑰也在其他電腦（{shown}）登記過，確認是否為刻意複製")
    return "；".join(notes) if notes else "—"


# ============================================================
# SSH config（~/.ssh/config）解析：讓報表看得出「這把金鑰實際連去哪」
# ============================================================
SSH_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".ssh", "config")


def _norm_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expanduser(path)))


def parse_ssh_config(path: str = SSH_CONFIG_PATH):
    """解析 SSH config，回傳 {normalize後的私鑰路徑: [host別名, ...]}。
    只認 Host/Match 區塊裡的 IdentityFile，不處理 Include（一般個人用 config 很少用到，避免過度複雜）。"""
    mapping = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return mapping
    current_hosts = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) < 2:
            continue
        key, value = parts[0].lower(), parts[1].strip().strip('"')
        if key == "host":
            current_hosts = [h for h in value.split() if h != "*"]
        elif key == "match":
            # Match Host <h> User <u> 或 Match OriginalHost <h> User <u> 這種寫法，
            # 把 Host/OriginalHost 值也當別名記下來
            m = re.search(r"\b(?:originalhost|host)\s+(\S+)", value, re.IGNORECASE)
            current_hosts = [m.group(1)] if m else []
        elif key == "identityfile" and current_hosts:
            idpath = _norm_path(value)
            for h in current_hosts:
                mapping.setdefault(idpath, []).append(h)
    return mapping


def rewrite_ssh_config_identity(old_path: str, new_path: str, config_path: str = SSH_CONFIG_PATH):
    """把 SSH config 裡指向 old_path 的 IdentityFile 行改指向 new_path（金鑰輪替用）。

    路徑比對走 _norm_path（跟 parse_ssh_config 同一套），值帶不帶引號都認得；
    改寫前先備份整份 config（.bak-時間戳）。回傳 (改了幾行, 訊息)。
    只動 IdentityFile 行本身、保留原縮排，其他行原封不動。"""
    try:
        with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        return 0, f"讀取 SSH config 失敗：{e}"
    target = _norm_path(old_path)
    changed = 0
    out_lines = []
    for line in lines:
        s = line.strip()
        parts = s.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "identityfile" \
                and _norm_path(parts[1].strip().strip('"')) == target:
            indent = line[:len(line) - len(line.lstrip())]
            out_lines.append(f'{indent}IdentityFile "{new_path}"\n')
            changed += 1
        else:
            out_lines.append(line)
    if not changed:
        return 0, "SSH config 裡沒有指向舊金鑰的 IdentityFile 行，未改動。"
    try:
        shutil.copy2(config_path, config_path + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        with open(config_path, "w", encoding="utf-8") as f:
            f.writelines(out_lines)
    except OSError as e:
        return 0, f"寫入 SSH config 失敗（未改動）：{e}"
    return changed, f"已把 {changed} 行 IdentityFile 改指向新金鑰（舊檔已備份）。"


def append_ssh_config_host(alias: str, hostname: str, user: str, identity_path: str):
    """把新的區塊附加到 SSH config；區塊已存在就不寫，避免覆蓋既有設定。

    user 有填：寫 `Match originalhost <hostname> user <user>` 區塊。像
    NasGitConnector 這類工具一律直接用 `ssh user@hostname` 連線，從不打別名，
    傳統 `Host <alias>` 區塊只有「真的手動輸入這個別名」才會生效，所以同一台主機
    給多個帳號共用時，Host 別名等於沒用——這是本機一次真實踩雷後才發現的：先前
    只寫 Host 區塊，帳號金鑰在 NAS 端已經加好，但沒人記得再手動改 config，導致
    ssh/git 連線一直卡在「有金鑰卻連不上」。Match originalhost 這種寫法不管怎麼連都自動
    生效，不用多一個「記得改 config」的步驟。
    user 沒填：維持原本的 `Host <alias>` 區塊（單一身份、慣用 `ssh <別名>` 連線的情境）。
    """
    try:
        if os.path.exists(SSH_CONFIG_PATH):
            with open(SSH_CONFIG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                existing = f.read()
        else:
            existing = ""
    except OSError as e:
        return False, f"讀取 SSH config 失敗：{e}"

    if user:
        match_re = re.compile(
            r"^match\s+originalhost\s+" + re.escape(hostname) + r"\s+user\s+" + re.escape(user) + r"\s*$",
            re.IGNORECASE)
        for line in existing.splitlines():
            if match_re.match(line.strip()):
                return False, (f"SSH config 裡已經有「{hostname}」+「{user}」的 Match 區塊，"
                                "為避免衝突不會自動改寫，請自行手動編輯。")
        block = f'\nMatch originalhost {hostname} user {user}\n    IdentityFile "{identity_path}"\n'
        desc = f"Match originalhost {hostname} user {user}"
    else:
        for line in existing.splitlines():
            s = line.strip()
            if s.lower().startswith("host "):
                if alias in s.split(None, 1)[1].split():
                    return False, f"SSH config 裡已經有 Host「{alias}」，為避免衝突不會自動改寫，請自行手動編輯。"
        block = f'\nHost {alias}\n    HostName {hostname}\n    IdentityFile "{identity_path}"\n'
        desc = f"Host {alias}"

    try:
        os.makedirs(os.path.dirname(SSH_CONFIG_PATH), exist_ok=True)
        with open(SSH_CONFIG_PATH, "a", encoding="utf-8") as f:
            f.write(block)
    except OSError as e:
        return False, f"寫入 SSH config 失敗：{e}"
    return True, f"已加入 SSH config：{desc}"


# ============================================================
# known_hosts（~/.ssh/known_hosts）檢視與清理
# ============================================================
KNOWN_HOSTS_PATH = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")


def parse_known_hosts(path: str = KNOWN_HOSTS_PATH):
    """解析 known_hosts，回傳每行的 {line_no, host, hashed, key_type}。
    注意：主機名雜湊過（HashKnownHosts，OpenSSH 預設行為）的話，同一台主機每次新增
    都會用不同的 salt 重新雜湊，光比對雜湊字串本身抓不出「這是不是同一台主機」，
    所以這裡只對『明碼主機名』做重複偵測，雜湊過的只列出、不做重複判斷。"""
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return entries
    for i, line in enumerate(lines):
        s = line.rstrip("\n").strip()
        if not s or s.startswith("#") or s.startswith("@"):
            continue
        parts = s.split(None, 2)
        if len(parts) < 2:
            continue
        host_field = parts[0]
        hashed = host_field.startswith("|1|")
        key_type = parts[1]
        entries.append({"line_no": i, "host": host_field, "hashed": hashed, "key_type": key_type})
    # 同一台主機同時有 ed25519/ecdsa/rsa 等不同類型是正常現象，不算重複；
    # 「同主機、同類型」出現超過一次才是真的重複（通常代表換過金鑰但舊條目沒清掉）。
    seen_plain = {}
    for e in entries:
        if not e["hashed"]:
            seen_plain.setdefault((e["host"], e["key_type"]), []).append(e)
    for e in entries:
        e["duplicate"] = (not e["hashed"]) and len(seen_plain.get((e["host"], e["key_type"]), [])) > 1
    return entries


def delete_known_hosts_entry(line_no: int, path: str = KNOWN_HOSTS_PATH):
    """刪除 known_hosts 指定行（先備份原檔）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        return False, f"讀取失敗：{e}"
    if line_no < 0 or line_no >= len(lines):
        return False, "行號超出範圍，可能檔案已被改動，請重新整理。"
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{path}.bak-{ts}"
    try:
        shutil.copy2(path, backup_path)
        del lines[line_no]
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except OSError as e:
        return False, f"寫入失敗：{e}"
    return True, f"已刪除第 {line_no + 1} 行（原檔已備份到 {backup_path}）"


def build_records(folders, errors: list = None, age_days: int = DEFAULT_KEY_AGE_DAYS):
    """掃描所有資料夾，配對公私鑰、補齊指紋/強度/時間/建議，回傳紀錄清單。

    folders 先正規化去重、並丟掉已被其他選取資料夾涵蓋的巢狀資料夾——同一資料夾
    加兩次（或同時加 ~ 和 ~/.ssh）會讓 .ppk 出現幽靈重複紀錄，還觸發假的
    「指紋相同」警告。errors 收 os.walk 讀不進去的子目錄清單。"""
    normed = []
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        nf = _norm_path(folder)
        if nf not in normed:
            normed.append(nf)
    roots = [f for f in normed
             if not any(f != g and (f + os.sep).startswith(g + os.sep) for g in normed)]

    all_pub, all_priv, all_ppk = [], [], []
    priv_info_map = {}
    seen_ppk = set()
    for folder in roots:
        p, pr, pk, pinfo = scan_folder(folder, errors=errors)
        all_pub += p
        all_priv += pr
        priv_info_map.update(pinfo)
        for x in pk:
            nx = _norm_path(x)
            if nx not in seen_ppk:
                seen_ppk.add(nx)
                all_ppk.append(x)

    def base_key(path):
        d = os.path.dirname(path)
        b = os.path.basename(path)
        if b.endswith(".pub"):
            b = b[:-4]
        return (d, b)

    priv_by_base = {base_key(p): p for p in all_priv}
    pub_by_base = {base_key(p): p for p in all_pub}
    bases = set(priv_by_base) | set(pub_by_base)

    records = []
    for base in bases:
        priv_path = priv_by_base.get(base)
        pub_path = pub_by_base.get(base)
        rec = {"pub_path": pub_path, "priv_path": priv_path}
        if pub_path:
            parsed = parse_pubkey_file(pub_path)
            if parsed:
                rec.update(type=parsed["type"], blob=parsed["blob"], comment=parsed["comment"])
        if priv_path:
            priv_info = priv_info_map.get(priv_path) or classify_private_key_file(priv_path)
            rec["priv_format"] = priv_info["format"] if priv_info else "?"
            rec["priv_encrypted"] = priv_info["encrypted"] if priv_info else None
            if not pub_path and priv_info and priv_info["encrypted"] is False:
                derived, derive_err = derive_pubkey_via_sshkeygen(priv_path)
                if derived:
                    parsed = parse_pubkey_line(derived)
                    if parsed:
                        rec.update(type=parsed["type"], blob=parsed["blob"],
                                   comment=parsed["comment"], derived=True)
                else:
                    rec["derive_error"] = derive_err
            elif pub_path and rec.get("blob") is not None and priv_info and priv_info["encrypted"] is False:
                # 配對驗證：同 basename 不代表同一把——.pub 過期/被換過的話，
                # 指紋（所有跨機器比對的主鍵）、強度、agent 對應全都跟著錯，
                # 而且沒有這個檢查時完全無聲。加密私鑰無法驗證（要 passphrase），略過。
                derived, _err = derive_pubkey_via_sshkeygen(priv_path)
                if derived:
                    dparsed = parse_pubkey_line(derived)
                    if dparsed and dparsed["blob"] != rec["blob"]:
                        rec["pair_mismatch"] = True
            rec["perm_loose"] = check_private_key_permissions(priv_path)
        records.append(rec)

    for ppk_path in all_ppk:
        parsed = parse_ppk_pubkey(ppk_path)
        cls = classify_private_key_file(ppk_path)
        rec = {
            "pub_path": None, "priv_path": ppk_path,
            "priv_format": "ppk", "priv_encrypted": cls["encrypted"] if cls else None,
            "perm_loose": check_private_key_permissions(ppk_path),
        }
        if parsed:
            rec.update(type=parsed["type"], blob=parsed["blob"], comment=parsed["comment"])
        records.append(rec)

    fingerprints_seen = {}
    for rec in records:
        blob = rec.get("blob")
        if blob:
            fp = ssh_fingerprint(blob)
            rec["fingerprint"] = fp
            rec["strength"] = describe_key_strength(rec["type"], blob)
            fingerprints_seen.setdefault(fp, []).append(rec)
        else:
            rec["fingerprint"] = ""
            rec["strength"] = ""
        path_for_time = rec.get("priv_path") or rec.get("pub_path")
        try:
            rec["mtime"] = os.path.getmtime(path_for_time) if path_for_time else None
        except OSError:
            rec["mtime"] = None

    ssh_config_map = parse_ssh_config()
    for rec in records:
        priv_path = rec.get("priv_path")
        hosts = ssh_config_map.get(_norm_path(priv_path)) if priv_path else None
        rec["ssh_config_hosts"] = hosts or []

    # 跨機器資訊：從本機 registry.json 裡（若曾經同步過）帶的 seen_hosts 讀出來，
    # 純本機比對，不觸發任何網路動作——同步時寫入，之後每次掃描都能用到，不用每次都連線。
    seen_hosts_by_fp = {}
    for entry in load_registry().values():
        fp, sh = entry.get("fingerprint"), entry.get("seen_hosts")
        if fp and sh:
            seen_hosts_by_fp.setdefault(fp, {}).update(sh)
    this_host = socket.gethostname() or ""
    for rec in records:
        rec["advisories"] = build_advisories(rec, fingerprints_seen, seen_hosts_by_fp, this_host, age_days,
                                             host_labels=nas_git_machine_labels())

    return records


# ============================================================
# 本機金鑰名冊（持久化歷史紀錄，即使金鑰被刪除也保留曾經存在過的記錄）
# ============================================================

HISTORY_CAP = 200  # 每個條目的 history 事件上限，超過丟最舊的（防止名冊與同步 payload 無限成長）


def _cap_history(history: list) -> list:
    return history[-HISTORY_CAP:] if len(history) > HISTORY_CAP else history


def load_registry():
    """讀名冊。檔案損壞時把原檔改名保留（.corrupt-時戳）再回空 dict——
    不然下一次 save_registry 會直接用「只剩本次掃描」的內容蓋掉整份歷史，
    使用者完全不會知道曾經有一份更完整的紀錄存在過。"""
    try:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            os.replace(REGISTRY_PATH, REGISTRY_PATH + f".corrupt-{ts}")
            audit_log("registry_corrupt", f"registry.json 無法解析，已改名保留為 registry.json.corrupt-{ts}")
        except OSError:
            pass
        return {}
    except OSError:
        return {}


def save_registry(reg: dict):
    """原子寫入：先寫暫存檔再 os.replace，中途斷電/當機不會留下半份 JSON。"""
    os.makedirs(APP_DIR, exist_ok=True)
    tmp = REGISTRY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, REGISTRY_PATH)


def update_registry_from_scan(records):
    reg = load_registry()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    seen_keys = set()
    for rec in records:
        key = rec.get("fingerprint") or rec.get("priv_path") or rec.get("pub_path")
        if not key:
            continue
        seen_keys.add(key)
        entry = reg.get(key, {"first_seen": now, "history": []})
        entry.update({
            "last_seen": now,
            "comment": rec.get("comment", ""),
            "type": rec.get("type", ""),
            "strength": rec.get("strength", ""),
            "fingerprint": rec.get("fingerprint", ""),
            "pub_path": rec.get("pub_path"),
            "priv_path": rec.get("priv_path"),
            "priv_format": rec.get("priv_format"),
            "priv_encrypted": rec.get("priv_encrypted"),
            "status": "active",
        })
        hist = entry.setdefault("history", [])
        # 「每次掃描都記一筆 scanned」會讓 history 無限成長、同步 payload 跟著爆炸；
        # 只在狀態有意義變化時記（第一次看到、或從 missing 回到 active）。
        if not hist or hist[-1].get("action") != "scanned":
            hist.append({"ts": now, "action": "scanned"})
        entry["history"] = _cap_history(hist)
        reg[key] = entry
    hostname = socket.gethostname() or "UNKNOWN"
    for key, entry in reg.items():
        if key in seen_keys or entry.get("status") != "active":
            continue
        # 從別台機器同步進來的條目本機本來就掃不到，不能翻成 missing——
        # 否則每次掃描都把外機金鑰標失蹤再推回 NAS，跨機器狀態整個爛掉。
        hosts = entry.get("seen_hosts") or {}
        if hosts and hostname not in hosts:
            continue
        entry["status"] = "missing"
        hist = entry.setdefault("history", [])
        if not hist or hist[-1].get("action") != "missing_from_scan":
            hist.append({"ts": now, "action": "missing_from_scan"})
        entry["history"] = _cap_history(hist)
    save_registry(reg)
    return reg


# ============================================================
# 跨機器同步（選用）：把金鑰名冊的中繼資料跟 NAS 上其他電腦互相同步。
# 私鑰檔案內容本身永遠不會出現在這一段的任何函式裡。
# ============================================================

def load_sync_config():
    try:
        with open(SYNC_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_sync_config(cfg: dict):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(SYNC_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def read_nas_git_connector_profiles():
    """唯讀窺看 NasGitConnector 的 QSettings 身份設定（同一個 Windows 使用者底下才看得到），
    只用來讓「從 NasGitConnector 帶入」省去重複輸入 host/user/identity_file。不寫回、
    NasGitConnector 沒裝過/沒設定過就回空 dict——不是必要依賴，只是省事的捷徑。"""
    s = QSettings("TerryTools", "NasGitConnector")
    names = s.value("profile_names", [])
    if isinstance(names, str):
        names = [names] if names else []
    result = {}
    for name in (names or []):
        machines = s.value(f"profiles/{name}/machines", [])
        if isinstance(machines, str):
            machines = [machines] if machines else []
        result[name] = {
            "user": s.value(f"profiles/{name}/user", ""),
            "host": s.value(f"profiles/{name}/host", ""),
            "remote_root": s.value(f"profiles/{name}/remote_root", ""),
            "identity_file": s.value(f"profiles/{name}/identity_file", ""),
            "machines": list(machines or []),
        }
    return result


def nas_git_machine_labels():
    """{hostname(lower): 身份標籤（家中/公司…）} 對照表——來源是 NasGitConnector 的
    profile 機器綁定（同一份唯讀 bridge）。讓報表把 hostname 翻成人看的標籤；
    對方沒裝/沒綁定就回空 dict，所有使用端都要能在空表下照常運作。"""
    labels = {}
    try:
        for name, p in read_nas_git_connector_profiles().items():
            for m in p.get("machines", []):
                if m and m.strip():
                    labels[m.strip().lower()] = str(name)
    except Exception:
        pass
    return labels


def label_host(hostname: str, labels: dict) -> str:
    """hostname → 'hostname（標籤）'；查不到標籤就原樣回傳（純函數，可測）。"""
    lab = (labels or {}).get((hostname or "").strip().lower())
    return f"{hostname}（{lab}）" if lab else hostname


def open_ssh_terminal(sync_cfg: dict):
    """用雲端同步身份開一個可互動的 ssh 終端機視窗（sudo 診斷/貼指令用）。

    Windows 限定（CREATE_NEW_CONSOLE）；獨立實作、不 import 手足工具的
    open_admin_terminal()——兩工具不共用程式碼的邊界維持不變，只是照同一個慣例。
    回傳 (ok, 訊息)。"""
    if os.name != "nt":
        return False, "開啟終端機功能目前只支援 Windows。"
    user = (sync_cfg.get("user") or "").strip()
    host = (sync_cfg.get("host") or "").strip()
    if not (user and host):
        return False, "同步設定未填 host/user。"
    args = ["ssh"]
    identity = (sync_cfg.get("identity_file") or "").strip()
    if identity:
        args += ["-i", identity, "-o", "IdentitiesOnly=yes"]
    args.append(f"{user}@{host}")
    try:
        subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True, f"已開啟 {user}@{host} 的終端機視窗。"
    except OSError as e:
        return False, f"開啟失敗：{e}"


def _sync_ssh(sync_cfg: dict, remote_cmd: str, input_text: str = ""):
    """對 NAS 執行遠端指令，只走 SSH 金鑰登入，不支援密碼——這支工具本來就只有
    ssh-keygen 這一個 subprocess 依賴，刻意不加 plink/密碼分支，比照
    nas_git_connector.py 的 _ssh() 但精簡到只剩同步需要的這一條路徑。"""
    user = sync_cfg.get("user", "")
    host = sync_cfg.get("host", "")
    identity_file = sync_cfg.get("identity_file", "")
    if not (user and host and identity_file):
        return 255, "", "同步設定未填完整（需要 user/host/identity_file）"
    args = [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10", "-i", identity_file, "-o", "IdentitiesOnly=yes",
        f"{user}@{host}", remote_cmd,
    ]
    try:
        cp = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=60, input=input_text,
                             creationflags=_NO_WINDOW if os.name == "nt" else 0)
        return cp.returncode, cp.stdout, cp.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 255, "", str(e)


def _between(text: str) -> str:
    """擷取 ___BEGIN___/___END___ 之間的內容，濾掉 SSH 登入橫幅等雜訊。跟
    nas_git_connector.py 的同名函式用途一致，各自獨立實作，不 import 對方。"""
    start = text.find("___BEGIN___")
    end = text.find("___END___")
    if start == -1 or end == -1:
        return text
    return text[start + len("___BEGIN___"):end].strip("\n")


# 描述「這台機器的磁碟現況」的欄位——合併時永遠以本機值為準，不能被另一台
# 機器「較新的 last_seen」整筆蓋掉：路徑/格式/狀態在別台機器上是另一回事，
# 蓋過來會讓報表指向不存在的檔案，連帶弄壞 nas_git_connector 讀 pub_path 的匯入橋。
MACHINE_LOCAL_FIELDS = ("pub_path", "priv_path", "priv_format", "priv_encrypted", "status")


def merge_registries(local: dict, remote: dict, hostname: str):
    """合併本機與雲端的金鑰名冊。key 選法跟 update_registry_from_scan 一致（指紋或路徑
    後備）。中繼欄位依 last_seen 較新者為準，但 MACHINE_LOCAL_FIELDS 一律保留本機值；
    history 串接去重（上限 HISTORY_CAP）；seen_hosts（這把鑰匙在哪些電腦出現過）一律
    聯集、只加不減，本機這次同步時把自己也蓋進去。"""
    merged = {}
    for key in set(local) | set(remote):
        l, r = local.get(key), remote.get(key)
        if l and not r:
            entry = dict(l)
        elif r and not l:
            entry = dict(r)
        else:
            entry = dict(r if (r.get("last_seen") or "") > (l.get("last_seen") or "") else l)
            for fld in MACHINE_LOCAL_FIELDS:
                if fld in l:
                    entry[fld] = l[fld]
            firsts = [x for x in (l.get("first_seen"), r.get("first_seen")) if x]
            if firsts:
                entry["first_seen"] = min(firsts)
            seen_pairs = {(h.get("ts"), h.get("action")) for h in l.get("history", [])}
            history = list(l.get("history", []))
            for h in r.get("history", []):
                pair = (h.get("ts"), h.get("action"))
                if pair not in seen_pairs:
                    history.append(h)
                    seen_pairs.add(pair)
            entry["history"] = _cap_history(history)
        seen_hosts = dict((l or {}).get("seen_hosts") or {})
        seen_hosts.update((r or {}).get("seen_hosts") or {})
        if l:
            seen_hosts[hostname] = l.get("last_seen", "")
        entry["seen_hosts"] = seen_hosts
        merged[key] = entry
    return merged


def keep_worker_alive(owner):
    """換手前把還在跑的舊 Worker 收進 owner._retired_workers，等它 finished 再釋放。

    在 done handler 裡直接 self.worker = Worker(...) 會丟掉「可能還沒完全收尾」的
    QThread 的最後一個引用 → 'QThread: Destroyed while thread is still running'
    整個程式中止，且時機相依、極難重現。每次重派 self.worker 前先呼叫這個。"""
    old = getattr(owner, "worker", None)
    if old is None or not old.isRunning():
        return
    pool = getattr(owner, "_retired_workers", None)
    if pool is None:
        pool = owner._retired_workers = []
    pool.append(old)
    old.finished.connect(lambda o=old, p=pool: p.remove(o) if o in p else None)


def confirm_close_ok(widget) -> bool:
    """回傳是否允許關閉：沒有跑中的 Worker → True；有 → 問過使用者，同意才等收尾。"""
    workers = [getattr(widget, "worker", None)] + list(getattr(widget, "_retired_workers", []))
    running = [w for w in workers if w is not None and w.isRunning()]
    if not running:
        return True
    r = QMessageBox.question(
        widget, "操作進行中",
        "還有背景操作在執行中，現在關閉可能讓動作做到一半（且不會留稽核紀錄）。\n確定要離開嗎？",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No)
    if r != QMessageBox.StandardButton.Yes:
        return False
    for w in running:
        w.wait(8000)
    return True


def confirm_close_with_worker(widget, event) -> None:
    """closeEvent 共用邏輯（QMainWindow 用）：還有 Worker 在跑就先確認，同意才關。
    QDialog 請改覆寫 done()（accept()/Esc 不會經過 closeEvent）。"""
    if confirm_close_ok(widget):
        event.accept()
    else:
        event.ignore()


# ============================================================
# 背景工作執行緒：所有檔案系統/subprocess 動作都走這裡，避免卡住 UI
# ============================================================
class Worker(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)
    result = pyqtSignal(object)

    def __init__(self, mode: str, params: dict = None):
        super().__init__()
        self.mode = mode
        self.params = params or {}

    def run(self):
        try:
            if self.mode == "scan":
                self._run_scan()
            elif self.mode == "generate":
                self._run_generate()
            elif self.mode == "delete":
                self._run_delete()
            elif self.mode == "backup":
                self._run_backup()
            elif self.mode == "list_archive":
                self._run_list_archive()
            elif self.mode == "restore_archive":
                self._run_restore_archive()
            elif self.mode == "purge_archive":
                self._run_purge_archive()
            elif self.mode == "read_private_raw":
                self._run_read_private_raw()
            elif self.mode == "list_known_hosts":
                self._run_list_known_hosts()
            elif self.mode == "delete_known_hosts_entry":
                self._run_delete_known_hosts_entry()
            elif self.mode == "sync_registry":
                self._run_sync_registry()
            elif self.mode == "encrypt_key":
                self._run_encrypt_key()
            elif self.mode == "rotate_key":
                self._run_rotate_key()
            elif self.mode == "list_agent_keys":
                self._run_list_agent_keys()
            elif self.mode == "convert_ppk":
                self._run_convert_ppk()
            elif self.mode == "rebuild_pub":
                self._run_rebuild_pub()
            elif self.mode == "compare_authorized_keys":
                self._run_compare_authorized_keys()
            else:
                self.done.emit(False, f"未知模式：{self.mode}")
        except Exception as e:
            self.done.emit(False, f"發生未預期錯誤：{e}")

    def _run_scan(self):
        folders = self.params.get("folders", [])
        age_days = self.params.get("age_days") or DEFAULT_KEY_AGE_DAYS
        self.log.emit(f"掃描 {len(folders)} 個資料夾中…")
        walk_errors = []
        records = build_records(folders, errors=walk_errors, age_days=age_days)
        for we in walk_errors[:20]:
            self.log.emit(f"⚠ 讀不到：{we}")
        if len(walk_errors) > 20:
            self.log.emit(f"⚠ 共 {len(walk_errors)} 個位置讀不到（僅列前 20）")
        # 名冊更新失敗（磁碟滿/權限）不該吃掉整份掃描結果——表格照樣顯示，訊息帶警語
        reg_note = ""
        try:
            update_registry_from_scan(records)
        except OSError as e:
            reg_note = f"\n⚠ 名冊 registry.json 更新失敗（{e}），本次掃描結果只顯示、未記錄。"
        self.result.emit(records)
        self.done.emit(True, f"掃描完成，共找到 {len(records)} 組金鑰。" + reg_note)

    def _run_generate(self):
        path = self.params.get("path", "")
        key_type = self.params.get("key_type", "ed25519")
        comment = self.params.get("comment", "")
        passphrase = self.params.get("passphrase", "")
        bits = self.params.get("bits")
        if not path:
            self.done.emit(False, "缺少檔名或儲存路徑。")
            return
        if os.path.exists(path) or os.path.exists(path + ".pub"):
            self.done.emit(False, f"檔案已存在，未覆蓋：{path}")
            return
        if not shutil.which("ssh-keygen"):
            self.done.emit(False, "找不到 ssh-keygen——請先安裝 Windows 內建 OpenSSH 用戶端"
                                  "（設定 → 應用程式 → 選用功能），再重試。")
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        args = ["ssh-keygen", "-t", key_type, "-N", passphrase, "-C", comment, "-f", path]
        if bits:
            args += ["-b", str(bits)]
        # masked_args 靠 "-N" 在 comment/path 之前這件事才能定位到正確的 passphrase 位置，
        # 之後若調整 args 組成順序，要記得同步檢查這裡還抓不抓得對。
        masked_args = list(args)
        if passphrase:
            masked_args[args.index("-N") + 1] = "***"
        self.log.emit("$ " + " ".join(a if a else "''" for a in masked_args))
        cp = subprocess.run(
            args, capture_output=True, text=True, timeout=30, input="",
            creationflags=_NO_WINDOW,
        )
        if cp.returncode != 0:
            self.done.emit(False, "產生金鑰失敗：" + (cp.stderr or cp.stdout).strip())
            return
        audit_log("generate", f"{path}（{key_type}, comment={comment}）")
        msg = f"已產生金鑰對：\n{path}\n{path}.pub"
        if self.params.get("write_ssh_config"):
            alias = self.params.get("ssh_config_alias", "")
            hostname = self.params.get("ssh_config_hostname", "")
            user = self.params.get("ssh_config_user", "")
            ok, cfg_msg = append_ssh_config_host(alias, hostname, user, path)
            audit_log("write_ssh_config", f"{alias} -> {path}（{'成功' if ok else '失敗：' + cfg_msg}）")
            msg += f"\n{cfg_msg}"
        self.done.emit(True, msg)

    def _run_delete(self):
        pub_path = self.params.get("pub_path")
        priv_path = self.params.get("priv_path")
        hard = self.params.get("hard", False)
        targets = [p for p in (pub_path, priv_path) if p and os.path.exists(p)]
        if not targets:
            self.done.emit(False, "找不到要處理的檔案。")
            return
        # 部分失敗（第一個刪掉、第二個炸掉）也要有稽核紀錄——逐檔記結果，
        # 不能等全部成功才記一筆（那正好在最需要紀錄的時候什麼都沒留）。
        if hard:
            done_list, fail_list = [], []
            for p in targets:
                try:
                    os.remove(p)
                    done_list.append(p)
                except OSError as e:
                    fail_list.append(f"{p}（{e}）")
            aud_ok = audit_log("delete_hard", "; ".join(done_list) or "(none)")
            if fail_list:
                self.done.emit(False, "部分刪除失敗：\n已刪：" + ("\n".join(done_list) or "無") +
                               "\n失敗：" + "\n".join(fail_list) + audit_failed_note(aud_ok))
            else:
                self.done.emit(True, "已永久刪除：\n" + "\n".join(done_list) + audit_failed_note(aud_ok))
        else:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            dest_dir = os.path.join(ARCHIVE_DIR, ts)
            os.makedirs(dest_dir, exist_ok=True)
            moved, fail_list = [], []
            for p in targets:
                dest = os.path.join(dest_dir, os.path.basename(p))
                try:
                    shutil.move(p, dest)
                    moved.append(dest)
                except OSError as e:
                    fail_list.append(f"{p}（{e}）")
            aud_ok = audit_log("archive", f"{'; '.join(moved) or '(none)'} -> {dest_dir}")
            if fail_list:
                self.done.emit(False, "部分封存失敗：\n已搬：" + ("\n".join(moved) or "無") +
                               "\n失敗：" + "\n".join(fail_list) + audit_failed_note(aud_ok))
            else:
                self.done.emit(True, f"已封存到：\n{dest_dir}" + audit_failed_note(aud_ok))

    def _run_backup(self):
        pub_path = self.params.get("pub_path")
        priv_path = self.params.get("priv_path")
        dest_dir = self.params.get("dest_dir")
        zip_pass = self.params.get("zip_passphrase", "")
        if not dest_dir:
            self.done.emit(False, "缺少備份目標資料夾。")
            return
        if zip_pass:
            # 加密備份：私鑰複製出去就是敏感物落地，能加密就不要明文散落。
            # pyzipper（AES zip）是選用依賴，UI 端已確認裝了才會走到這裡。
            if pyzipper is None:
                self.done.emit(False, "未安裝 pyzipper，無法產生加密備份（pip install pyzipper）。")
                return
            sources = [p for p in (pub_path, priv_path) if p and os.path.exists(p)]
            if not sources:
                self.done.emit(False, "找不到要備份的檔案。")
                return
            base = os.path.splitext(os.path.basename(priv_path or pub_path))[0]
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            zip_path = os.path.join(dest_dir, f"{base}-keys-{ts}.zip")
            if os.path.exists(zip_path):
                self.done.emit(False, f"目的地已有同名壓縮檔，未覆蓋：{zip_path}")
                return
            try:
                with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_LZMA,
                                         encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(zip_pass.encode("utf-8"))
                    for p in sources:
                        zf.write(p, os.path.basename(p))
            except OSError as e:
                self.done.emit(False, f"寫入加密備份失敗：{e}")
                return
            aud_ok = audit_log("backup", f"{zip_path}（AES 加密 zip，{len(sources)} 檔）")
            self.done.emit(True, f"已產生加密備份：\n{zip_path}\n"
                                 "（解壓需要剛才那組密碼；忘了密碼備份等於報廢）" + audit_failed_note(aud_ok))
            return
        copied, skipped = [], []
        for p in (pub_path, priv_path):
            if p and os.path.exists(p):
                dest = os.path.join(dest_dir, os.path.basename(p))
                # 不覆蓋既有備份：兩個資料夾各有一把 id_rsa 備到同個目的地，
                # 後備的默默蓋掉先備的正是備份最不該做的事。
                if os.path.exists(dest):
                    skipped.append(dest)
                    continue
                shutil.copy2(p, dest)
                copied.append(dest)
        if not copied and not skipped:
            self.done.emit(False, "找不到要備份的檔案。")
            return
        aud_ok = audit_log("backup", "; ".join(copied) or "(all skipped)")
        msg = ""
        if copied:
            msg += "已備份：\n" + "\n".join(copied)
        if skipped:
            msg += ("\n" if msg else "") + "⚠ 目的地已有同名檔案、未覆蓋：\n" + "\n".join(skipped)
        self.done.emit(not skipped, msg + audit_failed_note(aud_ok))

    def _run_list_archive(self):
        items = []
        if os.path.isdir(ARCHIVE_DIR):
            for name in sorted(os.listdir(ARCHIVE_DIR), reverse=True):
                full = os.path.join(ARCHIVE_DIR, name)
                if os.path.isdir(full):
                    files = ", ".join(os.listdir(full))
                    items.append((name, files))
        self.result.emit(items)
        self.done.emit(True, f"封存區共 {len(items)} 筆。")

    def _run_restore_archive(self):
        name = self.params.get("name")
        target_dir = self.params.get("target_dir")
        src_dir = os.path.join(ARCHIVE_DIR, name or "")
        if not name or not os.path.isdir(src_dir):
            self.done.emit(False, "找不到這筆封存紀錄。")
            return
        # 先驗證「全部」目的地都沒有同名檔案再動手——邊搬邊檢查會在第二個檔
        # 撞名時留下搬到一半的封存目錄，還回報「未還原」誤導使用者。
        names = os.listdir(src_dir)
        conflicts = [os.path.join(target_dir, fn) for fn in names
                     if os.path.exists(os.path.join(target_dir, fn))]
        if conflicts:
            self.done.emit(False, "目標已存在同名檔案，整筆未還原：\n" + "\n".join(conflicts))
            return
        restored = []
        for fn in names:
            shutil.move(os.path.join(src_dir, fn), os.path.join(target_dir, fn))
            restored.append(os.path.join(target_dir, fn))
        try:
            os.rmdir(src_dir)
        except OSError:
            pass
        audit_log("restore", f"{name} -> {target_dir}")
        self.done.emit(True, "已還原：\n" + "\n".join(restored))

    def _run_purge_archive(self):
        name = self.params.get("name")
        src_dir = os.path.join(ARCHIVE_DIR, name or "")
        if not name or not os.path.isdir(src_dir):
            self.done.emit(False, "找不到這筆封存紀錄。")
            return
        shutil.rmtree(src_dir)
        audit_log("purge_archive", name)
        self.done.emit(True, f"已永久刪除封存：{name}")

    def _run_read_private_raw(self):
        path = self.params.get("path", "")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            self.done.emit(False, f"讀取失敗：{e}")
            return
        audit_log("view_private_raw", path)
        self.result.emit(content)
        self.done.emit(True, "已讀取。")

    def _run_list_known_hosts(self):
        entries = parse_known_hosts()
        self.result.emit(entries)
        self.done.emit(True, f"共 {len(entries)} 筆 known_hosts 紀錄。")

    def _run_delete_known_hosts_entry(self):
        line_no = self.params.get("line_no")
        ok, msg = delete_known_hosts_entry(line_no)
        if ok:
            audit_log("delete_known_hosts_entry", msg)
        self.done.emit(ok, msg)

    def _run_sync_registry(self):
        """跨機器同步金鑰名冊中繼資料：拉遠端 → 跟本機合併 → 存回本機 → 推合併結果回 NAS。
        只碰 registry.json 的中繼資料欄位，私鑰檔案本身完全不會被讀取或傳輸。"""
        sync_cfg = self.params.get("sync_cfg", {})
        remote_root = (sync_cfg.get("remote_root") or "").rstrip("/")
        if not remote_root:
            self.done.emit(False, "同步設定未填 remote_root，請先到「⚙ 雲端同步設定…」設定。")
            return
        if "'" in remote_root or "\n" in remote_root:
            self.done.emit(False, "remote_root 含引號/換行等不安全字元，請修正同步設定。")
            return
        hostname = socket.gethostname() or "UNKNOWN"
        self.log.emit("--- 跨機器同步金鑰名冊 ---")

        # 「檔案不存在」與「檔案讀不到」必須分得出來。以前兩者都變成空的遠端名冊，
        # 而空的遠端名冊合併完就會被推回去——等於把別台機器的資料整份蓋掉。
        # 這不是假設：NAS 上的 km_registry_sync.json 是 600，家機用 kuoterry、
        # 公司機用 git_user2 同步，誰推誰就把檔案鎖成只有自己讀得到，另一台讀
        # 失敗被 `true` 吞掉、當成空的、再推回去蓋掉對方（2026-08-14 查出來，
        # 家機 8 筆全被公司機的 6 筆蓋掉，靠 NAS 端 .bak 才救回來）。
        pull_cmd = "\n".join([
            f"f='{remote_root}/config/km_registry_sync.json'",
            "if [ ! -e \"$f\" ]; then echo ___MISSING___; exit 0; fi",
            "if [ ! -r \"$f\" ]; then echo ___UNREADABLE___; exit 0; fi",
            "echo ___BEGIN___",
            "cat \"$f\" || { echo ___CATFAIL___; exit 0; }",
            "echo ___END___",
        ])
        rc, out, err = _sync_ssh(sync_cfg, pull_cmd)
        if rc != 0:
            self.done.emit(False, f"讀取雲端金鑰名冊失敗：{(err or out).strip()}")
            return
        if "___UNREADABLE___" in out or "___CATFAIL___" in out:
            self.done.emit(False,
                           "雲端金鑰名冊存在、但這個身份讀不到（權限不足），為避免把別台機器"
                           "的資料蓋掉，已中止同步。\n\n"
                           f"請在 NAS 上放寬權限，例如：\n"
                           f"  chmod 660 {remote_root}/config/km_registry_sync.json\n"
                           f"  chgrp git_devs {remote_root}/config/km_registry_sync.json\n\n"
                           "（兩台機器用不同 SSH 身份同步時會遇到這個問題：舊版推送後會把檔案"
                           "鎖成 600，只有推送者自己讀得到。）")
            return
        if "___MISSING___" in out:
            remote_reg = {}
            self.log.emit("雲端還沒有金鑰名冊，這次是第一次建立。")
        else:
            try:
                remote_reg = json.loads(_between(out) or "{}")
            except json.JSONDecodeError:
                self.done.emit(False, "雲端金鑰名冊解析失敗（JSON 壞掉），為避免蓋掉它已中止同步。"
                                      "\n請檢查 NAS 上的 km_registry_sync.json，必要時從同目錄的"
                                      " .bak-<時間戳> 還原。")
                return

        local_reg = load_registry()
        merged = merge_registries(local_reg, remote_reg, hostname)
        # 合併結果要蓋掉本機名冊前先留一份備份——遠端那份若是壞的/舊的/別台機器
        # 誤推的，這是唯一能把本機歷史找回來的路（NAS 端推送本來就有 .bak，本機比照）。
        if os.path.isfile(REGISTRY_PATH):
            try:
                shutil.copy2(REGISTRY_PATH, REGISTRY_PATH + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
            except OSError as e:
                self.done.emit(False, f"本機名冊備份失敗（{e}），為安全起見中止同步。")
                return
        save_registry(merged)

        payload = json.dumps(merged, ensure_ascii=False)
        b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        # b64 從 stdin 餵進去，不放 argv——名冊會隨 history 成長，Windows 命令列
        # 有 32767 字元上限，塞 argv 遲早在某次掃描後永久炸掉同步。
        push_cmd = "\n".join([
            f"d='{remote_root}/config'; f=\"$d/km_registry_sync.json\"",
            "mkdir -p \"$d\"",
            "[ -f \"$f\" ] && cp \"$f\" \"$f.bak-$(date +%Y%m%d-%H%M%S)\"",
            "base64 -d > \"$f.new\" && [ -s \"$f.new\" ] && mv \"$f.new\" \"$f\"",
            # 660 而不是 600：兩台機器各用自己的 git_devs 身份同步，600 會讓
            # 對方讀不到自己推的檔案（見上面 pull 那段的註解）。config/ 本來就是
            # drwxrwsr-x git_devs setgid，新檔會自動帶到 git_devs 群組。
            # 失敗不中止（檔案已經推上去了），但要說出來——靜默的權限失敗正是
            # 這個 bug 當初能活這麼久的原因。
            "chmod 660 \"$f\" 2>/dev/null || echo ___PERMFAIL___",
            "chgrp git_devs \"$f\" 2>/dev/null || echo ___PERMFAIL___",
            "echo ___OK___",
        ])
        rc2, out2, err2 = _sync_ssh(sync_cfg, push_cmd, input_text=b64)
        if rc2 != 0 or "___OK___" not in out2:
            self.done.emit(False, f"推送雲端金鑰名冊失敗：{(err2 or out2).strip()}")
            return
        perm_note = ""
        if "___PERMFAIL___" in out2:
            perm_note = ("\n⚠ 雲端檔案的權限/群組設定失敗，別台機器用不同身份同步時可能讀不到。"
                         f"\n　請手動執行：chmod 660 與 chgrp git_devs {remote_root}/config/km_registry_sync.json")
        audit_log("sync_registry", f"host={hostname} merged_keys={len(merged)}")
        self.result.emit(merged)
        hosts = sorted({h for e in merged.values() for h in (e.get("seen_hosts") or {})})
        labels = nas_git_machine_labels()
        hosts_text = "、".join(label_host(h, labels) for h in hosts) if hosts else "（無）"
        self.done.emit(True, f"已同步金鑰名冊，共 {len(merged)} 筆。\n涵蓋電腦：{hosts_text}" + perm_note)

    def _run_encrypt_key(self):
        """幫未加密的 OpenSSH/PEM 私鑰補上 passphrase（ssh-keygen -p，原地改寫）。
        .ppk 不走這裡（ssh-keygen 不認得），UI 端已擋。"""
        path = self.params.get("path", "")
        passphrase = self.params.get("passphrase", "")
        if not path or not os.path.exists(path):
            self.done.emit(False, f"找不到私鑰檔：{path}")
            return
        if not passphrase:
            self.done.emit(False, "密碼不可為空。")
            return
        if not shutil.which("ssh-keygen"):
            self.done.emit(False, "找不到 ssh-keygen——請先安裝 Windows 內建 OpenSSH 用戶端"
                                  "（設定 → 應用程式 → 選用功能），再重試。")
            return
        args = ["ssh-keygen", "-p", "-P", "", "-N", passphrase, "-f", path]
        masked_args = list(args)
        masked_args[args.index("-N") + 1] = "***"
        self.log.emit("$ " + " ".join(a if a else "''" for a in masked_args))
        cp = subprocess.run(
            args, capture_output=True, text=True, timeout=30, input="",
            creationflags=_NO_WINDOW,
        )
        if cp.returncode != 0:
            self.done.emit(False, "加密失敗：" + (cp.stderr or cp.stdout).strip() +
                           "\n（若這把私鑰其實已有密碼，掃描的判讀可能過時，請重新掃描確認）")
            return
        aud_ok = audit_log("encrypt_key", path)
        self.done.emit(True, f"已為私鑰加上密碼保護：\n{path}\n"
                             "（請妥善保管這組密碼——忘了就沒有任何方式救回這把私鑰）" + audit_failed_note(aud_ok))

    def _run_rotate_key(self):
        """本機金鑰輪替：產新鑰 → （可選）SSH config 改指新鑰 → （可選）封存舊鑰。
        NAS 端 authorized_keys 的換鑰不歸這裡管——用 NasGitConnector 的「金鑰輪替…」，
        兩個工具互不寫對方的狀態（既有邊界，維持不變）。"""
        old_priv = self.params.get("old_priv", "")
        old_pub = self.params.get("old_pub", "")
        new_path = self.params.get("new_path", "")
        key_type = self.params.get("key_type", "ed25519")
        bits = self.params.get("bits")
        comment = self.params.get("comment", "")
        passphrase = self.params.get("passphrase", "")
        update_config = self.params.get("update_ssh_config", False)
        archive_old = self.params.get("archive_old", True)
        if not old_priv or not os.path.exists(old_priv):
            self.done.emit(False, f"找不到舊私鑰：{old_priv}")
            return
        if not new_path:
            self.done.emit(False, "缺少新金鑰路徑。")
            return
        if os.path.exists(new_path) or os.path.exists(new_path + ".pub"):
            self.done.emit(False, f"新金鑰檔案已存在，未覆蓋：{new_path}")
            return
        if not shutil.which("ssh-keygen"):
            self.done.emit(False, "找不到 ssh-keygen——請先安裝 Windows 內建 OpenSSH 用戶端。")
            return
        # 1) 產新鑰（同 _run_generate 的防呆慣例：input=""、timeout、遮罩 -N）
        args = ["ssh-keygen", "-t", key_type, "-N", passphrase, "-C", comment, "-f", new_path]
        if bits:
            args += ["-b", str(bits)]
        masked_args = list(args)
        if passphrase:
            masked_args[args.index("-N") + 1] = "***"
        self.log.emit("$ " + " ".join(a if a else "''" for a in masked_args))
        cp = subprocess.run(args, capture_output=True, text=True, timeout=30, input="",
                            creationflags=_NO_WINDOW)
        if cp.returncode != 0:
            self.done.emit(False, "產生新金鑰失敗，輪替未進行：" + (cp.stderr or cp.stdout).strip())
            return
        steps = [f"已產生新金鑰對：\n{new_path}\n{new_path}.pub"]
        # 2) SSH config 改指新鑰（失敗不回滾新鑰——新鑰是好的，講清楚哪步沒做就好）
        if update_config:
            changed, msg = rewrite_ssh_config_identity(old_priv, new_path)
            self.log.emit(msg)
            steps.append(("✔ " if changed else "⚠ ") + msg)
        # 3) 封存舊鑰（沿用 archive 慣例：搬進 ~/.key_management/archive/<時間戳>/）
        if archive_old:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            dest_dir = os.path.join(ARCHIVE_DIR, ts)
            os.makedirs(dest_dir, exist_ok=True)
            moved, fail = [], []
            for p in (old_priv, old_pub):
                if p and os.path.exists(p):
                    try:
                        shutil.move(p, os.path.join(dest_dir, os.path.basename(p)))
                        moved.append(p)
                    except OSError as e:
                        fail.append(f"{p}（{e}）")
            if moved:
                steps.append("✔ 舊金鑰已封存到：" + dest_dir)
            if fail:
                steps.append("⚠ 舊金鑰封存失敗：" + "; ".join(fail))
        else:
            steps.append("ℹ 舊金鑰未封存，仍留在原位。")
        aud_ok = audit_log("rotate_key", f"{old_priv} -> {new_path}")
        steps.append("提醒：遠端 authorized_keys（NAS/GitHub…）還沒換——NAS 請用 NasGitConnector 的「金鑰輪替…」。")
        self.done.emit(True, "\n".join(steps) + audit_failed_note(aud_ok))

    def _run_list_agent_keys(self):
        """列出 ssh-agent 目前載入的金鑰（ssh-add -l）。只支援 OpenSSH agent；
        Pageant（PuTTY）走它自己的協定，不在此功能範圍。"""
        if not shutil.which("ssh-add"):
            self.done.emit(False, "找不到 ssh-add——請先安裝 Windows 內建 OpenSSH 用戶端。")
            return
        cp = subprocess.run(["ssh-add", "-l"], capture_output=True, text=True,
                            timeout=10, input="", creationflags=_NO_WINDOW)
        if cp.returncode == 0:
            lines = [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]
            self.result.emit(lines)
            self.done.emit(True, f"ssh-agent 目前載入 {len(lines)} 把金鑰。")
        elif cp.returncode == 1:
            self.result.emit([])
            self.done.emit(True, "ssh-agent 有在跑，但目前沒有載入任何金鑰。")
        else:
            self.done.emit(False, "連不到 ssh-agent（服務沒啟動？）：" +
                           (cp.stderr or cp.stdout).strip())

    def _run_convert_ppk(self):
        """把 .ppk 轉成 OpenSSH 私鑰格式（shell out 到 puttygen）。
        加密的 .ppk 需提供原密碼，走暫存檔（--old-passphrase-file）不進命令列；
        各版 puttygen 的 CLI 支援度不一（Windows 版尤其），失敗時原樣回報 stderr。"""
        ppk_path = self.params.get("ppk_path", "")
        out_path = self.params.get("out_path", "")
        passphrase = self.params.get("passphrase", "")
        if not ppk_path or not os.path.exists(ppk_path):
            self.done.emit(False, f"找不到 .ppk 檔：{ppk_path}")
            return
        if not out_path:
            self.done.emit(False, "缺少輸出路徑。")
            return
        if os.path.exists(out_path):
            self.done.emit(False, f"輸出檔已存在，未覆蓋：{out_path}")
            return
        puttygen = shutil.which("puttygen")
        if not puttygen:
            self.done.emit(False, "找不到 puttygen——請安裝 PuTTY（或改用 WinSCP 的金鑰轉換功能）。")
            return
        args = [puttygen, ppk_path, "-O", "private-openssh", "-o", out_path]
        pw_file = None
        try:
            if passphrase:
                fd, pw_file = tempfile.mkstemp(prefix="km_ppk_pw_")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(passphrase + "\n")
                args += ["--old-passphrase", pw_file]
            self.log.emit("$ " + " ".join(a if a != pw_file else "***" for a in args))
            cp = subprocess.run(args, capture_output=True, text=True, timeout=30, input="",
                                creationflags=_NO_WINDOW)
        finally:
            if pw_file:
                try:
                    os.remove(pw_file)
                except OSError:
                    pass
        if cp.returncode != 0 or not os.path.exists(out_path):
            self.done.emit(False, "轉換失敗：" + ((cp.stderr or cp.stdout).strip() or "puttygen 無輸出") +
                           "\n（此版 puttygen 可能不支援命令列轉換——可改用 PuTTYgen GUI 的 "
                           "Conversions → Export OpenSSH key，或 WinSCP 的 /keygen）")
            return
        aud_ok = audit_log("convert_ppk", f"{ppk_path} -> {out_path}")
        self.done.emit(True, f"已轉換為 OpenSSH 格式：\n{out_path}\n"
                             "（原 .ppk 保留未動；重新掃描後新檔會出現在報表）" + audit_failed_note(aud_ok))

    def _run_rebuild_pub(self):
        """從私鑰重建 .pub（配對驗證抓到 stale .pub 時的修復手段）。舊 .pub 先備份。"""
        priv_path = self.params.get("priv_path", "")
        pub_path = self.params.get("pub_path", "")
        if not priv_path or not os.path.exists(priv_path):
            self.done.emit(False, f"找不到私鑰：{priv_path}")
            return
        if not pub_path:
            pub_path = priv_path + ".pub"
        derived, reason = derive_pubkey_via_sshkeygen(priv_path)
        if not derived:
            self.done.emit(False, f"無法從私鑰推導公鑰：{reason}")
            return
        try:
            if os.path.exists(pub_path):
                backup = pub_path + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S")
                shutil.copy2(pub_path, backup)
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write(derived + "\n")
        except OSError as e:
            self.done.emit(False, f"寫入 .pub 失敗：{e}")
            return
        aud_ok = audit_log("rebuild_pub", pub_path)
        self.done.emit(True, f"已用私鑰重建 .pub：\n{pub_path}\n（舊檔已備份 .bak-時間戳）" + audit_failed_note(aud_ok))

    def _run_compare_authorized_keys(self):
        """唯讀比對 NAS 上「目前同步身份」的 authorized_keys 與本機金鑰——輪替流程的驗收閉環。
        只 cat 自己的 authorized_keys，不 sudo、不寫入；撤銷金鑰仍歸 NasGitConnector 管。"""
        sync_cfg = self.params.get("sync_cfg", {})
        local_fps = self.params.get("local_fps", {})   # {SHA256:xxx: 描述}
        fp_hosts = self.params.get("fp_hosts", {})     # {SHA256:xxx: [hostname, ...]}（名冊 seen_hosts）
        host_labels = self.params.get("host_labels", {})
        this_host = (socket.gethostname() or "").lower()
        if not (sync_cfg.get("host") and sync_cfg.get("user")):
            self.done.emit(False, "同步設定未填 host/user，請先到「⚙ 雲端同步設定…」設定。")
            return
        self.log.emit(f"--- 讀取 {sync_cfg.get('user')}@{sync_cfg.get('host')} 的 authorized_keys ---")
        cmd = "\n".join([
            "echo ___BEGIN___",
            "cat \"$HOME/.ssh/authorized_keys\" 2>/dev/null",
            "echo ___END___",
            "true",
        ])
        rc, out, err = _sync_ssh(sync_cfg, cmd)
        if rc != 0:
            self.done.emit(False, f"連線失敗：{(err or out).strip() or 'SSH 錯誤'}")
            return
        remote_lines = [ln.strip() for ln in _between(out).splitlines()
                        if ln.strip() and not ln.strip().startswith("#")]
        matched, remote_only = [], []
        seen_remote_fps = set()
        for ln in remote_lines:
            parsed = parse_pubkey_line(ln)
            fp = ssh_fingerprint(parsed["blob"]) if parsed else ""
            comment = parsed["comment"] if parsed else "（解析不了的行）"
            if fp:
                seen_remote_fps.add(fp)
            if fp and fp in local_fps:
                matched.append(f"✔ {fp}  {comment}\n   ↳ 本機：{local_fps[fp]}")
            else:
                # 名冊的 seen_hosts 若記得這把在別台機器出現過，問號直接變答案
                others = [h for h in (fp_hosts.get(fp) or []) if h and h.lower() != this_host]
                if others:
                    shown = "、".join(label_host(h, host_labels) for h in sorted(others))
                    remote_only.append(f"🖥 {fp}  {comment}\n   ↳ 名冊記錄：這是「{shown}」上的金鑰（正常）")
                else:
                    remote_only.append(f"❓ {fp or '?'}  {comment}\n   ↳ NAS 授權了，但這台機器沒有、"
                                       "名冊也沒記錄（別台還沒同步？還是該撤銷的殘留？）")
        local_only = [f"⬆ {fp}  {label}" for fp, label in sorted(local_fps.items())
                      if fp not in seen_remote_fps]
        report = [f"NAS（{sync_cfg.get('user')}@{sync_cfg.get('host')}）authorized_keys 共 {len(remote_lines)} 行\n"]
        report.append(f"== 兩邊都有（{len(matched)}）==")
        report += matched or ["（無）"]
        report.append(f"\n== 只在 NAS（{len(remote_only)}）==")
        report += remote_only or ["（無）"]
        report.append(f"\n== 只在本機（{len(local_only)}）——這些金鑰連不上這個 NAS 身份 ==")
        report += local_only or ["（無）"]
        report.append("\nℹ 撤銷 NAS 端金鑰請用 NasGitConnector 的「SSH 金鑰管理」；本工具只讀不寫。")
        self.result.emit("\n".join(report))
        self.done.emit(True, f"比對完成：兩邊都有 {len(matched)}、只在 NAS {len(remote_only)}、只在本機 {len(local_only)}。")


# ============================================================
# 對話框
# ============================================================
class TextViewDialog(QDialog):
    def __init__(self, parent, title, text):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(700, 500)
        lay = QVBoxLayout(self)
        edit = QPlainTextEdit()
        edit.setReadOnly(True)
        edit.setFont(QFont("Consolas", 10))
        edit.setPlainText(text)
        lay.addWidget(edit)
        close_b = QPushButton("關閉")
        close_b.clicked.connect(self.accept)
        lay.addWidget(close_b)


class GenerateKeyDialog(QDialog):
    def __init__(self, parent, default_dir):
        super().__init__(parent)
        self.setWindowTitle("產生新金鑰對")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        g = QGridLayout()
        g.addWidget(QLabel("類型："), 0, 0)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["ed25519", "rsa", "ecdsa"])
        g.addWidget(self.type_combo, 0, 1)
        g.addWidget(QLabel("位元數（僅 RSA/ECDSA 用，留空用預設）："), 1, 0)
        self.bits_edit = QLineEdit()
        self.bits_edit.setPlaceholderText("RSA 建議 4096")
        g.addWidget(self.bits_edit, 1, 1)
        g.addWidget(QLabel("檔名："), 2, 0)
        self.name_edit = QLineEdit("id_ed25519_new")
        g.addWidget(self.name_edit, 2, 1)
        g.addWidget(QLabel("儲存資料夾："), 3, 0)
        dir_row = QHBoxLayout()
        self.dir_edit = QLineEdit(default_dir)
        browse_b = QPushButton("瀏覽…")
        browse_b.clicked.connect(self.on_browse)
        dir_row.addWidget(self.dir_edit, stretch=1)
        dir_row.addWidget(browse_b)
        g.addLayout(dir_row, 3, 1)
        g.addWidget(QLabel("Comment（用途／使用者標籤）："), 4, 0)
        self.comment_edit = QLineEdit()
        g.addWidget(self.comment_edit, 4, 1)
        g.addWidget(QLabel("密碼（留空＝不加密）："), 5, 0)
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        g.addWidget(self.pass_edit, 5, 1)
        lay.addLayout(g)

        cfg_box = QGroupBox("同時寫入 SSH config（可選）")
        cfg_box.setCheckable(True)
        cfg_box.setChecked(False)
        self.ssh_config_box = cfg_box
        cg = QGridLayout(cfg_box)
        cg.addWidget(QLabel("Host 別名（User 留空時才需要）："), 0, 0)
        self.host_alias_edit = QLineEdit()
        self.host_alias_edit.setPlaceholderText("例如 nas-git_user2（要打 ssh <別名> 才會用這把金鑰）")
        cg.addWidget(self.host_alias_edit, 0, 1)
        cg.addWidget(QLabel("HostName（伺服器位址）："), 1, 0)
        self.hostname_edit = QLineEdit()
        self.hostname_edit.setPlaceholderText("例如 kcc3713.synology.me")
        cg.addWidget(self.hostname_edit, 1, 1)
        cg.addWidget(QLabel("User（同一主機多帳號共用請務必填）："), 2, 0)
        self.ssh_user_edit = QLineEdit()
        self.ssh_user_edit.setPlaceholderText("填了就自動生效：ssh user@hostname 不用打別名也吃得到這把金鑰")
        cg.addWidget(self.ssh_user_edit, 2, 1)
        lay.addWidget(cfg_box)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("產生")
        lay.addWidget(bb)

    def on_browse(self):
        d = QFileDialog.getExistingDirectory(self, "選擇儲存資料夾", self.dir_edit.text())
        if d:
            self.dir_edit.setText(d)

    def _ok(self):
        if self.ssh_config_box.isChecked():
            if not self.hostname_edit.text().strip():
                QMessageBox.information(self, "缺欄位", "要寫入 SSH config 的話，HostName 一定要填。")
                return
            if not self.ssh_user_edit.text().strip() and not self.host_alias_edit.text().strip():
                QMessageBox.information(
                    self, "缺欄位",
                    "User 留空的話（單一身份、慣用別名連線）就要填 Host 別名；"
                    "同一主機給多帳號共用的話，填 User 即可，別名可以留空。")
                return
        self.accept()

    def values(self):
        bits = self.bits_edit.text().strip()
        path = os.path.join(self.dir_edit.text().strip(), self.name_edit.text().strip())
        return {
            "key_type": self.type_combo.currentText(),
            "bits": int(bits) if bits.isdigit() else None,
            "path": path,
            "comment": self.comment_edit.text().strip(),
            "passphrase": self.pass_edit.text(),
            "write_ssh_config": self.ssh_config_box.isChecked(),
            "ssh_config_alias": self.host_alias_edit.text().strip(),
            "ssh_config_hostname": self.hostname_edit.text().strip(),
            "ssh_config_user": self.ssh_user_edit.text().strip(),
        }


class PassphraseDialog(QDialog):
    """要一組新密碼（輸入兩次防打錯）。加密私鑰 / 加密備份共用。"""

    def __init__(self, parent, title, hint=""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(380)
        lay = QVBoxLayout(self)
        if hint:
            h = QLabel(hint)
            h.setWordWrap(True)
            lay.addWidget(h)
        g = QGridLayout()
        g.addWidget(QLabel("密碼："), 0, 0)
        self.p1 = QLineEdit()
        self.p1.setEchoMode(QLineEdit.EchoMode.Password)
        g.addWidget(self.p1, 0, 1)
        g.addWidget(QLabel("再輸入一次："), 1, 0)
        self.p2 = QLineEdit()
        self.p2.setEchoMode(QLineEdit.EchoMode.Password)
        g.addWidget(self.p2, 1, 1)
        lay.addLayout(g)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ok(self):
        if not self.p1.text():
            QMessageBox.information(self, "密碼不可為空", "請輸入密碼。")
            return
        if self.p1.text() != self.p2.text():
            QMessageBox.information(self, "兩次不一致", "兩次輸入的密碼不同，請重打。")
            return
        self.accept()

    def passphrase(self):
        return self.p1.text()


class RotateLocalKeyDialog(QDialog):
    """本機金鑰輪替：產新鑰＋（可選）SSH config 改指新鑰＋（可選）封存舊鑰。
    遠端 authorized_keys 不在範圍內（NAS 用 NasGitConnector 的「金鑰輪替…」）。"""

    def __init__(self, parent, rec):
        super().__init__(parent)
        self.rec = rec
        old_priv = rec.get("priv_path", "")
        self.setWindowTitle("金鑰輪替（本機）")
        self.setMinimumWidth(500)
        lay = QVBoxLayout(self)
        info = QLabel(f"舊金鑰：{old_priv}\n"
                      "流程：產生新金鑰 → （可選）SSH config 的 IdentityFile 改指新鑰 → （可選）封存舊金鑰。\n"
                      "⚠ 遠端 authorized_keys（NAS/GitHub…）不會自動換——本機換完記得去遠端補上新公鑰。")
        info.setWordWrap(True)
        lay.addWidget(info)
        g = QGridLayout()
        g.addWidget(QLabel("新檔名："), 0, 0)
        base = os.path.basename(old_priv)
        self.name_edit = QLineEdit(f"{base}_{datetime.now().strftime('%Y%m%d')}")
        g.addWidget(self.name_edit, 0, 1)
        g.addWidget(QLabel("類型："), 1, 0)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["ed25519", "rsa", "ecdsa"])
        g.addWidget(self.type_combo, 1, 1)
        g.addWidget(QLabel("位元數（僅 RSA/ECDSA，留空用預設）："), 2, 0)
        self.bits_edit = QLineEdit()
        g.addWidget(self.bits_edit, 2, 1)
        g.addWidget(QLabel("Comment："), 3, 0)
        self.comment_edit = QLineEdit(rec.get("comment", "") or "")
        g.addWidget(self.comment_edit, 3, 1)
        g.addWidget(QLabel("新密碼（留空＝不加密）："), 4, 0)
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        g.addWidget(self.pass_edit, 4, 1)
        lay.addLayout(g)
        hosts = rec.get("ssh_config_hosts") or []
        self.cfg_check = QCheckBox("SSH config 的 IdentityFile 改指向新金鑰" +
                                   (f"（目前指到：{'、'.join(hosts)}）" if hosts else "（目前沒有任何區塊指到這把）"))
        self.cfg_check.setChecked(bool(hosts))
        lay.addWidget(self.cfg_check)
        self.archive_check = QCheckBox("封存舊金鑰（搬進封存區，可還原）")
        self.archive_check.setChecked(True)
        lay.addWidget(self.archive_check)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("輪替")
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ok(self):
        if not self.name_edit.text().strip():
            QMessageBox.information(self, "缺檔名", "請填新金鑰檔名。")
            return
        self.accept()

    def values(self):
        old_priv = self.rec.get("priv_path", "")
        bits = self.bits_edit.text().strip()
        return {
            "old_priv": old_priv,
            "old_pub": self.rec.get("pub_path") or "",
            "new_path": os.path.join(os.path.dirname(old_priv), self.name_edit.text().strip()),
            "key_type": self.type_combo.currentText(),
            "bits": int(bits) if bits.isdigit() else None,
            "comment": self.comment_edit.text().strip(),
            "passphrase": self.pass_edit.text(),
            "update_ssh_config": self.cfg_check.isChecked(),
            "archive_old": self.archive_check.isChecked(),
        }


class ArchiveManageDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.worker = None
        self.setWindowTitle("金鑰封存區")
        self.resize(580, 420)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"安全刪除的金鑰會先搬到這裡（{ARCHIVE_DIR}），可還原或永久刪除。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.restore_b = QPushButton("還原…")
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

    def done(self, result):
        # accept()/reject()/Esc/關閉鈕全都經過 done()；closeEvent 只涵蓋視窗 X
        if not confirm_close_ok(self):
            return
        super().done(result)

    def _busy(self, b):
        for x in (self.refresh_b, self.restore_b, self.purge_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
        keep_worker_alive(self)
        self.worker = Worker("list_archive")
        self.worker.result.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, entries):
        self.list.clear()
        for name, files in entries:
            it = QListWidgetItem(f"{name}    [{files}]")
            it.setData(Qt.ItemDataRole.UserRole, name)
            self.list.addItem(it)

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def _sel(self):
        it = self.list.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def on_restore(self):
        name = self._sel()
        if not name:
            self.status.setText("請先選一筆。")
            return
        d = QFileDialog.getExistingDirectory(
            self, "還原到哪個資料夾", os.path.join(os.path.expanduser("~"), ".ssh"))
        if not d:
            return
        self._busy(True)
        keep_worker_alive(self)
        self.worker = Worker("restore_archive", {"name": name, "target_dir": d})
        self.worker.done.connect(self._on_action_done)
        self.worker.start()

    def on_purge(self):
        name = self._sel()
        if not name:
            self.status.setText("請先選一筆。")
            return
        r = QMessageBox.question(self, "永久刪除", f"確定永久刪除封存「{name}」？此動作無法復原。")
        if r != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        keep_worker_alive(self)
        self.worker = Worker("purge_archive", {"name": name})
        self.worker.done.connect(self._on_action_done)
        self.worker.start()

    def _on_action_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            self.refresh()


class RegistryDialog(QDialog):
    """金鑰名冊檢視：報表表格只看得到「這次掃描找到的」，名冊才記得「曾經存在過的」。
    這裡把 status=missing 的條目、first_seen、最近歷史事件攤開來看，並提供清除
    過時條目的入口（唯一會縮小 registry.json 的地方，走確認＋稽核）。"""

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("金鑰名冊歷史（含已消失的金鑰）")
        self.resize(920, 480)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"檔案：{REGISTRY_PATH}\n"
            "「missing」＝以前掃到過、最近一次掃描沒找到（被刪/搬走/資料夾沒加入掃描）。"
            "從別台電腦同步來的條目不會被本機掃描標成 missing。"))
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["狀態", "指紋", "備註(comment)", "類型", "首次記錄", "最後看到", "最近事件"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table, stretch=1)
        row = QHBoxLayout()
        self.prune_b = QPushButton("刪除選取條目（僅名冊紀錄，不動檔案）…")
        self.prune_b.clicked.connect(self.on_prune)
        close_b = QPushButton("關閉")
        close_b.clicked.connect(self.accept)
        row.addWidget(self.prune_b)
        row.addStretch(1)
        row.addWidget(close_b)
        lay.addLayout(row)
        self.refresh()

    def refresh(self):
        self.reg = load_registry()
        rows = sorted(self.reg.items(), key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
        self._row_keys = [k for k, _ in rows]
        self.table.setRowCount(len(rows))
        for i, (_key, e) in enumerate(rows):
            hist = e.get("history", [])
            recent = "；".join(f"{h.get('ts', '')} {h.get('action', '')}" for h in hist[-3:])
            status = e.get("status", "")
            vals = [status, e.get("fingerprint", "") or _key, e.get("comment", ""),
                    e.get("type", ""), e.get("first_seen", ""), e.get("last_seen", ""), recent]
            for col, val in enumerate(vals):
                it = QTableWidgetItem(str(val))
                if status == "missing" and col == 0:
                    it.setForeground(Qt.GlobalColor.red)
                self.table.setItem(i, col, it)

    def on_prune(self):
        picked = sorted({ix.row() for ix in self.table.selectedIndexes()})
        if not picked:
            return
        keys = [self._row_keys[r] for r in picked]
        r = QMessageBox.question(
            self, "刪除名冊條目",
            f"確定從名冊刪除 {len(keys)} 筆紀錄？\n只刪除歷史紀錄本身，不會動到任何金鑰檔案。\n"
            "注意：若之後執行跨機器同步，已同步到雲端的同一筆條目會再被合併回來。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if r != QMessageBox.StandardButton.Yes:
            return
        for k in keys:
            self.reg.pop(k, None)
        try:
            save_registry(self.reg)
        except OSError as e:
            QMessageBox.warning(self, "寫入失敗", f"名冊寫入失敗：{e}")
            return
        aud_ok = audit_log("registry_prune", "; ".join(keys))
        self.refresh()
        if not aud_ok:
            QMessageBox.warning(self, "稽核失敗", "條目已刪除，但稽核紀錄寫入失敗（audit.log 不可寫）。")


class AuditLogDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("本機操作稽核紀錄")
        self.resize(660, 420)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"檔案：{AUDIT_LOG_PATH}"))
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(QFont("Consolas", 10))
        lay.addWidget(self.text, stretch=1)
        close_b = QPushButton("關閉")
        close_b.clicked.connect(self.accept)
        lay.addWidget(close_b)
        try:
            with open(AUDIT_LOG_PATH, encoding="utf-8") as f:
                self.text.setPlainText(f.read())
        except OSError:
            self.text.setPlainText("（目前沒有紀錄）")


class KnownHostsDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.worker = None
        self.setWindowTitle("known_hosts 管理")
        self.resize(640, 460)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"檔案：{KNOWN_HOSTS_PATH}\n"
            "主機名雜湊過的（HashKnownHosts，OpenSSH 預設行為）看不出實際主機名，也沒辦法判斷重複；"
            "只有明碼主機名才會標記「重複」。刪除前會先備份原檔。"))
        self.list = QListWidget()
        lay.addWidget(self.list, stretch=1)
        row = QHBoxLayout()
        self.refresh_b = QPushButton("重新整理")
        self.delete_b = QPushButton("刪除選取…")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.refresh_b)
        row.addWidget(self.delete_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.refresh_b.clicked.connect(self.refresh)
        self.delete_b.clicked.connect(self.on_delete)
        self.close_b.clicked.connect(self.accept)
        self.refresh()

    def done(self, result):
        # accept()/reject()/Esc/關閉鈕全都經過 done()；closeEvent 只涵蓋視窗 X
        if not confirm_close_ok(self):
            return
        super().done(result)

    def _busy(self, b):
        for x in (self.refresh_b, self.delete_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
        keep_worker_alive(self)
        self.worker = Worker("list_known_hosts")
        self.worker.result.connect(self.on_entries)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_entries(self, entries):
        self.list.clear()
        for e in entries:
            host = "（已雜湊，看不出主機名）" if e["hashed"] else e["host"]
            dup = "　⚠ 重複" if e.get("duplicate") else ""
            it = QListWidgetItem(f"{host}    {e['key_type']}{dup}")
            it.setData(Qt.ItemDataRole.UserRole, e["line_no"])
            self.list.addItem(it)

    def on_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    def on_delete(self):
        it = self.list.currentItem()
        if not it:
            self.status.setText("請先選一筆。")
            return
        line_no = it.data(Qt.ItemDataRole.UserRole)
        r = QMessageBox.question(self, "刪除", f"確定刪除這筆 known_hosts 紀錄？\n\n{it.text()}\n\n原檔會先備份。")
        if r != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        keep_worker_alive(self)
        self.worker = Worker("delete_known_hosts_entry", {"line_no": line_no})
        self.worker.done.connect(self._on_delete_done)
        self.worker.start()

    def _on_delete_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            self.refresh()


class SyncConfigDialog(QDialog):
    """跨機器同步的連線設定：host/user/remote_root/identity_file，存在本機
    sync_config.json。只支援金鑰登入，可以從 NasGitConnector 的 QSettings 一鍵帶入，
    省去重複輸入 SSH 連線資訊。"""
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("雲端同步設定")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "設定完成後，「🌐 跨電腦金鑰總覽…」才能連上 NAS 同步。只支援 SSH 金鑰登入。\n"
            "同步只會上傳金鑰的中繼資料（指紋／備註／類型／時間戳／看過它的電腦名稱），\n"
            "私鑰檔案內容本身永遠不會被讀取或上傳。"))
        g = QGridLayout()
        g.addWidget(QLabel("NAS 主機："), 0, 0)
        self.host_edit = QLineEdit()
        g.addWidget(self.host_edit, 0, 1)
        g.addWidget(QLabel("SSH 使用者："), 1, 0)
        self.user_edit = QLineEdit()
        g.addWidget(self.user_edit, 1, 1)
        g.addWidget(QLabel("Git_Server 根："), 2, 0)
        self.root_edit = QLineEdit()
        self.root_edit.setPlaceholderText("/volume1/Git_Server")
        g.addWidget(self.root_edit, 2, 1)
        g.addWidget(QLabel("私鑰檔案："), 3, 0)
        id_row = QHBoxLayout()
        self.identity_edit = QLineEdit()
        id_browse_b = QPushButton("瀏覽…")
        id_row.addWidget(self.identity_edit)
        id_row.addWidget(id_browse_b)
        g.addLayout(id_row, 3, 1)
        lay.addLayout(g)

        import_b = QPushButton("從 NasGitConnector 帶入…")
        lay.addWidget(import_b)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.bb.accepted.connect(self.on_save)
        self.bb.rejected.connect(self.reject)
        lay.addWidget(self.bb)

        id_browse_b.clicked.connect(self.on_browse_identity)
        import_b.clicked.connect(self.on_import)
        self._load()

    def _load(self):
        cfg = load_sync_config()
        self.host_edit.setText(cfg.get("host", ""))
        self.user_edit.setText(cfg.get("user", ""))
        self.root_edit.setText(cfg.get("remote_root", ""))
        self.identity_edit.setText(cfg.get("identity_file", ""))

    def on_browse_identity(self):
        start = self.identity_edit.text().strip() or os.path.join(os.path.expanduser("~"), ".ssh")
        path, _ = QFileDialog.getOpenFileName(self, "選擇同步用的私鑰檔案", start)
        if path:
            self.identity_edit.setText(path)

    def on_import(self):
        profiles = read_nas_git_connector_profiles()
        if not profiles:
            self.status.setText("找不到 NasGitConnector 的身份設定（可能沒裝過或還沒設定過任何身份）。")
            self.status.setStyleSheet("color:#b06f00;")
            return
        names = list(profiles.keys())
        name, ok = QInputDialog.getItem(self, "從 NasGitConnector 帶入", "選一個身份：", names, 0, False)
        if not ok or not name:
            return
        vals = profiles[name]
        self.host_edit.setText(vals.get("host", ""))
        self.user_edit.setText(vals.get("user", ""))
        self.root_edit.setText(vals.get("remote_root", ""))
        if vals.get("identity_file"):
            self.identity_edit.setText(vals["identity_file"])
            self.status.setText(f"已帶入身份「{name}」。")
            self.status.setStyleSheet("color:#1a7f37;")
        else:
            self.status.setText(
                f"已帶入身份「{name}」的 host/user/remote_root，但這個身份是密碼登入——"
                "Key_Management 同步僅支援金鑰登入，請自行填一個私鑰檔案路徑。")
            self.status.setStyleSheet("color:#b06f00;")

    def on_save(self):
        cfg = {
            "host": self.host_edit.text().strip(),
            "user": self.user_edit.text().strip(),
            "remote_root": self.root_edit.text().strip(),
            "identity_file": self.identity_edit.text().strip(),
        }
        save_sync_config(cfg)
        self.accept()


class SyncOverviewDialog(QDialog):
    """跨電腦金鑰總覽：唯讀顯示本機 registry.json（同步過的話就含所有電腦的中繼資料），
    也可以按「立即同步」重新拉取/推送最新狀態。"""
    def __init__(self, parent):
        super().__init__(parent)
        self.worker = None
        self.setWindowTitle("跨電腦金鑰總覽")
        self.resize(900, 480)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            "顯示本機金鑰名冊裡記錄到的所有電腦（按「立即同步」才會連 NAS 拉最新狀態；"
            "不按的話這裡只是上次同步當下的快照）。"))
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["SHA256 指紋", "備註", "類型", "看過的電腦", "最後看到時間", "建議"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table, stretch=1)
        row = QHBoxLayout()
        self.sync_b = QPushButton("🔄 立即同步")
        self.close_b = QPushButton("關閉")
        row.addWidget(self.sync_b)
        row.addStretch(1)
        row.addWidget(self.close_b)
        lay.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.sync_b.clicked.connect(self.on_sync)
        self.close_b.clicked.connect(self.accept)
        self.refresh_from_local()

    def done(self, result):
        # accept()/reject()/Esc/關閉鈕全都經過 done()；closeEvent 只涵蓋視窗 X
        if not confirm_close_ok(self):
            return
        super().done(result)

    def refresh_from_local(self):
        self._populate(load_registry())

    def _populate(self, reg: dict):
        this_host = socket.gethostname() or ""
        labels = nas_git_machine_labels()   # 一次讀，整表共用（讀 QSettings 不用每列一次）
        rows = [(key, entry) for key, entry in reg.items() if entry.get("fingerprint")]
        rows.sort(key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
        self.table.setRowCount(len(rows))
        for i, (_key, entry) in enumerate(rows):
            seen_hosts = entry.get("seen_hosts") or {}
            hosts_text = ("、".join(label_host(h, labels) for h in sorted(seen_hosts))
                          if seen_hosts else "（尚未同步過）")
            advisory = "⚠ 也存在其他電腦" if len(seen_hosts) > 1 or (
                seen_hosts and this_host not in seen_hosts) else "—"
            for col, val in enumerate([
                entry.get("fingerprint", ""),
                entry.get("comment", ""),
                entry.get("type", ""),
                hosts_text,
                entry.get("last_seen", ""),
                advisory,
            ]):
                self.table.setItem(i, col, QTableWidgetItem(str(val)))

    def on_sync(self):
        sync_cfg = load_sync_config()
        if not (sync_cfg.get("host") and sync_cfg.get("user") and sync_cfg.get("identity_file")):
            self.status.setText("尚未設定同步連線資訊，請先按「⚙ 雲端同步設定…」設定。")
            self.status.setStyleSheet("color:#b06f00;")
            return
        self.sync_b.setEnabled(False)
        self.status.setText("同步中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("sync_registry", {"sync_cfg": sync_cfg})
        self.worker.result.connect(self._populate)
        self.worker.done.connect(self.on_sync_done)
        self.worker.start()

    def on_sync_done(self, ok, msg):
        self.sync_b.setEnabled(True)
        self.status.setText(("✔ " if ok else "❌ ") + msg)
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")


# ============================================================
# 主視窗
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # 標題掛機器標籤（家中/公司，來自 NasGitConnector 的機器綁定，唯讀 bridge）——
        # 沒綁定/對方沒裝就只顯示 hostname，一樣能分辨在哪台機器
        _host = socket.gethostname() or "?"
        self.setWindowTitle(f"金鑰管理工具 v{__version__}｜{label_host(_host, nas_git_machine_labels())}")
        self.setMinimumSize(1120, 660)
        self.worker = None
        self.records = []

        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        note = QLabel(
            "掃描本機的 SSH 金鑰（OpenSSH + PuTTY .ppk），整理成報表並提供管理功能"
            "（產生、封存刪除、永久刪除、備份、還原）。私鑰內容絕不會出現在報表匯出中，"
            "除非匯出時主動勾選「包含私鑰原始內容」。所有管理動作都會留下本機稽核紀錄。"
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#666;")
        lay.addWidget(note)

        folder_box = QGroupBox("掃描資料夾")
        fb = QVBoxLayout(folder_box)
        self.folder_list = QListWidget()
        self.settings = QSettings("TerryTools", "KeyManagement")
        saved_folders = self.settings.value("scan_folders", [], type=list)
        for f in (saved_folders or [os.path.join(os.path.expanduser("~"), ".ssh")]):
            self.folder_list.addItem(f)
        fb.addWidget(self.folder_list)
        frow = QHBoxLayout()
        add_b = QPushButton("新增資料夾…")
        add_b.clicked.connect(self.on_add_folder)
        remove_b = QPushButton("移除選取")
        remove_b.clicked.connect(self.on_remove_folder)
        self.scan_b = QPushButton("開始掃描")
        self.scan_b.clicked.connect(self.on_scan)
        frow.addWidget(add_b)
        frow.addWidget(remove_b)
        frow.addStretch(1)
        frow.addWidget(QLabel("輪替提醒（天）："))
        self.age_spin = QSpinBox()
        self.age_spin.setRange(30, 3650)
        self.age_spin.setValue(int(self.settings.value("advisory_age_days", DEFAULT_KEY_AGE_DAYS)))
        self.age_spin.setToolTip(f"金鑰超過這個天數未變更就在「建議」欄提醒輪替（預設 {DEFAULT_KEY_AGE_DAYS} 天）。")
        self.age_spin.valueChanged.connect(
            lambda v: self.settings.setValue("advisory_age_days", v))
        frow.addWidget(self.age_spin)
        # 掃描後自動同步：名冊的 seen_hosts 就是「這把鑰匙在哪幾台電腦出現過」那份
        # 紀錄，合併本來就與先後順序無關（per-fingerprint、seen_hosts 聯集）。
        # 少掉「掃完還要記得再按一次同步」這一步，兩台各按一次「開始掃描」就夠。
        self.autosync_check = QCheckBox("掃描後自動同步")
        self.autosync_check.setToolTip(
            "掃描完成後自動跑一次跨機器同步，把本機結果併進雲端名冊、也把別台的帶回來。\n"
            "需要先設定「⚙ 雲端同步設定…」；沒設定就自動略過，不會報錯。")
        self.autosync_check.setChecked(
            self.settings.value("autosync_after_scan", False, type=bool))
        self.autosync_check.toggled.connect(
            lambda v: self.settings.setValue("autosync_after_scan", v))
        frow.addWidget(self.autosync_check)
        frow.addWidget(self.scan_b)
        fb.addLayout(frow)
        lay.addWidget(folder_box)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ["金鑰使用者", "檔名", "類型與強度", "SHA256 指紋", "私鑰狀態",
             "SSH config Host", "最後修改", "建議", "路徑"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        lay.addWidget(self.table, stretch=1)

        arow = QHBoxLayout()
        self.gen_b = QPushButton("產生新金鑰對…")
        self.gen_b.clicked.connect(self.on_generate)
        self.archive_del_b = QPushButton("封存（安全刪除）…")
        self.archive_del_b.setEnabled(False)
        self.archive_del_b.clicked.connect(self.on_archive_delete)
        self.hard_del_b = QPushButton("永久刪除…")
        self.hard_del_b.setEnabled(False)
        self.hard_del_b.clicked.connect(self.on_hard_delete)
        self.backup_b = QPushButton("備份選取…")
        self.backup_b.setEnabled(False)
        self.backup_b.clicked.connect(self.on_backup)
        self.view_raw_b = QPushButton("檢視私鑰原始內容…")
        self.view_raw_b.setEnabled(False)
        self.view_raw_b.clicked.connect(self.on_view_raw)
        self.encrypt_b = QPushButton("加上密碼保護…")
        self.encrypt_b.setEnabled(False)
        self.encrypt_b.setToolTip("幫未加密的私鑰補上 passphrase（ssh-keygen -p，原地改寫）。.ppk 不適用。")
        self.encrypt_b.clicked.connect(self.on_encrypt_key)
        self.rotate_b = QPushButton("輪替（產新換舊）…")
        self.rotate_b.setEnabled(False)
        self.rotate_b.setToolTip("產生新金鑰、SSH config 改指新鑰、封存舊鑰；遠端 authorized_keys 要另外換。")
        self.rotate_b.clicked.connect(self.on_rotate_key)
        self.convert_b = QPushButton(".ppk 轉 OpenSSH…")
        self.convert_b.setEnabled(False)
        self.convert_b.setToolTip("用 puttygen 把 PuTTY .ppk 轉成 OpenSSH 私鑰格式（原檔保留）。")
        self.convert_b.clicked.connect(self.on_convert_ppk)
        self.rebuild_pub_b = QPushButton("重建 .pub")
        self.rebuild_pub_b.setEnabled(False)
        self.rebuild_pub_b.setToolTip("配對驗證抓到 .pub 與私鑰不一致時，用私鑰重新推導 .pub（舊檔備份）。")
        self.rebuild_pub_b.clicked.connect(self.on_rebuild_pub)
        self.copy_pub_b = QPushButton("複製公鑰")
        self.copy_pub_b.setEnabled(False)
        self.copy_pub_b.clicked.connect(self.on_copy_pub)
        self.open_folder_b = QPushButton("開啟所在資料夾")
        self.open_folder_b.setEnabled(False)
        self.open_folder_b.clicked.connect(self.on_open_folder)
        for b in (self.gen_b, self.archive_del_b, self.hard_del_b, self.backup_b,
                  self.view_raw_b, self.encrypt_b, self.rotate_b, self.convert_b,
                  self.rebuild_pub_b, self.copy_pub_b, self.open_folder_b):
            arow.addWidget(b)
        arow.addStretch(1)
        lay.addLayout(arow)

        brow = QHBoxLayout()
        self.archive_mgmt_b = QPushButton("金鑰封存區…")
        self.archive_mgmt_b.clicked.connect(self.on_archive_mgmt)
        self.audit_b = QPushButton("稽核紀錄…")
        self.audit_b.clicked.connect(self.on_audit_log)
        self.registry_b = QPushButton("名冊歷史…")
        self.registry_b.setToolTip("看曾經存在過（含已消失 missing）的金鑰紀錄，可清除過時條目。")
        self.registry_b.clicked.connect(self.on_registry)
        self.known_hosts_b = QPushButton("known_hosts 管理…")
        self.known_hosts_b.clicked.connect(self.on_known_hosts)
        self.agent_b = QPushButton("ssh-agent 盤點…")
        self.agent_b.setToolTip("列出 ssh-agent 目前載入的金鑰，比對名冊/本次掃描結果。不含 Pageant。")
        self.agent_b.clicked.connect(self.on_agent_keys)
        self.authcmp_b = QPushButton("NAS 授權比對…")
        self.authcmp_b.setToolTip("唯讀比對 NAS 上（雲端同步身份）authorized_keys 與本機金鑰——"
                                  "輪替後驗證「本機這把在遠端到底認不認」。撤銷仍走 NasGitConnector。")
        self.authcmp_b.clicked.connect(self.on_compare_authorized)
        self.terminal_b = QPushButton("🖥 開啟 NAS 終端機")
        self.terminal_b.setToolTip("用雲端同步身份開一個 ssh 視窗（sudo 診斷、貼指令用）。Windows 限定。")
        self.terminal_b.clicked.connect(self.on_open_terminal)
        self.sync_config_b = QPushButton("⚙ 雲端同步設定…")
        self.sync_config_b.clicked.connect(self.on_sync_config)
        self.sync_overview_b = QPushButton("🌐 跨電腦金鑰總覽…")
        self.sync_overview_b.clicked.connect(self.on_sync_overview)
        self.export_b = QPushButton("匯出 CSV 報表…")
        self.export_b.clicked.connect(self.on_export_csv)
        brow.addWidget(self.archive_mgmt_b)
        brow.addWidget(self.audit_b)
        brow.addWidget(self.registry_b)
        brow.addWidget(self.known_hosts_b)
        brow.addWidget(self.agent_b)
        brow.addWidget(self.authcmp_b)
        brow.addWidget(self.terminal_b)
        brow.addWidget(self.sync_config_b)
        brow.addWidget(self.sync_overview_b)
        brow.addStretch(1)
        brow.addWidget(self.export_b)
        lay.addLayout(brow)

        self.status = QLabel(f"金鑰名冊/稽核紀錄/封存區都在 {APP_DIR}")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        # 背景動作進度 log：Worker.log 過去是死訊號（emit 了沒人接），大資料夾掃描
        # 只看得到靜止的「掃描中…」，分不出慢跟卡死。
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        self.log_view.setFixedHeight(90)
        self.log_view.setPlaceholderText("背景動作進度會顯示在這裡（掃描/產生/同步…）")
        lay.addWidget(self.log_view)

    def append_log(self, line: str):
        self.log_view.appendPlainText(line)

    def _save_folders(self):
        self.settings.setValue(
            "scan_folders",
            [self.folder_list.item(i).text() for i in range(self.folder_list.count())])

    def closeEvent(self, event):
        confirm_close_with_worker(self, event)

    def _busy(self, b):
        for x in (self.scan_b, self.gen_b, self.archive_mgmt_b, self.audit_b, self.export_b,
                  self.archive_del_b, self.hard_del_b, self.backup_b, self.view_raw_b,
                  self.encrypt_b, self.rotate_b, self.convert_b, self.rebuild_pub_b,
                  self.agent_b, self.authcmp_b,
                  self.known_hosts_b, self.sync_config_b, self.sync_overview_b, self.registry_b):
            x.setEnabled(not b)
        if not b:
            self.on_selection_changed()

    # ---------- 掃描資料夾管理 ----------
    def on_add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "選擇要掃描的資料夾")
        if d:
            self.folder_list.addItem(d)
            self._save_folders()

    def on_remove_folder(self):
        for it in self.folder_list.selectedItems():
            self.folder_list.takeItem(self.folder_list.row(it))
        self._save_folders()

    # ---------- 掃描 ----------
    def on_scan(self):
        folders = [self.folder_list.item(i).text() for i in range(self.folder_list.count())]
        if not folders:
            self.status.setText("請先加入至少一個資料夾。")
            return
        self._busy(True)
        self.status.setText("掃描中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("scan", {"folders": folders, "age_days": self.age_spin.value()})
        self.worker.log.connect(self.append_log)
        self.worker.result.connect(self.on_scan_result)
        self.worker.done.connect(self.on_scan_done)
        self.worker.start()

    def on_scan_result(self, records):
        self.records = records
        self.populate_table(records)

    def on_scan_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok and self.autosync_check.isChecked():
            self._start_autosync()

    def _start_autosync(self):
        """掃描成功後接著跑一次跨機器同步。設定不全就安靜略過——自動流程不該
        因為「還沒設定雲端同步」每次掃描都跳一個錯誤給使用者看。"""
        cfg = load_sync_config()
        if not (cfg.get("user") and cfg.get("host") and cfg.get("identity_file")):
            self.status.setText(self.status.text() + "　（未設定雲端同步，略過自動同步）")
            return
        self._busy(True)
        self.status.setText("掃描完成，同步中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("sync_registry", {"sync_cfg": cfg})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_autosync_done)
        self.worker.start()

    def _on_autosync_done(self, ok, msg):
        self._busy(False)
        # 同步失敗不能吃掉——這個功能存在的理由就是「同步靜默失敗了兩個月沒人發現」
        self.status.setText(("✔ 掃描完成｜同步：" if ok else "❌ 掃描完成，但同步失敗：")
                            + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if not ok:
            QMessageBox.warning(self, "自動同步失敗", msg)

    # ---------- 表格 ----------
    def _row_values(self, rec):
        comment = rec.get("comment", "") or "（無註解）"
        base = os.path.basename(rec.get("priv_path") or rec.get("pub_path") or "")
        type_strength = rec.get("strength") or rec.get("type") or "未知"
        fp = rec.get("fingerprint") or "—"
        if rec.get("priv_path"):
            enc = rec.get("priv_encrypted")
            priv_status = "存在・已加密" if enc else ("存在・未加密" if enc is False else "存在・無法判斷")
        else:
            priv_status = "不存在"
        ssh_hosts = "、".join(rec.get("ssh_config_hosts", [])) or "（未設定）"
        mtime = rec.get("mtime")
        mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime else "—"
        advisories = rec.get("advisories", "—")
        path = rec.get("pub_path") or rec.get("priv_path") or ""
        return [comment, base, type_strength, fp, priv_status, ssh_hosts, mtime_str, advisories, path]

    def populate_table(self, records):
        self.table.setRowCount(0)
        for rec in records:
            row = self._row_values(rec)
            r = self.table.rowCount()
            self.table.insertRow(r)
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, rec)
                self.table.setItem(r, c, item)
        self.table.resizeColumnsToContents()

    def _selected_record(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def on_selection_changed(self):
        rec = self._selected_record()
        has = rec is not None
        has_priv = has and bool(rec.get("priv_path"))
        has_pub_content = has and (bool(rec.get("pub_path")) or rec.get("blob") is not None)
        self.archive_del_b.setEnabled(has)
        self.hard_del_b.setEnabled(has)
        self.backup_b.setEnabled(has)
        self.view_raw_b.setEnabled(has_priv)
        # 加密：確定未加密、且不是 .ppk（ssh-keygen 不認得 ppk）
        self.encrypt_b.setEnabled(has_priv and rec.get("priv_encrypted") is False
                                  and rec.get("priv_format") != "ppk")
        self.rotate_b.setEnabled(has_priv and rec.get("priv_format") != "ppk")
        self.convert_b.setEnabled(has_priv and rec.get("priv_format") == "ppk")
        self.rebuild_pub_b.setEnabled(has_priv and bool(rec.get("pair_mismatch")))
        self.copy_pub_b.setEnabled(has_pub_content)
        self.open_folder_b.setEnabled(has)

    # ---------- 產生新金鑰 ----------
    def on_generate(self):
        default_dir = (self.folder_list.item(0).text() if self.folder_list.count()
                       else os.path.join(os.path.expanduser("~"), ".ssh"))
        dlg = GenerateKeyDialog(self, default_dir)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        vals = dlg.values()
        if not vals["path"] or not os.path.basename(vals["path"]):
            self.status.setText("請填檔名。")
            return
        self._busy(True)
        self.status.setText("產生金鑰中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("generate", vals)
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_generate_done)
        self.worker.start()

    def _on_generate_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok:
            QMessageBox.information(self, "完成", msg)
            self.on_scan()

    # ---------- 封存 / 永久刪除 ----------
    def on_archive_delete(self):
        rec = self._selected_record()
        if not rec:
            return
        r = QMessageBox.question(
            self, "封存（安全刪除）",
            f"確定把這組金鑰搬到封存區？（{ARCHIVE_DIR}，可還原）\n"
            f"公鑰：{rec.get('pub_path') or '（無）'}\n私鑰：{rec.get('priv_path') or '（無）'}")
        if r != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        self.status.setText("封存中…")
        keep_worker_alive(self)
        self.worker = Worker("delete", {
            "pub_path": rec.get("pub_path"), "priv_path": rec.get("priv_path"), "hard": False})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_delete_done)
        self.worker.start()

    def on_hard_delete(self):
        rec = self._selected_record()
        if not rec:
            return
        base = os.path.basename(rec.get("priv_path") or rec.get("pub_path") or "")
        text, ok = QInputDialog.getText(
            self, "永久刪除", f"此動作無法復原。請輸入檔名「{base}」確認：")
        if not ok or text.strip() != base:
            self.status.setText("確認文字不符，已取消。")
            return
        self._busy(True)
        self.status.setText("永久刪除中…")
        keep_worker_alive(self)
        self.worker = Worker("delete", {
            "pub_path": rec.get("pub_path"), "priv_path": rec.get("priv_path"), "hard": True})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_delete_done)
        self.worker.start()

    def _on_delete_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok:
            self.on_scan()

    # ---------- 備份 ----------
    def on_backup(self):
        rec = self._selected_record()
        if not rec:
            return
        d = QFileDialog.getExistingDirectory(self, "備份到哪個資料夾")
        if not d:
            return
        # 備份是唯一會把私鑰檔複製到任意使用者選定資料夾（可能是雲端同步資料夾）
        # 的路徑——CSV 匯出含私鑰前會問，這裡比照，含私鑰就先確認一次。
        zip_pass = ""
        if rec.get("priv_path"):
            if pyzipper is not None:
                r = QMessageBox.question(
                    self, "加密備份？",
                    "要把備份打包成「AES 加密 zip」嗎？\n\n"
                    "・是：備份落地即加密，放雲端同步資料夾也不算裸奔（忘記密碼＝備份報廢）\n"
                    "・否：維持原樣明文複製",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes)
                if r == QMessageBox.StandardButton.Yes:
                    dlg = PassphraseDialog(self, "設定備份 zip 密碼",
                                           "解壓縮時需要這組密碼；忘了就沒有任何方式救回備份內容。")
                    if dlg.exec() != QDialog.DialogCode.Accepted:
                        return
                    zip_pass = dlg.passphrase()
            if not zip_pass:
                r = QMessageBox.question(
                    self, "備份包含私鑰",
                    f"備份會把「私鑰檔」複製到：\n{d}\n\n"
                    "若該資料夾會同步到雲端（OneDrive/Dropbox 等），私鑰等同外流。\n確定要備份？"
                    + ("" if pyzipper is not None else "\n\n（提示：pip install pyzipper 之後可改用加密 zip 備份）"),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No)
                if r != QMessageBox.StandardButton.Yes:
                    return
        self._busy(True)
        self.status.setText("備份中…")
        keep_worker_alive(self)
        self.worker = Worker("backup", {
            "pub_path": rec.get("pub_path"), "priv_path": rec.get("priv_path"), "dest_dir": d,
            "zip_passphrase": zip_pass})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_backup_done)
        self.worker.start()

    def _on_backup_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")

    # ---------- 檢視私鑰原始內容 ----------
    def on_view_raw(self):
        rec = self._selected_record()
        if not rec or not rec.get("priv_path"):
            return
        r = QMessageBox.question(
            self, "檢視私鑰原始內容",
            "接下來會直接顯示私鑰檔案的完整原始內容，這個動作會記錄到稽核紀錄。\n"
            "確定要繼續嗎？")
        if r != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        keep_worker_alive(self)
        self.worker = Worker("read_private_raw", {"path": rec["priv_path"]})
        self.worker.log.connect(self.append_log)
        self.worker.result.connect(self._show_raw)
        self.worker.done.connect(self._on_view_raw_done)
        self.worker.start()

    def _on_view_raw_done(self, ok, msg):
        self._busy(False)
        if not ok:
            QMessageBox.warning(self, "讀取失敗", msg)

    def _show_raw(self, content):
        dlg = TextViewDialog(self, "私鑰原始內容（請小心保管視窗內容，關閉前避免截圖/分享）", content)
        dlg.exec()

    # ---------- 加密私鑰 / 本機輪替 / .ppk 轉換 / ssh-agent 盤點 ----------
    def _on_mutating_done(self, ok, msg):
        """encrypt/rotate/convert 共用的收尾：顯示結果，成功就重掃刷新報表與名冊。"""
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if ok:
            QMessageBox.information(self, "完成", msg)
            self.on_scan()
        else:
            QMessageBox.warning(self, "失敗", msg)

    def on_encrypt_key(self):
        rec = self._selected_record()
        if not rec or not rec.get("priv_path") or rec.get("priv_encrypted") is not False \
                or rec.get("priv_format") == "ppk":
            return
        dlg = PassphraseDialog(
            self, "設定私鑰密碼",
            f"將為以下私鑰加上 passphrase（原地改寫，動作會留稽核紀錄）：\n{rec['priv_path']}\n"
            "⚠ 忘了這組密碼就沒有任何方式救回這把私鑰。")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._busy(True)
        self.status.setText("加密私鑰中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("encrypt_key", {"path": rec["priv_path"], "passphrase": dlg.passphrase()})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_mutating_done)
        self.worker.start()

    def on_rotate_key(self):
        rec = self._selected_record()
        if not rec or not rec.get("priv_path") or rec.get("priv_format") == "ppk":
            return
        dlg = RotateLocalKeyDialog(self, rec)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._busy(True)
        self.status.setText("金鑰輪替中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("rotate_key", dlg.values())
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_mutating_done)
        self.worker.start()

    def on_convert_ppk(self):
        rec = self._selected_record()
        if not rec or not rec.get("priv_path") or rec.get("priv_format") != "ppk":
            return
        ppk_path = rec["priv_path"]
        base = os.path.basename(ppk_path)
        default_name = (base[:-4] if base.lower().endswith(".ppk") else base) + "_openssh"
        name, okp = QInputDialog.getText(self, ".ppk 轉 OpenSSH",
                                         "輸出檔名（存到 .ppk 同資料夾）：", text=default_name)
        if not okp or not name.strip():
            return
        passphrase = ""
        if rec.get("priv_encrypted"):
            passphrase, okp2 = QInputDialog.getText(
                self, "原 .ppk 密碼", "這個 .ppk 有加密，請輸入它的原密碼（轉出的檔會沿用同一組）：",
                QLineEdit.EchoMode.Password)
            if not okp2:
                return
        self._busy(True)
        self.status.setText(".ppk 轉換中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("convert_ppk", {
            "ppk_path": ppk_path,
            "out_path": os.path.join(os.path.dirname(ppk_path), name.strip()),
            "passphrase": passphrase})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_mutating_done)
        self.worker.start()

    def on_rebuild_pub(self):
        rec = self._selected_record()
        if not rec or not rec.get("priv_path") or not rec.get("pair_mismatch"):
            return
        r = QMessageBox.question(
            self, "重建 .pub",
            f"將用私鑰重新推導並覆寫：\n{rec.get('pub_path') or rec['priv_path'] + '.pub'}\n"
            "（舊 .pub 會先備份成 .bak-時間戳）\n\n"
            "⚠ 先想一下：如果其實是「私鑰被換過、.pub 才是對的」，該修的是私鑰不是 .pub。確定重建？")
        if r != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        self.status.setText("重建 .pub 中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("rebuild_pub", {"priv_path": rec["priv_path"],
                                             "pub_path": rec.get("pub_path") or ""})
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self._on_mutating_done)
        self.worker.start()

    def on_compare_authorized(self):
        sync_cfg = load_sync_config()
        if not (sync_cfg.get("host") and sync_cfg.get("user")):
            QMessageBox.information(self, "需要同步設定",
                                    "這個功能用「⚙ 雲端同步設定…」的連線身份去讀 NAS 上的 authorized_keys，"
                                    "請先設定 host/user（與金鑰）。")
            return
        # 本機指紋集：本次掃描 + 名冊（讀不到名冊就只用掃描結果）
        local_fps = {}
        for rec in (getattr(self, "records", None) or []):
            fp = rec.get("fingerprint")
            if fp:
                local_fps.setdefault(fp, rec.get("priv_path") or rec.get("pub_path")
                                     or rec.get("comment") or "")
        fp_hosts = {}
        this_host = (socket.gethostname() or "").lower()
        try:
            for entry in load_registry().values():
                fp = entry.get("fingerprint")
                if not fp:
                    continue
                sh = entry.get("seen_hosts") or {}
                if sh:
                    fp_hosts[fp] = sorted(sh)
                # 名冊條目只有「本機看過」（seen_hosts 含本機，或從沒同步過）才算「本機有」；
                # 純粹從別台同步進來的鑰匙不算——它們該走 🖥「別台機器的」標註
                if fp not in local_fps and (not sh or any(h.lower() == this_host for h in sh)):
                    local_fps[fp] = "（名冊）" + (entry.get("comment") or entry.get("pub_path") or "")
        except Exception:
            pass
        if not local_fps:
            QMessageBox.information(self, "先掃描", "還沒有本機金鑰資料——先跑一次掃描再比對。")
            return
        self._busy(True)
        self.status.setText("讀取 NAS authorized_keys 中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("compare_authorized_keys",
                             {"sync_cfg": sync_cfg, "local_fps": local_fps,
                              "fp_hosts": fp_hosts, "host_labels": nas_git_machine_labels()})
        self.worker.log.connect(self.append_log)
        self.worker.result.connect(self._show_authcmp)
        self.worker.done.connect(self._on_agent_done)
        self.worker.start()

    def _show_authcmp(self, report):
        TextViewDialog(self, "NAS 授權比對", report).exec()

    def on_open_terminal(self):
        # 不掛 _busy：開終端機不佔 Worker，掃描跑到一半也能開視窗查東西
        sync_cfg = load_sync_config()
        if not (sync_cfg.get("host") and sync_cfg.get("user")):
            QMessageBox.information(self, "需要同步設定",
                                    "用「⚙ 雲端同步設定…」的連線身份開終端機，請先設定 host/user。")
            return
        ok, msg = open_ssh_terminal(sync_cfg)
        if ok:
            self.status.setText("✔ " + msg)
            self.status.setStyleSheet("color:#1a7f37;")
        else:
            QMessageBox.warning(self, "開啟終端機失敗", msg)

    def on_agent_keys(self):
        self._busy(True)
        self.status.setText("查詢 ssh-agent 中…")
        self.status.setStyleSheet("")
        keep_worker_alive(self)
        self.worker = Worker("list_agent_keys", {})
        self.worker.log.connect(self.append_log)
        self.worker.result.connect(self._show_agent_keys)
        self.worker.done.connect(self._on_agent_done)
        self.worker.start()

    def _on_agent_done(self, ok, msg):
        self._busy(False)
        self.status.setText(("✔ " if ok else "❌ ") + msg.replace("\n", "　"))
        self.status.setStyleSheet("color:#1a7f37;" if ok else "color:#b00020;")
        if not ok:
            QMessageBox.warning(self, "ssh-agent 盤點失敗", msg)

    def _show_agent_keys(self, lines):
        """agent 指紋比對本次掃描結果＋名冊，標出「這台機器管不到的鑰匙」。"""
        known = {}
        for rec in (getattr(self, "records", None) or []):
            fp = rec.get("fingerprint")
            if fp:
                known.setdefault(fp, rec.get("priv_path") or rec.get("pub_path")
                                 or rec.get("comment") or "")
        try:
            for entry in load_registry().values():
                fp = entry.get("fingerprint")
                if fp and fp not in known:
                    known[fp] = "（名冊）" + (entry.get("comment") or entry.get("pub_path") or "")
        except Exception:
            pass  # 名冊讀不到就只比對本次掃描，盤點本身照樣能看
        out = []
        for ln in lines:
            fp = next((t for t in ln.split() if t.startswith("SHA256:")), "")
            if fp and fp in known:
                out.append(f"✔ {ln}\n   ↳ 對應：{known[fp]}")
            else:
                out.append(f"❓ {ln}\n   ↳ 不在名冊/本次掃描中（別台機器的金鑰？或還沒加進掃描資料夾）")
        if not out:
            out = ["（ssh-agent 目前沒有載入任何金鑰）"]
        out.append("\nℹ 只盤點 OpenSSH ssh-agent（ssh-add -l）；PuTTY 的 Pageant 不在範圍。")
        TextViewDialog(self, "ssh-agent 盤點", "\n".join(out)).exec()

    # ---------- 複製公鑰 / 開啟資料夾 ----------
    def on_copy_pub(self):
        rec = self._selected_record()
        if not rec:
            return
        content = ""
        pub_path = rec.get("pub_path")
        if pub_path and os.path.exists(pub_path):
            try:
                with open(pub_path, encoding="utf-8", errors="replace") as f:
                    content = f.read().strip()
            except OSError:
                content = ""
        elif rec.get("type") and rec.get("blob"):
            content = f"{rec['type']} {base64.b64encode(rec['blob']).decode()} {rec.get('comment', '')}".strip()
        if content:
            QApplication.clipboard().setText(content)
            self.status.setText("已複製公鑰內容到剪貼簿。")
            self.status.setStyleSheet("color:#1a7f37;")
        else:
            self.status.setText("❌ 讀不到公鑰內容（檔案不存在或無法讀取），未複製。")
            self.status.setStyleSheet("color:#b00020;")

    def on_open_folder(self):
        rec = self._selected_record()
        if not rec:
            return
        path = rec.get("priv_path") or rec.get("pub_path")
        if not (path and os.path.exists(path)):
            return
        if os.name != "nt":
            self.status.setText("開啟資料夾功能目前只支援 Windows。")
            return
        try:
            # Qt slot 內未攔截的例外會讓 PyQt6 直接中止程式，這裡不能裸呼叫
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)],
                             creationflags=_NO_WINDOW)
        except OSError as e:
            self.status.setText(f"❌ 開啟檔案總管失敗：{e}")
            self.status.setStyleSheet("color:#b00020;")

    # ---------- 封存區 / 稽核紀錄 ----------
    def on_archive_mgmt(self):
        dlg = ArchiveManageDialog(self)
        dlg.exec()

    def on_audit_log(self):
        dlg = AuditLogDialog(self)
        dlg.exec()

    def on_registry(self):
        dlg = RegistryDialog(self)
        dlg.exec()

    def on_known_hosts(self):
        dlg = KnownHostsDialog(self)
        dlg.exec()

    # ---------- 跨機器同步 ----------
    def on_sync_config(self):
        dlg = SyncConfigDialog(self)
        dlg.exec()

    def on_sync_overview(self):
        dlg = SyncOverviewDialog(self)
        dlg.exec()

    # ---------- 匯出 CSV ----------
    def on_export_csv(self):
        if not self.records:
            self.status.setText("目前沒有可匯出的資料，請先掃描。")
            return
        include_raw = QMessageBox.question(
            self, "匯出選項",
            "是否要在報表中包含私鑰檔案的原始內容？\n\n"
            "⚠ 不建議：這個 CSV 檔案如果外流，等於私鑰跟著外流。\n"
            "選「否」的話，報表只會有公鑰內容跟中繼資料。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes
        path, _ = QFileDialog.getSaveFileName(self, "匯出報表", "key_report.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                header = ["金鑰使用者", "檔名", "類型與強度", "SHA256指紋", "私鑰狀態", "SSH config Host",
                          "最後修改", "建議", "公鑰路徑", "私鑰路徑", "公鑰內容"]
                if include_raw:
                    header.append("私鑰原始內容")
                writer.writerow(header)
                for rec in self.records:
                    comment = rec.get("comment", "") or "（無註解）"
                    base = os.path.basename(rec.get("priv_path") or rec.get("pub_path") or "")
                    type_strength = rec.get("strength") or rec.get("type") or "未知"
                    fp = rec.get("fingerprint") or "—"
                    enc = rec.get("priv_encrypted")
                    priv_status = ("存在・已加密" if enc else
                                   ("存在・未加密" if enc is False else
                                    ("不存在" if not rec.get("priv_path") else "存在・無法判斷")))
                    mtime = rec.get("mtime")
                    mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime else "—"
                    pub_content = ""
                    if rec.get("type") and rec.get("blob"):
                        pub_content = f"{rec['type']} {base64.b64encode(rec['blob']).decode()} {comment}".strip()
                    ssh_hosts = "、".join(rec.get("ssh_config_hosts", [])) or "（未設定）"
                    row = [comment, base, type_strength, fp, priv_status, ssh_hosts, mtime_str,
                           rec.get("advisories", "—"), rec.get("pub_path") or "",
                           rec.get("priv_path") or "", pub_content]
                    if include_raw:
                        raw = ""
                        priv_path = rec.get("priv_path")
                        if priv_path and os.path.exists(priv_path):
                            try:
                                with open(priv_path, "r", encoding="utf-8", errors="replace") as pf:
                                    raw = pf.read()
                            except OSError:
                                raw = "(讀取失敗)"
                        row.append(raw)
                    writer.writerow(row)
        except OSError as e:
            QMessageBox.warning(self, "匯出失敗", str(e))
            return
        audit_log("export_csv", f"{path}（含私鑰原始內容={include_raw}）")
        self.status.setText(f"✔ 已匯出：{path}")
        self.status.setStyleSheet("color:#1a7f37;")


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.showMaximized()  # 自動貼合目前螢幕可用區域，不用每次自己按最大化
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
