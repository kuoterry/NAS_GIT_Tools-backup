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
import shutil
import socket
import subprocess
import time
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QComboBox, QCheckBox,
    QFileDialog, QMessageBox, QGroupBox, QInputDialog, QListWidget, QListWidgetItem,
    QDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem, QAbstractItemView,
)

__version__ = "1.3.0"

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


def audit_log(action: str, detail: str):
    """所有管理動作（產生/封存/刪除/備份/還原/檢視私鑰原始內容）都留一筆本機紀錄。"""
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{action}\t{detail}\n")
    except OSError:
        pass


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
    first_line = content.splitlines()[0] if content.splitlines() else ""
    return parse_pubkey_line(first_line)


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
    for i, ln in enumerate(lines):
        if ln.startswith("PuTTY-User-Key-File-"):
            key_type = ln.split(":", 1)[1].strip()
        elif ln.startswith("Comment:"):
            comment = ln.split(":", 1)[1].strip()
        elif ln.startswith("Public-Lines:"):
            count = int(ln.split(":", 1)[1].strip())
            pub_b64_lines = lines[i + 1:i + 1 + count]
            break
    if not key_type or not pub_b64_lines:
        return None
    try:
        blob = base64.b64decode("".join(pub_b64_lines))
    except Exception:
        return None
    return {"type": key_type, "blob": blob, "comment": comment}


def derive_pubkey_via_sshkeygen(path: str):
    """只對「已確認未加密」的私鑰呼叫，純本機執行，不會把檔案內容傳到任何地方。"""
    try:
        cp = subprocess.run(
            ["ssh-keygen", "-y", "-f", path],
            capture_output=True, text=True, timeout=5, input="",
            creationflags=_NO_WINDOW,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return cp.stdout.strip()
    except Exception:
        pass
    return None


def scan_folder(folder: str):
    """遞迴掃描資料夾，依副檔名/內容判斷分成公鑰／私鑰／ppk 三類路徑清單。"""
    pub_files, priv_files, ppk_files = [], [], []
    for root, _dirs, files in os.walk(folder):
        for name in files:
            if name in SKIP_FILENAMES:
                continue
            path = os.path.join(root, name)
            if name.endswith(".pub"):
                pub_files.append(path)
            elif name.endswith(".ppk"):
                ppk_files.append(path)
            else:
                if classify_private_key_file(path):
                    priv_files.append(path)
    return pub_files, priv_files, ppk_files


def build_advisories(rec: dict, fingerprints_seen: dict, seen_hosts_by_fp: dict = None, this_host: str = "") -> str:
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
        notes.append("ℹ 私鑰未加密")
    if rec.get("pub_path") and not rec.get("priv_path"):
        notes.append("ℹ 找不到對應私鑰（可能已刪除或不在掃描範圍）")
    if rec.get("priv_path") and not rec.get("pub_path") and not rec.get("blob"):
        if rec.get("priv_encrypted"):
            notes.append("ℹ 私鑰已加密且找不到公鑰，需密碼才能取得指紋")
        else:
            notes.append("⚠ 找不到公鑰且無法自動推導")
    if rec.get("derived"):
        notes.append("✔ 已自動從私鑰推導出公鑰")
    mtime = rec.get("mtime")
    if mtime:
        age_days = (time.time() - mtime) / 86400
        if age_days > 730:
            notes.append(f"ℹ 已 {int(age_days)} 天未變更，可考慮輪替")
    fp = rec.get("fingerprint")
    if fp and len(fingerprints_seen.get(fp, [])) > 1:
        notes.append("⚠ 與其他檔案指紋相同，可能是重複複製的金鑰")
    if fp and seen_hosts_by_fp:
        others = sorted(h for h in seen_hosts_by_fp.get(fp, {}) if h and h != this_host)
        if others:
            notes.append(f"⚠ 這把金鑰也在其他電腦（{'、'.join(others)}）登記過，確認是否為刻意複製")
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


def build_records(folders):
    """掃描所有資料夾，配對公私鑰、補齊指紋/強度/時間/建議，回傳紀錄清單。"""
    all_pub, all_priv, all_ppk = [], [], []
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        p, pr, pk = scan_folder(folder)
        all_pub += p
        all_priv += pr
        all_ppk += pk

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
            priv_info = classify_private_key_file(priv_path)
            rec["priv_format"] = priv_info["format"] if priv_info else "?"
            rec["priv_encrypted"] = priv_info["encrypted"] if priv_info else None
            if not pub_path and priv_info and priv_info["encrypted"] is False:
                derived = derive_pubkey_via_sshkeygen(priv_path)
                if derived:
                    parsed = parse_pubkey_line(derived)
                    if parsed:
                        rec.update(type=parsed["type"], blob=parsed["blob"],
                                   comment=parsed["comment"], derived=True)
        records.append(rec)

    for ppk_path in all_ppk:
        parsed = parse_ppk_pubkey(ppk_path)
        cls = classify_private_key_file(ppk_path)
        rec = {
            "pub_path": None, "priv_path": ppk_path,
            "priv_format": "ppk", "priv_encrypted": cls["encrypted"] if cls else None,
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
        rec["advisories"] = build_advisories(rec, fingerprints_seen, seen_hosts_by_fp, this_host)

    return records


# ============================================================
# 本機金鑰名冊（持久化歷史紀錄，即使金鑰被刪除也保留曾經存在過的記錄）
# ============================================================

def load_registry():
    try:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_registry(reg: dict):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=2)


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
        entry.setdefault("history", []).append({"ts": now, "action": "scanned"})
        reg[key] = entry
    for key, entry in reg.items():
        if key not in seen_keys and entry.get("status") == "active":
            entry["status"] = "missing"
            entry.setdefault("history", []).append({"ts": now, "action": "missing_from_scan"})
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
        result[name] = {
            "user": s.value(f"profiles/{name}/user", ""),
            "host": s.value(f"profiles/{name}/host", ""),
            "remote_root": s.value(f"profiles/{name}/remote_root", ""),
            "identity_file": s.value(f"profiles/{name}/identity_file", ""),
        }
    return result


def _sync_ssh(sync_cfg: dict, remote_cmd: str):
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
                             errors="replace", timeout=30,
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


def merge_registries(local: dict, remote: dict, hostname: str):
    """合併本機與雲端的金鑰名冊。key 選法跟 update_registry_from_scan 一致（指紋或路徑
    後備）。每筆依 last_seen 較新的欄位為準；history 串接去重；seen_hosts（這把鑰匙在
    哪些電腦出現過）一律聯集、只加不減，本機這次同步時把自己也蓋進去。"""
    merged = {}
    for key in set(local) | set(remote):
        l, r = local.get(key), remote.get(key)
        if l and not r:
            entry = dict(l)
        elif r and not l:
            entry = dict(r)
        else:
            entry = dict(r if (r.get("last_seen") or "") > (l.get("last_seen") or "") else l)
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
            entry["history"] = history
        seen_hosts = dict((l or {}).get("seen_hosts") or {})
        seen_hosts.update((r or {}).get("seen_hosts") or {})
        if l:
            seen_hosts[hostname] = l.get("last_seen", "")
        entry["seen_hosts"] = seen_hosts
        merged[key] = entry
    return merged


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
            else:
                self.done.emit(False, f"未知模式：{self.mode}")
        except Exception as e:
            self.done.emit(False, f"發生未預期錯誤：{e}")

    def _run_scan(self):
        folders = self.params.get("folders", [])
        self.log.emit(f"掃描 {len(folders)} 個資料夾中…")
        records = build_records(folders)
        update_registry_from_scan(records)
        self.result.emit(records)
        self.done.emit(True, f"掃描完成，共找到 {len(records)} 組金鑰。")

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
        if hard:
            for p in targets:
                os.remove(p)
            audit_log("delete_hard", "; ".join(targets))
            self.done.emit(True, "已永久刪除：\n" + "\n".join(targets))
        else:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            dest_dir = os.path.join(ARCHIVE_DIR, ts)
            os.makedirs(dest_dir, exist_ok=True)
            moved = []
            for p in targets:
                dest = os.path.join(dest_dir, os.path.basename(p))
                shutil.move(p, dest)
                moved.append(dest)
            audit_log("archive", f"{'; '.join(targets)} -> {dest_dir}")
            self.done.emit(True, f"已封存到：\n{dest_dir}")

    def _run_backup(self):
        pub_path = self.params.get("pub_path")
        priv_path = self.params.get("priv_path")
        dest_dir = self.params.get("dest_dir")
        if not dest_dir:
            self.done.emit(False, "缺少備份目標資料夾。")
            return
        copied = []
        for p in (pub_path, priv_path):
            if p and os.path.exists(p):
                dest = os.path.join(dest_dir, os.path.basename(p))
                shutil.copy2(p, dest)
                copied.append(dest)
        if not copied:
            self.done.emit(False, "找不到要備份的檔案。")
            return
        audit_log("backup", "; ".join(copied))
        self.done.emit(True, "已備份：\n" + "\n".join(copied))

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
        restored = []
        for fn in os.listdir(src_dir):
            src = os.path.join(src_dir, fn)
            dest = os.path.join(target_dir, fn)
            if os.path.exists(dest):
                self.done.emit(False, f"目標已存在同名檔案，未還原：{dest}")
                return
            shutil.move(src, dest)
            restored.append(dest)
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
        hostname = socket.gethostname() or "UNKNOWN"
        self.log.emit("--- 跨機器同步金鑰名冊 ---")

        pull_cmd = "\n".join([
            "echo ___BEGIN___",
            f"f='{remote_root}/config/km_registry_sync.json'",
            "if [ -f \"$f\" ]; then cat \"$f\"; else echo '{}'; fi",
            "echo ___END___",
            "true",
        ])
        rc, out, err = _sync_ssh(sync_cfg, pull_cmd)
        if rc != 0:
            self.done.emit(False, f"讀取雲端金鑰名冊失敗：{(err or out).strip()}")
            return
        try:
            remote_reg = json.loads(_between(out) or "{}")
        except json.JSONDecodeError:
            remote_reg = {}

        local_reg = load_registry()
        merged = merge_registries(local_reg, remote_reg, hostname)
        save_registry(merged)

        payload = json.dumps(merged, ensure_ascii=False)
        b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        push_cmd = "\n".join([
            f"d='{remote_root}/config'; f=\"$d/km_registry_sync.json\"",
            "mkdir -p \"$d\"",
            "[ -f \"$f\" ] && cp \"$f\" \"$f.bak-$(date +%Y%m%d-%H%M%S)\"",
            f"printf '%s' '{b64}' | base64 -d > \"$f\"",
            "chmod 600 \"$f\"",
            "echo ___OK___",
        ])
        rc2, out2, err2 = _sync_ssh(sync_cfg, push_cmd)
        if rc2 != 0 or "___OK___" not in out2:
            self.done.emit(False, f"推送雲端金鑰名冊失敗：{(err2 or out2).strip()}")
            return
        audit_log("sync_registry", f"host={hostname} merged_keys={len(merged)}")
        self.result.emit(merged)
        self.done.emit(True, f"已同步金鑰名冊，共 {len(merged)} 筆（涵蓋所有已同步過的電腦）。")


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

    def _busy(self, b):
        for x in (self.refresh_b, self.restore_b, self.purge_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
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
        self.worker = Worker("purge_archive", {"name": name})
        self.worker.done.connect(self._on_action_done)
        self.worker.start()

    def _on_action_done(self, ok, msg):
        self.on_done(ok, msg)
        if ok:
            self.refresh()


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

    def _busy(self, b):
        for x in (self.refresh_b, self.delete_b):
            x.setEnabled(not b)

    def refresh(self):
        self.list.clear()
        self._busy(True)
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

    def refresh_from_local(self):
        self._populate(load_registry())

    def _populate(self, reg: dict):
        this_host = socket.gethostname() or ""
        rows = [(key, entry) for key, entry in reg.items() if entry.get("fingerprint")]
        rows.sort(key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
        self.table.setRowCount(len(rows))
        for i, (_key, entry) in enumerate(rows):
            seen_hosts = entry.get("seen_hosts") or {}
            hosts_text = "、".join(sorted(seen_hosts)) if seen_hosts else "（尚未同步過）"
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
        self.setWindowTitle(f"金鑰管理工具 v{__version__}")
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
        self.folder_list.addItem(os.path.join(os.path.expanduser("~"), ".ssh"))
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
        self.copy_pub_b = QPushButton("複製公鑰")
        self.copy_pub_b.setEnabled(False)
        self.copy_pub_b.clicked.connect(self.on_copy_pub)
        self.open_folder_b = QPushButton("開啟所在資料夾")
        self.open_folder_b.setEnabled(False)
        self.open_folder_b.clicked.connect(self.on_open_folder)
        for b in (self.gen_b, self.archive_del_b, self.hard_del_b, self.backup_b,
                  self.view_raw_b, self.copy_pub_b, self.open_folder_b):
            arow.addWidget(b)
        arow.addStretch(1)
        lay.addLayout(arow)

        brow = QHBoxLayout()
        self.archive_mgmt_b = QPushButton("金鑰封存區…")
        self.archive_mgmt_b.clicked.connect(self.on_archive_mgmt)
        self.audit_b = QPushButton("稽核紀錄…")
        self.audit_b.clicked.connect(self.on_audit_log)
        self.known_hosts_b = QPushButton("known_hosts 管理…")
        self.known_hosts_b.clicked.connect(self.on_known_hosts)
        self.sync_config_b = QPushButton("⚙ 雲端同步設定…")
        self.sync_config_b.clicked.connect(self.on_sync_config)
        self.sync_overview_b = QPushButton("🌐 跨電腦金鑰總覽…")
        self.sync_overview_b.clicked.connect(self.on_sync_overview)
        self.export_b = QPushButton("匯出 CSV 報表…")
        self.export_b.clicked.connect(self.on_export_csv)
        brow.addWidget(self.archive_mgmt_b)
        brow.addWidget(self.audit_b)
        brow.addWidget(self.known_hosts_b)
        brow.addWidget(self.sync_config_b)
        brow.addWidget(self.sync_overview_b)
        brow.addStretch(1)
        brow.addWidget(self.export_b)
        lay.addLayout(brow)

        self.status = QLabel(f"金鑰名冊/稽核紀錄/封存區都在 {APP_DIR}")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

    def _busy(self, b):
        for x in (self.scan_b, self.gen_b, self.archive_mgmt_b, self.audit_b, self.export_b,
                  self.archive_del_b, self.hard_del_b, self.backup_b, self.view_raw_b):
            x.setEnabled(not b)
        if not b:
            self.on_selection_changed()

    # ---------- 掃描資料夾管理 ----------
    def on_add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "選擇要掃描的資料夾")
        if d:
            self.folder_list.addItem(d)

    def on_remove_folder(self):
        for it in self.folder_list.selectedItems():
            self.folder_list.takeItem(self.folder_list.row(it))

    # ---------- 掃描 ----------
    def on_scan(self):
        folders = [self.folder_list.item(i).text() for i in range(self.folder_list.count())]
        if not folders:
            self.status.setText("請先加入至少一個資料夾。")
            return
        self._busy(True)
        self.status.setText("掃描中…")
        self.status.setStyleSheet("")
        self.worker = Worker("scan", {"folders": folders})
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
        self.worker = Worker("generate", vals)
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
        self.worker = Worker("delete", {
            "pub_path": rec.get("pub_path"), "priv_path": rec.get("priv_path"), "hard": False})
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
        self.worker = Worker("delete", {
            "pub_path": rec.get("pub_path"), "priv_path": rec.get("priv_path"), "hard": True})
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
        self._busy(True)
        self.status.setText("備份中…")
        self.worker = Worker("backup", {
            "pub_path": rec.get("pub_path"), "priv_path": rec.get("priv_path"), "dest_dir": d})
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
        self.worker = Worker("read_private_raw", {"path": rec["priv_path"]})
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

    def on_open_folder(self):
        rec = self._selected_record()
        if not rec:
            return
        path = rec.get("priv_path") or rec.get("pub_path")
        if path and os.path.exists(path):
            subprocess.run(["explorer", "/select,", os.path.normpath(path)])

    # ---------- 封存區 / 稽核紀錄 ----------
    def on_archive_mgmt(self):
        dlg = ArchiveManageDialog(self)
        dlg.exec()

    def on_audit_log(self):
        dlg = AuditLogDialog(self)
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
