"""把 QSettings 裡存的密碼用 Windows DPAPI 加密，取代明碼存登錄檔。

改寫自 `Tunnel\\secret_store.py` 的 `protect()`/`unprotect()`（同一套 DPAPI 手法），
只留這裡用得到的部分——不需要 Tunnel 那邊的 SSH_ASKPASS helper／ssh wrapper 產生器。

**加密方式**：Windows DPAPI（`CryptProtectData`），密文綁「這個 Windows 使用者＋這台
機器」。換帳號或換機器都解不開，複製登錄檔匯出檔出去也沒用。額外帶一組本工具專屬的
entropy 字串，跟 Tunnel 的密文不能互解（那邊用的是 `NASGitTunnel/bbu_git/v1`）。

**格式**：`encode_secret()`/`decode_secret()` 操作的是要塞進 QSettings 的字串，格式為
`dpapi:v1:<base64>`。`decode_secret()` 讀到沒有這個前綴的舊資料（先前版本存的明碼）會
原樣傳回，讓呼叫端可以無感遷移——讀到舊格式就立刻用 `encode_secret()` 重新寫回，不需要
使用者重新輸入密碼。
"""

import base64
import ctypes
from ctypes import wintypes

# 本工具專屬的 entropy，跟其他工具（例如 Tunnel）的密文不能互解
ENTROPY = b"NasGitConnector/pw/v1"

_PREFIX = "dpapi:v1:"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: DATA_BLOB) -> bytes:
    out = ctypes.string_at(blob.pbData, blob.cbData)
    ctypes.windll.kernel32.LocalFree(blob.pbData)
    return out


def protect(plaintext: str) -> bytes:
    out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(_blob(plaintext.encode("utf-8"))),
        "NasGitConnector",
        ctypes.byref(_blob(ENTROPY)),
        None, None, 0,
        ctypes.byref(out),
    )
    if not ok:
        raise OSError("CryptProtectData 失敗：{}".format(ctypes.GetLastError()))
    return _blob_bytes(out)


def unprotect(ciphertext: bytes) -> str:
    out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(_blob(ciphertext)),
        None,
        ctypes.byref(_blob(ENTROPY)),
        None, None, 0,
        ctypes.byref(out),
    )
    if not ok:
        raise OSError(
            "CryptUnprotectData 失敗（{}）。密文只有「原本存它的那個 Windows 帳號＋"
            "那台機器」解得開。".format(ctypes.GetLastError())
        )
    return _blob_bytes(out).decode("utf-8")


def encode_secret(plaintext: str) -> str:
    """加密後轉成可以直接塞進 QSettings 的字串。空字串原樣傳回，不加密也不加前綴。"""
    if not plaintext:
        return ""
    return _PREFIX + base64.b64encode(protect(plaintext)).decode("ascii")


def decode_secret(stored: str) -> str:
    """解密 QSettings 讀出來的字串。

    讀到 `dpapi:v1:` 開頭視為新格式，解密回傳。
    讀到沒有這個前綴的非空字串，視為升級前存的舊明碼資料，原樣傳回——
    呼叫端應該在這個分支立刻呼叫 `encode_secret()` 重新寫回 QSettings，完成遷移。
    """
    if not stored:
        return ""
    if stored.startswith(_PREFIX):
        blob = base64.b64decode(stored[len(_PREFIX):])
        return unprotect(blob)
    return stored
