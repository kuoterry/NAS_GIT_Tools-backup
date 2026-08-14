"""讀出 key_management.py 的 __version__，並可產生 PyInstaller 的版本資源檔。

用法：
    python get_version.py                       印出版本號（build_exe.bat 的 for /f 靠這個）
    python get_version.py --version-file <路徑>  寫出 PyInstaller --version-file 用的資源檔

為什麼版本號要用獨立腳本讀、不寫成 batch 裡的 python -c：
cmd.exe 沒有 \" 這種跳脫，for /f ('...') 是靠引號奇偶數判斷指令在哪結束，
內嵌雙引號會讓整行解析失敗、VERSION 沒被設定，而 PyInstaller 主建置照樣成功——
也就是靜默失敗。詳見 ../docs/INCIDENTS.md（2026-07-22）。

無參數時**只能**印出版本號本身，不要多印任何東西，否則會餵壞那個 for /f。
"""
import re
import sys

SOURCE = "key_management.py"
INTERNAL_NAME = "KeyManagement"
DESCRIPTION = "金鑰管理工具"

# PyInstaller 的 --version-file 是一段會被 eval 的 Python 字面值。
# filevers/prodvers 必須是四個整數的 tuple，Windows 的「檔案版本」欄位吃的是這個；
# 字串區的 FileVersion/ProductVersion 才是使用者在檔案內容裡看到的文字。
VERSION_FILE_TEMPLATE = """\
# 由 get_version.py 自動產生，請勿手動編輯（改 {source} 的 __version__ 才是正解）。
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={vers}, prodvers={vers},
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040404b0', [
        StringStruct('CompanyName', 'TerryTools'),
        StringStruct('FileDescription', '{desc}'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', '{internal}'),
        StringStruct('OriginalFilename', '{internal}.exe'),
        StringStruct('ProductName', '{desc}'),
        StringStruct('ProductVersion', '{version}'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1028, 1200])])
  ]
)
"""


def read_version(path=SOURCE):
    with open(path, encoding="utf-8") as f:
        match = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
    return match.group(1) if match else ""


def version_tuple(version):
    """"2.12.3" -> (2, 12, 3, 0)。非數字段落一律當 0，長度不足補到 4 個。"""
    parts = []
    for chunk in version.split(".")[:4]:
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts + [0] * (4 - len(parts)))


def render_version_file(version):
    return VERSION_FILE_TEMPLATE.format(
        source=SOURCE, vers=version_tuple(version), version=version,
        desc=DESCRIPTION, internal=INTERNAL_NAME)


def main(argv):
    version = read_version()
    if not version:
        return 1
    if "--version-file" in argv:
        out = argv[argv.index("--version-file") + 1]
        with open(out, "w", encoding="utf-8") as f:
            f.write(render_version_file(version))
        return 0
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
