"""讀出 nas_git_connector.py 的 __version__，並可產生 PyInstaller 的版本資源檔。

用法：
    python get_version.py                       印出版本號（build_exe.bat 的 for /f 靠這個）
    python get_version.py --version-file <路徑>  寫出 PyInstaller --version-file 用的資源檔

為什麼版本號要用獨立腳本讀、不寫成 batch 裡的 python -c：
cmd.exe 沒有 \" 這種跳脫，for /f ('...') 是靠引號奇偶數判斷指令在哪結束，
內嵌雙引號會讓整行解析失敗、VERSION 沒被設定，而 PyInstaller 主建置照樣成功——
也就是靜默失敗。詳見 docs/INCIDENTS.md（2026-07-22）。

無參數時**只能**印出版本號本身，不要多印任何東西，否則會餵壞那個 for /f。
"""
import re
import sys

from pe_version_resource import render_version_file as _render_version_file

SOURCE = "nas_git_connector.py"
INTERNAL_NAME = "NasGitConnector"
DESCRIPTION = "NAS Git 專案串接工具"

# 樣板本體在 pe_version_resource.py，跟 pyqt-serial-toolkit 共用同一份（2026-09-02
# 抽出，vendor 一份副本進來而非用 submodule——這個 repo 一貫是單檔／少相依的風格，
# 見 secret_store.py 同樣的 vendor 慣例）。這裡只加一行自動產生標頭註解。


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
    header = f"# 由 get_version.py 自動產生，請勿手動編輯（改 {SOURCE} 的 __version__ 才是正解）。\n"
    return header + _render_version_file(
        company_name="TerryTools",
        file_description=DESCRIPTION,
        version=version,
        internal_name=INTERNAL_NAME,
        original_filename=f"{INTERNAL_NAME}.exe",
        product_name=DESCRIPTION,
    )


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
