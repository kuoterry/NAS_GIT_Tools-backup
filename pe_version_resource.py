"""共用的 PyInstaller Windows 版本資源檔（VSVersionInfo）產生器。

抽自 make_money 七個子專案與 NAS_GIT_Tools 各自維護的同一份樣板（欄位、結構
幾乎逐字相同，只有 CompanyName/FileDescription/InternalName/OriginalFilename/
ProductName 這幾個字串值不同）。抽取時**用逐案輸出比對過**，確認每個既有呼叫端
換成呼叫這支函式後，產生的資源檔內容與換之前一個位元組不差——見各專案自己的
`get_version.py`/`make_version_file.py` 改動時附的比對記錄。

用法：呼叫端的 get_version.py／make_version_file.py 匯入 render_version_file()，
自己決定要填哪些欄位值（各專案的欄位語意不完全一致，例如 CompanyName 有些填公司
名、有些直接填專案名——這支函式不替呼叫端做決定，原樣照填）。
"""
from __future__ import annotations


def version_tuple(version: str) -> tuple[int, int, int, int]:
    """把 "2.12.3" 這種點分版號字串轉成四段整數 tuple，不足四段補 0，多的截斷。

    非數字段落視為 0（沿用 NAS_GIT_Tools 原本的寬容行為，例如 "1.0-beta" 的
    "0-beta" 段會被當成 0，不會拋例外中止建置）。
    """
    import re

    parts = []
    for chunk in version.split(".")[:4]:
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group()) if digits else 0)
    parts += [0] * (4 - len(parts))
    return tuple(parts)  # type: ignore[return-value]


_TEMPLATE = """\
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={ver_tuple},
    prodvers={ver_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable('040404b0', [
        StringStruct('CompanyName', '{company_name}'),
        StringStruct('FileDescription', '{file_description}'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', '{internal_name}'),
        StringStruct('OriginalFilename', '{original_filename}'),
        StringStruct('ProductName', '{product_name}'),
        StringStruct('ProductVersion', '{version}'),
      ]),
    ]),
    VarFileInfo([VarStruct('Translation', [0x0404, 1200])]),
  ],
)
"""


def render_version_file(
    *,
    company_name: str,
    file_description: str,
    version: str,
    internal_name: str,
    original_filename: str,
    product_name: str,
) -> str:
    """回傳可以直接寫進 PyInstaller --version-file 的資源檔內容（字串）。

    所有欄位都要求明確傳入，不猜測誰該等於誰——各呼叫端過去的用法本來就不一致
    （有的 CompanyName 填實際公司名、有的直接填專案名；OriginalFilename 有的帶
    版號、有的固定不帶），這支函式只負責套樣板，語意由呼叫端決定。
    """
    return _TEMPLATE.format(
        ver_tuple=version_tuple(version),
        company_name=company_name,
        file_description=file_description,
        version=version,
        internal_name=internal_name,
        original_filename=original_filename,
        product_name=product_name,
    )
