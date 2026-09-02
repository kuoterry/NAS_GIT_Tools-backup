@echo off
chcp 65001 >nul
rem 找一支「真的能跑」的 Python 直譯器，不是只看檔案存不存在——
rem 抽自 D:\git\Tunnel\build.bat 的手法（該專案曾踩過「檔案在但 venv 壞掉」的坑），
rem 供本 repo 的 run_demo.bat / build_exe.bat 共用。
rem
rem 用法：呼叫端務必用明確路徑 call "%~dp0find_python.bat"，不要寫裸檔名
rem "call find_python.bat"——本機設了 NoDefaultCurrentDirectoryInExePath=1，
rem cmd.exe 不會隱式搜目前目錄，裸檔名會直接「不是內部或外部命令」，且不會有
rem 任何提示原因是這個環境變數（2026-09-02 實測踩過，找了好一陣子才定位到）。
rem 成功：PY_EXE 被設成可用的直譯器（"py" 或完整路徑），errorlevel 0
rem 失敗：印錯誤訊息，errorlevel 1，PY_EXE 不會被設
rem 可用 NASGT_PY 環境變數強制指定：set NASGT_PY=完整路徑\python.exe

if defined NASGT_PY (
    call :check_py "%NASGT_PY%" && (set "PY_EXE=%NASGT_PY%" & exit /b 0)
    echo [WARN] NASGT_PY 指定的直譯器跑不動: %NASGT_PY%
)

call :check_py "py" && (set "PY_EXE=py" & exit /b 0)
call :check_py "python" && (set "PY_EXE=python" & exit /b 0)

echo [ERROR] 找不到可用的 Python（py / python 都跑不動）
echo         用 set NASGT_PY=完整路徑\python.exe 指定一個
exit /b 1

:check_py
if "%~1"=="" exit /b 1
"%~1" -c "import sys" >nul 2>&1
exit /b %errorlevel%
