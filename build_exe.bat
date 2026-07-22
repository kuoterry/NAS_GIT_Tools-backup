@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================
echo   Build NasGitConnector.exe
echo   (onefile / windowed / auto-install deps)
echo ============================================
echo.

rem === locate Python ===
rem 1) try the known full path on this machine
set "PY=C:\Users\kuote\AppData\Local\Programs\Python\Python313\python.exe"
if exist "%PY%" goto found

rem 2) fall back to py / python on PATH
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3"
if not defined PY (
  python --version >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo [X] Cannot find Python. Edit this .bat and set PY= to your python.exe full path.
  pause
  exit /b 1
)

:found
echo Using Python: %PY%
%PY% --version
echo.

echo [1/3] Installing / updating dependencies (PyQt6, pyinstaller)...
%PY% -m pip install --upgrade pip
%PY% -m pip install PyQt6 pyinstaller
if errorlevel 1 (
  echo [ERROR] pip install failed. Check network or pip.
  pause
  exit /b 1
)
echo.

echo [2/3] Packaging...
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name NasGitConnector nas_git_connector.py
if errorlevel 1 (
  echo [ERROR] Packaging failed. See messages above.
  pause
  exit /b 1
)
echo.

echo [3/4] Tagging a versioned copy...
set "VERSION="
for /f "delims=" %%v in ('%PY% "%~dp0get_version.py"') do set "VERSION=%%v"
if defined VERSION (
  copy /y "%~dp0dist\NasGitConnector.exe" "%~dp0dist\NasGitConnector_v%VERSION%.exe" >nul
  echo   Versioned copy: "%~dp0dist\NasGitConnector_v%VERSION%.exe"
) else (
  echo   [WARN] Could not read __version__ from nas_git_connector.py, skipped versioned copy.
)
echo.

echo [4/4] Done!
echo   EXE (stable name, use this for your desktop shortcut): "%~dp0dist\NasGitConnector.exe"
echo   Drag dist\NasGitConnector.exe to the desktop and double-click to use.
echo.
echo   Note: the PC still needs git and ssh (Windows built-in OpenSSH),
echo         and passwordless SSH login to the NAS. These are NOT bundled.
echo.
pause
