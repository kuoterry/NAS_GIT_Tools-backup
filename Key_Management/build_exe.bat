@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================
echo   Build KeyManagement.exe
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
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name KeyManagement key_management.py
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
  copy /y "%~dp0dist\KeyManagement.exe" "%~dp0dist\KeyManagement_v%VERSION%.exe" >nul
  echo   Versioned copy: "%~dp0dist\KeyManagement_v%VERSION%.exe"
) else (
  echo   [WARN] Could not read __version__ from key_management.py, skipped versioned copy.
)
echo.

echo [4/4] Done!
echo   EXE (stable name, use this for your desktop shortcut): "%~dp0dist\KeyManagement.exe"
echo   Drag dist\KeyManagement.exe to the desktop and double-click to use.
echo.
echo   Note: "Generate new key pair" and deriving a public key from an
echo         unencrypted orphaned private key both shell out to ssh-keygen
echo         (Windows built-in OpenSSH client) - it must be on PATH. This
echo         tool is otherwise fully local; it never touches the network.
echo.
pause
