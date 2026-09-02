@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================
echo   Build NasGitConnector.exe
echo   (onefile / windowed / auto-install deps)
echo ============================================
echo.

rem === locate Python (shared helper: actually runs each candidate, not just
rem     checks it exists -- see find_python.bat header for why "if exist" isn't
rem     enough) ===
set "NASGT_PY=C:\Users\kuote\AppData\Local\Programs\Python\Python313\python.exe"
call "%~dp0find_python.bat"
if errorlevel 1 (
  pause
  exit /b 1
)
set "PY=%PY_EXE%"

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
rem Generate the Windows version resource from __version__ so that
rem right-click - Properties - Details shows the real version. Without this the
rem version only exists in the filename, which nothing verifies against the exe.
%PY% "%~dp0get_version.py" --version-file "%~dp0version_info.txt"
if not exist "%~dp0version_info.txt" (
  echo [ERROR] Could not generate version_info.txt - check __version__ in nas_git_connector.py.
  pause
  exit /b 1
)
rem --add-data: bundle the server-side scheduled scripts so the frozen exe can
rem deploy them to NAS tools/ and hash-compare them in the health check.
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name NasGitConnector ^
  --version-file "%~dp0version_info.txt" ^
  --add-data "sync_github_mirrors.sh;." ^
  --add-data "ci_daily_violation_report.sh;." ^
  --add-data "git_stats_report.sh;." ^
  --add-data "send_email.py;." ^
  --add-data "offsite_backup_sync.sh;." ^
  --add-data "nas_git_healthcheck.sh;." ^
  nas_git_connector.py
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
