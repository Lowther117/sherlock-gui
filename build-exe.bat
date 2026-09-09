@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
set "APP=Sherlock GUI"
set "LOG=%~dp0build-win-log.txt"
set "VENV=%~dp0.venv-build"

echo ==== %APP% Windows build  %DATE% %TIME% ==== > "%LOG%"
echo.
echo  %APP% - Windows build
echo  (full log: build-win-log.txt)
echo.

echo [1/5] Finding or installing Python...
set "PY="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_python.ps1"`) do set "PY=%%P"
if not defined PY (
    echo Could not find or install Python. See build-win-log.txt.
    echo Could not find or install Python >> "%LOG%"
    goto :fail
)
echo       using %PY%
echo Python: %PY% >> "%LOG%"

echo [2/5] Creating build environment...
if exist "%VENV%\Scripts\python.exe" (
    "%VENV%\Scripts\python.exe" -c "import sys; sys.exit(0)" >nul 2>&1 || rmdir /s /q "%VENV%"
)
if not exist "%VENV%\Scripts\python.exe" (
    "%PY%" -m venv "%VENV%" >> "%LOG%" 2>&1 || goto :fail
)
set "VPY=%VENV%\Scripts\python.exe"
"%VPY%" -m pip install --upgrade pip --only-binary :all: >> "%LOG%" 2>&1

echo [3/5] Installing dependencies...
rem stem (Tor support, pulled in by sherlock-project) is pure Python but ships no wheel - install it first without the wheel-only rule
"%VPY%" -m pip install "stem>=1.8" >> "%LOG%" 2>&1 || goto :fail
"%VPY%" -m pip install --only-binary :all: -r requirements.txt pyinstaller >> "%LOG%" 2>&1 || goto :fail
echo       optional extras (Maigret, holehe, whois) - wheels first, then allowing source packages...
"%VPY%" -m pip install --only-binary :all: -r requirements-optional.txt >> "%LOG%" 2>&1 || (
    "%VPY%" -m pip install -r requirements-optional.txt >> "%LOG%" 2>&1 || (
        echo       some optional extras could not be installed - trying them one by one
        for %%R in (maigret holehe httpx python-whois) do "%VPY%" -m pip install %%R >> "%LOG%" 2>&1
    )
)
set "EXTRA="
for %%M in (maigret socid_extractor cloudscraper holehe httpx trio whois PIL) do (
    "%VPY%" -c "import %%M" >nul 2>&1 && set "EXTRA=!EXTRA! --collect-all %%M"
)
echo       bundling extras:!EXTRA! >> "%LOG%"
echo       bundling extras:!EXTRA!

echo [4/5] Building dist\%APP%\%APP%.exe (this takes a few minutes)...
if exist "dist\%APP%" rmdir /s /q "dist\%APP%"
"%VPY%" -m PyInstaller --noconfirm --clean --onedir --windowed --name "%APP%" ^
  --collect-all sherlock_project ^
  --collect-all certifi ^
  --collect-all phonenumbers ^
  --collect-submodules dns ^
  --collect-submodules requests_futures ^
  --collect-submodules requests ^
  --hidden-import sherlock_gui --hidden-import engines --hidden-import tools --hidden-import site_info --hidden-import images ^
  --hidden-import colorama --hidden-import pandas --hidden-import openpyxl ^
  --hidden-import tkinter --hidden-import tkinter.ttk --hidden-import PIL._tkinter_finder ^
  !EXTRA! ^
  sherlock_gui_app.py >> "%LOG%" 2>&1 || goto :fail

echo [5/5] Self-test...
if exist "dist\%APP%\sherlock-gui-selftest.txt" del /q "dist\%APP%\sherlock-gui-selftest.txt"
start /wait "" "dist\%APP%\%APP%.exe" selftest
echo selftest exit code: %ERRORLEVEL% >> "%LOG%"
set "RC=1"
if exist "dist\%APP%\sherlock-gui-selftest.txt" (
    type "dist\%APP%\sherlock-gui-selftest.txt"
    type "dist\%APP%\sherlock-gui-selftest.txt" >> "%LOG%"
    findstr /C:"RESULT: OK" "dist\%APP%\sherlock-gui-selftest.txt" >nul && set "RC=0"
) else (
    echo (no selftest output written)
)
echo.
if not "%RC%"=="0" (
    echo PROBLEMS FOUND - see above and build-win-log.txt
    pause
    exit /b 1
)
echo Built: dist\%APP%\%APP%.exe   (keep the whole "dist\%APP%" folder together)
echo Build OK >> "%LOG%"
pause
exit /b 0

:fail
echo.
echo BUILD FAILED. Last lines of the log:
echo ----------------------------------------
powershell -NoProfile -Command "Get-Content -LiteralPath '%LOG%' -Tail 40"
echo ----------------------------------------
pause
exit /b 1
