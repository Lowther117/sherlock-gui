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

echo [1/6] Finding or installing Python...
set "PY="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_python.ps1"`) do set "PY=%%P"
if not defined PY (
    echo Could not find or install Python. See build-win-log.txt.
    echo Could not find or install Python >> "%LOG%"
    goto :fail
)
echo       using %PY%
echo Python: %PY% >> "%LOG%"

echo [2/6] Creating build environment...
if exist "%VENV%\Scripts\python.exe" (
    "%VENV%\Scripts\python.exe" -c "import sys; sys.exit(0)" >nul 2>&1 || rmdir /s /q "%VENV%"
)
if not exist "%VENV%\Scripts\python.exe" (
    "%PY%" -m venv "%VENV%" >> "%LOG%" 2>&1 || goto :fail
)
set "VPY=%VENV%\Scripts\python.exe"
"%VPY%" -m pip install --upgrade pip --only-binary :all: >> "%LOG%" 2>&1

echo [3/6] Installing Sherlock...
rem stem (Tor support, pulled in by sherlock-project) is pure Python but ships no wheel - install it first without the wheel-only rule
"%VPY%" -m pip install "stem>=1.8" >> "%LOG%" 2>&1 || goto :fail
rem Sherlock itself, newest release every build (so the site list is current):
rem wheels first, then source packages allowed, then straight from its GitHub repo.
"%VPY%" -m pip install --upgrade --only-binary :all: sherlock-project >> "%LOG%" 2>&1 || (
    echo       wheel-only install failed - allowing source packages...
    "%VPY%" -m pip install --upgrade sherlock-project >> "%LOG%" 2>&1 || (
        echo       PyPI install failed - installing Sherlock from GitHub...
        "%VPY%" -m pip install --upgrade "https://github.com/sherlock-project/sherlock/archive/refs/heads/master.zip" >> "%LOG%" 2>&1
    )
)
rem Proof, not hope: the build stops here unless the engine really imports.
if exist "sherlock-check.txt" del /q "sherlock-check.txt"
"%VPY%" check_sherlock.py > "sherlock-check.txt" 2>&1
set "SHRC=%ERRORLEVEL%"
type "sherlock-check.txt"
type "sherlock-check.txt" >> "%LOG%"
del /q "sherlock-check.txt" >nul 2>&1
if not "%SHRC%"=="0" (
    echo.
    echo Sherlock could not be installed into the build environment, so no app was built.
    echo Sherlock could not be installed into the build environment >> "%LOG%"
    goto :fail
)

echo [4/6] Installing the other dependencies...
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

rem The optional extras pull in their own dependencies - make sure none of them broke Sherlock.
"%VPY%" check_sherlock.py >> "%LOG%" 2>&1 || (
    echo Installing the optional extras broke Sherlock - see build-win-log.txt
    goto :fail
)

echo [5/6] Building dist\%APP%\%APP%.exe (this takes a few minutes)...
if exist "dist\%APP%" rmdir /s /q "dist\%APP%"
"%VPY%" -m PyInstaller --noconfirm --clean --onedir --windowed --name "%APP%" ^
  --collect-all sherlock_project ^
  --copy-metadata sherlock-project ^
  --hidden-import sherlock_project.sherlock --hidden-import sherlock_project.sites --hidden-import sherlock_project.notify --hidden-import sherlock_project.result ^
  --hidden-import tomli ^
  --collect-all certifi ^
  --collect-all phonenumbers ^
  --collect-submodules dns ^
  --collect-submodules requests_futures ^
  --collect-submodules requests ^
  --hidden-import sherlock_gui --hidden-import engines --hidden-import tools --hidden-import site_info --hidden-import images --hidden-import theme ^
  --hidden-import colorama --hidden-import pandas --hidden-import openpyxl ^
  --hidden-import tkinter --hidden-import tkinter.ttk --hidden-import PIL._tkinter_finder ^
  !EXTRA! ^
  sherlock_gui_app.py >> "%LOG%" 2>&1 || goto :fail

echo [6/6] Self-test (fails if Sherlock is not inside the app)...
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
