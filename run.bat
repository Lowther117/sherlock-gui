@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "VENV=%~dp0.venv-win"

if exist "%VENV%\Scripts\pythonw.exe" (
    "%VENV%\Scripts\python.exe" -c "import sherlock_project, requests_futures, PIL" >nul 2>&1 && goto :run
)

echo First run - setting up (finds/installs Python, creates .venv-win, installs Sherlock)...
set "PY="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_python.ps1"`) do set "PY=%%P"
if not defined PY (
    echo Could not find or install Python.
    pause
    exit /b 1
)
if not exist "%VENV%\Scripts\python.exe" "%PY%" -m venv "%VENV%" || (pause & exit /b 1)
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip --only-binary :all: >nul 2>&1
"%VENV%\Scripts\python.exe" -m pip install "stem>=1.8" || (pause & exit /b 1)
"%VENV%\Scripts\python.exe" -m pip install --only-binary :all: -r requirements.txt || (pause & exit /b 1)
"%VENV%\Scripts\python.exe" -m pip install --only-binary :all: -r requirements-optional.txt || "%VENV%\Scripts\python.exe" -m pip install -r requirements-optional.txt

:run
start "" "%VENV%\Scripts\pythonw.exe" "%~dp0sherlock_gui.py"
exit /b 0
