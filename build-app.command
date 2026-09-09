#!/bin/bash
# build-app.command - build dist/Sherlock GUI.app on macOS.  Double-click it.
# Installs whatever is missing itself (Homebrew, a bundle-able Python with Tk 8.6+).
# Full log: build-mac-log.txt beside this file.

cd "$(dirname "$0")" || exit 1
# Self-heal: keep both .command files double-clickable and un-quarantined so nobody
# ever needs chmod / xattr by hand (the executable bit is also committed in git).
chmod +x build-app.command run.command 2>/dev/null
xattr -d com.apple.quarantine build-app.command run.command 2>/dev/null
APP="Sherlock GUI"
LOG="$PWD/build-mac-log.txt"
VENV="$PWD/.venv-build-mac"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export HOMEBREW_NO_AUTO_UPDATE=1
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "==== $APP macOS build  $(date) ===="

ensure_brew() {
    if command -v brew >/dev/null 2>&1; then return 0; fi
    echo "Homebrew not found - installing it (you will be asked for your password once)..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/tty
    export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
    command -v brew >/dev/null 2>&1
}

brew_install() {
    ensure_brew || { echo "Homebrew unavailable - cannot install $*"; return 1; }
    echo "brew install $* ..."
    brew install "$@" < /dev/null
}

# Pick a Python that can be bundled: NOT Apple's /usr/bin/python3 (Tk 8.5 - the app
# builds but never opens), 3.9+ with tkinter.TkVersion >= 8.6.  Resolve with readlink,
# never by running "python3" (a fresh Mac pops the Xcode CLT installer for that).
pick_python() {
    local cands=()
    if [ -n "$SHERLOCK_GUI_BUILD_PYTHON" ]; then cands+=("$SHERLOCK_GUI_BUILD_PYTHON"); fi
    for v in 3.14 3.13 3.12 3.11 3.10 3.9; do
        cands+=("/opt/homebrew/opt/python@$v/bin/python$v" "/usr/local/opt/python@$v/bin/python$v"
                "/Library/Frameworks/Python.framework/Versions/$v/bin/python$v")
    done
    cands+=("/opt/homebrew/bin/python3" "/usr/local/bin/python3")
    for c in "${cands[@]}"; do
        [ -x "$c" ] || continue
        local real
        real="$(readlink -f "$c" 2>/dev/null || echo "$c")"
        case "$real" in /usr/bin/*|/System/*|/Library/Developer/CommandLineTools/*|/Applications/Xcode.app/*) continue;; esac
        local out
        out="$("$c" -c 'import sys, tkinter; print(sys.version_info[0], sys.version_info[1], tkinter.TkVersion)' 2>/dev/null)" || continue
        set -- $out
        if [ "$1" -eq 3 ] && [ "$2" -ge 9 ] && awk "BEGIN{exit !($3 >= 8.6)}"; then
            echo "$c"; return 0
        fi
    done
    return 1
}

echo "[1/6] Finding a bundle-able Python..."
PY="$(pick_python)"
if [ -z "$PY" ]; then
    echo "      none found - installing python + python-tk via Homebrew..."
    brew_install python python-tk
    PY="$(pick_python)"
fi
if [ -z "$PY" ]; then
    echo "PROBLEMS FOUND: no Python with Tk 8.6+ could be found or installed. See $LOG"
    read -r -p "Press Enter to close." < /dev/tty
    exit 1
fi
echo "      using $PY ($("$PY" -c 'import sys,tkinter;print(sys.version.split()[0],"Tk",tkinter.TkVersion)'))"

echo "[2/6] Creating build environment..."
if [ -x "$VENV/bin/python" ] && ! "$VENV/bin/python" -c 'import sys' >/dev/null 2>&1; then rm -rf "$VENV"; fi
[ -x "$VENV/bin/python" ] || "$PY" -m venv "$VENV" || exit 1
VPY="$VENV/bin/python"
"$VPY" -m pip install --upgrade pip --only-binary :all: >/dev/null 2>&1

echo "[3/6] Installing dependencies..."
# stem (Tor support, pulled in by sherlock-project) is pure Python but ships no wheel - install it first without the wheel-only rule
"$VPY" -m pip install "stem>=1.8" || { echo "PROBLEMS FOUND: could not install stem (see $LOG)"; read -r -p "Press Enter to close." < /dev/tty; exit 1; }
"$VPY" -m pip install --only-binary :all: -r requirements.txt pyinstaller || {
    echo "PROBLEMS FOUND: dependency install failed (see $LOG)"; read -r -p "Press Enter to close." < /dev/tty; exit 1; }
echo "      optional extras (Maigret, holehe, whois) - wheels first, then allowing source packages..."
"$VPY" -m pip install --only-binary :all: -r requirements-optional.txt || "$VPY" -m pip install -r requirements-optional.txt || {
    echo "      some optional extras could not be installed - trying them one by one"
    for r in maigret holehe httpx python-whois; do "$VPY" -m pip install "$r" || true; done
}
EXTRA=()
for m in maigret socid_extractor cloudscraper holehe httpx trio whois PIL; do
    "$VPY" -c "import $m" >/dev/null 2>&1 && EXTRA+=(--collect-all "$m")
done
echo "      bundling extras: ${EXTRA[*]}"

echo "[4/6] Building dist/$APP.app (a few minutes)..."
rm -rf "dist/$APP.app" "dist/$APP"
"$VPY" -m PyInstaller --noconfirm --clean --windowed --name "$APP" \
    --collect-all sherlock_project \
    --collect-all certifi \
    --collect-all phonenumbers \
    --collect-submodules dns \
    --collect-submodules requests_futures \
    --collect-submodules requests \
    --hidden-import sherlock_gui --hidden-import engines --hidden-import tools --hidden-import site_info --hidden-import images \
    --hidden-import colorama --hidden-import pandas --hidden-import openpyxl \
    --hidden-import tkinter --hidden-import tkinter.ttk --hidden-import PIL._tkinter_finder \
    --osx-bundle-identifier uk.lowther.sherlockgui \
    "${EXTRA[@]}" \
    sherlock_gui_app.py || {
    echo "PROBLEMS FOUND: PyInstaller failed (see $LOG)"; read -r -p "Press Enter to close." < /dev/tty; exit 1; }

echo "[5/6] Clearing quarantine + ad-hoc signing (needed on Apple silicon)..."
xattr -cr "dist/$APP.app" 2>/dev/null
codesign --force --deep --sign - "dist/$APP.app" 2>&1 | grep -v "replacing existing signature" || true

echo "[6/6] Self-test..."
rm -f "dist/sherlock-gui-selftest.txt"
"dist/$APP.app/Contents/MacOS/$APP" selftest
echo "selftest exit code: $?"
RC=1
if [ -f "dist/sherlock-gui-selftest.txt" ]; then
    cat "dist/sherlock-gui-selftest.txt"
    grep -q "RESULT: OK" "dist/sherlock-gui-selftest.txt" && RC=0
else
    echo "(no selftest output written)"
fi
echo
if [ "$RC" -ne 0 ]; then
    echo "PROBLEMS FOUND - see above and $LOG"
    read -r -p "Press Enter to close." < /dev/tty
    exit 1
fi
echo "Built: dist/$APP.app"
read -r -p "Done. Press Enter to close." < /dev/tty
