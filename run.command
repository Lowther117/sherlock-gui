#!/bin/bash
# run.command - run Sherlock GUI from source on macOS.  Double-click it.
# First run creates .venv-mac and installs Sherlock into it (installs Homebrew
# python + python-tk first if the Mac has no usable Python).

cd "$(dirname "$0")" || exit 1
chmod +x build-app.command run.command 2>/dev/null
xattr -d com.apple.quarantine build-app.command run.command 2>/dev/null
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export HOMEBREW_NO_AUTO_UPDATE=1
VENV="$PWD/.venv-mac"

pick_python() {
    local cands=()
    for v in 3.14 3.13 3.12 3.11 3.10 3.9; do
        cands+=("/opt/homebrew/opt/python@$v/bin/python$v" "/usr/local/opt/python@$v/bin/python$v"
                "/Library/Frameworks/Python.framework/Versions/$v/bin/python$v")
    done
    cands+=("/opt/homebrew/bin/python3" "/usr/local/bin/python3")
    for c in "${cands[@]}"; do
        [ -x "$c" ] || continue
        local out
        out="$("$c" -c 'import sys, tkinter; print(sys.version_info[0], sys.version_info[1], tkinter.TkVersion)' 2>/dev/null)" || continue
        set -- $out
        if [ "$1" -eq 3 ] && [ "$2" -ge 9 ] && awk "BEGIN{exit !($3 >= 8.6)}"; then echo "$c"; return 0; fi
    done
    return 1
}

if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import sherlock_project, requests_futures, tkinter, PIL' >/dev/null 2>&1; then
    exec "$VENV/bin/python" "$PWD/sherlock_gui.py"
fi

echo "First run - setting up..."
PY="$(pick_python)"
if [ -z "$PY" ]; then
    if ! command -v brew >/dev/null 2>&1; then
        echo "Installing Homebrew (password asked once)..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/tty
        export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
    fi
    brew install python python-tk < /dev/null
    PY="$(pick_python)"
fi
[ -n "$PY" ] || { echo "No Python with Tk 8.6+ available."; read -r -p "Press Enter." < /dev/tty; exit 1; }
rm -rf "$VENV"
"$PY" -m venv "$VENV" || exit 1
"$VENV/bin/python" -m pip install --upgrade pip --only-binary :all: >/dev/null 2>&1
"$VENV/bin/python" -m pip install "stem>=1.8" >/dev/null 2>&1
"$VENV/bin/python" -m pip install --only-binary :all: -r requirements.txt || { read -r -p "Install failed. Press Enter." < /dev/tty; exit 1; }
"$VENV/bin/python" -m pip install --only-binary :all: -r requirements-optional.txt || "$VENV/bin/python" -m pip install -r requirements-optional.txt || true
exec "$VENV/bin/python" "$PWD/sherlock_gui.py"
