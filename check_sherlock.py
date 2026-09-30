"""Proof that the real Sherlock engine is installed in *this* Python.

The build scripts run this with the build environment's Python straight after
installing the dependencies, and refuse to build an app if it fails - so a
"successful" build can never again be one that quietly left Sherlock out and
fell back to the built-in checker.

    python check_sherlock.py        exit 0 and "SHERLOCK OK ..." when it is there
                                    exit 1 and "SHERLOCK MISSING ..." when not

Nothing here touches the network: the site list is read from the data.json
inside the installed package.
"""

import json
import os
import sys

MIN_SITES = 100     # the real list has ~400; fewer means a broken or stub install


def check():
    """Return (ok, [lines])."""
    lines = []

    try:
        import sherlock_project
    except BaseException as e:      # noqa: BLE001 - SystemExit included on purpose
        return False, ["the sherlock_project package is not installed in %s (%r)"
                       % (sys.executable, e)]
    pkg_dir = os.path.dirname(os.path.abspath(sherlock_project.__file__))
    lines.append("package: %s" % pkg_dir)

    # sherlock.py calls sys.exit(1) when its own package import fails, so catch
    # BaseException - an "except Exception" would let that end this script.
    try:
        from sherlock_project.sherlock import sherlock as engine
    except BaseException as e:      # noqa: BLE001
        return False, lines + ["(usually a missing dependency - pandas, requests-futures, "
                               "colorama, tomli - or missing package metadata)",
                               "the engine (sherlock_project.sherlock) does not import: %r" % e]

    try:
        import inspect
        params = list(inspect.signature(engine).parameters)
        missing = [p for p in ("username", "site_data", "query_notify") if p not in params]
        if missing:
            return False, lines + ["sherlock() no longer takes %s - the app needs updating "
                                   "for this Sherlock release (it has: %s)"
                                   % (", ".join(missing), ", ".join(params))]
    except (TypeError, ValueError):
        pass

    for mod in ("sherlock_project.sites", "sherlock_project.notify", "sherlock_project.result"):
        try:
            __import__(mod)
        except BaseException as e:  # noqa: BLE001
            return False, lines + ["%s does not import: %r" % (mod, e)]

    data = os.path.join(pkg_dir, "resources", "data.json")
    if not os.path.isfile(data):
        return False, lines + ["the site list is missing: %s" % data]
    try:
        with open(data, "r", encoding="utf-8") as f:
            raw = json.load(f)
        sites = sum(1 for k, v in raw.items() if isinstance(v, dict) and not k.startswith("$"))
    except Exception as e:          # noqa: BLE001
        return False, lines + ["the site list cannot be read (%s): %r" % (data, e)]
    if sites < MIN_SITES:
        return False, lines + ["the site list only has %d sites (%s)" % (sites, data)]

    version = ""
    try:
        from importlib.metadata import version as _v
        version = _v("sherlock-project")
    except Exception:               # noqa: BLE001
        # PyInstaller needs this metadata (--copy-metadata sherlock-project):
        # newer Sherlock releases read their own version from it on import.
        return False, lines + ["sherlock-project's package metadata is missing, so it "
                               "cannot be bundled - reinstall it with pip"]
    lines.append("version: %s" % version)
    lines.append("sites: %d" % sites)
    return True, lines


def main():
    ok, lines = check()
    if ok:
        info = dict(l.split(": ", 1) for l in lines)
        print("SHERLOCK OK - sherlock-project %s, %s sites, engine imports (%s)"
              % (info.get("version", "?"), info.get("sites", "?"), info.get("package", "?")))
        return 0
    # The last line is the reason; anything before it is context.
    print("SHERLOCK MISSING - " + lines[-1])
    for l in lines[:-1]:
        print("  " + l)
    print("  python: %s" % sys.executable)
    return 1


if __name__ == "__main__":
    sys.exit(main())
