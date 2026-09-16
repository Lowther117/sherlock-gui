"""Frozen entry point for Sherlock GUI (PyInstaller builds).

Sub-modes:
  (none)      open the app
  selftest    print + write sherlock-gui-selftest.txt beside the app, exit 0/1

Anything that goes wrong at start-up lands in sherlock-gui-crash.log beside
the app and in a dialog - never silence.
"""

import multiprocessing
import os
import sys
import traceback


def _strip_finder_args(argv):
    # Finder launches apps with "-psn_0_12345"; keep argparse-style code happy.
    return [a for a in argv if not a.startswith("-psn_")]


def _crash(text):
    try:
        import sherlock_gui
        p = os.path.join(sherlock_gui.HERE, "sherlock-gui-crash.log")
    except Exception:
        p = os.path.join(os.path.dirname(os.path.realpath(sys.executable)), "sherlock-gui-crash.log")
    try:
        with open(p, "a", encoding="utf-8") as f:
            f.write(text + "\n\n")
    except Exception:
        pass
    try:
        import tkinter
        from tkinter import messagebox
        r = tkinter.Tk()
        r.withdraw()
        messagebox.showerror("Sherlock GUI failed to start",
                             text[-2000:] + "\n\nDetails: " + p)
        r.destroy()
    except Exception:
        pass


def main():
    multiprocessing.freeze_support()
    sys.argv = _strip_finder_args(sys.argv)
    try:
        import sherlock_gui
        if len(sys.argv) > 1 and sys.argv[1] == "selftest":
            ok, text = sherlock_gui.selftest()
            try:
                print(text)
            except Exception:
                pass
            try:
                with open(os.path.join(sherlock_gui.HERE, "sherlock-gui-selftest.txt"), "w",
                          encoding="utf-8") as f:
                    f.write(text + "\n")
            except Exception:
                pass
            sys.exit(0 if ok else 1)
        sherlock_gui.main()
    except SystemExit:
        raise
    except Exception:
        _crash(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
