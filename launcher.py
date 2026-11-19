"""
EventHawk Launcher
------------------
Tiny entry-point compiled to EventHawk.exe via PyInstaller.

    pyinstaller --onefile --windowed --name EventHawk --icon resources/images/eventhawk_logo.ico launcher.py

The compiled exe:
  - lives in the same directory as evtx_tool.py
  - finds the system Python via the Windows registry
  - launches:  pythonw.exe evtx_tool.py gui [optional .evtx path]
  - no console window, no bundled heavy dependencies
"""

from __future__ import annotations
import os
import sys
import subprocess
import ctypes


def _find_pythonw() -> str | None:
    """Search the Windows registry for the newest installed pythonw.exe."""
    import winreg

    import re as _re

    def _vkey(v: str):
        # By version NUMBER: as text "3.9" sorted above "3.12" (Gemini 11-09).
        return [int(x) for x in _re.findall(r"\d+", v)] or [0]

    # Every registered Python of both hives, then the newest: the per-user
    # hive was searched first and won outright, so an old per-user 3.9 beat a
    # machine-wide 3.12 (Gemini audit 13-03).  Free-threaded builds ("3.13t")
    # are skipped, as install.bat refuses them.
    found: list = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for subpath in (r"SOFTWARE\Python\PythonCore",
                        r"SOFTWARE\Wow6432Node\Python\PythonCore"):
            try:
                with winreg.OpenKey(hive, subpath) as core:
                    idx = 0
                    while True:
                        try:
                            ver = winreg.EnumKey(core, idx)
                        except OSError:
                            break
                        idx += 1
                        if _re.search(r"\dt(-32)?$", ver.lower()):   # e.g. "3.13t"
                            continue
                        try:
                            with winreg.OpenKey(core, rf"{ver}\InstallPath") as inst:
                                install_dir = winreg.QueryValue(inst, "").strip()
                        except OSError:
                            continue
                        pythonw = os.path.join(install_dir, "pythonw.exe")
                        if os.path.isfile(pythonw):
                            found.append((_vkey(ver), pythonw))
            except OSError:
                continue
    if not found:
        return None
    return max(found, key=lambda f: f[0])[1]


def _error(msg: str) -> None:
    ctypes.windll.user32.MessageBoxW(0, msg, "EventHawk", 0x10)  # MB_ICONERROR


def main() -> None:
    # Locate evtx_tool.py next to this exe
    base = os.path.dirname(os.path.abspath(
        sys.executable if getattr(sys, "frozen", False) else __file__
    ))
    script = os.path.join(base, "evtx_tool.py")

    if not os.path.isfile(script):
        _error(f"evtx_tool.py not found next to the launcher.\nExpected: {script}")
        return

    # The standalone build (build_standalone.ps1) carries its own Python and
    # every package next to this exe: use it, never a system Python that may
    # lack the packages (the newest one found could have no PySide6).
    bundled = os.path.join(base, "pythonw.exe")
    pythonw = bundled if os.path.isfile(bundled) else _find_pythonw()
    if not pythonw:
        _error(
            "Python 3 not found on this system.\n"
            "Please install Python 3.10 or newer from python.org."
        )
        return

    # argv[1] is the .evtx file path passed by Windows "Open with"
    args = [pythonw, script, "gui"] + sys.argv[1:]

    # Strip PyInstaller bootstrap vars so the spawned Python gets a clean env
    env = os.environ.copy()
    for _k in [k for k in env if k.startswith("_MEI")]:
        env.pop(_k, None)

    try:
        subprocess.Popen(
            args,
            cwd=base,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    except Exception as exc:
        _error(f"Failed to launch EventHawk:\n\n{exc}\n\nCommand:\n{' '.join(args)}")


if __name__ == "__main__":
    main()
