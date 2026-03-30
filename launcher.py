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

    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for subpath in (r"SOFTWARE\Python\PythonCore",
                        r"SOFTWARE\Wow6432Node\Python\PythonCore"):
            try:
                with winreg.OpenKey(hive, subpath) as core:
                    versions: list[str] = []
                    idx = 0
                    while True:
                        try:
                            versions.append(winreg.EnumKey(core, idx))
                            idx += 1
                        except OSError:
                            break
                    for ver in sorted(versions, reverse=True):
                        try:
                            with winreg.OpenKey(core, rf"{ver}\InstallPath") as inst:
                                install_dir = winreg.QueryValue(inst, "").strip()
                                pythonw = os.path.join(install_dir, "pythonw.exe")
                                if os.path.isfile(pythonw):
                                    return pythonw
                        except OSError:
                            continue
            except OSError:
                continue
    return None


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

    pythonw = _find_pythonw()
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
