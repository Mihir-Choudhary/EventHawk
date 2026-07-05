# Building the Standalone (no-Python-required) Build

## What this covers

How to build the **fully self-contained** EventHawk distribution — the one end
users can run with **no Python and no pip installed**. This is different from the
launcher build in [20-building-release.md](20-building-release.md), which needs a
system Python.

It produces three artifacts in `dist\`:

| Artifact | Size | For |
|---|---|---|
| `EventHawk-1.3.0-Setup.exe` | ~57 MB | **Installer.** Admin → Program Files (all users); non-admin → LocalAppData (current user). Creates Desktop + Start-Menu shortcuts. |
| `EventHawk-portable.exe` | ~56 MB | **Portable self-extractor.** Double-click → unpacks and runs `EventHawk.cmd`. No 7-Zip needed. |
| `EventHawk-portable.7z` | ~56 MB | **Portable, smallest.** Extract with 7-Zip / WinRAR, then run `EventHawk.cmd`. |

---

## The scripts (what to touch for future fixes)

| File | Role |
|---|---|
| [`build_standalone.ps1`](../build_standalone.ps1) | The whole build. Run it; it does everything below. |
| [`EventHawk.iss`](../EventHawk.iss) | Inno Setup installer definition (shortcuts, install modes, publisher). |
| [`eventhawk_gui.py`](../eventhawk_gui.py) | The entry point the bundle launches. |
| `requirements.txt` | The dependency list installed into the bundle. |

**Where things live:** the app code is `evtx_tool\`; the icon is
`evtx_tool\resources\images\eventhawk_logo.ico`; the app version is
`evtx_tool\__init__.py`. Update those, re-run `build_standalone.ps1`, and you
get fresh artifacts.

---

## Prerequisites

```powershell
winget install JRSoftware.InnoSetup   # the ISCC.exe installer compiler
winget install 7zip.7zip              # for the portable archives (optional)
```

Internet access (the build downloads a fresh signed Python) and ~1.5 GB free
disk for the temporary build.

---

## Build it

```powershell
powershell -ExecutionPolicy Bypass -File build_standalone.ps1
```

That's the whole thing. To point at an already-installed Inno compiler:

```powershell
.\build_standalone.ps1 -ISCC "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

---

## How the build works (the "clean-room" design)

`build_standalone.ps1` deliberately trusts **nothing** on the build machine:

1. **Fresh, verified Python.** Downloads the official Windows *embeddable* Python
   from python.org and **aborts unless `python.exe` is Authenticode-signed by the
   Python Software Foundation**.
2. **Isolated dependencies.** Bootstraps `pip`, then `pip install -r
   requirements.txt` straight from PyPI into that runtime, with
   `PYTHONNOUSERSITE=1` so your machine's global `AppData\Roaming\Python`
   packages are never read. The deployed app's `._pth` is likewise isolated.
3. **Trim (no features cut).** A full install is ~250 MB, mostly PySide6's Qt
   WebEngine/QML/translations that EventHawk never imports. The script keeps only
   Qt Core/Gui/Widgets/Svg and drops dead weight — PyArrow + DuckDB Juggernaut
   mode stay fully intact. It keeps every package's `.dist-info` (DuckDB reads its
   own version via `importlib.metadata` at runtime).
4. **Package.** Inno Setup (LZMA2 ultra64) → the installer; 7-Zip → the portable
   `.zip` and `.7z`.

### Why not PyInstaller

This build ships the **code-signed** `pythonw.exe` and installs via Inno Setup
to a normal install location — a standard signed Python runtime rather than a
one-file bootloader stub, so it stays self-contained and easy to update.

---

## Gotchas

- **MAX_PATH.** Build from a short path. The script uses
  `%LOCALAPPDATA%\eh-build`; building under a very long path (deep `lxml`
  schematron files) overflows Windows' 260-char limit and the Inno compile
  aborts.
- **Logs.** The app writes logs to `%LOCALAPPDATA%\EventHawk\logs`, never next to
  itself — a Program Files install is read-only for non-admin users, so logging
  beside the app would crash startup. See `evtx_tool\gui\app.py`.
- **Version bumps.** The installer version is defined in `EventHawk.iss`
  (`MyAppVersion`); keep it in step with `evtx_tool\__init__.py`.

---

## Related docs

- [Installation](01-installation.md)
- [Building a Release (launcher build)](20-building-release.md)
