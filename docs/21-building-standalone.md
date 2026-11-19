# Building the standalone Windows package

`build_standalone.ps1` makes the installer and the portable ZIP that a [release](20-building-release.md) ships. The release workflow runs it on GitHub; you can also run it yourself.

## Run it

```powershell
powershell -ExecutionPolicy Bypass -File build_standalone.ps1 [-Launcher dist\EventHawk.exe] [-SkipInstaller]
```

| Parameter | Default | Meaning |
|---|---|---|
| `PyVersion` | 3.12.10 | Embeddable Python from python.org. The version the test suite runs on. |
| `WorkDir` | `%LOCALAPPDATA%\eh-build` | Build folder. **Deleted and re-made on every run**: use one that holds nothing else. |
| `OutDir` | `.\dist` | Where the ZIP and installer go. |
| `ISCC` | found automatically | Inno Setup 6 compiler (`winget install JRSoftware.InnoSetup`). |
| `Launcher` | none | `EventHawk.exe` built from `launcher.py` (`py -3.12 -m PyInstaller EventHawk.spec` gives `dist\EventHawk.exe`); copied into the package. |
| `SkipInstaller` | off | Build the runtime and ZIP only (no Inno Setup needed). |

It needs internet access (python.org, PyPI).

## What it does

1. Downloads the embeddable Python and stops unless `python.exe` is validly signed by the Python Software Foundation.
2. Unpacks one pinned pip wheel, checked by SHA-256, then installs `requirements-lock.txt` with `--require-hashes --only-binary=:all:`: the exact package versions the test suite runs on, each checked by hash. `requirements.txt` (minimum versions) is for running from source and is not used here.
3. Copies `evtx_tool`, `sentinel`, `evtx_tool.py`, `eventhawk_gui.py`, the licence, the icon, `EventHawk.cmd` and, with `-Launcher`, `EventHawk.exe`.
4. Trims files the app does not use (other Qt modules, pip, caches). The final `python312._pth` keeps the runtime isolated from any Python on the user's machine.
5. Writes `EventHawk-<version>-portable.zip` (one `EventHawk` folder).
6. Compiles `EventHawk.iss` into `EventHawk-<version>-Setup.exe`, version from `evtx_tool/__init__.py`.

## The installer

- Per-user install by default (no admin, `%LOCALAPPDATA%\Programs\EventHawk`), or all users (`Program Files`) after elevating.
- Start Menu and optional Desktop shortcuts run the bundled, PSF-signed `pythonw.exe` with `eventhawk_gui.py`.
- An upgrade replaces the program's code folders whole, so files an older version had do not linger.
- Uninstalling removes the program only. `%LOCALAPPDATA%\EventHawk` (your profiles, logs and Sentinel's baseline key) is kept.

## Test what you built

Run the smoke test with the package's own Python, on a log whose record count you took from Windows:

```powershell
$n = @(Get-WinEvent -Path C:\path\log.evtx -Oldest).Count
<package>\python.exe scripts\smoke_standalone.py <package> C:\path\log.evtx $n 2.0.0
```

It checks that everything loads from the package, the CLI and Sentinel start, a CLI parse and a Juggernaut parse each read exactly `$n` events, and the main window opens.

Some antivirus engines flag the Rust EVTX parser (`evtx\_native.pyd`) on a fresh install; that is a false positive on an open-source parser.

See [testing](22-testing.md) and [installation](01-installation.md).
