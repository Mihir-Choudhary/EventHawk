# Release builds (GitHub Actions)

`.github/workflows/build-release.yml` builds, tests and publishes the Windows programs. It runs on GitHub's Windows machines; nothing is built on yours.

## What a release holds

| File | What it is |
|---|---|
| `EventHawk-<version>-Setup.exe` | Installer. Installs for the current user (no admin) or, after elevating, for all users. Adds Start Menu and Desktop shortcuts, so EventHawk can be found from Windows search, and an uninstaller. |
| `EventHawk-<version>-portable.zip` | No install. Extract anywhere and run `EventHawk.exe` (or `EventHawk.cmd`). |
| `SHA256SUMS.txt` | SHA-256 of both files. |

Both carry their own Python 3.12 and the exact packages the test suite runs on (`requirements-lock.txt`); nothing else needs to be installed. See [standalone build](21-building-standalone.md) for how they are made.

## When it runs

| Event | Result |
|---|---|
| Push to `beta` | Build, test suite, test of both packages. The files are kept as a workflow artifact (Actions tab). Never published. |
| Push to `main`, version not yet released | The same, then **publishes** release `v<version>` on the pushed commit. |
| Push to `main`, version already released | Build and test only. |
| Push of tag `v<version>` | Publishes that version (the tag must equal `__version__`). |
| Manual run (Actions > Run workflow) | Dry run: build and test, artifact only. |

The version is `__version__` in `evtx_tool/__init__.py`. To release: raise it (and `version_info.txt`, `EventHawk.iss`; `tests/test_version_doc_drift.py` checks they agree), merge to `main`, push.

## What every run checks

1. The test suite (`tests/run_suite.py`) on the locked packages. Tests that need the real test logs skip their corpus parts: those logs never leave the maintainer's PC. Any failure stops the run; nothing is published.
2. The launcher `EventHawk.exe` is built from `launcher.py` (PyInstaller, pinned version). It starts the bundled `pythonw.exe` next to it.
3. `build_standalone.ps1` builds the runtime, the portable ZIP and the installer.
4. The portable ZIP is extracted and `scripts/smoke_standalone.py` runs with its own Python on the runner's own Application log, exported with `wevtutil`. The CLI and a Juggernaut parse must each read exactly the record count Windows' `Get-WinEvent` reports, and the main window must open and close. `EventHawk.exe` must leave the app running.
5. The installer is run silently for the current user, the Start Menu shortcut is checked, the same smoke test runs on the installed copy, then it is uninstalled. The program must be gone and the user's `%LOCALAPPDATA%\EventHawk` (profiles, logs, Sentinel's baseline key) must still be there.
6. `SHA256SUMS.txt` is written; the files are uploaded.

## Limits

- The runner's Application log is small and holds no attack data; parsing breadth is covered by the test suite and by the maintainer's corpus runs, not here.
- The programs are not code-signed. Windows SmartScreen may warn on first run; the bundled `python.exe` / `pythonw.exe` are signed by the Python Software Foundation (checked at build time).
- pySigma is bundled for Sentinel's Sigma pre-tagging; no Sigma rules are bundled (the user supplies them).

See [installation](01-installation.md) and [tests](22-testing.md).
