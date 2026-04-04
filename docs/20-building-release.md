# Building a Release

## What This Covers

How to compile `EventHawk.exe`, create the release ZIP, and publish a GitHub Release.

---

## Prerequisites

```bat
pip install pyinstaller
```

Python 3.10+ and all dependencies from `requirements.txt` must be installed in the environment you build from.

---

## Step 1 — Build the EXE

The `EventHawk.spec` PyInstaller spec file is included in the repo. It compiles `launcher.py` into a single self-contained EXE.

```bat
pyinstaller EventHawk.spec
```

Output: `dist\EventHawk.exe` (~7–10 MB).

If you prefer to build without the spec file, use this equivalent command from the repo root:

```bat
pyinstaller --onefile --windowed --name EventHawk --icon evtx_tool\resources\images\eventhawk_logo.ico launcher.py
```

### What the spec does

- `--onefile` — single EXE, no companion DLLs
- `--windowed` — no console window opens on launch (GUI mode)
- `launcher.py` — the entry point: finds the system Python and runs `evtx_tool.py gui`

### Critical: EXE placement

After building, **copy `EventHawk.exe` to the same folder as `evtx_tool.py`** (the repo root). The launcher hardcodes this — it looks for `evtx_tool.py` in the same directory as the EXE. If they are in different folders, launching will fail with:

```
evtx_tool.py not found next to the launcher.
```

```bat
copy dist\EventHawk.exe .
```

> **Note:** The EXE is a launcher, not a fully bundled application. It locates the system Python at runtime. This keeps the EXE small and means users can update Python dependencies without rebuilding the EXE.

---

## Step 2 — Create the Release ZIP

```bat
REM Create staging folder
mkdir dist\release

REM Copy files
copy dist\EventHawk.exe         dist\release\
copy requirements.txt           dist\release\
copy install.bat                dist\release\
copy run.bat                    dist\release\
copy README.md                  dist\release\

REM Copy default profiles for user convenience
xcopy evtx_tool\profiles\defaults dist\release\profiles\defaults\ /E /I /Q

REM Create ZIP
powershell Compress-Archive -Path dist\release\* -DestinationPath EventHawk-v1.3-win64.zip -Force
```

### Release ZIP contents

```
EventHawk-v1.3-win64.zip
├── EventHawk.exe          ← Double-click launcher
├── requirements.txt       ← For install.bat / manual pip install
├── install.bat            ← Run once if dependencies are missing
├── run.bat                ← Alternative launch (py evtx_tool.py gui)
├── README.md
└── profiles\
    └── defaults\
        └── *.json         ← 20 built-in DFIR profiles
```

---

## Step 3 — Publish a GitHub Release

**Tag the release:**

```bat
git tag v1.3.0
git push origin v1.3.0
```

**Create the release via GitHub CLI:**

```bat
gh release create v1.3.0 ^
    EventHawk-v1.3-win64.zip ^
    --title "EventHawk v1.3" ^
    --notes "See README.md — What's New in v1.3"
```

Or create manually via the GitHub web UI:
1. Go to **Releases → Draft a new release**.
2. Set tag: `v1.3.0`.
3. Upload `EventHawk-v1.3-win64.zip`.
4. Add release notes.
5. Click **Publish release**.

---

## Version Numbering

Use [Semantic Versioning](https://semver.org/):

| Version | When to increment |
|---|---|
| `v1.3.0` → `v1.4.0` | New feature added |
| `v1.3.0` → `v1.3.1` | Bug fix only |
| `v1.3.0` → `v2.0.0` | Breaking change (incompatible profiles, changed CLI args) |

**Update version in:**
- `evtx_tool/__init__.py` — `__version__ = "1.3.0"`
- `sentinel/__init__.py` — `__version__ = "0.1.0"`
- `evtx_tool/tui.py` — `title: str = "EventHawk v1.3"`
- `evtx_tool/cli.py` — `@click.version_option("1.3.0", ...)`
- `evtx_tool/gui/main_window.py` — window title and about dialog
- `install.bat` — installer banner
- `README.md` — version badge

---

## What NOT to Include in the Release ZIP

| File / folder | Why excluded |
|---|---|
| `__pycache__/` | Compiled bytecode — not portable, regenerated automatically |
| `evtx_tool_logs/` | Runtime logs — user-specific |
| `.claude/` | Development tooling — not user-facing |
| `_test_ev_str.py` | Internal debug script |
| `*.evtx` | User data — never ship sample EVTX files |
| `*.parquet`, `parquet_manifest.json` | Runtime temp files |
| `*.pkl` | Sentinel baseline artifacts — user-generated |
| `baseline/` | User-generated baseline directories |
| `EventHawk.spec` | Build config — belongs in source repo, not release ZIP |
| `launcher.py` | Source for the EXE — included in repo but not needed in ZIP |
| `evtx_tool/resources/images/Remove background*.png` | Dev assets with messy filenames |

---

## Limitations

- The EXE is a launcher, not a fully self-contained bundle. Python 3.10+ and all pip dependencies must be installed on the target machine. This is by design — it keeps the EXE small and dependencies updatable.
- PyInstaller builds are Windows-specific. A Linux/macOS release would require building on those platforms.
- Antivirus software may flag the freshly compiled EXE as suspicious (false positive — common with PyInstaller). Submitting the EXE to VirusTotal before release and noting the clean result in the release notes is recommended.
- The `EventHawk.spec` targets `launcher.py`. If you rename or move `launcher.py`, update the spec `Analysis(scripts=[...])` entry accordingly.

---

## Related Docs

- [Installation](01-installation.md)
- [GUI Overview](02-gui-overview.md)
