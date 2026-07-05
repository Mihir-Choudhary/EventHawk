# Installation

## What It Is

EventHawk can be installed in two ways: as a **pre-built Windows executable** (no Python required by the user) or **from source** using Python. Both result in an identical application.

---

## Option A — Standalone (recommended for most users)

### When to use
You just want to run EventHawk. **No Python, no setup, nothing to configure.**

### Steps

1. Go to the [Releases page](../../releases) on GitHub.
2. Download **one** of these:

   | File | What it does |
   |---|---|
   | `EventHawk-1.3.0-Setup.exe` | **Installer.** Creates a Desktop / Start-Menu shortcut. Run it as a normal user (installs to your account, no admin needed) or as admin (installs for all users). |
   | `EventHawk-portable.exe` | **Portable.** Double-click — it unpacks and runs. Nothing is installed. |
   | `EventHawk-portable.7z` | Same as portable but smaller; extract with 7-Zip, then run `EventHawk.cmd`. |

3. Launch it — the GUI opens maximized.

Everything (Python 3.14, PySide6/Qt, DuckDB, PyArrow, the Rust EVTX parser and
all 20 DFIR profiles) is bundled inside — about 57 MB. To analyze a `.evtx`
file, open it from within the app.

> **Uninstall:** installer → Settings → Apps → *EventHawk* → Uninstall.
> Portable → just delete the folder; it leaves nothing behind.

---

## Option B — From Source (Developers / advanced users)

### When to use
You want to modify the code, contribute, or run on a system where compiling to EXE is not desired.

### Requirements

| Requirement | Minimum version |
|---|---|
| Python | 3.10 |
| pip | 22.0+ |
| Git | Any |
| RAM | 4 GB (8 GB+ for large datasets) |
| OS | Windows 10/11 64-bit |

### Steps

**1. Clone the repository**

```bat
git clone https://github.com/Mihir-Choudhary/EventHawk.git
cd EventHawk
```

**2. Install dependencies**

```bat
install.bat
```

Or manually:

```bat
py -3 -m pip install -r requirements.txt
```

**3. Launch the GUI**

```bat
py -3 evtx_tool.py gui
```

**4. Or run the CLI**

```bat
py -3 evtx_tool.py --help
```

---

## GPU Acceleration (Linux / WSL2 only)

EventHawk runs CPU-only on Windows. On Linux or WSL2 with an NVIDIA GPU, you can enable RAPIDS cuDF for GPU-accelerated dataframe operations:

```bash
# CUDA 12.x
pip install cudf-cu12 --extra-index-url=https://pypi.nvidia.com

# CUDA 11.x
pip install cudf-cu11 --extra-index-url=https://pypi.nvidia.com
```

cuDF is detected automatically at startup. If absent, the tool silently falls back to CPU mode.

---

## Limitations

- Windows only for the compiled EXE. Source mode works on any OS where PySide6 and pyevtx-rs are available.
- The `evtx` package (`pyevtx-rs`) uses a compiled Rust extension. On rare systems with unusual Python builds, the wheel may fail — in that case install Rust and build from source: `pip install evtx --no-binary evtx`.
- GPU acceleration is not available on Windows regardless of hardware.

---

## Related Docs

- [GUI Overview](02-gui-overview.md)
- [Normal Mode](03-normal-mode.md)
- [CLI Mode](12-cli.md)
- [Building a Release](20-building-release.md)
- [Building the Standalone](21-building-standalone.md)
