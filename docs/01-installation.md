# Installation

## What It Is

EventHawk can be installed in two ways: as a **pre-built Windows executable** (no Python required by the user) or **from source** using Python. Both result in an identical application.

---

## Option A — Pre-built EXE (Recommended for most users)

### When to use
You want to get started quickly and do not want to manage Python environments.

### Steps

1. Go to the [Releases page](../../releases) on GitHub.
2. Download `EventHawk-v1.1-win64.zip`.
3. Extract the zip to any folder (e.g. `C:\Tools\EventHawk\`).
4. Double-click **`EventHawk.exe`** to launch the GUI.

> **Note:** Python 3.10+ must still be installed on the machine. The launcher (`EventHawk.exe`) locates your system Python automatically — it does not need to be in PATH. If Python is not found, you will see a prompt to install it.

### What the zip contains

```
EventHawk-v1.1-win64.zip
├── EventHawk.exe          ← Double-click to launch
├── requirements.txt       ← For reference / reinstalling deps
├── install.bat            ← Run if EXE says dependencies are missing
├── run.bat                ← Alternative launch script
└── README.md
```

### If dependencies are missing

If the EXE starts but immediately closes or shows a missing-module error, run `install.bat` once:

```bat
install.bat
```

This installs all required Python packages from `requirements.txt`.

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
git clone https://github.com/YOUR_USERNAME/EventHawk.git
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
