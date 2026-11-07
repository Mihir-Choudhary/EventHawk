# Installation

## Source checkout

Use a Python environment with the dependencies in `requirements.txt`. Python 3.12 is the environment used for these source instructions; this guide does not establish compatibility with every Python or operating-system version. Run from the repository root in PowerShell:

```powershell
git clone --branch beta https://github.com/Mihir-Choudhary/EventHawk.git
cd EventHawk
py -3.12 -m pip install -r requirements.txt
py -3.12 evtx_tool.py --help
py -3.12 evtx_tool.py gui
```

For an existing checkout, omit clone/cd. To queue inputs at startup:

```powershell
py -3.12 evtx_tool.py gui .\logs
```

Inputs are `.evtx` files or folders containing them. This is not a reader for legacy `.evt` files. `evtx` is the Rust-backed parser dependency; `python-evtx` is a different package. PySide6 supplies the GUI; Arrow and DuckDB supply Juggernaut. Sentinel's optional Sigma dependency is described in [its guide](18-sentinel-sigma.md).

## Windows packages

There are two build paths in this repository. Check the package you actually received rather than assuming every file called `EventHawk.exe` contains the application and Python.

| Build path | Runtime requirement |
|---|---|
| `EventHawk.spec` / `launcher.py` | Thin launcher. Requires system Python, installed application dependencies, and `evtx_tool.py` with the application packages beside the launcher. |
| `build_standalone.ps1` / `EventHawk.iss` | Stages an embeddable Python runtime and the application; generates portable/installer outputs according to installed build tools. |

See [thin launcher](20-building-release.md) and [standalone build](21-building-standalone.md). These guides describe source build behavior, not a guarantee that a particular release asset is available or tested on your machine.

## Troubleshooting

Run from a terminal to see startup errors. Use **Help > Open Log Folder** for GUI logs; the normal Windows location is `%LOCALAPPDATA%\EventHawk\logs`, with fallback locations when unavailable. CLI logging uses `evtx_tool_logs` in its working directory.

If parsing or an optional analysis fails, retain the reported error and identify which operation failed. An empty result can mean no matches; it is not by itself proof that all inputs were read successfully. No fixed RAM requirement or input-size ceiling is established here.

Next: [GUI overview](02-gui-overview.md) or [CLI](12-cli.md).
