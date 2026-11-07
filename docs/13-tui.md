# Terminal dashboard and interactive wizard

The normal CLI parse command uses a Rich live progress display. It reports work and resource state as the processing engine updates it, then prints a summary. It is not a terminal event-grid application with GUI-equivalent pivots, tabs, keyboard filters or export menus.

```powershell
py -3.12 evtx_tool.py parse .\logs -o .\events.json
py -3.12 evtx_tool.py parse .\logs --no-tui -o .\events.json
```

Use **--no-tui** for plain terminal progress, automation or redirected output. This changes the display path, not the requested filter/output format. The dashboard labels Ctrl+C as stop; an interrupted run is not a successfully completed export. Read cancellation/error messages and inspect any output before relying on it.

## Interactive

```powershell
py -3.12 evtx_tool.py interactive .\logs
```

Without paths, the wizard prompts for an EVTX path. It lists profiles and accepts profile numbers, all, or blank. It then asks about ATT&CK (default Yes), IOC extraction (No), correlation (No), output and worker count. An output extension determines format; an unrecognized extension prompts for one. Blank output selects console reporting.

The wizard launches one parse and exits. It does not accept REPL commands such as open, filter, export or quit. For reproducible filtering, saving configurations and timeline anchors, use the explicit [parse options](12-cli.md).
