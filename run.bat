@echo off
setlocal
:: EventHawk launcher (Windows).
::
:: Two bugs this replaces:
::   1. it ran evtx_tool.py (the CLI) while run.sh runs the GUI, so the same
::      double-click behaved differently on Windows and Linux;
::   2. with dependencies missing it died on a raw ImportError traceback
::      instead of saying what to do.
::
:: It deliberately uses the SYSTEM Python ("py -3"), matching install.bat and
:: the README. run.sh uses a .venv only because Debian/Ubuntu ship a PySide6
:: namespace stub that collides with pip's copy -- a Linux-only problem. Adding
:: a venv here would make install.bat and run.bat install everything twice.
::
::   run.bat                  launch the GUI
::   run.bat --cli parse ...  run the CLI (evtx_tool.py) with those arguments
::
:: The CLI keeps the caller's folder (relative paths are the caller's), gets
:: its arguments exactly as typed, needs no GUI packages and never waits on
:: "pause" (Gemini audit 11-15: shift/rebuild split "4624,4625" and "a=b"
:: into separate words, and the cd and the GUI check came first).
if /i "%~1"=="--cli" goto cli

cd /d "%~dp0"

py -3 --version >nul 2>&1
if errorlevel 1 goto no_python

:: Fail with an instruction, not a traceback, when dependencies are missing.
py -3 -c "import PySide6.QtWidgets, evtx, duckdb, pyarrow" >nul 2>&1
if errorlevel 1 goto no_deps

py -3 eventhawk_gui.py %*
exit /b %errorlevel%

:cli
py -3 --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python 3 was not found on PATH. Install Python 3.10+ and run install.bat. 1>&2
    exit /b 1
)
:: Everything after the first --cli, unchanged (%* keeps , ; = and quotes).
set "ARGS=%*"
set "ARGS=%ARGS:*--cli=%"
py -3 "%~dp0evtx_tool.py" %ARGS%
exit /b %errorlevel%

:no_python
echo.
echo ERROR: Python 3 was not found on PATH.
echo        Install Python 3.10+ (64-bit) from https://python.org, then run
echo        install.bat.
echo.
pause
exit /b 1

:no_deps
echo.
echo ERROR: EventHawk's dependencies are not installed for this Python.
echo        Run install.bat first - it installs everything in requirements.txt.
echo.
pause
exit /b 1
