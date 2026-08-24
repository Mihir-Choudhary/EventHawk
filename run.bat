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
cd /d "%~dp0"

py -3 --version >nul 2>&1
if errorlevel 1 goto no_python

:: Fail with an instruction, not a traceback, when dependencies are missing.
py -3 -c "import PySide6.QtWidgets, evtx, duckdb, pyarrow" >nul 2>&1
if errorlevel 1 goto no_deps

if /i "%~1"=="--cli" goto cli

py -3 eventhawk_gui.py %*
exit /b %errorlevel%

:: Rebuild the argument list without --cli.  This must stay OUTSIDE a
:: parenthesised block: inside one, %ARGS% is expanded when the whole block is
:: parsed, so every pass would append to the value it had on entry.
:cli
shift
set "ARGS="
:collect
if "%~1"=="" goto run_cli
set ARGS=%ARGS% "%~1"
shift
goto collect
:run_cli
py -3 evtx_tool.py %ARGS%
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
