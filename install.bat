@echo off
setlocal enabledelayedexpansion

echo.
echo  ====================================================
echo   EventHawk v1.2 - Installer
echo  ====================================================
echo.

:: Check Python
py -3 --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 not found. Install from https://python.org
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('py -3 --version 2^>^&1') do set PY_VER=%%i
echo [OK] Found: %PY_VER%

:: Reject free-threaded Python (3.14t, 3.13t, etc.) — not supported by evtx wheel
echo %PY_VER% | findstr /i "t.exe t " >nul 2>&1
if not errorlevel 1 (
    echo.
    echo [ERROR] Free-threaded Python ^(e.g. 3.14t^) is not supported.
    echo         Please install a standard Python 3.10-3.12 release from python.org
    pause
    exit /b 1
)

:: Install dependencies
echo.
echo [*] Upgrading pip...
py -3 -m pip install --upgrade pip
echo.
echo [*] Installing dependencies (this may take a few minutes)...
echo     Note: evtx package requires a pre-built wheel (Python 3.10+, 64-bit Windows).
echo     If install fails on evtx, ensure you are using Python 3.10+ 64-bit.
echo.
py -3 -m pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install one or more dependencies.
    echo         Check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo [OK] All dependencies installed.

:: Create required directories
if not exist profiles mkdir profiles
if not exist evtx_tool_logs mkdir evtx_tool_logs

:: Verify install
echo.
echo [*] Verifying installation...
py -3 evtx_tool.py --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Verification failed. Run: py -3 evtx_tool.py --help
) else (
    echo [OK] EventHawk installed successfully.
)

echo.
echo  ====================================================
echo   Quick Start:
echo.
echo   py -3 evtx_tool.py interactive
echo   py -3 evtx_tool.py parse Logs\ --profile "Logon/Logoff Activity"
echo   py -3 evtx_tool.py parse Logs\ --event-id 4624,4625 -o results.html
echo   py -3 evtx_tool.py profiles list
echo   py -3 evtx_tool.py --help
echo  ====================================================
echo.
pause
