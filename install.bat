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

:: Install dependencies
echo.
echo [*] Installing dependencies...
py -3 -m pip install --upgrade pip >nul 2>&1
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
