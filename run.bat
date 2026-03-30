@echo off
:: EventHawk - Quick launcher
:: Usage: run.bat [evtx_tool.py arguments]
::
:: Examples:
::   run.bat interactive
::   run.bat parse Logs\ --profile "Logon/Logoff Activity" --output report.html
::   run.bat parse Logs\ --event-id 4624,4625 --output logons.csv
::   run.bat profiles list
::   run.bat benchmark Logs\
::   run.bat --help

py -3 "%~dp0evtx_tool.py" %*
