@echo off
:: Sentinel Network Assistant Launcher
:: This batch file launches the Sentinel GUI application

cd /d "J:\dev\Sentinel"

:: Try to find Python
if exist ".venv\Scripts\pythonw.exe" (
    .venv\Scripts\pythonw.exe -m sentinel.gui.app %*
) else if exist "C:\Python314\pythonw.exe" (
    C:\Python314\pythonw.exe -m sentinel.gui.app %*
) else (
    echo Could not find Python. Please ensure Python is installed.
    pause
)
