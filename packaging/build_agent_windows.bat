@echo off
REM Build MiniEDR Agent for Windows

echo Building MiniEDR Agent for Windows...
if "%PYTHON%"=="" set PYTHON=python
if "%PYINSTALLER_CONFIG_DIR%"=="" set PYINSTALLER_CONFIG_DIR=.pyinstaller
%PYTHON% -m pip install -q pyinstaller

%PYTHON% -m PyInstaller packaging\pyinstaller_agent.spec --distpath dist\windows

echo ✅ Agent binary: dist\windows\miniedr-agent.exe
echo Usage: dist\windows\miniedr-agent.exe --mode monitor
