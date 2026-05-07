@echo off
REM Build MiniEDR Agent for Windows

echo Building MiniEDR Agent for Windows...
pip install -q pyinstaller

pyinstaller packaging\pyinstaller_agent.spec --distpath dist\windows

echo ✅ Agent binary: dist\windows\miniedr-agent.exe
echo Usage: dist\windows\miniedr-agent.exe --mode monitor
