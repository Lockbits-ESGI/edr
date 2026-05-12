#!/bin/bash
set -e

echo "Building MiniEDR Agent for macOS..."
PYTHON_BIN="${PYTHON:-python3}"
export PYINSTALLER_CONFIG_DIR="${PYINSTALLER_CONFIG_DIR:-./.pyinstaller}"
mkdir -p "$PYINSTALLER_CONFIG_DIR"
"$PYTHON_BIN" -m pip install -q pyinstaller

"$PYTHON_BIN" -m PyInstaller packaging/pyinstaller_agent.spec --distpath dist/macos

chmod +x dist/macos/miniedr-agent

echo "✅ Agent binary: dist/macos/miniedr-agent"
echo "Usage: ./dist/macos/miniedr-agent --mode monitor"
