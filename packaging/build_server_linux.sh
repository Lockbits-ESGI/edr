#!/bin/bash
set -e

echo "Building MiniEDR Server for Linux..."
PYTHON_BIN="${PYTHON:-python3}"
export PYINSTALLER_CONFIG_DIR="${PYINSTALLER_CONFIG_DIR:-./.pyinstaller}"
mkdir -p "$PYINSTALLER_CONFIG_DIR"
"$PYTHON_BIN" -m pip install -q pyinstaller

"$PYTHON_BIN" -m PyInstaller packaging/pyinstaller_server.spec --distpath dist/linux

chmod +x dist/linux/miniedr-server

echo "✅ Server binary: dist/linux/miniedr-server"
echo "Usage: ./dist/linux/miniedr-server (or with uvicorn)"
