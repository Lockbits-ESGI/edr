#!/bin/bash
set -e

echo "Building MiniEDR Server for Linux..."
pip install -q pyinstaller

pyinstaller packaging/pyinstaller_server.spec --distpath dist/linux

chmod +x dist/linux/miniedr-server

echo "✅ Server binary: dist/linux/miniedr-server"
echo "Usage: ./dist/linux/miniedr-server (or with uvicorn)"
