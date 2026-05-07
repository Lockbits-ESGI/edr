#!/bin/bash
set -e

echo "Building MiniEDR Agent for macOS..."
pip install -q pyinstaller

pyinstaller packaging/pyinstaller_agent.spec --distpath dist/macos

chmod +x dist/macos/miniedr-agent

echo "✅ Agent binary: dist/macos/miniedr-agent"
echo "Usage: ./dist/macos/miniedr-agent --mode monitor"
