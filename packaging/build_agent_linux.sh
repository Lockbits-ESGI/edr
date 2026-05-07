#!/bin/bash
set -e

echo "Building MiniEDR Agent for Linux..."
pip install -q pyinstaller

pyinstaller packaging/pyinstaller_agent.spec --distpath dist/linux

chmod +x dist/linux/miniedr-agent

echo "✅ Agent binary: dist/linux/miniedr-agent"
echo "Usage: ./dist/linux/miniedr-agent --mode monitor"
