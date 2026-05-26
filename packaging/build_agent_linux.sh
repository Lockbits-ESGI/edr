#!/bin/bash
# build_agent_linux.sh — Build LockBits EDR Agent for Linux (legacy wrapper)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$SCRIPT_DIR/build_agent.sh" --target linux --arch "${ARCH:-amd64}"
