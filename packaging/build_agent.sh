#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<EOF
Usage: $0 --target <linux|darwin|windows> --arch <amd64|arm64> [options]

Build LockBits EDR Agent binary for the specified target.

Required:
  --target   Target OS: linux, darwin, windows
  --arch     Target arch: amd64, arm64

Options:
  --python   Python interpreter to use (default: python3)
  --dist     Output directory (default: dist/)
  --name     Binary name (default: lockbits-agent)
  --clean    Clean build artifacts before building
  --help     Show this help

Examples:
  $0 --target linux --arch amd64
  $0 --target linux --arch arm64
  $0 --target darwin --arch amd64
EOF
    exit 1
}

PYTHON_BIN="${PYTHON:-python3}"
DIST_DIR="dist"
BINARY_NAME="lockbits-agent"
CLEAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --python) PYTHON_BIN="$2"; shift 2 ;;
        --dist) DIST_DIR="$2"; shift 2 ;;
        --name) BINARY_NAME="$2"; shift 2 ;;
        --clean) CLEAN=true; shift ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [ -z "${TARGET:-}" ] || [ -z "${ARCH:-}" ]; then
    echo "Error: --target and --arch are required"
    usage
fi

VALID_TARGETS=("linux" "darwin" "windows")
VALID_ARCHS=("amd64" "arm64")
if [[ ! " ${VALID_TARGETS[*]} " =~ " ${TARGET} " ]]; then
    echo "Error: Invalid target '$TARGET'. Valid: ${VALID_TARGETS[*]}"
    exit 1
fi
if [[ ! " ${VALID_ARCHS[*]} " =~ " ${ARCH} " ]]; then
    echo "Error: Invalid arch '$ARCH'. Valid: ${VALID_ARCHS[*]}"
    exit 1
fi

OUTPUT_DIR="${DIST_DIR}/lockbits-agent-${TARGET}-${ARCH}"
echo "==> Building LockBits EDR Agent for ${TARGET}/${ARCH}"
echo "    Output: ${OUTPUT_DIR}/"
echo "    Binary: ${BINARY_NAME}"

cd "$PROJECT_ROOT"

if [ "$CLEAN" = true ]; then
    echo "==> Cleaning previous build artifacts..."
    rm -rf build/ dist/ __pycache__/ .pyinstaller
fi

export PYINSTALLER_CONFIG_DIR="${PYINSTALLER_CONFIG_DIR:-./.pyinstaller}"
mkdir -p "$PYINSTALLER_CONFIG_DIR"

echo "==> Ensuring PyInstaller is installed..."
"$PYTHON_BIN" -m pip install -q pyinstaller 2>/dev/null || {
    pip install pyinstaller
}

echo "==> Running PyInstaller..."
"$PYTHON_BIN" -m PyInstaller \
    packaging/pyinstaller_agent.spec \
    --distpath "$OUTPUT_DIR" \
    --workpath build/.pyinstaller

if [ "$TARGET" != "windows" ]; then
    chmod +x "$OUTPUT_DIR/$BINARY_NAME"
fi

echo ""
echo "============================================"
echo " Build complete!"
echo " Binary: $OUTPUT_DIR/$BINARY_NAME"
echo " Target: ${TARGET}/${ARCH}"
echo " Size:   $(du -h "$OUTPUT_DIR/$BINARY_NAME" 2>/dev/null | cut -f1)"
echo "============================================"
echo ""
echo "Quick test:"
echo "  $ $OUTPUT_DIR/$BINARY_NAME --mode scan"
echo ""
