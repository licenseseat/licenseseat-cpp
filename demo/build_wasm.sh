#!/bin/bash
#
# Build SynthDemo for WebAssembly
#
# Prerequisites:
#   - Emscripten SDK installed (3.1.51+)
#   - Via Homebrew: brew install emscripten binaryen
#   - Via emsdk: source /path/to/emsdk/emsdk_env.sh
#
# Usage:
#   ./build_wasm.sh [debug|release]
#
# Output:
#   build_wasm/synthdemo.html
#   build_wasm/synthdemo.js
#   build_wasm/synthdemo.wasm

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build_wasm"
BUILD_TYPE="${1:-Release}"

# Check for Emscripten
if ! command -v emcmake &> /dev/null; then
    echo "Error: Emscripten not found!"
    echo ""
    echo "Install via Homebrew (recommended for macOS):"
    echo "  brew install emscripten binaryen"
    echo ""
    echo "Or install via emsdk:"
    echo "  git clone https://github.com/emscripten-core/emsdk.git"
    echo "  cd emsdk"
    echo "  ./emsdk install latest"
    echo "  ./emsdk activate latest"
    echo "  source ./emsdk_env.sh"
    exit 1
fi

# Fix for Homebrew Emscripten - ensure EMSDK_PYTHON is set
# The Homebrew wrapper sets PYTHON but the underlying scripts use EMSDK_PYTHON
if [ -z "$EMSDK_PYTHON" ]; then
    # Try common Homebrew Python locations
    for py in /opt/homebrew/opt/python@3.14/bin/python3.14 \
              /opt/homebrew/opt/python@3.13/bin/python3.13 \
              /opt/homebrew/opt/python@3.12/bin/python3.12 \
              /usr/local/opt/python@3.14/bin/python3.14 \
              /usr/local/opt/python@3.13/bin/python3.13 \
              /usr/local/opt/python@3.12/bin/python3.12; do
        if [ -f "$py" ]; then
            export EMSDK_PYTHON="$py"
            break
        fi
    done
fi

# Show Emscripten version
echo "Emscripten version: $(emcc --version | head -1)"
echo ""

echo "Building SynthDemo for WebAssembly ($BUILD_TYPE)..."
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with Emscripten
# Note: emcmake automatically sets CMAKE_TOOLCHAIN_FILE
emcmake cmake \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DPLATFORM=Web \
    -DBUILD_EXAMPLES=OFF \
    ..

# Build
emmake make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo ""
echo "============================================"
echo "Build complete!"
echo "============================================"
echo ""
echo "Output files:"
echo "  $BUILD_DIR/synthdemo.html"
echo "  $BUILD_DIR/synthdemo.js"
echo "  $BUILD_DIR/synthdemo.wasm"
echo ""
echo "To test locally (pick one):"
echo "  npx serve -l 9090 $BUILD_DIR"
echo "  python3 -m http.server 9090 --directory $BUILD_DIR"
echo "  php -S localhost:9090 -t $BUILD_DIR"
echo ""
echo "  Open: http://localhost:9090/synthdemo.html"
echo ""
echo "Note: Audio requires user interaction (click/keypress)"
echo "      due to browser autoplay policies."
