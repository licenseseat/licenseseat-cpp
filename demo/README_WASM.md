# SynthDemo WASM Build

Build SynthDemo for the web using WebAssembly.

## Prerequisites

### macOS (Homebrew)

```bash
brew install emscripten binaryen
```

**Important:** After installing, you may need to fix the LLVM path in `~/.emscripten`:

```python
# ~/.emscripten
import os
LLVM_ROOT = '/opt/homebrew/Cellar/emscripten/5.0.4/libexec/llvm/bin'  # Use Emscripten's LLVM, not Homebrew's
BINARYEN_ROOT = '/opt/homebrew/opt/binaryen'
NODE_JS = '/opt/homebrew/bin/node'
EMSCRIPTEN_ROOT = '/opt/homebrew/Cellar/emscripten/5.0.4/libexec'
```

Check your version path with: `brew --prefix emscripten`

### Alternative: emsdk

Install the [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html) (version 3.1.51+):

```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
```

## Build

```bash
cd demo
./build_wasm.sh
```

Or manually:

```bash
mkdir build_wasm && cd build_wasm
emcmake cmake -DCMAKE_BUILD_TYPE=Release -DPLATFORM=Web ..
emmake make -j8
```

## Test Locally

Use any static file server:

```bash
cd build_wasm

# Option 1: npx serve (recommended)
npx serve -l 9090

# Option 2: Python
python3 -m http.server 9090

# Option 3: PHP
php -S localhost:9090
```

Open: http://localhost:9090/synthdemo.html

**Note:** Audio requires user interaction (click or keypress) due to browser autoplay policies.

## Test License Keys

The WASM build uses mock validation with Stripe-style test keys:

| Key | Result |
|-----|--------|
| `4242-4242-4242-4242` | Valid Pro license |
| `4000-0000-0000-0002` | Invalid key |
| `4000-0000-0000-0010` | Expired license |
| `4000-0000-0000-0020` | Suspended license |
| `4000-0000-0000-0069` | Seat limit exceeded |

## Emscripten Flags Used

The build uses these flags (per [raylib wiki](https://github.com/raysan5/raylib/wiki/Working-for-Web-(HTML5))):

| Flag | Purpose |
|------|---------|
| `-sUSE_GLFW=3` | Use Emscripten's GLFW implementation |
| `-sASYNCIFY` | Enable async/await for blocking calls |
| `-sWASM=1` | Explicit WebAssembly output |
| `-sASSERTIONS=1` | Runtime error checking |
| `-sGL_ENABLE_GET_PROC_ADDRESS=1` | Required since Emscripten 3.1.51 |
| `-sINITIAL_MEMORY=67108864` | 64MB initial heap |
| `-sALLOW_MEMORY_GROWTH=1` | Allow heap to grow |

## Differences from Native Build

The WASM demo mode (`__EMSCRIPTEN__` defined):

- **No SDK**: No HTTP calls, storage, or crypto
- **No SDK Admin button**: Simplified UI
- **No Deactivate button**: Only activate with test keys
- **No SDK status dot**: No connection status indicator
- **Instant validation**: No async, mock responses only

## Output Files

After building:

| File | Description |
|------|-------------|
| `synthdemo.html` | Main HTML file (uses shell.html template) |
| `synthdemo.js` | Emscripten runtime + glue code (~230KB) |
| `synthdemo.wasm` | WebAssembly binary (~300KB) |

## Embedding

The generated `synthdemo.js` reads these hooks off the `Module` object the host
page defines before loading it:

| Hook | When it fires |
|------|---------------|
| `Module.canvas` | The canvas to render into (required) |
| `Module.onRuntimeInitialized` | The runtime is up, just before `main()` runs |
| `Module.onDemoUnsupported(reason)` | The browser gave us no graphics context; the demo has stopped and nothing else will happen |
| `Module.onAbort(what)` | Emscripten aborted; `what` is runtime internals, not user-facing copy |

A page that embeds the demo should check WebGL support before pulling in the
~500 KB runtime, and treat `onDemoUnsupported` as the "show a screenshot
instead" signal. `licenseseat.com` does both from its Stimulus controller.

## Deployment

Copy the output files to your web server:

```bash
scp synthdemo.html synthdemo.js synthdemo.wasm user@server:/var/www/html/
```

The HTML file includes the test key documentation styled in.

## Troubleshooting

### Homebrew: emcmake hangs or times out

The `EMSDK_PYTHON` environment variable may not be set. The build script auto-detects this, but you can set it manually:

```bash
export EMSDK_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14
```

### Homebrew: "linker binary not found: wasm-ld"

The `~/.emscripten` config is pointing to the wrong LLVM. Update `LLVM_ROOT` to use Emscripten's bundled LLVM:

```python
LLVM_ROOT = '/opt/homebrew/Cellar/emscripten/5.0.4/libexec/llvm/bin'
```

### Audio not playing

Click or press a key first - browsers block audio until user interaction.

### Black screen / WebGL errors

The demo needs a WebGL context. When the browser refuses one -- no usable GPU, a
blocklisted graphics driver (common on Chromium/Linux), WebGL switched off, or
the per-page context limit already reached -- raylib logs:

```
WARNING: GLFW: Failed to initialize Window
WARNING: SYSTEM: Failed to initialize platform
ERROR: SYSTEM: No graphics context available, demo cannot run
```

and the demo stops there, calling `Module.onDemoUnsupported` (see *Embedding*).
It must stop: `InitWindow()` returns normally after that failure with rlgl left
uninitialized, so the next `BeginDrawing()` writes through a NULL matrix pointer
onto address zero and Emscripten kills the module with `Runtime error: The
application has corrupted its heap memory area (address zero)!`.

### Build errors with glfwGetProcAddress

Update to Emscripten 3.1.51+ and ensure `-sGL_ENABLE_GET_PROC_ADDRESS=1` is set.

### Empty page in browser

Try a different port (some ports may conflict with other services). Use `npx serve` which handles MIME types correctly.
