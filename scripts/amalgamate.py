#!/usr/bin/env python3
"""
Amalgamate LicenseSeat C++ SDK into a single header file.

This script generates a single-header distribution of the SDK for easy
integration into projects like VST plugins and Unreal Engine games.

Usage:
    python scripts/amalgamate.py > dist/licenseseat_single.hpp

The generated header uses the following pattern:
    - All declarations are in the header
    - Implementation is guarded by #define LICENSESEAT_IMPLEMENTATION
    - To use: In ONE .cpp file, #define LICENSESEAT_IMPLEMENTATION before including
"""

import os
import re
import sys
from pathlib import Path
from datetime import datetime

# Project root
ROOT = Path(__file__).parent.parent

# Headers to amalgamate (in dependency order)
HEADERS = [
    "include/licenseseat/licenseseat.hpp",
    "include/licenseseat/crypto.hpp",
    "include/licenseseat/device.hpp",
    "include/licenseseat/events.hpp",
    "include/licenseseat/http.hpp",
    "include/licenseseat/json.hpp",
    "include/licenseseat/storage.hpp",
]

# Source files for implementation
SOURCES = [
    "src/crypto.cpp",
    "src/device.cpp",
    "src/http.cpp",
    "src/storage.cpp",
    "src/client.cpp",
]

# Vendored libraries to embed
VENDORED = {
    "picosha2": "deps/PicoSHA2/picosha2.h",
    "ed25519": [
        "deps/ed25519/fixedint.h",
        "deps/ed25519/sha512.h",
        "deps/ed25519/fe.h",
        "deps/ed25519/ge.h",
        "deps/ed25519/sc.h",
        "deps/ed25519/precomp_data.h",
        "deps/ed25519/ed25519.h",
        "deps/ed25519/fe.c",
        "deps/ed25519/ge.c",
        "deps/ed25519/sc.c",
        "deps/ed25519/sha512.c",
        "deps/ed25519/add_scalar.c",
        "deps/ed25519/keypair.c",
        "deps/ed25519/key_exchange.c",
        "deps/ed25519/seed.c",
        "deps/ed25519/sign.c",
        "deps/ed25519/verify.c",
    ],
}

# Includes to remove (will be embedded or provided by user)
REMOVE_INCLUDES = {
    # Full paths (used by src/*.cpp)
    '"licenseseat/licenseseat.hpp"',
    '"licenseseat/crypto.hpp"',
    '"licenseseat/device.hpp"',
    '"licenseseat/events.hpp"',
    '"licenseseat/http.hpp"',
    '"licenseseat/json.hpp"',
    '"licenseseat/storage.hpp"',
    # Relative paths (used by include/licenseseat/*.hpp)
    '"licenseseat.hpp"',
    '"crypto.hpp"',
    '"device.hpp"',
    '"events.hpp"',
    '"http.hpp"',
    '"json.hpp"',
    '"storage.hpp"',
    # Vendored dependencies
    '"ed25519/ed25519.h"',
    '"PicoSHA2/picosha2.h"',
}

# Includes that require external dependencies (user must provide)
EXTERNAL_DEPS = {
    "<nlohmann/json.hpp>": "nlohmann/json (https://github.com/nlohmann/json)",
    "<httplib.h>": "cpp-httplib (https://github.com/yhirose/cpp-httplib)",
}


def read_file(path):
    """Read file contents."""
    full_path = ROOT / path
    if not full_path.exists():
        print(f"Warning: {path} not found", file=sys.stderr)
        return ""
    return full_path.read_text()


def strip_pragma_once(content):
    """Remove #pragma once from content."""
    return re.sub(r'#pragma\s+once\s*\n?', '', content)


def strip_local_includes(content, remove_set):
    """Remove specified #include directives."""
    lines = content.split('\n')
    result = []
    for line in lines:
        skip = False
        for inc in remove_set:
            if f'#include {inc}' in line or f'#include{inc}' in line:
                skip = True
                break
        if not skip:
            result.append(line)
    return '\n'.join(result)


def strip_ifdef_openssl(content):
    """Remove OpenSSL-specific code blocks."""
    # Remove #ifdef LICENSESEAT_USE_OPENSSL blocks
    content = re.sub(
        r'#ifdef\s+LICENSESEAT_USE_OPENSSL.*?#endif\s*//.*?LICENSESEAT_USE_OPENSSL',
        '',
        content,
        flags=re.DOTALL
    )
    # Remove #if defined(LICENSESEAT_USE_OPENSSL) blocks
    content = re.sub(
        r'#if\s+defined\s*\(\s*LICENSESEAT_USE_OPENSSL\s*\).*?#endif',
        '',
        content,
        flags=re.DOTALL
    )
    return content


def strip_duplicate_ed25519_helpers(content, filename):
    """Remove duplicate helper functions from ed25519 sc.c.

    The load_3 and load_4 functions are duplicated in both fe.c and sc.c.
    We keep them in fe.c (processed first) and remove from sc.c.
    """
    if 'sc.c' not in filename:
        return content

    # Remove load_3 function
    content = re.sub(
        r'static\s+uint64_t\s+load_3\s*\([^)]*\)\s*\{[^}]+\}',
        '// load_3 defined in fe.c',
        content
    )
    # Remove load_4 function
    content = re.sub(
        r'static\s+uint64_t\s+load_4\s*\([^)]*\)\s*\{[^}]+\}',
        '// load_4 defined in fe.c',
        content
    )
    return content


def wrap_extern_c(content, is_c_code=False):
    """Wrap C code in extern \"C\" for C++ compatibility."""
    if is_c_code:
        return f'extern "C" {{\n{content}\n}}\n'
    return content


def add_namespace_prefix_to_crypto(content):
    """Add licenseseat_internal:: prefix to ed25519 and picosha2 calls."""
    # Replace bare ed25519 function calls with namespaced versions
    content = re.sub(
        r'\bed25519_verify\s*\(',
        'licenseseat_internal::ed25519_verify(',
        content
    )
    content = re.sub(
        r'\bed25519_sign\s*\(',
        'licenseseat_internal::ed25519_sign(',
        content
    )
    content = re.sub(
        r'\bed25519_create_keypair\s*\(',
        'licenseseat_internal::ed25519_create_keypair(',
        content
    )
    # Replace picosha2 namespace with full path
    content = re.sub(
        r'\bpicosha2::',
        'licenseseat_internal::picosha2::',
        content
    )
    return content


def generate_header():
    """Generate the amalgamated header."""
    output = []

    # Header
    output.append(f'''/*
 * LicenseSeat C++ SDK - Single Header Distribution
 *
 * Generated: {datetime.now().isoformat()}
 * Version: 0.1.0
 *
 * This is an amalgamated single-header version of the LicenseSeat SDK.
 * It is designed for easy integration into:
 *   - VST/AU audio plugins (JUCE, iPlug2, etc.)
 *   - Unreal Engine games/plugins
 *   - Embedded systems
 *   - Any project wanting minimal dependencies
 *
 * USAGE:
 *   1. Include this header in your project
 *   2. In exactly ONE .cpp file, define LICENSESEAT_IMPLEMENTATION before including:
 *
 *      #define LICENSESEAT_IMPLEMENTATION
 *      #include "licenseseat_single.hpp"
 *
 *   3. In all other files, just include without the define:
 *
 *      #include "licenseseat_single.hpp"
 *
 * REQUIREMENTS:
 *   - C++17 compiler
 *   - nlohmann/json (https://github.com/nlohmann/json) - single header
 *   - cpp-httplib (https://github.com/yhirose/cpp-httplib) - single header (optional for offline-only)
 *
 * LICENSE:
 *   MIT License - see https://github.com/licenseseat/licenseseat-cpp
 *
 * This build does NOT require OpenSSL - uses vendored ed25519 and PicoSHA2.
 * HTTPS support requires cpp-httplib compiled with CPPHTTPLIB_OPENSSL_SUPPORT.
 */

#ifndef LICENSESEAT_SINGLE_HPP
#define LICENSESEAT_SINGLE_HPP

// Ensure we're using minimal crypto (no OpenSSL)
#ifndef LICENSESEAT_USE_OPENSSL
#define LICENSESEAT_MINIMAL_CRYPTO 1
#endif

''')

    # Add each header (declarations only)
    output.append("// ============================================================\n")
    output.append("// DECLARATIONS\n")
    output.append("// ============================================================\n\n")

    for header_path in HEADERS:
        output.append(f"// --- {header_path} ---\n")
        content = read_file(header_path)
        content = strip_pragma_once(content)
        content = strip_local_includes(content, REMOVE_INCLUDES)
        output.append(content)
        output.append("\n\n")

    # Implementation section
    output.append('''
// ============================================================
// IMPLEMENTATION
// ============================================================
// Define LICENSESEAT_IMPLEMENTATION in exactly one .cpp file
// before including this header to compile the implementation.

#ifdef LICENSESEAT_IMPLEMENTATION

''')

    # Embed vendored dependencies
    output.append("// --- Vendored: PicoSHA2 (SHA-256) ---\n")
    output.append("namespace licenseseat_internal {\n")
    picosha_content = read_file(VENDORED["picosha2"])
    picosha_content = strip_pragma_once(picosha_content)
    output.append(picosha_content)
    output.append("\n} // namespace licenseseat_internal\n\n")

    output.append("// --- Vendored: orlp/ed25519 ---\n")
    output.append("namespace licenseseat_internal {\n")
    output.append('extern "C" {\n')

    for ed_file in VENDORED["ed25519"]:
        output.append(f"\n// --- {ed_file} ---\n")
        content = read_file(ed_file)
        content = strip_pragma_once(content)
        # Remove internal includes between ed25519 files
        content = re.sub(r'#include\s*"[^"]+\.h"', '// (internal include removed)', content)
        # Remove duplicate helper functions from sc.c
        content = strip_duplicate_ed25519_helpers(content, ed_file)
        output.append(content)

    output.append('\n} // extern "C"\n')
    output.append("} // namespace licenseseat_internal\n\n")

    # Add source implementations
    for src_path in SOURCES:
        output.append(f"// --- {src_path} ---\n")
        content = read_file(src_path)
        content = strip_local_includes(content, REMOVE_INCLUDES)
        # Remove the vendored include directives (already embedded above)
        content = content.replace('#include "ed25519/ed25519.h"', '// ed25519 embedded above')
        content = content.replace('#include "PicoSHA2/picosha2.h"', '// picosha2 embedded above')
        content = strip_ifdef_openssl(content)

        # For crypto.cpp, add namespace prefixes for internal deps
        if 'crypto.cpp' in src_path:
            content = add_namespace_prefix_to_crypto(content)

        output.append(content)
        output.append("\n\n")

    # Close implementation section
    output.append('''
#endif // LICENSESEAT_IMPLEMENTATION

#endif // LICENSESEAT_SINGLE_HPP
''')

    return ''.join(output)


if __name__ == "__main__":
    print(generate_header())
