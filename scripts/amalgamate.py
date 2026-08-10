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
from datetime import datetime, timezone

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
    "include/licenseseat/telemetry.hpp",
]

# Source files for implementation
SOURCES = [
    "src/crypto.cpp",
    "src/device.cpp",
    "src/http.cpp",
    "src/storage.cpp",
    "src/telemetry.cpp",
    "src/client.cpp",
]

# Vendored header-only libraries to embed
VENDORED = {
    "picosha2": "deps/PicoSHA2/picosha2.h",
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
    '"licenseseat/telemetry.hpp"',
    # Relative paths (used by include/licenseseat/*.hpp)
    '"licenseseat.hpp"',
    '"crypto.hpp"',
    '"device.hpp"',
    '"events.hpp"',
    '"http.hpp"',
    '"json.hpp"',
    '"storage.hpp"',
    '"telemetry.hpp"',
    # Vendored dependencies
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


def wrap_extern_c(content, is_c_code=False):
    """Wrap C code in extern \"C\" for C++ compatibility."""
    if is_c_code:
        return f'extern "C" {{\n{content}\n}}\n'
    return content


def add_namespace_prefix_to_crypto(content):
    """Add the internal namespace prefix to bundled PicoSHA2 calls."""
    # Replace picosha2 namespace with full path
    content = re.sub(
        r'\bpicosha2::',
        'licenseseat_internal::picosha2::',
        content
    )
    return content


def get_version():
    """Extract version from licenseseat.hpp."""
    content = read_file("include/licenseseat/licenseseat.hpp")
    match = re.search(r'VERSION\s*=\s*"([^"]+)"', content)
    return match.group(1) if match else "unknown"


def generated_at():
    """Return a reproducible UTC generation time when SOURCE_DATE_EPOCH is set."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        moment = datetime.now(timezone.utc)
    else:
        try:
            timestamp = int(epoch)
            if timestamp < 0:
                raise ValueError
            moment = datetime.fromtimestamp(timestamp, timezone.utc)
        except (ValueError, OverflowError, OSError):
            print("Error: SOURCE_DATE_EPOCH must be a valid non-negative Unix timestamp", file=sys.stderr)
            raise SystemExit(1)
    return moment.isoformat().replace("+00:00", "Z")


def generate_header():
    """Generate the amalgamated header."""
    output = []
    version = get_version()

    # Header
    output.append(f'''/*
 * LicenseSeat C++ SDK - Single Header Distribution
 *
 * Generated: {generated_at()}
 * Version: {version}
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
 * This amalgamated build requires OpenSSL for HTTPS, Ed25519 verification,
 * and machine-file AES-256-GCM verification.
 * HTTPS support also requires cpp-httplib compiled with CPPHTTPLIB_OPENSSL_SUPPORT.
 */

#ifndef LICENSESEAT_SINGLE_HPP
#define LICENSESEAT_SINGLE_HPP

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

    # Add source implementations
    for src_path in SOURCES:
        output.append(f"// --- {src_path} ---\n")
        content = read_file(src_path)
        content = strip_local_includes(content, REMOVE_INCLUDES)
        # Remove the vendored include directive (already embedded above)
        content = content.replace('#include "PicoSHA2/picosha2.h"', '// picosha2 embedded above')
        content = strip_ifdef_openssl(content)

        # Prefix bundled dependency namespaces in every implementation that
        # uses them (currently crypto.cpp and storage.cpp).
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
