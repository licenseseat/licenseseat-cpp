#!/usr/bin/env python3
"""Validate a release tag against every source-of-truth version field."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SEMVER_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?")


def extract(path: str, pattern: str) -> str:
    content = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(pattern, content)
    if match is None:
        raise ValueError(f"could not find a version in {path}")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="release tag, including the leading v")
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args()

    if SEMVER_TAG.fullmatch(arguments.version) is None:
        print("error: release version must be a canonical v-prefixed semantic version", file=sys.stderr)
        raise SystemExit(1)

    versions = {
        "public header": extract(
            "include/licenseseat/licenseseat.hpp", r'VERSION\s*=\s*"([^"]+)"'
        ),
        "CMake project": extract("CMakeLists.txt", r"project\(licenseseat\s+VERSION\s+([^\s\)]+)"),
        "Conan recipe": extract("conanfile.py", r'version\s*=\s*"([^"]+)"'),
        "vcpkg manifest": json.loads((ROOT / "vcpkg.json").read_text(encoding="utf-8"))["version"],
        "Unreal plugin": json.loads(
            (ROOT / "integrations/unreal/LicenseSeat/LicenseSeat.uplugin").read_text(
                encoding="utf-8"
            )
        )["VersionName"],
        "changelog": extract("CHANGELOG.md", r"## \[([0-9]+\.[0-9]+\.[0-9]+)\]"),
    }
    expected = arguments.version[1:].split("-", 1)[0]
    mismatches = {name: version for name, version in versions.items() if version != expected}
    if mismatches:
        details = ", ".join(f"{name}={value}" for name, value in mismatches.items())
        print(f"error: {arguments.version} does not match source versions: {details}", file=sys.stderr)
        raise SystemExit(1)

    print(f"validated release {arguments.version} ({', '.join(versions)})")
    if arguments.github_output is not None:
        with arguments.github_output.open("a", encoding="utf-8") as output:
            output.write(f"version={arguments.version}\n")


if __name__ == "__main__":
    main()
