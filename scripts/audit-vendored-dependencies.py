#!/usr/bin/env python3
"""Verify vendored source provenance and optionally query OSV by Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEPS = ROOT / "deps"
MANIFEST = DEPS / "dependencies.json"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
MAX_OSV_RESPONSE_BYTES = 8 * 1024 * 1024


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_manifest() -> list[dict[str, object]]:
    try:
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {MANIFEST.relative_to(ROOT)}: {error}")

    if not isinstance(document, dict) or document.get("schema_version") != 1:
        fail("unsupported or malformed dependency manifest")
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        fail("dependency manifest must contain a non-empty dependencies array")
    return dependencies


def validate_local_files(dependencies: list[dict[str, object]]) -> None:
    seen_names: set[str] = set()
    seen_paths: set[Path] = set()

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            fail("dependency entries must be objects")
        name = dependency.get("name")
        version = dependency.get("version")
        commit = dependency.get("commit")
        files = dependency.get("files")
        if not isinstance(name, str) or not name or name in seen_names:
            fail("dependency names must be non-empty and unique")
        seen_names.add(name)
        if not isinstance(version, str) or not version:
            fail(f"{name}: version is missing")
        if (
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
        ):
            fail(f"{name}: commit must be a lowercase 40-character SHA-1")
        if not isinstance(files, list) or not files:
            fail(f"{name}: files must be a non-empty array")

        for file_entry in files:
            if not isinstance(file_entry, dict):
                fail(f"{name}: file entries must be objects")
            relative = file_entry.get("path")
            expected = file_entry.get("sha256")
            marker = file_entry.get("marker")
            if not isinstance(relative, str) or not relative:
                fail(f"{name}: file path is missing")
            path = DEPS / relative
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(DEPS.resolve())
            except (OSError, ValueError):
                fail(f"{name}: unsafe or missing vendored path: {relative}")
            if path.is_symlink() or not path.is_file() or resolved in seen_paths:
                fail(f"{name}: vendored path must be a unique regular file: {relative}")
            seen_paths.add(resolved)
            if (
                not isinstance(expected, str)
                or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)
            ):
                fail(f"{name}: invalid SHA-256 for {relative}")

            content = path.read_bytes()
            actual = hashlib.sha256(content).hexdigest()
            if actual != expected:
                fail(f"{name}: SHA-256 mismatch for {relative}: {actual}")
            if marker is not None:
                if not isinstance(marker, str) or marker.encode("utf-8") not in content:
                    fail(f"{name}: version marker is missing from {relative}")

        print(f"verified {name} {version} ({commit[:12]})")


def query_osv(dependencies: list[dict[str, object]]) -> None:
    payload = json.dumps(
        {"queries": [{"commit": dependency["commit"]} for dependency in dependencies]},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_BATCH,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "LicenseSeat-vendored-audit/1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(MAX_OSV_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as error:
        fail(f"OSV query failed closed: {error}")
    if len(body) > MAX_OSV_RESPONSE_BYTES:
        fail("OSV response exceeds the size limit")
    try:
        document = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"OSV returned invalid JSON: {error}")
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list) or len(results) != len(dependencies):
        fail("OSV returned an unexpected result shape")

    findings: list[str] = []
    for dependency, result in zip(dependencies, results):
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else None
        if not isinstance(vulnerabilities, list):
            fail(f"OSV returned an invalid entry for {dependency['name']}")
        identifiers = sorted(
            vulnerability.get("id", "unknown")
            for vulnerability in vulnerabilities
            if isinstance(vulnerability, dict)
        )
        if identifiers:
            findings.append(f"{dependency['name']}: {', '.join(identifiers)}")
    if findings:
        fail("OSV reports known vulnerabilities for vendored commits: " + "; ".join(findings))
    print("OSV reports no known vulnerabilities for the vendored commits")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--online",
        action="store_true",
        help="fail closed unless exact dependency commits are clean in OSV",
    )
    arguments = parser.parse_args()
    dependencies = load_manifest()
    validate_local_files(dependencies)
    if arguments.online:
        query_osv(dependencies)


if __name__ == "__main__":
    main()
