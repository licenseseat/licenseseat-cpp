# Vendored dependency provenance

These source files are vendored so normal SDK builds do not download executable
or source content at configure time. Verify them from this directory with:

```sh
shasum -a 256 -c DEPENDENCIES.sha256
```

| Dependency | Version | Upstream commit | Vendored file |
| --- | --- | --- | --- |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) | 0.52.0 | `095a5c1caf9e467ff840ee2ffd19be1a7852203b` | `httplib.h` |
| [nlohmann/json](https://github.com/nlohmann/json) | 3.12.0 | `55f93686c01528224f448c19128836e7df245f72` | `nlohmann/json.hpp` |
| [PicoSHA2](https://github.com/okdshin/PicoSHA2) | 1.0.1 | `161cb3fc4170fa7a3eca9e582cebd27cc4d1fe29` | `PicoSHA2/picosha2.h` |

The corresponding license notices are in `THIRD_PARTY_LICENSES.md` at the
repository root and `PicoSHA2/LICENSE`.

CI also runs `scripts/audit-vendored-dependencies.py --online`, which validates
the machine-readable provenance manifest and fails closed if OSV reports a
known vulnerability for any exact upstream commit.
