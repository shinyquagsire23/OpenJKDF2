# Release source identity

Ordinary builds continue to obtain the full commit and its abbreviation from
Git. An automated build or source archive can provide both values explicitly:

```sh
OPENJKDF2_RELEASE_COMMIT="$(git rev-parse HEAD)" \
OPENJKDF2_RELEASE_COMMIT_SHORT="$(git rev-parse --short=8 HEAD)" \
cmake -S . -B build
```

Both environment variables are required when either is present. The full value
must contain exactly 40 hexadecimal characters; the short value must contain
8 through 40 hexadecimal characters and match the full value's prefix. Values
are normalized to lowercase. Empty, incomplete, malformed or inconsistent
overrides stop configuration instead of silently falling back to another
checkout's identity. With neither variable set, existing Git behavior remains.

This identifies the source revision asserted by the build caller. It does not
prove that a checkout is clean or that a source archive matches that revision.
Release automation should separately record and check the source and submodule
state. No release upload or distribution behavior changes here.

## Regression coverage

Run `python3 -B src/Tests/test_version_override.py` with Python 3, CMake and Git
available. The fixture executes the actual `cmake_modules/version.cmake` in
temporary synthetic Git repositories and a directory without a Git checkout.
It checks Git fallback, override precedence, prefix lengths, case normalization,
invalid/incomplete pairs and the archive use case. It needs no engine build or
game data. Missing tools make the command fail rather than report skipped tests.
