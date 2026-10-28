# Native host regressions and retained evidence

This entry point runs the explicitly registered, asset-free host regressions on
Linux. It compiles standalone fixtures, not the engine, and does not launch a
game or claim retail gameplay parity. It requires Python 3, Git, a native C++17
compiler, EGL/OpenGL development headers, and a Mesa software renderer capable
of a surfaceless desktop OpenGL context. No game assets, submodules, or Python
packages are needed.

## Run locally

On Ubuntu, the workflow installs `build-essential git libegl-dev libgl-dev
libgl1-mesa-dri python3`. Run from the repository root, using new output paths:

```sh
python3 -B src/Tests/test_host_regression_runner.py
python3 -B src/Tests/run_host_regressions.py run --output /tmp/openjk-host-results
python3 -B src/Tests/run_host_regressions.py collect \
  --host-results /tmp/openjk-host-results --output /tmp/openjk-host-evidence
```

`--cxx` selects the native compiler. A missing compiler, header, linker input,
renderer, or test dependency is a failure, never an implicit skip. The runner
removes display variables and selects software GL for the graphics fixture.

## Initial registered regression

The pixel-unpack fixture includes the existing production
`Platform/GL/jkgm_pixel_unpack.hpp` unchanged. A private surfaceless EGL pbuffer
provides real OpenGL upload/readback of synthetic RGB/RGBA/BGR/BGRA pixels.
Eight widths and four incoming alignments produce 128 exact byte comparisons.
It also checks normalization and restoration of row length/skips/alignment,
unrelated pack-state preservation, early return, and a padded, fully owned
unprotected control buffer. No driver or game assets are distributed.

The group list and command plan are explicit. Further independent regression
PRs can register their commands and evidence names after those fixtures land;
this initial gate does not claim to run tests that are absent from upstream.

## Receipts and failures

Each command gets separate text logs, argv, exit status, and elapsed time. The
JSON receipt records the source commit, worktree status, runner hash, compiler
and Python versions, available Actions run metadata, and PR head identity.
The gate stops after a failure and leaves remaining groups explicitly
`not_run`. It checkpoints during execution, limits each child to 300 seconds
and the overall command schedule to 900 seconds, and terminates only its own
new process group if a command times out. The Actions job has a separate
20-minute limit.

Five orchestration tests cover setup failure, ordinary command failure,
remaining-group reporting, command timeout, allowed evidence, and rejected
binary/symlink candidates. These use short, harmless Python subprocesses.

## CI evidence boundary

The workflow uses read-only contents permission and a pinned checkout with
persisted credentials disabled. Collection runs after both success and
failure. The uploaded artifact lasts 14 days and contains only the named
UTF-8 text/JSON logs, summary, manifest, and optional orchestration logs.
Every collected file has a byte count and SHA-256 digest. Missing expected
files are listed rather than silently synthesized.

The collector rejects symlinks, non-files, files above 16 MiB, invalid JSON,
NUL bytes, and recognized binary headers. Engine executables, shared
libraries, images, game assets, archives, and arbitrary build-directory
contents are outside its explicit allowlist. The Actions summary states the
host result and each group's status. A successful host run does not certify
physical GPU behavior, rendered game scenes, or gameplay.
