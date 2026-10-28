# Windows x64 source verification

Run **Windows x64 source verification** from the Actions tab using **Run workflow**
and select the upstream branch to examine. Its resolved commit is recorded. This is
a manual, full MinGW cross-build on Ubuntu 24.04. It has no push or pull-request trigger. Existing platform
workflows retain their current triggers and feature gates.

The job checks out the selected commit and every recursive submodule at its recorded
Git commit, requires pristine worktrees before configuring, and builds the full
`openjkdf2-64` target with the existing MinGW toolchain. It does not set
`GITHUB_RUNNER_COMPILE`, so OpenAL and GameNetworkingSockets remain enabled. No
unmerged regression infrastructure or commit-version environment overrides are
required. The ordinary Git-based version selection remains in effect.

## Records and checks

Only the verification records are uploaded as a short-lived Actions artifact. The
executable and DLLs are staged under the runner's temporary directory for inspection.
The job creates no release, distributable binary archive, or game-data upload.

- `SOURCE_BEFORE.json` records the exact engine and recursive dependency commits,
  configured remote URLs, and clean statuses. Checkout HEAD must equal `GITHUB_SHA`.
- `SOURCE_AFTER.json` records recursive statuses and tracked diffs. The existing
  CMake dependency builds patch GameNetworkingSockets, SDL3_mixer/ogg and PhysicsFS
  sources; those diffs are retained as build inputs. Commit changes, missing
  submodules and unexpected root worktree changes fail verification. A clean initial
  checkout does not imply dependency worktrees remain pristine after building.
- `PE.json` checks every staged EXE/DLL using independent PE header fields (AMD64
  `0x8664`, PE32+ `0x020b`), MinGW objdump and `file`. Starting from the executable,
  OpenAL32, GameNetworkingSockets and FreeGLUT, staging resolves imports recursively,
  with case-insensitive DLL names. Each non-system import must resolve to a built
  DLL or a compiler-supplied runtime. Conflicting copies, missing imports and failing
  inspection tools fail the job. The explicit Windows system/API-set allowlist is
  in `scripts/ci/windows_x64_verification.py`; it is not a promise about the oldest
  supported Windows release. On-demand runtime loads beyond the explicit entry
  points and ordinary PE imports require separate runtime testing.
- `BINARY_ORIGINS.json` and `BINARY_SHA256.json` identify inspection inputs and verify
  their staged bytes. The binaries themselves are never uploaded.
- `licenses/` and `LICENSE_SOURCES.json` retain required engine/dependency notices
  with source hashes, using current SDL3 and SDL3_mixer vendored-codec paths.
  Required compiler static archives and any staged compiler runtime DLLs must have
  distro package ownership and copyright notices. `MINGW_RUNTIME_PACKAGES.json`
  records their versions and hashes. Missing required notices are fatal. These
  records support review; they do not establish compliance for a future binary
  distribution, whose packaging and corresponding-source obligations need review.
- `GENERATOR.txt` records the Python executable, Python version, actual installed
  `cogapp` version and frozen packages from **the build's `cogapp_venv`**. Existing
  CMake installs Cog there without a version pin. A separately preinstalled Cog
  would not constrain that environment. This workflow records the resolved version;
  it does not claim hermetic or bit-for-bit reproducible dependency resolution.
- `BUILD_TOOLCHAIN.txt`, `UBUNTU_PACKAGES.txt`, `CMakeCache.txt`, and configure/build
  logs record the actual build settings and tool versions. `SOURCE_URL.txt` points
  to the recorded checkout; `SHA256SUMS.json` covers all completed record files.

The artifact upload also runs on failure, so an artifact may contain incomplete
records. Inspect the Actions result and failing step before treating it as a
successful verification. The complete hash manifest is produced only after the
verification gates pass. A completed cross-build demonstrates architecture/import
and source-record checks; it does not demonstrate launching Windows, gameplay,
retail assets, graphics drivers or multiplayer compatibility.

## Current baseline build caveat

The unmodified MinGW runtime archive order can fail on the Ubuntu GCC 13 POSIX
compiler when C++ code pulls exception/thread-local-storage objects from
`libgcc_eh.a` after `libpthread.a` was scanned. A safe synthetic `std::string`
program reproduced unresolved `pthread_getspecific`, `pthread_once` and
`pthread_setspecific` symbols with the current upstream toolchain. The separate
MinGW runtime archive grouping topic resolves that fixture and is recommended
before a full hosted run. This verification topic keeps the existing toolchain
unchanged; build failures remain visible in its records. It has no dependency on
that topic's test files or version override APIs.

## Focused local validation

With Python 3, `git`, `file`, and the x86-64 MinGW compiler/binutils installed:

```sh
python3 -B scripts/ci/test_windows_x64_verification.py
```

The tests call the production verification helpers, compile a tiny synthetic EXE
and DLL, check transitive imports, and exercise missing dependencies, malformed or
wrong-architecture headers, absent inspection tools/licenses, dirty source and
changed hashes. They use no retail data and never execute the Windows binaries.
The workflow YAML can additionally be checked with `actionlint`.

## Attribution

Adapted from `.github/workflows/windows-x64-retail-fidelity.yml` in
[CodaLilitari/OpenJKDF2-MotS-Fixes at 6fa54630](https://github.com/CodaLilitari/OpenJKDF2-MotS-Fixes/blob/6fa54630a123485d8c7b602c47992613a1f397b5/.github/workflows/windows-x64-retail-fidelity.yml),
authored in that history as andreipemberton (Coda Lilitari). This adaptation retains
its source/submodule provenance, PE/import, dependency-license and hash checks,
and scopes delivery to upstream verification records.
