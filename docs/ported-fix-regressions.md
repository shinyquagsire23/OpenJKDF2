# Native regression coverage for incorporated fixes

These Linux CMake/CTest tests compile complete production translation units
with production headers and generated global declarations. They replace
regex extraction and copied structure definitions. The sole production
refactor moves the existing COG binding case into a private function with
identical flags, return value, and caller control flow; the public parser
continues to dispatch to it.

Install CMake, a C compiler and `cogapp` in a Python virtual environment:

```sh
python3 -m venv /tmp/openjk-test-venv
/tmp/openjk-test-venv/bin/pip install cogapp
/tmp/openjk-test-venv/bin/python src/Tests/run_cog_locality_test.py --cc gcc --ubsan
/tmp/openjk-test-venv/bin/python src/Tests/run_bitmap_test.py --cc gcc --ubsan
/tmp/openjk-test-venv/bin/python src/Tests/run_material_test.py --cc gcc --ubsan
```

Or configure once and run the four CTest entries:

```sh
cmake -S src/Tests/cmake/ported-fixes -B /tmp/openjk-source-tests \
  -DPython3_EXECUTABLE=/tmp/openjk-test-venv/bin/python -DENABLE_UBSAN=ON
cmake --build /tmp/openjk-source-tests --parallel 1
ctest --test-dir /tmp/openjk-source-tests --output-on-failure -V
```

The small Python wrappers retain `--cc`, `--ubsan`, and `--source-root` and
supply configure/build/test deadlines. CTest bounds each case to 30 seconds.
There are no source-spelling anchors or automatic source mutations. No retail
assets, submodules, SDL library, full engine build or display is required.
The source files use the desktop QOL types with a null sound backend. Unused
functions are discarded with GNU-compatible section GC; COG's loader seam
uses the linker's `--wrap`. This focused entry is Linux/GNU-or-Clang host
coverage, not a claim of validated macOS/MSVC/full-engine integration.

## Coverage and remaining boundaries

| Suite | Compiled production coverage | Controlled boundary |
| --- | --- | --- |
| COG locality | Full `sithThing.c` included to call its private class-binding function, plus separately compiled `sithCog.c` and `jk.c`. Real COG/script/thing/argument/HostServices types. 2,882 binding and 2,882 dispatch cases; 30,766 assertions. | Loader, executor and network callbacks; console output sink. The surrounding argument parser, script execution, actual packets, co-op and gameplay are not tested. Valid and failed loads, explicit SERVER/LOCAL/NOSYNC/GLOBAL/DEBUG flags, JK/MotS, host/client/singleplayer, disabled/paused/missing handlers and both dispatch APIs remain covered. |
| Bitmap conversion | Complete `stdBitmap.c` and `jk.c`, real bitmap, raster, buffer, color and HostServices types. Both default and SDL2 member layouts; 393 assertions each. | Display conversion and one-pixel conversion remain deterministic in-memory callbacks. Pixels live in fixture-owned arrays instead of invented tVBuffer members. The production pixel conversion backend is not exercised. |
| Packed MAT rows | Full `rdMaterial.c` included to call unchanged private I/O/layout helpers, with real HostServices, file-handle and texture-header types. 1,920 assertions and seven packed-cel sequences. | In-memory fileRead callback. Whole MAT loading, display allocation/cleanup, GPU output, retro/LRU paths and portable endian decoding remain separate acceptance. |

The helper fixtures include whole `.c` files because those functions are
private; no duplicate helper implementation or public test hook is added.
They do not prove the full callers execute those helpers. A future linked
engine test should exercise the parser/loader with authored assets. The
current change deliberately keeps that larger integration separate.

The MAT layout domain remains the loader's four mip slots. It does not test
hypothetical larger limits with out-of-width shifts. The old-inversion
negative control is a separate development check, not text mutation in the
normal test runner. The assertions themselves detect the wrong locality.

CI runs the three bounded commands (bitmap has two CTest cases) for relevant
source/header/build changes. Local results do not establish hosted CI success.

## Source attribution

Adapted from the Coda Lilitari MotS fixes fork. The original commits below
record Git author `andreipemberton`; this upstream adaptation is by Coda Lilitari:

- [COG routing regression, c77fc8f2](https://github.com/CodaLilitari/OpenJKDF2-MotS-Fixes/commit/c77fc8f2a67cea15a566678cd00c1acb8b2b7d21).
- [Bitmap regression, 218806ad](https://github.com/CodaLilitari/OpenJKDF2-MotS-Fixes/commit/218806adee57ab2109f448be385830878ccc2eff).
- [Packed MAT rows and original fixture, 685dd18e](https://github.com/CodaLilitari/OpenJKDF2-MotS-Fixes/commit/685dd18e29e4034a63dea5e8c995a2709c381bf9).

The packed MAT row and bitmap guard corrections were incorporated in upstream
[#487](https://github.com/shinyquagsire23/OpenJKDF2/pull/487); class locality is
present through the stacked [#490](https://github.com/shinyquagsire23/OpenJKDF2/pull/490)
and [#491](https://github.com/shinyquagsire23/OpenJKDF2/pull/491) history.
This contribution supplies regression coverage around that existing behavior.
