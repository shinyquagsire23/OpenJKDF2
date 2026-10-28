# Native regression coverage for incorporated fixes

These asset-free tests exercise production behavior already incorporated into
OpenJKDF2. They add coverage without changing production functions, public
headers, storage layouts, or build feature gates. Run from the repository root:

```sh
python3 -B src/Tests/run_cog_locality_test.py --cc gcc --ubsan
python3 -B src/Tests/run_bitmap_test.py --cc gcc --ubsan
python3 -B src/Tests/run_material_test.py --cc gcc --ubsan
```

Python 3 and a native GCC or Clang compiler are required. `--cc` selects the
compiler; otherwise the runners use `CC`, then search for gcc/clang/cc. `--ubsan`
requires UndefinedBehaviorSanitizer and stops on its first diagnostic. Omit it
for a plain native run. There are no game assets, Python package, renderer,
submodule, or full engine build dependencies. The scripts can also be invoked
by absolute path from outside the checkout.

Each runner extracts complete function bodies from the current source, compiles
them in a temporary directory, and executes independent assertions. The common
`source_test_utils.py` supports extraction and explicit compiler/process error
reporting. Ambiguous or missing source anchors, compiler errors, process
failures, and timeouts fail the runner. Each successful run prints compiler
identity and production input hashes and verifies that those files stayed
unchanged. Extracted source and executable files are removed on exit.

## Coverage and substitutes

| Suite | Production code executed | Checks and substitutes |
| --- | --- | --- |
| COG locality | `THINGPARAM_COG` case from `sithThing.c`; complete `sithCog_SendMessage` and `sithCog_SendMessageEx` bodies | JK/MotS class flags, preservation of explicit SERVER/LOCAL/NOSYNC/GLOBAL/DEBUG flags, singleplayer/host/client routing, NEWPLAYER/TIMER/PULSE/STARTUP/SHUTDOWN/DAMAGED messages, both dispatch APIs, disabled/paused/missing/empty handlers, null COGs, argument forwarding, parameters and return values. Minimal named-field structs and loader, executor, and network-transport stubs isolate binding and routing. Constants and scalar COG types come from production declarations. |
| Bitmap conversion | Complete `stdBitmap_ConvertColorFormat` body; production `stdBitmap` and `rdTexFormat` declarations | Null bitmap without dependent access; identical-format and indexed-format no-ops; zero through three mip surfaces; both RGB565/RGB555 directions; transparent/nontransparent palettes; pointer replacement, metadata commit order, color-key calls and unrelated-field preservation. Both default and SDL2 structure layouts compile and run. Display conversion and one-pixel conversion are deterministic in-memory stubs, so their arithmetic is **not** production pixel-converter coverage. |
| Packed MAT rows | Unchanged static `rdMaterial_ReadExact`, `rdMaterial_ReadPackedRows`, and `rdMaterial_ValidTextureLayout` bodies from `rdMaterial.c`; production `rdTextureHeader` | Fourteen sequential 2x2 8-bit cels; literal padded-byte and final-offset expectations; 1/2/3/4/6-byte row widths; 8/16-bit synthetic inputs; tight/padded destinations; one-byte and other short reads; EOF/truncated headers/pixels; destination boundary bytes; zeroed padding; invalid stride/capacity/zero dimensions; mip and dimension boundaries. A small HostServices `fileRead` substitute reads an in-memory byte array. The opaque file handle uses `intptr_t`. |

The COG suite also builds a **safe behavioral negative control** that only
inverts the MotS SERVER condition in its temporary binding fragment. It must
exit at the expected flag assertion, demonstrating that the matrix detects
the locality inversion. No source file is changed. Bitmap and MAT tests only
execute corrected production code; no removed-guard or historical memory-path
mutants are built or run.

The MAT fixture uses a maximum of four mip levels, matching the current loader's
fixed mip storage. It does not invoke the static layout helper with hypothetical
larger array limits and out-of-width shifts. Generated header bytes are native
to the host; this tests helper I/O and row alignment, not portable on-disk endian
decoding or a complete MAT-file parser. No duplicate MAT helper header or test
seam is added to production.

## Integration boundary

The COG fixture does not load or execute real scripts, validate the production
struct ABI, deliver network packets, cover co-op objective/death branches, or
enable debug-name printing. A real MotS host and second client are still needed
to establish end-to-end class-script delivery and gameplay behavior.

Bitmap tests establish conversion orchestration with defined dependencies.
They do not allocate real display surfaces, run the actual pixel conversion
backend, upload textures, or certify rendered output. The SDL2 variant checks
the conditional bitmap members without linking SDL.

MAT tests establish the behavior of the upstream static I/O/layout helpers.
They do not execute `rdMaterial_LoadEntry_Common`, create or unlock a display
surface, cover its platform-specific allocation/cleanup and retro/LRU paths,
or certify material appearance in-game. Full engine/platform builds and a game
session with appropriate authored content remain separate acceptance work.

The focused GitHub workflow runs these three suites on Ubuntu with GCC and
UBSan for relevant pull requests, relevant pushes to `master`, and manual
dispatch. Local test results do not establish that hosted CI has run.
EGL pixel unpack and VectorCross coverage belong to their separate submissions.

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
