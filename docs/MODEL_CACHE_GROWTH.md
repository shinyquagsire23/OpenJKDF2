# Stable world model-cache growth

A world's declared model count currently fixes the size of its model array.
Loading additional distinct models eventually reaches that capacity even when
the requested resources exist. Reallocating the array would invalidate
`rdModel3*` values already held by things and render objects, together with the
filename strings borrowed by the model cache.

This change adds nonmoving overflow storage for source-built engines. It is
independent of sound-cache growth and does not change sound allocation.

## Storage, publication, and ownership

`SithWorld.aModels` keeps its original pointer type and initial contiguous
allocation. Under `NO_JK_MMAP`, a world-owned sidecar records the initial
capacity and a list of independently allocated pages. Capacity grows
geometrically, with a minimum increment of 32 records. A world declaring zero
model slots receives a cleanable initial allocation of 32 records.

`SITHMODEL_MAX_MODELS` and `SITHMODEL_MIN_PAGE_MODELS` are defined in
`engine_config.h`. The maximum of 32,768 is constrained by the existing ID
encoding: current-world IDs occupy `0x0000..0x7fff`, and the static-world tag
occupies bit 15. It must not be raised without revisiting that encoding.

Existing headers and filename keys never move. When the initial array or a page
fills, the loader allocates a candidate page but does not publish it immediately.
It loads the candidate model and inserts its cache entry first. Only then does
the page join the store and increase the world's capacity and loaded count.
Initial-array, sidecar, and page allocation failures leave existing storage
unchanged. A failed cache insertion releases the fully loaded candidate's
geometry; its materials remain owned by the world.

`sithModel_GetWorldModelByIndex` resolves loaded records from either the initial
array or a page. COG model lookup uses `sithModel_GetModelByIndex`, and world
memory accounting uses the world/index accessor. Invalid negative and
out-of-range IDs are rejected before decoding the static-world tag. Current
and static stores retain separate ownership, and cached model reuse does not
increase occupancy.

Teardown removes borrowed cache keys while the headers are alive, releases each
loaded model's geometry, detaches the sidecar, and frees its pages and initial
array. The source-built current-world shutdown fallback also releases its model
store before freeing the world address. The hash table owns its nodes, not the
model headers.

## Original-executable compatibility

Overflow pages are disabled without `NO_JK_MMAP`. Original executable consumers
can index `aModels` directly, so that build retains fixed contiguous storage.
No fields are added to `SithWorld` or `rdModel3`, and the public `aModels` pointer
type is unchanged. The guard follows the storage consumer distinction rather
than changing an original binary's layout through a quality-of-life option.

The fixture tests the fixed-allocation branch in a separate build. Its reduced
world/model structs do not establish binary offsets or qualify live retail
executable injection. Bounds validation and failed-cache handling also apply
to the fixed-storage code; preservation of layout is not a claim of identical
behavior for every invalid input.

## Reproducible source tests

The focused runner needs Python 3 and GCC on Linux. It has no game-data,
third-party Python package, SDL, or audio dependency. Use a new output directory:

```sh
python3 -B src/Tests/run_model_cache_test.py --output /tmp/model-cache-test-new
```

The runner compiles the actual storage, load, lookup, free, and world-shutdown
code with a synthetic model parser, allocator failure controls, and a borrowed
key cache fixture. The geometry memory-reporting function is excluded; the
runner checks that its world caller uses the accessor. The COG integration is
checked in source. It exercises:

- Initial-array, sidecar, page, synthetic geometry, and completed-candidate cache
  failures, plus missing-file handling and cleanup.
- Stable loaded pointers and borrowed keys across 1,024 loads, reverse lookup,
  and reuse of existing cache entries.
- Separate current/static stores, 20 growth/free cycles, reused world addresses,
  and hash-before-world shutdown.
- Both 32,768-record boundaries, final valid current/static IDs, invalid IDs,
  and rejection of another uncached model at the ceiling.
- A build without `NO_JK_MMAP` that retains fixed contiguous allocation.
- An expected-failure control that restores the old capacity behavior and must
  fail the specific growth assertion.

Positive builds use AddressSanitizer and UndefinedBehaviorSanitizer with leak
detection enabled. The runner rejects unexpected failures, verifies that source
bytes remain unchanged, and writes `receipt.json` containing the run results
and SHA-256 values of its inputs. Temporary test executables are removed. The
negative control is built only from a temporary source copy.

The dedicated `model-cache-regressions.yml` workflow runs this one suite for
pull requests targeting `master`, pushes to `master`, and manual dispatch. It
has a ten-minute job timeout, read-only repository permissions, and cancellation
of superseded runs. Its checkout action is pinned. It uploads no binaries,
game resources, or evaluation archives.

## Validation boundaries

This upstream submission is based directly on
`798f930402525a23b94671d85b97b00390342fa0`. Its source fixture does not establish
rendering, animation, save/load equivalence, connected multiplayer, complete
mod compatibility, or behavior on every supported platform. Those need separate
runtime and platform validation. It does not depend on fork-specific gameplay,
team-model, capture, or observation-probe changes.

The model parser is synthetic. Arbitrary `rdModel3_LoadEntry` partial-parse
cleanup is not made transactional, and existing parser-owned geometry/material
side effects remain outside this change. The cache rollback controls use unique
canonical flat names; preexisting path-qualified or truncated filename aliases
and replacement/OOM behavior are not repaired here.
