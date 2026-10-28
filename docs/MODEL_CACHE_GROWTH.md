# Stable world model-cache growth

Repeated legitimate appearance changes can exhaust a world's declared model
slots even when every requested model exists. In the reproduced MotS `k1.jkl`
case, the initial world held 93 models in 109 slots. The eighteenth distinct
appearance request exhausted those slots and the production appearance path
selected a fallback. Reversing the same 32-model sequence failed on a different
model; both failing models loaded in fresh processes. Repeating a cached model
32 times did not increase occupancy.

The fix grows the world model store without moving a loaded `rdModel3` header.
The unchanged 32-model sequence now completes in either order, ending at 124
models in 218 slots. This is a model-storage result. The separate WAV pool still
rejects sound loads, and matching soundclass identity does not establish that
all its events loaded.

## Storage and compatibility

`SithWorld.aModels` retains its original pointer type and initial contiguous
allocation. Source-built engines (`NO_JK_MMAP`) keep a world-owned sidecar with
nonmoving overflow pages. A new page grows capacity geometrically, with a
minimum increment of 32 and an explicit maximum of 32,768 slots per world.
A zero-declared source-built world gets 32 initial slots so later dynamic loads
and normal teardown have the same ownership path.

Existing model addresses and the filename strings borrowed by the model hash
remain stable. A page is staged before loading its first candidate and attached
only after a successful load and cache insertion. Initial-array, sidecar and
page allocation failures do not publish partial storage. Cache insertion
failure frees a fully loaded candidate's geometry before discarding its header;
the materials remain owned by the world.

The validated `sithModel_GetWorldModelByIndex` accessor resolves both the initial
array and pages. The COG model-pop path uses `sithModel_GetModelByIndex`, and
world memory accounting uses the world/index accessor. Only the internal slot
accessor directly indexes the initial model array. Invalid negative and
out-of-range IDs are rejected before the static-world bit is decoded.

IDs stay append-only: current-world indexes are `0x0000..0x7fff`, and static
indexes retain the `0x8000` tag through `0xffff`. Current and static stores have
separate ownership. Teardown removes borrowed cache keys while their headers
are alive, frees each loaded geometry once, detaches the sidecar, then frees its
pages and initial array. Hash shutdown does not own those allocations. The
source-built current-world shutdown fallback also releases its model store
before freeing the world address.

Overflow pages are intentionally disabled for original-executable injection.
Some original binary consumers still index `aModels` directly and are not
replaced by hooks. That build retains its fixed contiguous layout; changing
the struct's pointer type would not make those consumers compatible.

## Source tests

Run with GCC on Linux, using a new output directory:

```text
python3 -B src/Tests/run_model_cache_test.py --output /tmp/model-cache-test-new
python3 -B src/Tests/run_team_model_test.py --cc gcc --ubsan
```

The model test compiles the production storage/load/index/free functions with
a synthetic model parser, allocator-failure injection and a borrowed-key cache
fixture. It excludes the geometry memory-reporting routine and stubs unrelated
world cleanup; it is not a malformed-3DO parser test. AddressSanitizer,
UndefinedBehaviorSanitizer and leak detection passed for:

- Initial-array, sidecar, growth-page and synthetic geometry allocation failure,
  plus completed-candidate cache insertion failure and missing-file controls.
- Stable loaded pointers and borrowed filename keys across 1,024 loads, reverse
  lookup and cache reuse.
- Static/current cache reuse and independent teardown, 20 grow/free cycles with
  reused world addresses, and hash-before-world shutdown ordering.
- Both 32,768-slot boundaries, valid final current/static IDs, invalid IDs, and
  rejection of a further uncached model.
- A separate build without `NO_JK_MMAP` retaining fixed contiguous storage.
- An old fixed-capacity negative control that fails the required growth assertion.

The existing team/model packet suite also passed its 102 cases and 2,037
assertions, including its old-index-mapping negative control and UBSan cases.

## Bounded runtime evidence, 2026-09-20

The Windows Release qualification build combined base
`28ec799f1dab3f3954b4d395d19711c2204c43b1`, this six-file source/test change, and a
separately preserved opt-in observation probe. The probe exercises the ordinary
MotS appearance function on a real local player, records requested and actual
model/soundclass identity and resource counters, and retains full-pool sound
rejections. The observation probe is not part of this source change.

The native map and converted overlay were unchanged in every run. Runs were
sequential, hidden, used null audio, and recorded no visible or foreground owned
window at the 100 ms sampling interval. Sampling cannot exclude a transient
between observations. No maps, models or sound resources were edited.

| Control | Identity requests passed | Initial/final model use | Sound rejection events |
| --- | ---: | --- | ---: |
| Forward, 32 distinct Al models | 32/32 | 93/109 to 124/218 | 212 |
| Reverse, same 32 models | 32/32 | 93/109 to 124/218 | 179 |
| Cached Vallo, repeated 32 times | 32/32 | 93/109 to 93/109 | 0 |
| Fresh Muftak | 1/1 | 93/109 unchanged | 6 |
| Fresh Duros | 1/1 | 93/109 unchanged | 6 |
| Fresh Bespin Chewbacca | 1/1 | 93/109 unchanged | 0 |

All six processes exited zero with the expected multiplayer world and mode.
The forward/reverse static model store stayed at 27/32; material use reached
753/1288 without a material-capacity rejection. The cached run's model and
material counts remained unchanged. The WAV pool still reached 153/153.

Separate native initial-render controls passed for MotS Kyle and Mara in
`k1.jkl`, and JK in `m2.jkl`, with the appearance probe disabled and no resource
diagnostics. A first Mara receipt was rejected by the case-sensitive checker
because it expected table spelling `kyMJ.3do`, while the engine canonicalized it
to `kymj.3do`. That receipt is preserved; the subsequent explicit canonical-name
control passed. This was a checker correction, not a resource substitution.

The rendered images confirm bounded world rendering. They do not show every
selected skin or prove its animation; the identity checks come from the actual
player's model and soundclass bindings.

Provenance SHA-256 values for the private evidence:

| Artifact | SHA-256 |
| --- | --- |
| Six-file growth patch before this document | `b1877ff575216aa1b28a7f457c189ca306903ed0568eedecb99a2460c640fdf6` |
| Observation probe patch | `e84edd5b001d94ada705dc14418beb02a801f492ab9b1eb1ef8f704826d3e089` |
| Combined patch, replayed against the exact base | `eddfe7914c8ae82cf9f1110b010814a7105e6df9092e9ce92ed138a2f90776a1` |
| Windows qualification executable | `caebc2ac8ba28f3c34ecdfeb702c99aa758ecefe60f84bc2d5e1703ea160c945` |

The whole engine build completed using an isolated copied dependency cache.
The 2,601 pinned engine source files were verified unchanged after the build.
It was not a warning-free build: existing unrelated COG/world warnings and
dependency patch reapplication messages remain in the retained build log.
There were no model-source compiler warnings. The combined capture contract/UI
tests passed under ASan/UBSan, including the unsafe-window-raise negative control.

## Qualification on the synchronized base, 2026-10-28

The original model-cache commit `bf7a46f8dc30ddc6fd4734326935a6ea07081ef7`
was carried onto fork main `6fa54630a123485d8c7b602c47992613a1f397b5`, which
contains upstream `798f930402525a23b94671d85b97b00390342fa0`. Git's three-way
application preserved the current upstream context. The production model-store
sanitizer fixture passes on this base, including leak checks, the fixed-layout
injection build, and the old-capacity negative control. The team/model runner
also passes its 102 cases and 2,037 assertions under UBSan.

The three changed production units (`sithModel.c`, `sithWorld.c`, and
`sithCogExec.c`) compile successfully with the current native Linux build's
CMake-derived flags and dependency headers. This is a focused compilation,
not a new full-engine link or game launch. The known COG stack-copy warning
is a separate proposed correction. The new cache CI job runs the asset-free
model and team checks on relevant pull requests and main pushes.

The September Windows/MotS results above remain historical evidence at their
named base. This requalification has not rerun the MotS appearance sequence,
save/load, connected multiplayer, or audible playback on the synchronized
engine. Those remain acceptance gates before treating this draft as a
general mod-compatibility guarantee.

## Remaining boundaries

- Sound allocation is unchanged. This result does not establish complete audio,
  audible playback, original-game parity or complete mod support.
- The rollback fixture uses unique canonical flat names, as do these Al inputs.
  Preexisting path-qualified/truncated filename aliases can replace a canonical
  hash entry; that alias/OOM behavior is not repaired here.
- Arbitrary `rdModel3_LoadEntry` partial-parse cleanup is not transactional today.
  This fix does not claim to undo partial geometry/material side effects from a
  malformed 3DO or repair the parser's existing cleanup limitations.
- The runtime probe repeatedly changes one real local player in one world. It
  does not establish 32 simultaneous peers, GUI traversal, save/load equivalence,
  multiplayer serialization/load-order equivalence or complete gameplay.
- The sanitizer fixture and Windows Release runtime are separate evidence.
  Runtime model-growth success is not a claim that the full game ran under
  sanitizers or that every allocator-failure path in the engine is covered.
