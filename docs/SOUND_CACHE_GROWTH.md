# Stable world sound-cache growth

Legitimate appearance changes can exhaust a world's declared sound slots even
when the requested WAVs exist. In the reproduced MotS `k1.jkl` case, the fixed
pool reached 153/153. Soundclass identity still matched, because the class
loader skipped events whose WAV headers could not be loaded. The earlier
model-only fix therefore did not establish complete soundclass bindings. Its
separate evidence remains in [MODEL_CACHE_GROWTH.md](MODEL_CACHE_GROWTH.md).

This change grows sound-header storage without moving published `sithSound`
records. With the same map, overlay and 32-appearance sequence, forward and
reverse requests now finish at 191 sounds in 409 slots, with no model or sound
capacity rejection. An independent comparison also checks every linked event
and its WAV header against the exact mounted source bytes. This is not an
audible-playback result.

## Storage and compatibility

`SithWorld.sounds` keeps its original pointer type and initial contiguous
allocation. Source-built engines (`NO_JK_MMAP`) append nonmoving pages of up to
256 sound records. The page registry identifies its owning world; current and
static worlds remain separate. Soundclass nodes, mixer voices, sector sound
pointers and the cache's borrowed filename keys keep their original addresses.
PCM buffers remain separately managed by the existing audio backend.

The maximum is 32,767 records per world. Current-world indexes stop at `0x7ffe`;
static indexes retain the `0x8000` tag and stop at `0xfffe`, leaving `0xffff`
unallocated because signed network handling uses `-1` as a sentinel. This patch
does not change signed packet decoding or claim to repair preexisting
static-sound wire behavior. Declared counts are checked before allocation in
source-built engines. The existing MotS reservation remains included in the
total, and a lazily populated empty world receives one cleanable initial slot.

At the full-pool boundary, a page is staged before parsing the new WAV header.
It is published only after parsing and cache insertion succeed. Allocation,
synthetic parse and cache-insertion failures leave loaded counts and previously
published headers unchanged; staged pages are freed, candidate headers cleared,
and opened files closed. A first failed load in an empty world can retain its
one-slot initial reserve until normal cleanup. These transaction claims cover
unique canonical flat names, not the preexisting alias behavior discussed below.

`sithSound_GetWorldSoundByIndex` resolves both initial records and overflow
pages. The COG sound-pop path, ordinary ID lookup, memory accounting, PCM
eviction and teardown use it. PCM eviction retains the existing playing,
recent-use and `field_40` protection checks for page records as well as initial
records. Teardown removes borrowed cache keys while headers remain alive,
unloads each buffer once, detaches/frees pages, and then frees the initial array.
Hash shutdown does not own those allocations. The source-built current-world
shutdown fallback now releases both model and sound stores before freeing the
world address.

Original-executable injection keeps fixed contiguous allocation. Overflow is
disabled without `NO_JK_MMAP`; unhooked original binary consumers may still
index the original array directly. Neither `SithWorld` nor `sithSound` changes
layout.

## Source tests

Run with GCC on Linux, using new output directories:

```text
python3 -B src/Tests/run_sound_cache_test.py --output /tmp/sound-cache-test-new
python3 -B src/Tests/run_model_cache_test.py --output /tmp/model-cache-test-new
```

The combined source passed both storage suites under AddressSanitizer,
UndefinedBehaviorSanitizer and leak detection. The sound fixture compiles the
production storage, ID lookup, COG sound-pop, memory-accounting, PCM eviction,
free and shutdown functions with synthetic WAV/audio/cache I/O. It checks:

- Initial/page allocation failure, parse failure, cache-insertion failure,
  missing files, closed file handles and cleanable empty-world failures.
- Stable published pointers and borrowed keys across growth and cache reuse,
  separate current/static ownership, repeated grow/free and world-address reuse.
- The 32,767-record ceilings in both worlds, final valid IDs, sentinel and
  invalid-ID rejection, and rejection of another uncached sound at the ceiling.
- PCM accounting and eviction of page records, including playing, recent-use
  and `field_40` protection, plus global-cache-before-world shutdown.
- A separate build without `NO_JK_MMAP` retaining fixed contiguous storage.
- Five mutations that must fail their intended assertions: restored fixed
  capacity, ignored cache failure, eviction skipping pages, leaked pages, and
  incorrect static tagging.

The model fixture also passed after the shared COG/world integration. Each
fixture stubs the other store as empty while testing actual shared shutdown;
it does not claim synthetic joint model-and-sound backend teardown coverage.
Both stores coexist in the separate full-engine runtime below.

## Bounded runtime evidence, 2026-09-20

The private Windows Release build combines model commit
`bf7a46f8dc30ddc6fd4734326935a6ea07081ef7`, this sound integration and a separately
preserved opt-in observation probe, on original base
`28ec799f1dab3f3954b4d395d19711c2204c43b1`. Probe code is not part of this source
change. It calls the ordinary appearance setter on one real local player and
records actual model/soundclass identity, store counts and linked event data.

All six Al processes exited zero in the expected multiplayer world and mode.
The exact native world and converted overlay remained unchanged. Runs were
sequential and hidden with null audio. No owned visible or foreground window
was observed at the 100 ms sampling interval; that sampling does not exclude
a transient between observations. No map, model or sound asset was edited.

| Control | Requests passed | Sound use before/after | Linked events checked | Distinct sound IDs |
| --- | ---: | --- | ---: | ---: |
| Forward, 32 distinct Al models | 32/32 | 152/153 to 191/409 | 2,119 | 80 |
| Reverse, same 32 models | 32/32 | 158/409 to 191/409 | 2,119 | 80 |
| Cached Vallo, repeated 32 times | 32/32 | 152/153 unchanged | 1,920 | 37 |
| Fresh Muftak | 1/1 | 158/409 unchanged | 70 | 43 |
| Fresh Duros | 1/1 | 158/409 unchanged | 70 | 43 |
| Fresh Bespin Chewbacca | 1/1 | 147/153 unchanged | 68 | 36 |

Some fresh profiles already need a page while loading their initial character,
before the first probe request. Forward/reverse model occupancy moves from
93/109 to 124/218; static models remain 27/32. The cached model and sound stores
do not grow. No model, sound or material capacity rejection occurs in these six
runs.

The independent offline comparator pins the archive bytes, provider precedence,
production mode table and per-run evidence hashes. It compares all ordered
authored SND rows, including explicit `none`, flags and radii/volume defaults
(`0x40`, `0.5`, `2.5`, `1.0`), with the actual linked event lists. It validates
loaded sound IDs against their world/index pointer and independently parses
the selected WAV's sample rate, channel flag, bit depth, data length and offset.
Repeated cached classes must retain identical semantic event lists. All six
comparisons pass with zero omission allowance. Its synthetic controls reject
15 deliberately corrupted/missing event, header, parameter, pointer, mode,
resource, provider-hash and parser cases.

Separate native initial-render controls pass for MotS Kyle and Mara in
`k1.jkl`, and JK in `m2.jkl`, with the appearance probe disabled, three rendered
frames, no resource diagnostics and unchanged inputs. Rendered images were
inspected and show textured initial scenes. First-person views do not establish
the selected character's body or animation.

The first combined build was rejected before any game launch: its private
observation source lacked the sound API header, causing an implicit function
declaration and pointer/integer comparison warnings. The rejected executable,
log and explicit rejection receipt remain preserved. The replacement includes
the declaration and has no changed model/sound/probe source warnings. Existing
unrelated engine/dependency warnings remain; this is not a warning-free build.
All 2,604 pinned source-file hashes were unchanged after the successful build.
Capture contract/UI tests and the separate binding-probe fixture passed under
ASan/UBSan; the full Windows game itself was a Release build.

Private-evidence SHA-256 values, without redistribution of game assets:

| Artifact | SHA-256 |
| --- | --- |
| Sound source/test integration patch relative to the model commit, before this document | `3efafd8d7b3031420ec6a1d06714ef793f32a40aa3103e93d81f5602ae61f8d1` |
| Combined model/sound/probe patch, replayed against the exact original base | `dd75def9e6307fd6b5f4077ff40e69ee6e61e6cdc0b744324d9215e4889be705` |
| Rejected first executable, never launched | `caf5cfb6e7b5bdd1e8c1428c42c4ea08a53532053d50780211b2563a3e6c0045` |
| Qualified replacement executable | `658ff65ebb6ddfc8feab5bc2721ee02fcbda5a97bd38cd62f43e7d3b630a28e6` |
| Independent binding comparator | `75e5fe435a6cd985fe4fd7e44bbffb8696eeefcdbea769643b6e69bb55ee9e4f` |
| Forward binding-comparison receipt | `1f81b3eca974ac44778e7f7bf8612746566331ff151a85d468e13f70cfdba79a` |
| Reverse binding-comparison receipt | `4ead692e65c34e4536e9a8c04fb984966b4066ca499f3bbf965da242eb901381` |

## Remaining boundaries

- Linked event/header completeness does not prove PCM decoding, actual backend
  playback, audible sound, original-game parity or complete mod support. The
  null-audio runs do not exercise those playback paths.
- Qualification covers the selected 32 models and their 13 soundclasses, not
  all 135 characters or every source mod dependency. It does not resolve native
  voice-content differences or unrelated original missing resources.
- Runtime requests repeatedly change one local player in one world. They do
  not establish GUI traversal, 32 simultaneous peers, save/load equivalence,
  network load-order equivalence or complete gameplay.
- The fixture uses a synthetic WAV parser and audio backend. This change does
  not harden the real WAV parser, repair arbitrary malformed-input side effects,
  or change its accepted formats. The offline comparator rejects unreviewed
  grammar/encoding cases instead of generalizing from these inputs.
- Canonical flat names of at most 31 bytes are used by these controls.
  Preexisting path-qualified/truncated-name alias and cache replacement/OOM
  behavior remains outside the transaction claim.
- Original-executable injection is tested with the storage fixture, not a
  live retail executable. This work remains on the stated base; no later
  upstream merge or broader allocator redesign is implied.
