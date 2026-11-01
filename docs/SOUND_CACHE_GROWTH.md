# Stable world sound-cache growth

A world's declared sound count currently fixes its sound-header capacity.
Later requests for distinct existing WAV resources can fill that array, so
soundclass loading can lose event bindings despite the requested files being
available. Reallocating the array would move `sithSound*` values retained by
soundclass nodes, mixer voices, sectors, and the filename cache.

This change adds nonmoving sound-header pages in source-built engines. It is
based directly on upstream and is independent of the model-cache proposal:
model allocation, model accessors, and model tests are unchanged.

## Storage, publication, and ownership

`SithWorld.sounds` keeps its original pointer type and initial contiguous
allocation. Under `NO_JK_MMAP`, each overflow page records its owning world and
index interval. Pages hold up to 256 records and never move. PCM buffers remain
separately managed by the existing audio backend.

`SITHSOUND_MAX_RECORDS` and `SITHSOUND_PAGE_RECORDS` live in `engine_config.h`.
The maximum of 32,767 records is constrained by the existing ID encoding:
current IDs stop at `0x7ffe`, static IDs retain the `0x8000` tag and stop at
`0xfffe`, and `0xffff` remains unallocated because signed network handling uses
`-1` as a sentinel. Raising the maximum requires revisiting that encoding. This
change does not alter signed packet decoding or repair preexisting static-sound
wire behavior.

Declared counts are checked before source-built allocation. The existing MotS
reservation remains included in the total. A lazily populated empty world
receives one cleanable initial slot. On a full pool, a new page is staged before
parsing the candidate WAV header and attached only after parsing and cache
insertion succeed. Allocation, synthetic parse, and cache-insertion failures
leave loaded counts and existing headers unchanged, clear the candidate, free
staged pages, and close opened files. A first failed load can retain the empty
world's one-slot reserve until normal cleanup.

`sithSound_GetWorldSoundByIndex` resolves both initial records and overflow
pages. Ordinary ID lookup, COG sound-pop, memory accounting, PCM eviction, and
teardown use it. Eviction preserves the existing playing, recent-use, and
`field_40` protection checks for records on pages as well as the initial array.

Teardown removes cache keys while their headers remain alive, unloads each
buffer once, unlinks only this world's pages, and frees its initial array. The
source-built current-world shutdown fallback also releases its sound store
before freeing the world address. The hash table owns its nodes, not the sound
headers. No model-cache cleanup is introduced by this independent change.

Original-executable injection retains fixed contiguous storage. Overflow is
disabled without `NO_JK_MMAP`, because unhooked original binary consumers may
index the original array directly. Neither `SithWorld` nor `sithSound` changes
layout. The guard follows the storage consumer distinction rather than changing
an original binary's layout through a quality-of-life option.

## File-handle compatibility

The current upstream `stdFile_t` is pointer-sized. File search, WAV-header
loading, and close retain that type throughout the modified path. The fixture
extracts the production typedef and, on a 64-bit host, uses a handle above
`UINT32_MAX`; parsing and close must receive the exact same value. A compile-time
check prevents a narrowed production typedef from silently weakening this
control. The actual PCM-loading path is stubbed, so this check does not claim
coverage of every audio or file backend.

## Reproducible source tests

The focused runner needs Python 3 and GCC on Linux. It requires no game data,
third-party Python package, SDL, or audio backend. Use a new output directory:

```sh
python3 -B src/Tests/run_sound_cache_test.py --output /tmp/sound-cache-test-new
```

The runner compiles production storage, ID lookup, COG sound-pop, sound memory
accounting, PCM eviction/free, and world-shutdown code. It uses the production
sound struct and file-handle typedef, a reduced world struct, and controlled
WAV/audio/cache I/O. It exercises:

- Initial/page allocation failure, synthetic parse failure, failed cache insertion,
  missing files, wide file handles, and cleanable empty-world failures.
- Stable pointers and borrowed keys through growth and cache reuse, separate
  current/static ownership, and repeated growth/free with world-address reuse.
- Both 32,767-record ceilings, final valid IDs, sentinel and invalid-ID behavior,
  MotS reservation accounting, and rejection of another sound at the ceiling.
- PCM accounting and page-record eviction, including playing, recent-use, and
  `field_40` protection, plus cache-before-world shutdown.
- A build without `NO_JK_MMAP` that retains fixed contiguous allocation.
- Five expected-failure controls: restored fixed capacity, ignored cache failure,
  eviction skipping pages, leaked pages, and incorrect static ID tagging. Each
  must fail its intended assertion.

Positive builds use AddressSanitizer and UndefinedBehaviorSanitizer with leak
detection enabled. The runner checks that source bytes remain unchanged and
writes `receipt.json` containing run results and input SHA-256 values. Test
executables and altered negative-control sources stay in a temporary directory
and are removed afterward.

The dedicated `sound-cache-regressions.yml` workflow runs this one suite for
pull requests targeting `master`, pushes to `master`, and manual dispatch. It
has a ten-minute timeout, read-only repository permissions, cancellation of
superseded runs, and a pinned checkout action. It uploads no binaries, game
resources, or evaluation archives.

## Validation boundaries

This upstream submission is based directly on
`798f930402525a23b94671d85b97b00390342fa0`. It has no dependency on the separate
model-cache branch or on fork-specific team-model, gameplay, capture, or
observation-probe changes. No historical combined-fork runtime result is a
qualification of this independent source revision.

The fixture uses a synthetic WAV parser and backend. It does not establish real
PCM decoding, audible playback, backend shutdown behavior, rendering, save/load,
connected multiplayer, full mod compatibility, or every supported platform.
The fixed-allocation test does not establish original binary offsets or live
retail injection. Those need separate runtime and platform validation.

The rollback controls use unique canonical flat names. Preexisting
path-qualified/truncated-name aliases and cache replacement/OOM behavior remain
outside the transaction claim. This change does not alter the real WAV parser's
accepted formats or make its arbitrary partial-parse side effects transactional.

## Shutdown composition and growth policy

The fixture retains the complete production `sithWorld_Shutdown` body. Its
reduced world represents the other cache's pointer as opaque storage and provides
an unrelated-cache cleanup stub. The composed run supplies a live counterpart
allocation and requires its cleanup before the world is freed, while the real
cache under test must release all of its own pages. The independent run and
fixed-allocation build remain covered. This is a host ownership boundary test;
it does not run the other parser/backend or establish full-engine ABI behavior.
The composed cleanup is added only to a temporary extracted fragment when the
other topic has not landed; source files are never rewritten by the runner.

Overflow growth is intentionally enabled for `NO_JK_MMAP` source-built engines,
including source-built non-QOL configurations. It is not currently gated by
`QOL_IMPROVEMENTS`. Original-executable injection retains fixed contiguous
storage. This correction changes tests and CI scope, not that feature policy.

A safe control removes only the temporary counterpart cleanup call and must
fail the pre-world-free ownership assertion; a compile error does not count.
