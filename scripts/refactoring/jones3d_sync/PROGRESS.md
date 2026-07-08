# OpenJKDF2 ↔ OpenJones3D naming-sync project

## What this is (read me first — context for future sessions)

**OpenJones3D** (`~/workspace/OpenJones3D`) is a sister decompilation project to
**OpenJKDF2** (`~/workspace/OpenJKDF2`). Jones3D (Indiana Jones and the Infernal
Machine, 1999) runs on a later, modified version of the same **Sith engine** that
powers Jedi Knight: Dark Forces II (JK.EXE, 1997). Because both games share the
Sith engine lineage, they share most engine modules: the `sith`, `std`, `rdroid`,
`sound`, and `w32util` libraries.

The two decompilations were reverse-engineered independently, so **the same
function often has a different name in each project** (e.g. OpenJKDF2
`sithTime_Tick` ↔ OpenJones3D `sithTime_Advance`; `sithTime_SetMs` ↔
`sithTime_SetGameTime`). OpenJones3D was decompiled later against richer symbol
data and generally has more accurate/canonical names (it also carries `J3DAPI`
calling-convention annotations and matched RTI symbol tables).

**Goal of this project:** for every engine module shared by both codebases, rename
the OpenJKDF2 function / struct / member / enum names to match the OpenJones3D
names, one function at a time. This makes the two trees cross-referenceable and
lets fixes/insights flow between them.

## Phases (in order)

1. **Functions** — rename function names. ✅ COMPLETE (91/91).
2. **Globals** — rename file-scope globals via `symbols.syms`. ✅ COMPLETE (37 modules renamed; 8 had only bare-static/DF2-only globals). Build green.
3. **Structs / members / typedefs / enums** ◐ IN PROGRESS. Order names → enums →
   members. Enum adoption width-safe only; member renames name-only +
   layout-preserving (DF2 structs are JK.EXE-hooked — do NOT adopt J3D structural
   reorganizations like union↔sub-struct).
   - **3a struct type NAMES ✅** — sith (43: `sithThing`→`SithThing`, …) + std
     (11: `stdVBuffer`→`tVBuffer`, `stdHashTable`→`tHashTable`, `stdGob`→`Gob`, …);
     `rd*` names already matched. Build green. HAZARD: many type names double as
     module/file names → the apply must not rewrite `.h`/`.c` refs in `#include`s
     (scratchpad `apply_types.py` has a `(?!\.[ch])` lookahead + covers `.cpp`).
     Skipped `stdFileSearch`→`FindFileData` (would shadow a local WIN32_FIND_DATA).
   - **3b enum CONSTANTS ✅** — 115 constant renames (`SITH_TF_LIGHT`→`SITH_TF_EMITLIGHT`,
     `ITEMINFO_*`→`SITHINVENTORY_TYPE_*`, `SITH_PF_*`, `SITH_AF_*`, `COG_*`, `RD_GEOMODE_*`→
     `RD_GEOMETRY_*`, …). DF2 constants already largely matched J3D. **Excluded as
     semantically divergent** (would change behavior): `RD_LIGHTMODE_*` (FULLYLIT↔NONE
     flip), `SITHCOLLISION_THING*` (bit values swapped between projects),
     `SITH_MESSAGE_AUTOSELECT/SKILL` (different messages). Collision-checked, build green.
   - Enum **TYPE naming** (bare `enum THINGTYPE` → `typedef enum eSithThingType {…}
     SithThingType`) is FOLDED INTO 3c — a typedef is only useful once a field adopts
     it, so create the typedef + retype the width-matching field together per struct.
     Map is in scratchpad (27 enums: THINGTYPE→SithThingType, SITH_TF→SithThingFlag,
     MOVETYPE→SithThingMoveType, SITH_CT→SithControlType, ATTACHFLAGS→SithAttachFlag, …).
   - **3c struct members + enum-type field retyping** ◐ IN PROGRESS.
     - **thing-family structs ✅** — 106 member renames (SithThing, SithSector,
       SithSurface, SithWorld, SithActorInfo, SithPhysicsInfo, SithWeaponInfo,
       SithItemInfo, SithExplosionInfo, SithParticleInfo): `thingflags`→`flags`,
       `lifeLeftMs`→`msecLifeLeft`, `nextThing`→`pNextThingInSector`, World's
       `numXLoaded`/`numX`→`numX`/`sizeX` swap-cycles, … Verified on **macOS + TWL
       + Dreamcast** (all three built green).
     - **HARD LESSON (member renames):** member names are NOT globally unique, so
       token-renaming a shared name is unsafe. Must (a) drop cross-struct
       CONFLICTS (`surfaces`/`adjoins` map differently in Sector vs World),
       positional `field_XX`, and generic-common names; (b) **build macOS + TWL +
       Dreamcast** — member accesses live in platform-specific files the macOS
       build never compiles (e.g. `timer`→`msecTimerTime` silently hit maxmod's
       `mm_stream.timer` in `Platform/TWL/stdSound.c`; only the TWL build caught it).
     - **cog/AI/camera/player/event structs ✅** — 64 member renames (SithCog,
       SithCogScript, SithCogSymbol[Table/Value/Ref], SithCamera, SithPlayer,
       SithInventoryType/Item, SithPuppetClass[Submode], SithEvent[Params/Task],
       SithSurfaceAdjoin, SithPathFrame/MoveInfo, SithAIControlBlock, SithAIClass,
       SithAIInstinct[State]). All three platforms green. Tooling: scratchpad
       `process_members.py` (normalizes the 3 agent map formats + filters) →
       `apply_types.py` → build macOS+TWL+DC. The processor now also drops any old
       name shared across >1 CURRENT struct (caught the cross-batch `pLocalPlayer`
       collision).
     - **DEFERRED generic members** (need scoped/AST rename, not token): `position`,
       `sector`, `timer`, `vel`, `flags`, `type`, `surface`, `heap`, `next`, `val`,
       `state`, `thing`, `param1/2/3`, `nextUpdate`, `trigId`, `keyframe`, `func`,
       `linkid`, all `field_XX`, and other shared-in-N names (see process_members.py
       GENERIC list + shared-drop). ~39 dropped in batch 2 alone.
     - **rd* (render) structs ✅** — 42 member renames (rdCamera, rdCanvas,
       rdClipFrustum, rdLight, rdThing, rdKeyframe, rdJoint, rdAnimEntry,
       rdPuppetTrack, rdPuppet, rdMaterial, rdSprite, rdParticle, rdPolyline,
       rdFace, rdMesh, rdGeoset, rdModel3, rdMeshinfo). All three platforms green.
       Compile-driven loop caught: within-struct dupes (`numJoints2`/`cloudRadius`),
       cross-batch `renderData`→`pThing` (collides with SithThing.renderData), and
       maxmod `callback`→`pfCallback` in Platform/TWL/stdSound.c (mm_stream.callback —
       TWL-only, like the earlier `timer` case). Added length guard (drop olds <4
       chars: r/g/b/id/vel) + all-headers uniqueness scan to the processor.
       rd *type*-name diffs (rdThing→rdThingData, rdFace→rdPrimit3, rdColor24→rdRGB,
       rdMeshinfo→rdModel3Mesh) DEFERRED — fuzzy/3a-scope.
     - **std*/sound/collision structs ✅** — 35 member renames (Gob, GobFileHandle,
       tHashTable, tLinkListNode, tMemoryState, tRasterInfo, tVBuffer, StdDisplayInfo,
       StdConffileEntry, stdFileSearch, SithCollision, SithCollideResult,
       sithSoundClass[Entry], sithSound). All three platforms green, no pruning needed
       (hardened processor caught everything upfront). Added guards: drop PascalCase
       olds (a type used as a field, e.g. `StdVideoMode`→`aModes`) and `gap*` positional.
     - **MEMBER NAME RENAMING (3c names) ✅** — 247 renames across ~55 structs, 4
       committed batches, all verified macOS+TWL+Dreamcast.
     - **STILL TODO in 3c**: **enum-type field retyping** (`uint32_t type`→`SithThingType`)
       — 29 targets in scratchpad `all_retypes.json`. NEEDS: (1) convert the bare
       DF2 enums to `typedef enum eName {…} Name;` (structural edits to types_enums.h;
       27-enum map in scratchpad), (2) **reconcile each target's field name** — many
       point at the J3D new name (`rdFace.flags`) but that name rename was DROPPED
       (`type`→`flags` blocklisted), so the field is still its old name; retype the
       ACTUAL current field, (3) verify width/signedness on all 3 platforms.
     - **DEFERRED generic members** — recoverable via clang-AST scoped rename; the
       full drop list is regenerable from `process_members.py` (GENERIC/short/PascalCase/
       positional/shared-in-N filters).
4. **Style match (final)** — for each function, match OpenJones3D's *style* as
   closely as possible **without changing functionality**:
   - **argument names** → adopt J3D's parameter names.
   - **de-inlining** → where DF2 inlined code that J3D factored into a separate
     (already-renamed) helper, call the helper instead — only when behavior is
     identical.
   - **debug prints & asserts** → add J3D's `SITHLOG_*` / `SITH_ASSERTREL` /
     equivalent debug output and assertions.
   - **enum usage** → replace magic-number literals with J3D's named enum
     constants where they already exist in DF2.
   - **HARD LIMIT:** do NOT import additional OpenJones3D *functionality* or new
     code paths — only debug prints and asserts may be added. Everything else must
     be behavior-preserving. NOT STARTED.

## Hard constraints

- **Don't re-home files across directories** to mirror OpenJones3D's
  `Libs/<lib>/<Category>/` tree — that cross-directory reorganization is a
  *future* project. OpenJKDF2 keeps its flat `src/<Category>/` layout.
- **DO rename a C/H file when the module's *file* name differs** between the two
  projects (e.g. `rdPolyLine`↔`rdPolyline`, `stdHashTable`↔`stdHashtbl`,
  `stdLinklist`↔`stdLinkList`), and **split/merge files** when the module
  decomposition differs (e.g. DF2 `sithAICmd` ↔ J3D `sithAIInstinct` +
  `sithAIMove` + `sithAIUtil`) — refactor to match OpenJones3D's file
  organization, staying within the current directory. A file rename also touches
  the `#include`s and the include-guard macro.
  (NB: a differing *function prefix* does not always imply a file rename — J3D's
  `sithMessage_*` functions still live in a file named `sithComm.c`, so `sithComm`
  keeps its filename and only its functions are renamed.)
  - **CMake:** sources come from `file(GLOB ...)` in the root `CMakeLists.txt`
    (no per-file list). A *genuine* file rename (e.g. `stdHashTable.c`→
    `stdHashtbl.c`) must be followed by re-running `cmake .` in the build dir so
    the glob refreshes, or `make` fails looking for the old name. A *case-only*
    rename (`rdPolyLine.c`→`rdPolyline.c`, `stdLinklist.c`→`stdLinkList.c`)
    builds without reconfigure on macOS's case-insensitive FS (same inode), but
    reconfigure anyway to be safe.
  - The type/typedef that shares the module's name (e.g. the `stdHashTable`
    struct, `stdLinklist` struct) is a **type rename → deferred to the struct
    phase**. During the functions pass, rename only the `<module>_*` functions
    (and file); leave the bare type name, so a file can be temporarily
    mixed (`stdHashtbl_*` funcs but still a `stdHashTable` type).
- **Prefer the OpenJKDF2 name when it is clearer than the OpenJones3D name.** The
  goal is the best canonical name, not blind matching. In particular, **skip any
  rename whose J3D target is an unnamed `sub_XXXXXX`** (a Jones3D binary address,
  meaningless in JK.EXE and a loss of information) — keep the DF2 name. The
  reverse, DF2 `sub_XXXXXX` → a descriptive J3D name, **is** applied.
- Follow the OpenJKDF2 `CLAUDE.md` conventions. When a rename changes original
  in-`JK.EXE` code, keep loose-Hungarian conventions; add `// Added:` notes only
  where behavior (not just a name) diverges from the decomp baseline. Pure
  identifier renames that preserve behavior don't need `// Added:`.
- OpenJones3D is the **reference** and is never modified — we only read it.

### Globals-pass naming policy (confirmed with user)

OpenJones3D declares cross-module globals as `<module>_g_<name>` far-vars
(`J3D_DECL_FAR_VAR` in the header; the `.c` body uses a short `g_<name>` alias —
that's the "for g_ symbols the module can be omitted" convention). It also has
many plain **bare file-static** vars with no prefix (`aControlFlags`,
`horizonScale`, `numThingLinks`, `aEvents`).

- For a J3D **far-var** (`<module>_g_<name>`): rename the DF2 global to the full
  `<module>_g_<name>` form (matches J3D's DECL; no cross-module collisions).
- For a J3D **bare file-static** (unprefixed): **SKIP** — DF2 keeps these as
  address-mapped globals in `symbols.syms`, and an unprefixed `extern` would
  pollute the global namespace / risk collisions. Keep the DF2 name.
- Mechanism: globals live in `symbols.syms` (`name 0xADDR c_type`), which cog
  regenerates into `extern`/`_ADDR`. Renaming the name column there + all uses is
  enough — `make` re-runs cog (symbols.syms is a build DEPENDS).

## Method (per module)

1. Open the OpenJKDF2 `.c`/`.h` and the OpenJones3D `.c`/`.h` for the module.
2. Build a function-by-function correspondence. Match by call order, arguments,
   behavior, and referenced globals — **not** by assuming same-name = same-function.
   Use the Ghidra MCP (`http://localhost:8089`, JK.EXE/JKM.EXE) to disambiguate
   when a mapping is unclear.
3. For each confirmed pair where the name differs, rename the OpenJKDF2 symbol to
   the OpenJones3D name across the *whole* OpenJKDF2 tree. Do them **one at a
   time** and keep the build green.
4. Do the same for struct names, struct members, enums, and file-scope globals.

### Where a name lives — every place a rename must touch

A single OpenJKDF2 symbol is referenced from several files beyond the source.
Renaming must be consistent across **all** of them or the build / decomp tooling
breaks:

- **Function name** →
  - `.h` declaration + `.c` definition + every caller `.c`/`.h` in `src/`.
  - Per-function address define `#define <fn>_ADDR (0x...)` — hard-coded in the
    module's own `.h` (e.g. `sithTime.h`), **not** in `symbols.syms`. Rename the
    `<fn>` prefix of the define too.
  - **`ida_copypaste_funclist_nostdlib.txt`** (repo root) — tab-separated IDA
    export used to import function names into Ghidra. Format
    `name\t.text\tADDR\t…`; rename the `name` column.
- **File-scope / cross-module global** →
  - **`symbols.syms`** (repo root) — master global table, format
    `name 0xADDR c_type`. Fed to `globals.h.cog` / `globals.c.cog` by
    `cmake_modules/precompile_globals.cmake`, which auto-generates the
    `extern <type> <name>;` decls and `<name>_ADDR` defines. A global is
    **declared only here** — the `.c` uses it directly, there is no hand-written
    `extern` to edit. Rename the `name` column + every use in `src/`.
  - Some symbols also live in **`symbols_static.sym`** (`name 0xADDR group`) —
    grep both.
- **struct / member / enum** → `types.h`, `types_enums.h` (or a module-internal
  header) + every use.

`scripts/ghidra/importSymbols.py` / `importDataSymbols.py` import `symbols.syms`
into Ghidra, so keeping names synced there also keeps the decompiler DB aligned.

5. **Build macOS after every module** to prove the refactor is complete and
   consistent (this is mandatory, not optional):
   ```sh
   export PATH="/opt/homebrew/opt/llvm/bin:$PATH" MACOSX_DEPLOYMENT_TARGET=10.15 \
          CC=/opt/homebrew/opt/llvm/bin/clang CXX=/opt/homebrew/opt/llvm/bin/clang++
   (cd build_darwin64 && OPENJKDF2_NO_ASAN=1 make -j10 openjkdf2-64)
   ```
   (TWL/DC builds too when touching platform-shared code — see repo `CLAUDE.md`.)
6. **On a green build, commit that module by itself.** `git add` only the files
   the rename changed — `.c` / `.h` / `ida_copypaste_funclist_nostdlib.txt` /
   `symbols.syms` (+ `symbols_static.sym` if touched) — then:
   ```sh
   git commit -m "MODULENAME sync to OpenJones3D names"
   ```
   One commit per module keeps each rename bisectable. Then update this file's
   checkbox + notes (tracker updates can ride along or be a follow-up commit).

Symbols with **no** OpenJones3D counterpart (JK-only features, platform backends,
`jk*` game layer) are left as-is.

## Artifacts

- `module_map.json` — machine-readable map: each shared module → its OpenJKDF2 and
  OpenJones3D source/header paths, plus name/case-difference flags, candidate
  semantic pairs, and the unmatched-module lists. Regenerate with the scratchpad
  generator if the trees change.
- `PROGRESS.md` (this file) — human-readable status. **Source of truth for
  progress.** Tick the ☐ → ☑ per module and jot notes as you go.

## Status legend

`☐` not started `◐` in progress `☑fn` functions-pass done (build green)
`☑` fully done (functions + globals + members) `—` no counterpart / skip

## Progress

**91 shared engine modules** identified (52 sith · 20 rdroid · 18 std · 1 w32util).
Functions-only pass completed: **91 / 91** ✅ COMPLETE.

Current phase: **functions only** (per project decision, globals → struct
members/names/typedefs come in later passes). `_Startup` functions are **kept**
as-is (DF2 soft-reset convention), not renamed to J3D's `_Reset`/`_ResetGlobals`.

### Completed module log

- **sithTime** ☑ (functions-only, build green on darwin64). Renames applied to
  `.c`/`.h`/`_ADDR` defines/callers + `ida_copypaste_funclist_nostdlib.txt`:
  - `sithTime_Tick` → `sithTime_Advance`
  - `sithTime_SetDelta` → `sithTime_SetFrameTime`
  - `sithTime_SetMs` → `sithTime_SetGameTime`
  - Kept (matched already): `sithTime_Pause`, `sithTime_Resume`.
  - Kept per policy: `sithTime_Startup` (J3D calls it `sithTime_Reset`).
  - No J3D counterpart in DF2: `sithTime_InstallHooks`, `sithTime_ResetGlobals`,
    `sithTime_IsPaused` (DF2 reads the `sithTime_bRunning` global directly).
  - Deferred to globals pass: `sithTime_curMs`→`sithTime_g_msecGameTime`,
    `sithTime_deltaMs`→`sithTime_g_frameTime`, `sithTime_curSeconds`→
    `sithTime_g_secGameTime`, `sithTime_TickHz`→`sithTime_g_fps`,
    `sithTime_curMsAbsolute`→`sithTime_g_clockTime`, `sithTime_bRunning`→
    `sithTime_g_bPaused`, `sithTime_pauseTimeMs`→`sithTime_msecPauseStartTime`,
    `sithTime_deltaSeconds`→`sithTime_g_frameTimeFlex` (all in `symbols.syms`).

### sith  (52 modules)

| ☐ | DF2 module | J3D module | DF2 src | J3D src | Notes |
|---|-----------|-----------|---------|---------|-------|
| ☑fn | `sithAI` | `sithAI` | AI/sithAI.c | Libs/sith/AI/sithAI.c |  |
| ☑fn | `sithAIAwareness` | `sithAIAwareness` | AI/sithAIAwareness.c | Libs/sith/AI/sithAIAwareness.c |  |
| ☑fn | `sithAIClass` | `sithAIClass` | AI/sithAIClass.c | Libs/sith/AI/sithAIClass.c |  |
| ☑fn | `sithActor` | `sithActor` | World/sithActor.c | Libs/sith/World/sithActor.c |  |
| ☑fn | `sithCamera` | `sithCamera` | Engine/sithCamera.c | Libs/sith/Engine/sithCamera.c |  |
| ☑fn | `sithCog` | `sithCog` | Cog/sithCog.c | Libs/sith/Cog/sithCog.c |  |
| ☑fn | `sithCogExec` | `sithCogExec` | Cog/sithCogExec.c | Libs/sith/Cog/sithCogExec.c |  |
| ☑fn | `sithCogFunction` | `sithCogFunction` | Cog/sithCogFunction.c | Libs/sith/Cog/sithCogFunction.c |  |
| ☑fn | `sithCogFunctionAI` | `sithCogFunctionAI` | Cog/sithCogFunctionAI.c | Libs/sith/Cog/sithCogFunctionAI.c |  |
| ☑fn | `sithCogFunctionPlayer` | `sithCogFunctionPlayer` | Cog/sithCogFunctionPlayer.c | Libs/sith/Cog/sithCogFunctionPlayer.c |  |
| ☑fn | `sithCogFunctionSector` | `sithCogFunctionSector` | Cog/sithCogFunctionSector.c | Libs/sith/Cog/sithCogFunctionSector.c |  |
| ☑fn | `sithCogFunctionSound` | `sithCogFunctionSound` | Cog/sithCogFunctionSound.c | Libs/sith/Cog/sithCogFunctionSound.c |  |
| ☑fn | `sithCogFunctionSurface` | `sithCogFunctionSurface` | Cog/sithCogFunctionSurface.c | Libs/sith/Cog/sithCogFunctionSurface.c |  |
| ☑fn | `sithCogFunctionThing` | `sithCogFunctionThing` | Cog/sithCogFunctionThing.c | Libs/sith/Cog/sithCogFunctionThing.c |  |
| ☑fn | `sithCogParse` | `sithCogParse` | Cog/sithCogParse.c | Libs/sith/Cog/sithCogParse.c |  |
| ☑fn | `sithCollision` | `sithCollision` | Engine/sithCollision.c | Libs/sith/Engine/sithCollision.c |  |
| ☑fn | `sithComm` | `sithComm` | Devices/sithComm.c | Libs/sith/Devices/sithComm.c |  |
| ☑fn | `sithCommand` | `sithCommand` | Main/sithCommand.c | Libs/sith/Main/sithCommand.c |  |
| ☑fn | `sithConsole` | `sithConsole` | Devices/sithConsole.c | Libs/sith/Devices/sithConsole.c |  |
| ☑fn | `sithControl` | `sithControl` | Devices/sithControl.c | Libs/sith/Devices/sithControl.c |  |
| ☑fn | `sithDSS` | `sithDSS` | Dss/sithDSS.c | Libs/sith/Dss/sithDSS.c |  |
| ☑fn | `sithDSSCog` | `sithDSSCog` | Dss/sithDSSCog.c | Libs/sith/Dss/sithDSSCog.c |  |
| ☑fn | `sithDSSThing` | `sithDSSThing` | Dss/sithDSSThing.c | Libs/sith/Dss/sithDSSThing.c |  |
| ☑fn | `sithEvent` | `sithEvent` | Gameplay/sithEvent.c | Libs/sith/Gameplay/sithEvent.c |  |
| ☑fn | `sithExplosion` | `sithExplosion` | World/sithExplosion.c | Libs/sith/World/sithExplosion.c |  |
| ☑fn | `sithGamesave` | `sithGamesave` | Dss/sithGamesave.c | Libs/sith/Dss/sithGamesave.c |  |
| ☑fn | `sithIntersect` | `sithIntersect` | Engine/sithIntersect.c | Libs/sith/Engine/sithIntersect.c |  |
| ☑fn | `sithInventory` | `sithInventory` | Gameplay/sithInventory.c | Libs/sith/Gameplay/sithInventory.c |  |
| ☑fn | `sithItem` | `sithItem` | World/sithItem.c | Libs/sith/World/sithItem.c |  |
| ☑fn | `sithMain` | `sithMain` | Main/sithMain.c | Libs/sith/Main/sithMain.c |  |
| ☑fn | `sithMaterial` | `sithMaterial` | World/sithMaterial.c | Libs/sith/World/sithMaterial.c |  |
| ☑fn | `sithModel` | `sithModel` | World/sithModel.c | Libs/sith/World/sithModel.c |  |
| ☑fn | `sithMulti` | `sithMulti` | Dss/sithMulti.c | Libs/sith/Dss/sithMulti.c |  |
| ☑fn | `sithOverlayMap` | `sithOverlayMap` | Gameplay/sithOverlayMap.c | Libs/sith/Gameplay/sithOverlayMap.c |  |
| ☑fn | `sithParticle` | `sithParticle` | Engine/sithParticle.c | Libs/sith/Engine/sithParticle.c |  |
| ☑fn | `sithPhysics` | `sithPhysics` | Engine/sithPhysics.c | Libs/sith/Engine/sithPhysics.c |  |
| ☑fn | `sithPlayer` | `sithPlayer` | Gameplay/sithPlayer.c | Libs/sith/Gameplay/sithPlayer.c |  |
| ☑fn | `sithPlayerActions` | `sithPlayerActions` | Gameplay/sithPlayerActions.c | Libs/sith/Gameplay/sithPlayerActions.c |  |
| ☑fn | `sithPuppet` | `sithPuppet` | Engine/sithPuppet.c | Libs/sith/Engine/sithPuppet.c |  |
| ☑fn | `sithRender` | `sithRender` | Engine/sithRender.c | Libs/sith/Engine/sithRender.c |  |
| ☑fn | `sithRenderSky` | `sithRenderSky` | Engine/sithRenderSky.c | Libs/sith/Engine/sithRenderSky.c | funcs done; globals/members pending |
| ☑fn | `sithSector` | `sithSector` | World/sithSector.c | Libs/sith/World/sithSector.c |  |
| ☑fn | `sithSound` | `sithSound` | Devices/sithSound.c | Libs/sith/Devices/sithSound.c |  |
| ☑fn | `sithSoundClass` | `sithSoundClass` | World/sithSoundClass.c | Libs/sith/World/sithSoundClass.c |  |
| ☑fn | `sithSoundMixer` | `sithSoundMixer` | Devices/sithSoundMixer.c | Libs/sith/Devices/sithSoundMixer.c |  |
| ☑fn | `sithSprite` | `sithSprite` | World/sithSprite.c | Libs/sith/World/sithSprite.c |  |
| ☑fn | `sithSurface` | `sithSurface` | World/sithSurface.c | Libs/sith/World/sithSurface.c |  |
| ☑fn | `sithTemplate` | `sithTemplate` | World/sithTemplate.c | Libs/sith/World/sithTemplate.c |  |
| ☑fn | `sithThing` | `sithThing` | World/sithThing.c | Libs/sith/World/sithThing.c |  |
| ☑fn | `sithTime` | `sithTime` | Gameplay/sithTime.c | Libs/sith/Gameplay/sithTime.c | funcs done; globals/members pending |
| ☑fn | `sithWeapon` | `sithWeapon` | World/sithWeapon.c | Libs/sith/World/sithWeapon.c |  |
| ☑fn | `sithWorld` | `sithWorld` | World/sithWorld.c | Libs/sith/World/sithWorld.c |  |

### rdroid  (20 modules)

| ☐ | DF2 module | J3D module | DF2 src | J3D src | Notes |
|---|-----------|-----------|---------|---------|-------|
| ☑fn | `rdCache` | `rdCache` | already matched — no renames | Libs/rdroid/Raster/rdCache.c |  |
| ☑fn | `rdCamera` | `rdCamera` | Engine/rdCamera.c | Libs/rdroid/Engine/rdCamera.c |  |
| ☑fn | `rdCanvas` | `rdCanvas` | already matched — no renames | Libs/rdroid/Engine/rdCanvas.c |  |
| ☑fn | `rdClip` | `rdClip` | Engine/rdClip.c | Libs/rdroid/Engine/rdClip.c |  |
| ☑fn | `rdFace` | `rdFace` | already matched — no renames | Libs/rdroid/Raster/rdFace.c |  |
| ☑fn | `rdKeyframe` | `rdKeyframe` | Engine/rdKeyframe.c | Libs/rdroid/Engine/rdKeyframe.c |  |
| ☑fn | `rdLight` | `rdLight` | already matched — no renames | Libs/rdroid/Engine/rdLight.c |  |
| ☑fn | `rdMaterial` | `rdMaterial` | already matched — no renames | Libs/rdroid/Engine/rdMaterial.c |  |
| ☑fn | `rdMath` | `rdMath` | Primitives/rdMath.c | Libs/rdroid/Math/rdMath.c |  |
| ☑fn | `rdMatrix` | `rdMatrix` | Primitives/rdMatrix.c | Libs/rdroid/Math/rdMatrix.c |  |
| ☑fn | `rdModel3` | `rdModel3` | Primitives/rdModel3.c | Libs/rdroid/Primitives/rdModel3.c |  |
| ☑fn | `rdParticle` | `rdParticle` | Primitives/rdParticle.c | Libs/rdroid/Primitives/rdParticle.c |  |
| ☑fn | `rdPolyLine` | `rdPolyline` | Primitives/rdPolyLine.c | Libs/rdroid/Primitives/rdPolyline.c | case differs |
| ☑fn | `rdPrimit2` | `rdPrimit2` | Primitives/rdPrimit2.c | Libs/rdroid/Primitives/rdPrimit2.c |  |
| ☑fn | `rdPrimit3` | `rdPrimit3` | Primitives/rdPrimit3.c | Libs/rdroid/Primitives/rdPrimit3.c |  |
| ☑fn | `rdPuppet` | `rdPuppet` | Engine/rdPuppet.c | Libs/rdroid/Engine/rdPuppet.c |  |
| ☑fn | `rdSprite` | `rdSprite` | already matched — no renames | Libs/rdroid/Primitives/rdSprite.c |  |
| ☑fn | `rdThing` | `rdThing` | already matched — no renames | Libs/rdroid/Engine/rdThing.c |  |
| ☑fn | `rdVector` | `rdVector` | Primitives/rdVector.c | Libs/rdroid/Math/rdVector.c |  |
| ☑fn | `rdroid` | `rdroid` | Engine/rdroid.c | Libs/rdroid/Main/rdroid.c |  |

### std  (18 modules)

| ☐ | DF2 module | J3D module | DF2 src | J3D src | Notes |
|---|-----------|-----------|---------|---------|-------|
| ☑fn | `std` | `std` | already matched — no renames | Libs/std/General/std.c |  |
| ☑fn | `std3D` | `std3D` | GL/platform reimpl — no confident renames | Libs/std/Win95/std3D.c | 5 platform variants |
| ☑fn | `stdBmp` | `stdBmp` | already matched — no renames | Libs/std/General/stdBmp.c |  |
| ☑fn | `stdColor` | `stdColor` | already matched — no renames | Libs/std/General/stdColor.c |  |
| ☑fn | `stdComm` | `stdComm` | Win95/stdComm.c | Libs/std/Win95/stdComm.c |  |
| ☑fn | `stdConffile` | `stdConffile` | General/stdConffile.c | Libs/std/General/stdConffile.c |  |
| ☑fn | `stdConsole` | `stdConsole` | Win95/stdConsole.c | Libs/std/Win95/stdConsole.c |  |
| ☑fn | `stdControl` | `stdControl` | Platform/Common/stdControl.c<br>Platform/Dreamcast/stdControl.c<br>Platform/SDL2/stdControl.c<br>Platform/TWL/stdControl.c | Libs/std/Win95/stdControl.c | 4 platform variants |
| ☑fn | `stdDisplay` | `stdDisplay` | already matched — no renames | Libs/std/Win95/stdDisplay.c |  |
| ☑fn | `stdFileUtil` | `stdFileUtil` | General/stdFileUtil.c | Libs/std/General/stdFileUtil.c |  |
| ☑fn | `stdFnames` | `stdFnames` | already matched — no renames | Libs/std/General/stdFnames.c |  |
| ☑fn | `stdGob` | `stdGob` | Win95/stdGob.c | Libs/std/Win95/stdGob.c |  |
| ☑fn | `stdHashTable` | `stdHashtbl` | General/stdHashTable.c | Libs/std/General/stdHashtbl.c | **semantic rename** |
| ☑fn | `stdLinklist` | `stdLinkList` | General/stdLinklist.c | Libs/std/General/stdLinkList.c | case differs |
| ☑fn | `stdMath` | `stdMath` | General/stdMath.c | Libs/std/General/stdMath.c |  |
| ☑fn | `stdMemory` | `stdMemory` | General/stdMemory.c | Libs/std/General/stdMemory.c |  |
| ☑fn | `stdPlatform` | `stdPlatform` | already matched — no renames | Libs/std/General/stdPlatform.c |  |
| ☑fn | `stdStrTable` | `stdStrTable` | General/stdStrTable.c | Libs/std/General/stdStrTable.c |  |

### w32util  (1 modules)

| ☐ | DF2 module | J3D module | DF2 src | J3D src | Notes |
|---|-----------|-----------|---------|---------|-------|
| ☑fn | `wuRegistry` | `wuRegistry` | Platform/Posix/wuRegistry.c<br>Platform/Win32/wuRegistry.c | Libs/w32util/wuRegistry.c | 2 platform variants |

## Candidate semantic pairs (different filenames — verify before acting)

| DF2 | J3D | Note |
|-----|-----|------|
| `sithAICmd` | `sithAIInstinct`, `sithAIMove`, `sithAIUtil` | DF2 merged AI cmd/instinct into one file; J3D splits |
| `sithAnimClass / sithKeyFrame` | `sithAnimate` | keyframe/anim naming differs |
| `util` | `stdUtil` | verify identity |
| `stdSound` | `Sound`, `AudioLib`, `Driver` | J3D sound stack split across sound lib |
| `stdFont` | `rdFont` | font lives under rdroid in J3D |
| `Window / Windows` | `wkernel` | windowing/kernel layer |
| `std / WinIdk` | `stdWin95` | win95 platform glue |
| `sithStrTable` | `sithString` | verify identity |

## Unmatched — OpenJones3D modules with no direct OpenJKDF2 file (40)

`AudioLib`, `Driver`, `Indy3D`, `JonesConsole`, `JonesControl`, `JonesDialog`, `JonesDisplay`, `JonesFile`, `JonesHud`, `JonesMain`, `Sound`, `dllmain`, `exemain`, `jonesCog`, `jonesConfig`, `jonesInventory`, `jonesString`, `rdFont`, `rdQClip`, `rdWallpaper`, `sithAIInstinct`, `sithAIMove`, `sithAIUtil`, `sithAnimate`, `sithCogFlex`, `sithCogYacc`, `sithFX`, `sithPVS`, `sithPathMove`, `sithPlayerControls`, `sithShadow`, `sithString`, `sithVehicleControls`, `sithVoice`, `sithWhip`, `stdCircBuf`, `stdEffect`, `stdUtil`, `stdWin95`, `wkernel`

## Unmatched — OpenJKDF2 modules with no direct OpenJones3D file (113)

`Darray`, `DirectX`, `InstallHelper`, `Main`, `Video`, `WinIdk`, `Window`, `Window_Dreamcast`, `Window_Twl`, `Windows`, `crc32`, `dcDebug`, `dcFault`, `dcRamFat`, `dcStorage`, `dcVmu`, `dlmalloc`, `hook`, `jk`, `jkAI`, `jkCog`, `jkControl`, `jkCredits`, `jkCutscene`, `jkDSS`, `jkDev`, `jkEpisode`, `jkGUI`, `jkGUIBuildMulti`, `jkGUIControlOptions`, `jkGUIControlSaveLoad`, `jkGUIDecision`, `jkGUIDialog`, `jkGUIDisplay`, `jkGUIEsc`, `jkGUIForce`, `jkGUIGameplay`, `jkGUIGeneral`, `jkGUIJoystick`, `jkGUIKeyboard`, `jkGUIMain`, `jkGUIMap`, `jkGUIMods`, `jkGUIMouse`, `jkGUIMultiTally`, `jkGUIMultiplayer`, `jkGUINetHost`, `jkGUIObjectives`, `jkGUIPlayer`, `jkGUIRend`, `jkGUISaveLoad`, `jkGUISetup`, `jkGUISingleTally`, `jkGUISingleplayer`, `jkGUISound`, `jkGUITitle`, `jkGame`, `jkGob`, `jkHud`, `jkHudCameraView`, `jkHudInv`, `jkHudScope`, `jkMain`, `jkPlayer`, `jkQuakeConsole`, `jkRes`, `jkSaber`, `jkSmack`, `jkStrings`, `jkgm`, `lex.yy`, `main`, `main_globals`, `md5`, `rdActive`, `rdColormap`, `rdDebug`, `rdRaster`, `rle_test`, `shader_utils`, `sithAICmd`, `sithAnimClass`, `sithArchLighting`, `sithCvar`, `sithKeyFrame`, `sithMap`, `sithStrTable`, `sithTrackThing`, `stdBitmap`, `stdBitmapRle`, `stdComm_GNS`, `stdComm_basic`, `stdComm_none`, `stdDisplay_Dreamcast`, `stdDisplay_Twl`, `stdEmbeddedRes`, `stdFont`, `stdGdi`, `stdHttp`, `stdJSON`, `stdLbm`, `stdMci`, `stdPalEffects`, `stdPcx`, `stdSingleLinklist`, `stdSound`, `stdString`, `stdUpdater`, `unusedWontImpl`, `util`, `version`, `wprintf`, `y.tab`
