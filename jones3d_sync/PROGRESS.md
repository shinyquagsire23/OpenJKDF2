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
  the `#include`s, the include-guard macro, and `CMakeLists.txt`.
  (NB: a differing *function prefix* does not always imply a file rename — J3D's
  `sithMessage_*` functions still live in a file named `sithComm.c`, so `sithComm`
  keeps its filename and only its functions are renamed.)
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
Functions-only pass completed: **72 / 91**.

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
| ☐ | `std` | `std` | Win95/std.c | Libs/std/General/std.c |  |
| ☐ | `std3D` | `std3D` | Platform/D3D/std3D.c<br>Platform/Dreamcast/std3D.c<br>Platform/GL/std3D.c<br>Platform/GL11/std3D.c<br>Platform/TWL/std3D.c | Libs/std/Win95/std3D.c | 5 platform variants |
| ☐ | `stdBmp` | `stdBmp` | General/stdBmp.c | Libs/std/General/stdBmp.c |  |
| ☐ | `stdColor` | `stdColor` | General/stdColor.c | Libs/std/General/stdColor.c |  |
| ☐ | `stdComm` | `stdComm` | Win95/stdComm.c | Libs/std/Win95/stdComm.c |  |
| ☐ | `stdConffile` | `stdConffile` | General/stdConffile.c | Libs/std/General/stdConffile.c |  |
| ☐ | `stdConsole` | `stdConsole` | Win95/stdConsole.c | Libs/std/Win95/stdConsole.c |  |
| ☐ | `stdControl` | `stdControl` | Platform/Common/stdControl.c<br>Platform/Dreamcast/stdControl.c<br>Platform/SDL2/stdControl.c<br>Platform/TWL/stdControl.c | Libs/std/Win95/stdControl.c | 4 platform variants |
| ☐ | `stdDisplay` | `stdDisplay` | Win95/stdDisplay.c | Libs/std/Win95/stdDisplay.c |  |
| ☐ | `stdFileUtil` | `stdFileUtil` | General/stdFileUtil.c | Libs/std/General/stdFileUtil.c |  |
| ☐ | `stdFnames` | `stdFnames` | General/stdFnames.c | Libs/std/General/stdFnames.c |  |
| ☐ | `stdGob` | `stdGob` | Win95/stdGob.c | Libs/std/Win95/stdGob.c |  |
| ☐ | `stdHashTable` | `stdHashtbl` | General/stdHashTable.c | Libs/std/General/stdHashtbl.c | **semantic rename** |
| ☐ | `stdLinklist` | `stdLinkList` | General/stdLinklist.c | Libs/std/General/stdLinkList.c | case differs |
| ☐ | `stdMath` | `stdMath` | General/stdMath.c | Libs/std/General/stdMath.c |  |
| ☐ | `stdMemory` | `stdMemory` | General/stdMemory.c | Libs/std/General/stdMemory.c |  |
| ☐ | `stdPlatform` | `stdPlatform` | ./stdPlatform.c | Libs/std/General/stdPlatform.c |  |
| ☐ | `stdStrTable` | `stdStrTable` | General/stdStrTable.c | Libs/std/General/stdStrTable.c |  |

### w32util  (1 modules)

| ☐ | DF2 module | J3D module | DF2 src | J3D src | Notes |
|---|-----------|-----------|---------|---------|-------|
| ☐ | `wuRegistry` | `wuRegistry` | Platform/Posix/wuRegistry.c<br>Platform/Win32/wuRegistry.c | Libs/w32util/wuRegistry.c | 2 platform variants |

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
