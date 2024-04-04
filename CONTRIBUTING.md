## Contribution Guide

OpenJKDF2 is a function-by-function decompilation of JKDF2, and as such has several functions which were decompiled without full knowledge of what they do. The result is that while the game functions identically, the code is sometimes opaque or unreadable. The following is a guide to the types of code patterns you may see in OpenJKDF2, and how to improve them.

Contributors are *not* expected to fix every problem in a file they touch! PRs should generally focus on one kind of cleanup type, or perform different cleanup items in different commits (ie, cleaning placeholder variables in one commit, then renaming a struct variable names in the next)

### Additional behavior or bugfixes

Bugfixes should always be notated with `// Added:`, `// Removed:`, or `// Altered:`, followed by a note on the addition. Added features should generally be contained within `#ifdef QOL_IMPROVEMENTS`/`#endif // QOL_IMPROVEMENTS`, especially if the addition alters static variables (ie, in UI code).

Additions to structs must always be contatined within `#ifdef QOL_IMPROVEMENTS` so that struct definitions can be imported into Ghidra. Struct additions should be tested with ASAN to ensure allocations are of the correct size (while most missing `sizeof`s have been accounted for, there are some instances of casting `char[]` to a struct).

Example:
```c
// Added: fixed off-by-one in loop comparison
for (size_t v3 = 0; v3 < sithAI_inittedActors; ++v3 )
{
    // Added: prevent OOB access
    // TODO: define this maximum
    if (v3 >= 256) break;
    ...
```

### Increasing resource limits

Resource limits should be defined in `engine_config.h`. Original engine variables can be found in `symbols.syms` and `symbols_static.syms`. Resource limits should be increased with caution, knowing that it could potentially affect scripting/rendering behavior in unexpected ways.

### Original symbol names and file paths

Original symbol names and file paths are generally considered to override existing names/paths. Exceptions are made for function arguments which don't follow Hungarian Notation, as well as static variables missing a modular name.

### Modular names
JKDF2 is designed primarily around modular programming. Each function name is prefixed with the filename its implementation belongs to:

Examples:
```c
void sithComm_FileWrite(sithCogMsg* ctx);
int sithSoundClass_Startup();
void sithWeapon_Tick(sithThing* weapon, float deltaSeconds);
```

Modular names also apply to all global and static variables.

### 'Hungarian' notation

Function arguments, local variables, and global variables should follow [Hungarian notation](https://learn.microsoft.com/en-us/windows/win32/stg/coding-style-conventions). Global variables must be prefixed by their owning class. This primarily means that all pointers passed into functions are notated starting with `p`, an allocated array of structs would start with `pa`, and an allocated array of struct pointers would be `pap`. There are some notable exceptions, namely if a struct is always allocated, a fixed array of struct pointers might be notated `aStructs` instead. If a struct contains a pointer to an array of pointers, the name should be notated with `ap` instead of `pap`, ie `pWorld->apActors`.

Wide-char arrays are generally notated with `wstr`, `wa` or `w`, and char arrays are generally notated with `str` or `a`. Notating string pointers as `pa` is generally discouraged in favor of just `pStr` or similar. `aw` should be refactorered to `wa`.

Function pointers can be notated with just `fn` instead of `p`. A notable exception is made for vtable-like structs which contain only function pointers (ie, `HostServices`/`pHS`), in which case functions can be defined without the fn prefix. As a rule of thumb, callback functions, functions as arguments, and global function pointers should always have `fn`.

Boolean variables should always be prefixed with `b`.

Pointer `*`s should always be placed to the right of the type, ie `sithSector** paSectors` and not `sithSector **paSectors`.

Examples:
```c
rdVector3 rdModel3_aLocalLightPos[64]; // An array of rdVector3 structs defined in rdModel3.c
sithSector* sithRender_aSectors[SITH_MAX_VISIBLE_SECTORS]; // An array of sithSector* pointers defined in sithRender.c

const wchar_t* openjkdf2_waReleaseVersion; // A constant wchar_t string
const char* openjkdf2_aReleaseCommitShort; // A constant char string

static int stdControl_bStartup;
static int stdControl_bOpen;
```

### 'Hungarian' notation and structs/typedefs

TODO: I'm actually debating on whether to follow this convention, for now do not refactor struct names unless they are used exclusively by another struct and the struct typedef does not get used in function arguments.

Struct names should be prefixed with `s`, and typedefs should be prefixed with `t`. This may not have been followed especially well within LEC, particularly in any RenderDroid components, as Grim Fandango Remastered shows vec3s written as `rdVector3`. As a rule of thumb, avoid refactoring any structs starting with `rd`, and *do* refactor structs starting with `sith` or `jk`. Where there are layers of inheritance (ex: `rdThing` and `sithThing`), be sure to keep a `tSith` or `tJk` prefix, and do not refactor structs starting with `rd`.

Where there is 

All types should be defined in `types.h` and `types_enums.h`. RenderDroid types may be refactored to `rdTypes.h` at a later date.

Examples:
```c
typedef struct sSithCvar
{
    const char* pName;
    const char* pNameLower;
    void* pLinkPtr;
    int32_t type;
    int32_t flags;
    union
    {
        intptr_t val;
        char* pStrVal;
        int32_t intVal;
        int32_t boolVal;
        float flexVal;
    };
    union
    {
        intptr_t defaultVal;
        char* pDefaultStrVal;
        int32_t defaultIntVal;
        int32_t defaultBoolVal;
        float defaultFlexVal;
    };
} tSithCvar;

typedef struct sBMHeader
{
    ...
} tBMHeader;
```

### Function arguments 

Function arguments should follow Hungarian notation.

Before cleanup:
<details>

```c
void sithThing_SetSyncFlags(sithThing *thing, int flags)
{
    if (!sithComm_multiplayerFlags) return;

    for (uint32_t v3 = 0; v3 < sithNet_syncIdx; v3++)
    {
        if (sithNet_aSyncThings[v3] == thing) {
            sithNet_aSyncFlags[v3] |= flags;
            return;
        }
    }

    if ( sithNet_syncIdx < SITH_MAX_SYNC_THINGS ) // Added: != -> <
    {
        sithNet_aSyncThings[sithNet_syncIdx] = thing;
        sithNet_aSyncFlags[sithNet_syncIdx] = flags;
        sithNet_syncIdx++;
    }
}
```
</details>

After cleanup:
<details>

```c
void sithThing_SetSyncFlags(sithThing *pThing, int flags)
{
    if (!sithComm_multiplayerFlags) return;

    for (uint32_t v3 = 0; v3 < sithNet_syncIdx; v3++)
    {
        if (sithNet_aSyncThings[v3] == pThing) {
            sithNet_aSyncFlags[v3] |= flags;
            return;
        }
    }

    if ( sithNet_syncIdx < SITH_MAX_SYNC_THINGS ) // Added: != -> <
    {
        sithNet_aSyncThings[sithNet_syncIdx] = pThing;
        sithNet_aSyncFlags[sithNet_syncIdx] = flags;
        sithNet_syncIdx++;
    }
}
```
</details>

### Simplifying local variables

All local variables are defined C89-style at the start of the function. Refactoring or simplifying local variables which are only used once is encouraged. If a local variable is only used in one scope, its declaration can also be moved to the start of that scope.

Before cleanup:
<details>

```c
if ( sithNet_isMulti )
{
    v17 = sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESPAWN");
}
else if ( !__strnicmp(sithGamesave_autosave_fname, "_JKAUTO_", 8u) )
{
    v17 = sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESTART");
}
else
{
    v17 = sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESTORE");
}
sithConsole_PrintUniStr(v17); 
```

</details>

After cleanup:
<details>

```c
if ( sithNet_isMulti )
{
    sithConsole_PrintUniStr(sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESPAWN"));
}
else if ( !__strnicmp(sithGamesave_autosave_fname, "_JKAUTO_", 8u) )
{
    sithConsole_PrintUniStr(sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESTART"));
}
else
{
    sithConsole_PrintUniStr(sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESTORE"));
}
```

</details>

### Placeholder variable/function names

Variable names whose behavior/function are unclear should always be prefixed as `v[number]`. This allows contributors to easily find functions which need refactoring. Variable names which are unclear (ex: `int idk3;`) should be refactored to a clear name, refactored away entirely, or refactored or back to a `v[number]` designation.

Function names which are placeholders (ex: `sithThing_sub_4CD100`) or are unclear (`jkStrings_GetText2`) should be refactored to describe their function clearly.

Example:
```
jkStrings_GetText -> jkStrings_GetUniStringWithFallback
jkStrings_GetText2 -> jkStrings_GetUniString
```

`goto` labels should **NEVER** be refactored to clear names, and should instead be refactored out entirely. See `for loop/goto untangling` for details.

## Incorrectly named functions

Some functions or modules are sometimes named incorrectly. Ex: `stdString_WstrRemoveCharsAt` was once incorrectly named `stdString_wstrncpy`. If a function is named incorrectly, it should be rectified ASAP.

### if statements

If statements should avoid spaces around parenthesis, and redundant `!= 0`/`== 0`s (unless the comparison is against an enum, in which case the enum name should be inserted in place of `0`):

Before cleanup:
```c
if ( sithNet_isMulti != 0 )
```

After cleanup:
```c
if (sithNet_isMulti)
```

### for loop/goto untangling

Gotos should only be used to clean up resource allocations in the event of failure, or to leave nested loops whose function cannot better be represented without gotos.

For loops are often decompiled as 
```c
i = start_idx;
if (i < end_idx)
{
    while (1)
    {
LABEL_122:
        if (some_cond) goto LABEL_123;
        if (other_cond) break;
        ...
        if (++i >= end_idx) goto LABEL_123;
    }
    // other_cond
    ...
    goto LABEL_122;
}
LABEL_123:
...
```

and should instead be refactored to:

```c
for (int i = start_idx; i < end_idx; i++)
{
    if (some_cond) break;
    if (other_cond) {
        // other_cond
        ...
        continue;
    }
    ...
}
// LABEL_123
...
```

Before cleanup:
<details>

```c
uint32_t update_steps = (sithMulti_dword_832664 + deltaMs) / MULTI_BIG_UPDATE_INTERVAL_MS;
sithMulti_dword_832664 = (sithMulti_dword_832664 + deltaMs) - MULTI_BIG_UPDATE_INTERVAL_MS * update_steps;

for (int i = 0; i < update_steps; i++)
{
    switch ( stdComm_currentBigSyncStage )
    {
    case 1:
        v10 = sithWorld_pCurrentWorld->numSectors;
        if ( stdComm_dword_832208 >= v10 )
            goto LABEL_42;
        v11 = &sithWorld_pCurrentWorld->sectors[stdComm_dword_832208];
        while ( 1 )
        {
            v12 = v11;
            ++stdComm_dword_832208;
            ++v11;
            if ( v12->flags & SITH_SECTOR_SYNC )
                break;
            if ( (v12->flags & SITH_SECTOR_ADJOINS_SET) != 0 )
            {
                sithDSS_SendSectorFlags(v12, sithMulti_sendto_id, 1);
                goto LABEL_41;
            }
            if ( stdComm_dword_832208 >= v10 )
            {
LABEL_42:
                if ( stdComm_dword_832208 >= sithWorld_pCurrentWorld->numSectors )
                {
                    stdComm_dword_832208 = 0;
                    stdComm_currentBigSyncStage = 3;
                    stdComm_dword_832208 = 0;
                }
                ++stdComm_dword_832210;
                goto LABEL_64;
            }
        }
        sithDSS_SendSectorStatus(v12, sithMulti_sendto_id, 1);
LABEL_41:
        goto LABEL_42;
    case 2:
        v7 = sithWorld_pCurrentWorld->numSurfaces;
        if ( stdComm_dword_832208 >= v7 )
            goto LABEL_30;
        v8 = &sithWorld_pCurrentWorld->surfaces[stdComm_dword_832208];
        while ( 1 )
        {
            v9 = v8;
            ++stdComm_dword_832208;
            ++v8;
            if ( (v9->surfaceFlags & SITH_SURFACE_CHANGED) != 0 )
                break;
            if ( stdComm_dword_832208 >= v7 )
            {
                goto LABEL_30;
            }
        }
        sithDSS_SendSurfaceStatus(v9, sithMulti_sendto_id, 1);
LABEL_30:
        if ( stdComm_dword_832208 >= sithWorld_pCurrentWorld->numSurfaces )
        {
            stdComm_dword_832208 = 0;
            stdComm_currentBigSyncStage = 1;
            stdComm_dword_832208 = 0;
        }
        ++stdComm_dword_832200;
        goto LABEL_64;
    case 3:
        if (stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings )
            goto LABEL_56;
        break;
    case 4:
        if ( stdComm_dword_832208 >= sithMulti_dword_83265C
                || (sithDSSThing_SendDestroyThing(sithMulti_arr_832218[stdComm_dword_832208], sithMulti_sendto_id),
                    ++stdComm_dword_832208,
                    stdComm_dword_832208 >= sithMulti_dword_83265C) )
        {
            if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 && (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
                jkPlayer_playerInfos[sithMulti_requestConnectIdx].teamNum = (sithMulti_requestConnectIdx & 1) + 1;
            sithMulti_verbosePrintf("Last sync %x %x\n", sithMulti_sendto_id, sithMulti_requestConnectIdx);
            jkPlayer_playerInfos[sithMulti_requestConnectIdx].net_id = sithMulti_sendto_id;
            sithMulti_SendLeaveJoin(sithMulti_sendto_id, 1);
            sithMulti_SendWelcome(sithMulti_sendto_id, sithMulti_requestConnectIdx, sithMulti_sendto_id);

            sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
            sithMulti_sendto_id = 0;
            stdComm_currentBigSyncStage = 2;
            stdComm_dword_832208 = 0;
            sithNet_bSyncScores = 1;
        }
        goto LABEL_64;
    default:
        return;
    }

    // Sync stage 3 (TODO: fix flow)
    while ( 1 )
    {
        v14 = &sithWorld_pCurrentWorld->things[stdComm_dword_832208];
        stdComm_dword_832208++;
        if ( sithThing_ShouldSync(v14) )
        {
            if ( v14->type != SITH_THING_WEAPON && v14->type != SITH_THING_EXPLOSION )
                break;
        }
        if ( stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings )
            goto LABEL_55;
    }

    if ( (v14->thing_id & 0xFFFF0000) != 0 )
        sithDSSThing_SendFullDesc(v14, sithMulti_sendto_id, 1);
    else
        sithDSSThing_SendSyncThing(v14, sithMulti_sendto_id, 1);

    sithDSSThing_SendPos(v14, sithMulti_sendto_id, 0);

    // Added: co-op
    if (v14->type == SITH_THING_CORPSE || ((v14->type == SITH_THING_ACTOR || v14->type == SITH_THING_PLAYER) && v14->thingflags & SITH_TF_DEAD)) {
        if (v14->rdthing.puppet)
            sithDSS_SendSyncPuppet(v14, sithMulti_sendto_id, 255);
    }

LABEL_55:
    if (stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings)
    {
LABEL_56:
        stdComm_dword_832208 = 0;
        stdComm_currentBigSyncStage = 4;
        stdComm_dword_832208 = 0;
    }
    ++sithNet_dword_832620;
LABEL_64:
    continue;
}
```
</details>

After cleanup:
<details>

```c
uint32_t update_steps = (sithMulti_dword_832664 + deltaMs) / MULTI_BIG_UPDATE_INTERVAL_MS;
sithMulti_dword_832664 = (sithMulti_dword_832664 + deltaMs) - MULTI_BIG_UPDATE_INTERVAL_MS * update_steps;

for (int i = 0; i < update_steps; i++)
{
    switch ( stdComm_currentBigSyncStage )
    {
    case 1:
        while (stdComm_dword_832208 < sithWorld_pCurrentWorld->numSectors)
        {
            v11 = &sithWorld_pCurrentWorld->sectors[stdComm_dword_832208++];
            if (v11->flags & SITH_SECTOR_SYNC )
            {
                sithDSS_SendSectorStatus(v11, sithMulti_sendto_id, 1);
                break;
            }
            else if (v11->flags & SITH_SECTOR_ADJOINS_SET)
            {
                sithDSS_SendSectorFlags(v11, sithMulti_sendto_id, 1);
                break;
            }
        }

        if ( stdComm_dword_832208 >= sithWorld_pCurrentWorld->numSectors )
        {
            stdComm_dword_832208 = 0;
            stdComm_currentBigSyncStage = 3;
            stdComm_dword_832208 = 0;
        }
        ++stdComm_dword_832210;
        continue;
    case 2:
        while (stdComm_dword_832208 < sithWorld_pCurrentWorld->numSurfaces)
        {
            v8 = &sithWorld_pCurrentWorld->surfaces[stdComm_dword_832208++];
            if (v8->surfaceFlags & SITH_SURFACE_CHANGED)
            {
                sithDSS_SendSurfaceStatus(v8, sithMulti_sendto_id, 1);
                break;
            }
        }
        
        if ( stdComm_dword_832208 >= sithWorld_pCurrentWorld->numSurfaces )
        {
            stdComm_dword_832208 = 0;
            stdComm_currentBigSyncStage = 1;
            stdComm_dword_832208 = 0;
        }
        ++stdComm_dword_832200;
        continue;
    case 3:
        // Sync stage 3 (TODO: is there an off-by-one here...? not touching it for now.)
        while (stdComm_dword_832208 <= sithWorld_pCurrentWorld->numThings)
        {
            v14 = &sithWorld_pCurrentWorld->things[stdComm_dword_832208++];
            if ( sithThing_ShouldSync(v14) )
            {
                if ( v14->type != SITH_THING_WEAPON && v14->type != SITH_THING_EXPLOSION )
                {
                    if ( (v14->thing_id & 0xFFFF0000) != 0 )
                        sithDSSThing_SendFullDesc(v14, sithMulti_sendto_id, 1);
                    else
                        sithDSSThing_SendSyncThing(v14, sithMulti_sendto_id, 1);

                    sithDSSThing_SendPos(v14, sithMulti_sendto_id, 0);

                    // Added: co-op
                    if (v14->type == SITH_THING_CORPSE || ((v14->type == SITH_THING_ACTOR || v14->type == SITH_THING_PLAYER) && v14->thingflags & SITH_TF_DEAD)) {
                        if (v14->rdthing.puppet)
                            sithDSS_SendSyncPuppet(v14, sithMulti_sendto_id, 255);
                    }
                }
            }
        }

        if (stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings)
        {
            stdComm_dword_832208 = 0;
            stdComm_currentBigSyncStage = 4;
            stdComm_dword_832208 = 0;
        }
        ++sithNet_dword_832620;

        continue;
    case 4:
        if ( stdComm_dword_832208 >= sithMulti_dword_83265C
                || (sithDSSThing_SendDestroyThing(sithMulti_arr_832218[stdComm_dword_832208], sithMulti_sendto_id),
                    ++stdComm_dword_832208,
                    stdComm_dword_832208 >= sithMulti_dword_83265C) )
        {
            if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 && (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
                jkPlayer_playerInfos[sithMulti_requestConnectIdx].teamNum = (sithMulti_requestConnectIdx & 1) + 1;
            sithMulti_verbosePrintf("Last sync %x %x\n", sithMulti_sendto_id, sithMulti_requestConnectIdx);
            jkPlayer_playerInfos[sithMulti_requestConnectIdx].net_id = sithMulti_sendto_id;
            sithMulti_SendLeaveJoin(sithMulti_sendto_id, 1);
            sithMulti_SendWelcome(sithMulti_sendto_id, sithMulti_requestConnectIdx, sithMulti_sendto_id);

            sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
            sithMulti_sendto_id = 0;
            stdComm_currentBigSyncStage = 2;
            stdComm_dword_832208 = 0;
            sithNet_bSyncScores = 1;
        }
        continue;
    default:
        return;
    }                    
}
```
</details>

### Inlined functions

Some 'unused' functions are actually functions which were inlined into other functions. Code should be refactored to appear as it would have been in the LEC codebase. Inlined functions can usually be sussed out if a function in a module is unused, if a `bInitialized` variable is checked multiple times, or if a variable is checked `NULL` in the middle of a function.

All operations on `rdVector3`s/`rdMatrix34`s are usually inlined. Usually good places to double-check are `stdMath` or `rdMath` if something feels inlined but isn't present in `rdVector`/`rdMatrix`.

Before cleanup:
<details>

```c
...

if (sithSoundMixer_bInitted)
{
    sithSoundMixer_musicVolume = stdMath_Clamp(sithSoundMixer_musicVolume, 0.0, 1.0);
    stdMci_SetVolume(sithSoundMixer_globalVolume * sithSoundMixer_musicVolume);
}

...
```
</details>

After cleanup:
<details>

```c
sithSoundMixer_SetMusicVol(sithSoundMixer_musicVolume);
```
</details>