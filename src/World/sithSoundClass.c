#include "sithSoundClass.h"

#include "stdPlatform.h"
#include "General/stdHashtbl.h"
#include "General/stdString.h"
#include "Devices/sithSound.h"
#include "Devices/sithSoundMixer.h"
#include "Win95/stdSound.h"
#include "World/sithWorld.h"

static const char* sithSoundClass_aKeys[SITH_SC_MAX] = {
    "--reserved--",
    "create",
    "activate",
    "startmove",
    "stopmove",
    "moving",
    "lwalkhard",
    "rwalkhard",
    "lrunhard",
    "rrunhard",
    "lwalkmetal",
    "rwalkmetal",
    "lrunmetal",
    "rrunmetal",
    "lwalkwater",
    "rwalkwater",
    "lrunwater",
    "rrunwater",
    "lwalkpuddle",
    "rwalkpuddle",
    "lrunpuddle",
    "rrunpuddle",
    "lwalkearth",
    "rwalkearth",
    "lrunearth",
    "rrunearth",
    "enterwater",
    "enterwaterslow",
    "exitwater",
    "exitwaterslow",
    "lswimsurface",
    "rswimsurface",
    "treadsurface",
    "lswimunder",
    "rswimunder",
    "treadunder",
    "jump",
    "jumpmetal",
    "jumpwater",
    "jumpearth",
    "landhard",
    "landmetal",
    "landwater",
    "landpuddle",
    "landearth",
    "landhurt",
    "hithard",
    "hitmetal",
    "hitearth",
    "deflected",
    "scrapehard",
    "scrapemetal",
    "scrapeearth",
    "hitdamaged",
    "falling",
    "corpsehit",
    "hurtimpact",
    "hurtenergy",
    "hurtfire",
    "hurtmagic",
    "hurtspecial",
    "drowning",
    "choking",
    "death1",
    "death2",
    "deathunder",
    "drowned",
    "splattered",
    "pant",
    "breath",
    "gasp",
    "fire1",
    "fire2",
    "fire3",
    "fire4",
    "curious",
    "alert",
    "idle",
    "gloat",
    "fear",
    "boast",
    "happy",
    "victory",
    "help",
    "flee",
    "search",
    "calm",
    "surprise",
    "reserved1",
    "reserved2",
    "reserved3",
    "reserved4",
    "reserved5",
    "reserved6",
    "reserved7",
    "reserved8",
};

#define IS_ANNOYING_SOUND(sc_id) ( \
           sc_id == SITH_SC_ENTERWATER \
        || sc_id == SITH_SC_ENTERWATERSLOW \
        || sc_id == SITH_SC_EXITWATER \
        || sc_id == SITH_SC_EXITWATERSLOW \
        || sc_id == SITH_SC_LANDHARD \
        || sc_id == SITH_SC_LANDHURT \
        || sc_id == SITH_SC_LANDMETAL \
        || sc_id == SITH_SC_LANDWATER \
        || sc_id == SITH_SC_LANDPUDDLE \
        || sc_id == SITH_SC_LANDEARTH \
        || sc_id == SITH_SC_MOVING \
        )

int sithSoundClass_Startup()
{
    sithSoundClass_pHashtblModes = stdHashtbl_New(64);
    sithSoundClass_pHashTable = stdHashtbl_New(192);
    if ( sithSoundClass_pHashtblModes && sithSoundClass_pHashTable )
    {
        for (int i = 1; i < SITH_SC_MAX; i++)
        {
            stdHashtbl_Add(sithSoundClass_pHashTable, sithSoundClass_aKeys[i], (void *)(intptr_t)i);
        }
        return 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithSoundClass.c", 214, "Could not allocate hashtable for soundclasses.\n", 0, 0, 0, 0);
        return 0;
    }
}

void sithSoundClass_Shutdown()
{
    if ( sithSoundClass_pHashtblModes )
    {
        stdHashtbl_Free(sithSoundClass_pHashtblModes);
        sithSoundClass_pHashtblModes = 0;
    }
    if ( sithSoundClass_pHashTable )
    {
        stdHashtbl_Free(sithSoundClass_pHashTable);
        sithSoundClass_pHashTable = 0;
    }
}

int sithSoundClass_ReadSoundClassesListText(SithWorld *pWorld, int bSkip)
{
    int num_soundclasses; // ebx
    signed int result; // eax
    sithSoundClass *aSoundClasses; // edi
    char *v6; // ebp
    int idx; // eax
    sithSoundClass *current_soundclass; // esi
    tHashTable *v10; // [esp-Ch] [ebp-9Ch]
    char soundclass_fname[128]; // [esp+10h] [ebp-80h] BYREF

    if ( bSkip )
        return 0;

    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_g_entry.aArgs[0].value, "world") || _strcmp(stdConffile_g_entry.aArgs[1].value, "soundclasses") ) {
        jk_printf("OpenJKDF2: sithSoundClass_ReadSoundClassesListText failed first strcmp");
        return 0;
    }

    num_soundclasses = _atoi(stdConffile_g_entry.aArgs[2].value);

    // Added
    if ( num_soundclasses <= 0 ) {
        jk_printf("OpenJKDF2: num soundclasses <= 0");
        return 1;
    }
    if ( sithNet_isMulti ) {
        num_soundclasses += 32;
    }
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-width fields, parsed once
    aSoundClasses = (sithSoundClass *)SITH_ALLOC(sizeof(sithSoundClass) * num_soundclasses);
    TWL_EXTRAM_RESTORE(pSithHS); }
    pWorld->aSoundClasses = aSoundClasses;
    if ( aSoundClasses )
    {
        pWorld->sizeSoundClasses = num_soundclasses;
        pWorld->numSoundClasses = 0;
        stdPlatform_Memzero32(aSoundClasses, sizeof(sithSoundClass) * num_soundclasses); // Added: word-safe
    }
    else
    {
        goto failed;
    }
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "end") )
            break;
        v6 = stdConffile_g_entry.aArgs[1].value;
        if ( _strcmp(stdConffile_g_entry.aArgs[1].value, "none") && sithWorld_g_pLastLoadedWorld->aSoundClasses)
        {
            _sprintf(soundclass_fname, "%s%c%s", "misc\\snd", 92, stdConffile_g_entry.aArgs[1].value);
            if ( !stdHashtbl_Find(sithSoundClass_pHashtblModes, v6) )
            {
                idx = sithWorld_g_pLastLoadedWorld->numSoundClasses;
                if ( idx != sithWorld_g_pLastLoadedWorld->sizeSoundClasses )
                {
                    current_soundclass = &sithWorld_g_pLastLoadedWorld->aSoundClasses[idx];
#ifdef STDHASHTABLE_CRC32_KEYS
                    current_soundclass->nameCrc = stdCrc32(v6, strlen(v6));
#endif
#ifdef SITH_DEBUG_STRUCT_NAMES
                    stdString_SafeStrCopy(current_soundclass->aName, v6, 32);
#endif
                    if ( sithSoundClass_LoadEntry(current_soundclass, soundclass_fname) )
                    {
                        v10 = sithSoundClass_pHashtblModes;
                        ++sithWorld_g_pLastLoadedWorld->numSoundClasses;
#ifdef SITH_DEBUG_STRUCT_NAMES
                        stdHashtbl_Add(v10, current_soundclass->aName, current_soundclass); // this is load-bearing
#else
                        stdHashtbl_Add(v10, v6, current_soundclass); // current_soundclass->aName -> v6
#endif
                    }
                }
            }
        }
    }
    return 1;

failed:
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithSoundClass.c", 321, "Memory error while reading soundclasses, line %d.\n", stdConffile_linenum);
    return 0;
}

sithSoundClass* sithSoundClass_Load(char *pName)
{
    SithWorld *v1; // ebx
    sithSoundClass *result; // eax
    int v3; // eax
    sithSoundClass *v4; // esi
    tHashTable *v5; // [esp-Ch] [ebp-9Ch]
    char v6[128]; // [esp+10h] [ebp-80h] BYREF

    v1 = sithWorld_g_pLastLoadedWorld;
    if ( !_strcmp(pName, "none") || !sithWorld_g_pLastLoadedWorld->aSoundClasses )
        return 0;
    _sprintf(v6, "%s%c%s", "misc\\snd", '\\', pName);
    result = (sithSoundClass *)stdHashtbl_Find(sithSoundClass_pHashtblModes, pName);
    if ( result )
        return result;
    v3 = v1->numSoundClasses;
    if ( v3 == v1->sizeSoundClasses )
        return 0;
    v4 = &v1->aSoundClasses[v3];
#ifdef STDHASHTABLE_CRC32_KEYS
    v4->nameCrc = stdCrc32(pName, strlen(pName));
#endif
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(v4->aName, pName, 32);
#endif
    if ( !sithSoundClass_LoadEntry(v4, v6) )
        return 0;
    v5 = sithSoundClass_pHashtblModes;
    ++v1->numSoundClasses;
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdHashtbl_Add(v5, v4->aName, v4); // this is a load-bearing ifdef
#else
    stdHashtbl_Add(v5, pName, v4);
#endif
    return v4;
}

int sithSoundClass_LoadEntry(sithSoundClass *pClass, char *pPath)
{
    uint32_t soundIdx; // ebp
    sithSound *v5; // ebx
    sithSoundClassEntry *newEntry; // esi
    sithSoundClassEntry *v8; // edi
    sithSoundClassEntry *v9; // ecx
    int v10; // edx
    sithSoundClassEntry *i; // eax

    SITH_ASSERTREL(pClass && pPath); // Added: from OpenJones3D

    if (!stdConffile_Open(pPath))
        return 0;

    while ( stdConffile_ReadArgs() )
    {
        if ( stdConffile_g_entry.numArgs < 2u ) {
            SITHLOG_ERROR("Short line in file %s, line %d.\n", pPath, stdConffile_linenum); // Added: from OpenJones3D
            continue;
        }

        soundIdx = (uint32_t)((intptr_t)stdHashtbl_Find(sithSoundClass_pHashTable, (const char*)(intptr_t)stdConffile_g_entry.aArgs[0].value) & 0xFFFFFFFF);
        if (soundIdx < 0 || soundIdx >= SITH_SC_MAX) {
            SITHLOG_ERROR("Mode %s not recognized in file %s.\n", stdConffile_g_entry.aArgs[0].value, pPath); // Added: from OpenJones3D
            continue;
        }

        //printf("%s, %s\n", fpath, stdConffile_g_entry.aArgs[1].value);
        if ( !_strcmp(stdConffile_g_entry.aArgs[1].value, "none") )
        {
            v5 = 0;
        }
        else {
            v5 = sithSound_Load(stdConffile_g_entry.aArgs[1].value, 0);
            if (!v5)
                continue;
        }

        { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-width fields, parsed once
        newEntry = (sithSoundClassEntry *)SITH_ALLOC(sizeof(sithSoundClassEntry));
        TWL_EXTRAM_RESTORE(pSithHS); }
        if ( newEntry )
        {
            stdPlatform_Memzero32(newEntry, sizeof(sithSoundClassEntry)); // Added: word-safe
            newEntry->sound = v5;
            newEntry->playflags = 64;
            newEntry->minRadius = 0.5;
            newEntry->maxRadius = 2.5;
            newEntry->maxVolume = 1.0;
            if (stdConffile_g_entry.numArgs > 2u)
                _sscanf(stdConffile_g_entry.aArgs[2].value, "%x", &newEntry->playflags);
            if ( stdConffile_g_entry.numArgs > 3u )
                newEntry->minRadius = _atof(stdConffile_g_entry.aArgs[3].value);
            if ( stdConffile_g_entry.numArgs > 4u )
                newEntry->maxRadius = _atof(stdConffile_g_entry.aArgs[4].value);
            if ( stdConffile_g_entry.numArgs > 5u )
                newEntry->maxVolume = _atof(stdConffile_g_entry.aArgs[5].value);
            if ( (newEntry->playflags & 0x4000) != 0 && newEntry->sound )
                sithSound_LoadFileData(newEntry->sound);
            v8 = pClass->entries[soundIdx];
            if ( v8 )
            {
                v9 = pClass->entries[soundIdx];
                v10 = 1;
                for ( i = v8->pNextMode; i; i = i->pNextMode )
                {
                    v9 = i;
                    ++v10;
                }
                v9->pNextMode = newEntry;
                v8->numEntries = v10 + 1;
            }
            else
            {
                pClass->entries[soundIdx] = newEntry;
                newEntry->numEntries = 1;
            }
        }
    }
    stdConffile_Close();

    return 1;
}

void sithSoundClass_PlayModeFirst(SithThing *pThing, unsigned int mode)
{
    sithSoundClass *pSoundClass; // eax
    sithSoundClassEntry *v3; // eax

    SITH_ASSERTREL(pThing); // Added: from OpenJones3D

    pSoundClass = pThing->pSoundClass;
    if ( pSoundClass && mode < SITH_SC_MAX )
    {
#ifdef QOL_IMPROVEMENTS
        if (IS_ANNOYING_SOUND(mode))
        {
            if (sithTime_g_msecGameTime - pThing->lastAnnoyingSoundSpamMs < 300) {
                return;
            }
            pThing->lastAnnoyingSoundSpamMs = sithTime_g_msecGameTime;
        }
#endif

        v3 = pSoundClass->entries[mode];
        if ( v3 )
            sithSoundClass_PlayModeEntry(pThing, v3, 1.0);
    }
}

sithPlayingSound* sithSoundClass_PlayMode(SithThing *pThing, int mode, flex_t selectionRatio)
{
    sithSoundClassEntry *v4; // esi
    unsigned int v5; // edi
    uint32_t v6; // eax
    int v7; // eax

    SITH_ASSERTREL(pThing); // Added: from OpenJones3D

    if (!pThing->pSoundClass) return NULL;

    if ( (unsigned int)mode < SITH_SC_MAX )
    {
        // Try to prevent sound spam at the source
#ifdef QOL_IMPROVEMENTS
        if (IS_ANNOYING_SOUND(mode))
        {
            if (sithTime_g_msecGameTime - pThing->lastAnnoyingSoundSpamMs < 300) {
                return NULL;
            }
            pThing->lastAnnoyingSoundSpamMs = sithTime_g_msecGameTime;
        }
#endif

        v4 = pThing->pSoundClass->entries[mode];
        if ( v4 )
        {
            v5 = v4->numEntries;
            if ( v5 > 1 )
            {
                v6 = (uint32_t)((flex_d_t)v5 * selectionRatio);
                if ( v6 > v5 - 1 )
                    v6 = v5 - 1;
                if ( v6 > 1 )
                {
                    v7 = v6 - 1;
                    do
                    {
                        v4 = v4->pNextMode;
                        --v7;
                    }
                    while ( v7 );
                }
            }
            return sithSoundClass_PlayModeEntry(pThing, v4, 1.0);
        }
    }
    return NULL;
}

void sithSoundClass_PlayModeFirstEx(SithThing *pThing, int mode, flex_t volume)
{
    sithSoundClassEntry *entry; // eax

    SITH_ASSERTREL(pThing); // Added: from OpenJones3D

    if ( pThing->pSoundClass && (unsigned int)mode < SITH_SC_MAX )
    {
        // Try to prevent sound spam at the source
#ifdef QOL_IMPROVEMENTS
        if (IS_ANNOYING_SOUND(mode)) 
        {
            if (sithTime_g_msecGameTime - pThing->lastAnnoyingSoundSpamMs < 300) {
                return;
            }
            pThing->lastAnnoyingSoundSpamMs = sithTime_g_msecGameTime;
        }
#endif

        entry = pThing->pSoundClass->entries[mode];
        if ( entry )
            sithSoundClass_PlayModeEntry(pThing, entry, volume);
    }
}

void sithSoundClass_StopMode(SithThing *pThing, unsigned int mode)
{
    sithSoundClassEntry *v3; // eax

    if ( pThing->pSoundClass && mode < SITH_SC_MAX )
    {
        v3 = pThing->pSoundClass->entries[mode];
        if ( v3 )
            sithSoundClass_StopSound(pThing, v3->sound);
    }
}

void sithSoundClass_FreeWorldSoundClasses(SithWorld *pWorld)
{
    sithSoundClass *v2; // esi
    sithSoundClassEntry **v3; // edi
    sithSoundClassEntry *v5; // eax
    sithSoundClassEntry *v6; // esi
    int v8; // [esp+8h] [ebp-4h]

    SITH_ASSERTREL(pWorld); // Added: from OpenJones3D

    if (!pWorld->sizeSoundClasses)
        return;

    for (v8 = 0; v8 < pWorld->numSoundClasses; v8++)
    {
        v2 = &pWorld->aSoundClasses[v8];
#ifdef STDHASHTABLE_CRC32_KEYS
        stdHashtbl_FreeKeyCrc32(sithSoundClass_pHashtblModes, v2->nameCrc);
#else
        stdHashtbl_Remove(sithSoundClass_pHashtblModes, v2->aName);
#endif
        v3 = v2->entries;
        for (int i = 0; i < SITH_SC_MAX; i++)
        {
            v5 = *v3;
            if ( *v3 )
            {
                do
                {
                    v6 = v5->pNextMode;
                    v5->pNextMode = NULL; // Added
                    SITH_FREE(v5);
                    v5 = v6;
                }
                while ( v6 );
            }
            ++v3;
        }
    }
    SITH_FREE(pWorld->aSoundClasses);
    pWorld->aSoundClasses = 0;
    pWorld->sizeSoundClasses = 0;
    pWorld->numSoundClasses = 0;
}

sithPlayingSound* sithSoundClass_PlayModeRandom(SithThing *pThing, uint32_t mode)
{
    sithSoundClassEntry *v3; // esi
    uint32_t v5; // rax

    if (!pThing->pSoundClass) return NULL;

    if ( mode < SITH_SC_MAX )
    {
        // Try to prevent sound spam at the source
#ifdef QOL_IMPROVEMENTS
        if (IS_ANNOYING_SOUND(mode)) 
        {
            if (sithTime_g_msecGameTime - pThing->lastAnnoyingSoundSpamMs < 300) {
                return NULL;
            }
            pThing->lastAnnoyingSoundSpamMs = sithTime_g_msecGameTime;
        }
#endif

        v3 = pThing->pSoundClass->entries[mode];
        if ( v3 )
        {
            if ( v3->numEntries > 1u )
            {
                v5 = (uint32_t)(_frand() * (flex_d_t)v3->numEntries);
                if ( v5 > v3->numEntries - 1 )
                    v5 = v3->numEntries - 1;
                for ( ; v5; v5-- )
                    v3 = v3->pNextMode;
            }

            return sithSoundClass_PlayModeEntry(pThing, v3, 1.0);
        }
    }
    return NULL;
}

sithPlayingSound* sithSoundClass_PlayModeEntry(SithThing *pThing, sithSoundClassEntry *pEntry, flex_t volume)
{
    sithSound* pSithSound = pEntry->sound;
    if ( !pEntry->sound )
        return 0;

    //printf("sithSoundClass_PlayModeEntry: %s %p %f, %f\n", pSithSound->sound_fname, thing, entry->maxVolume, a3);

    if (pEntry->playflags & SITHSOUNDFLAG_MUTUALLY_EXCLUSIVE_PLAYBACK_ABOLUTE)
    {
        if ( sithSoundMixer_GetThingSoundIdx(0, pSithSound) >= 0 ) {
            //printf("sithSoundClass_PlayModeEntry: %s already playing\n", pSithSound->sound_fname);
            return 0;
        }
    }
    else
    {
        if (pEntry->playflags & SITHSOUNDFLAG_MUTUALLY_EXCLUSIVE_PLAYBACK_THING) {
            if ( sithSoundMixer_GetThingSoundIdx(pThing, pSithSound) >= 0 ) {
                //printf("sithSoundClass_PlayModeEntry: %s already playing at thing\n", pSithSound->sound_fname);
                return 0;
            }
        }
    }
    
    if (pEntry->playflags & SITHSOUNDFLAG_ABSOLUTE) {
        //printf("absolute\n");
        return sithSoundMixer_PlaySoundPos(pSithSound, &pThing->position, pThing->sector, pEntry->maxVolume * volume, pEntry->minRadius, pEntry->maxRadius, pEntry->playflags);
    }
    else {
        //printf("thing\n");
        return sithSoundMixer_PlaySoundThing(pSithSound, pThing, pEntry->maxVolume * volume, pEntry->minRadius, pEntry->maxRadius, pEntry->playflags);
    }
}

void sithSoundClass_StopSound(SithThing *thing, sithSound *sound)
{
    sithPlayingSound* v3; // esi
    sithPlayingSound *v5; // edi

    if (!sithSoundMixer_bOpened)
        return;

    for (int i = 0; i < sithSoundMixer_numSoundsAvailable; i++)
    {
        v3 = &sithSoundMixer_aPlayingSounds[i];
        if ( v3->flags & SITHSOUNDFLAG_FOLLOWSTHING && thing == v3->thing && (!sound || v3->sound == sound) )
        {
            sithSoundMixer_StopSound(v3);
        }
    }

    if ( !sound && thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER )
        thing->actorParams.field_1BC = 0;
}

int sithSoundClass_SetThingClass(SithThing *pThing, sithSoundClass *pSoundClass)
{
    SITH_ASSERTREL(pThing && pSoundClass); // Added: from OpenJones3D
    if ( pThing->pSoundClass == pSoundClass )
        return 0;
    pThing->pSoundClass = pSoundClass;
    return 1;
}
