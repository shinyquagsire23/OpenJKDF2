#include "sithKeyFrame.h"

#include "Win95/std.h"
#include "World/sithWorld.h"
#include "Engine/rdKeyframe.h"
#include "Engine/sithPuppet.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "jk.h"

int sithKeyFrame_Load(SithWorld *pWorld, int bSkip)
{
    unsigned int alloc_size;

    flex_t percent_delta;
    flex_t load_percent = 80.0;

    if ( bSkip )
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "keyframes", 0xAu) )
        return 0;

    int sizeKeyframes = _atoi(stdConffile_g_entry.aArgs[2].value);
    if ( !sizeKeyframes )
        return 1;

    percent_delta = 15.0 / (flex_d_t)sizeKeyframes;
    if ( !sithKeyFrame_New(pWorld, sizeKeyframes) )
    {
        stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithPuppet.c", 1538, "Memory error while reading keyframes, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }

    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_g_entry.aArgs[0].value, "end", 4u) )
            return 1;
        
        // Weird inline?
        if ( !sithKeyFrame_LoadEntry(stdConffile_g_entry.aArgs[1].value) )
        {
            stdPrintf(
                pSithHS->errorPrint,
                ".\\Engine\\sithPuppet.c",
                1534,
                "Parse error while reading keyframes, line %d.\n",
                stdConffile_linenum,
                0,
                0,
                0);
            return 0;
        }

        load_percent = percent_delta + load_percent;
        if ( load_percent >= 95.0 )
            load_percent = 95.0;
        sithWorld_UpdateLoadProgress(load_percent);
    }
    return 1;
}

rdKeyframe* sithKeyFrame_GetByIdx(int index)
{
    rdKeyframe *result;

    SithWorld* world = sithWorld_g_pCurrentWorld;
    if ( (index & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        index &= ~0x8000;
    }

    if ( index < 0 || index >= world->numKeyframes )
        result = 0;
    else
        result = &world->aKeyframes[index];

    return result;
}

rdKeyframe* sithKeyFrame_LoadEntry(const char *pName)
{
    rdKeyframe *keyframe;
    char key_fpath[128];

    SithWorld* world = sithWorld_g_pLastLoadedWorld;
    if ( !sithWorld_g_pLastLoadedWorld->aKeyframes )
        return NULL;

    _sprintf(key_fpath, "%s%c%s", "3do\\key", 92, pName);
    keyframe = (rdKeyframe *)stdHashtbl_Find(sithPuppet_pKeyHashtable, pName);

    // Keyframe already loaded
    if (keyframe)
        return keyframe;

    // No space for another keyframe
    if ( world->numKeyframes >= world->sizeKeyframes )
        return NULL;

    // Allocate and load new keyframe
    keyframe = &world->aKeyframes[world->numKeyframes];
    if ( !rdKeyframe_LoadEntry(key_fpath, keyframe) )
        return NULL;

    keyframe->id = world->numKeyframes;
    if ((world->level_type_maybe & 1) || world == sithWorld_g_pStaticWorld) // Added: check world ptr just in case?
    {
        keyframe->id |= 0x8000;
    }

#ifdef SITH_DEBUG_STRUCT_NAMES
    stdHashtbl_Add(sithPuppet_pKeyHashtable, keyframe->name, keyframe);
#else
    stdHashtbl_Add(sithPuppet_pKeyHashtable, stdFileFromPath(key_fpath), keyframe);
#endif
    ++world->numKeyframes;
    return keyframe;
}

int sithKeyFrame_New(SithWorld *pWorld, int size)
{
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: rdKeyframe fields are word-width on RETRO
    pWorld->aKeyframes = (rdKeyframe *)SITH_ALLOC(sizeof(rdKeyframe) * size);
    TWL_EXTRAM_RESTORE(pSithHS); }
    if ( !pWorld->aKeyframes )
        return 0;
    pWorld->sizeKeyframes = size;
    pWorld->numKeyframes = 0;
    _memset(pWorld->aKeyframes, 0, sizeof(rdKeyframe) * size);
    return 1;
}

void sithKeyFrame_Free(SithWorld *pWorld)
{
    if (!pWorld->sizeKeyframes)
        return;

    for (int idx = 0; idx < pWorld->numKeyframes; idx++)
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        stdHashtbl_Remove(sithPuppet_pKeyHashtable, pWorld->aKeyframes[idx].name);
#else
        stdHashtbl_FreeKeyCrc32(sithPuppet_pKeyHashtable, pWorld->aKeyframes[idx].namecrc);
#endif
        rdKeyframe_FreeEntry(&pWorld->aKeyframes[idx]);
    }
    
    SITH_FREE(pWorld->aKeyframes);
    pWorld->aKeyframes = 0;
    pWorld->numKeyframes = 0;
    pWorld->sizeKeyframes = 0;
}
