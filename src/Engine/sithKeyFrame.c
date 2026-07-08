#include "sithKeyFrame.h"

#include "Win95/std.h"
#include "World/sithWorld.h"
#include "Engine/rdKeyframe.h"
#include "Engine/sithPuppet.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "jk.h"

int sithKeyFrame_Load(SithWorld *world, int a2)
{
    unsigned int alloc_size;

    flex_t percent_delta;
    flex_t load_percent = 80.0;

    if ( a2 )
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "aKeyframes", 0xAu) )
        return 0;

    int sizeKeyframes = _atoi(stdConffile_g_entry.aArgs[2].value);
    if ( !sizeKeyframes )
        return 1;

    percent_delta = 15.0 / (flex_d_t)sizeKeyframes;
    if ( !sithKeyFrame_New(world, sizeKeyframes) )
    {
        stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithPuppet.c", 1538, "Memory error while reading aKeyframes, line %d.\n", stdConffile_linenum, 0, 0, 0);
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
                "Parse error while reading aKeyframes, line %d.\n",
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

rdKeyframe* sithKeyFrame_GetByIdx(int idx)
{
    rdKeyframe *result;

    SithWorld* world = sithWorld_g_pCurrentWorld;
    if ( (idx & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000;
    }

    if ( idx < 0 || idx >= world->numKeyframes )
        result = 0;
    else
        result = &world->aKeyframes[idx];

    return result;
}

rdKeyframe* sithKeyFrame_LoadEntry(const char *fpath)
{
    rdKeyframe *keyframe;
    char key_fpath[128];

    SithWorld* world = sithWorld_g_pLastLoadedWorld;
    if ( !sithWorld_g_pLastLoadedWorld->aKeyframes )
        return NULL;

    _sprintf(key_fpath, "%s%c%s", "3do\\key", 92, fpath);
    keyframe = (rdKeyframe *)stdHashtbl_Find(sithPuppet_pKeyHashtable, fpath);

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

int sithKeyFrame_New(SithWorld *world, int sizeKeyframes)
{
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: rdKeyframe fields are word-width on RETRO
    world->aKeyframes = (rdKeyframe *)SITH_ALLOC(sizeof(rdKeyframe) * sizeKeyframes);
    TWL_EXTRAM_RESTORE(pSithHS); }
    if ( !world->aKeyframes )
        return 0;
    world->sizeKeyframes = sizeKeyframes;
    world->numKeyframes = 0;
    _memset(world->aKeyframes, 0, sizeof(rdKeyframe) * sizeKeyframes);
    return 1;
}

void sithKeyFrame_Free(SithWorld *world)
{
    if (!world->sizeKeyframes)
        return;

    for (int idx = 0; idx < world->numKeyframes; idx++)
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        stdHashtbl_Remove(sithPuppet_pKeyHashtable, world->aKeyframes[idx].name);
#else
        stdHashtbl_FreeKeyCrc32(sithPuppet_pKeyHashtable, world->aKeyframes[idx].namecrc);
#endif
        rdKeyframe_FreeEntry(&world->aKeyframes[idx]);
    }
    
    SITH_FREE(world->aKeyframes);
    world->aKeyframes = 0;
    world->numKeyframes = 0;
    world->sizeKeyframes = 0;
}
