#include "sithKeyFrame.h"

#include "World/sithWorld.h"
#include "Engine/rdKeyframe.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "jk.h"

int sithKeyFrame_Load(sithWorld *world, int a2)
{
    unsigned int alloc_size;

    float percent_delta;
    float load_percent = 80.0;

    if ( a2 )
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_entry.args[0].value, "world", 6u) || _memcmp(stdConffile_entry.args[1].value, "keyframes", 0xAu) )
        return 0;

    int numKeyframes = _atoi(stdConffile_entry.args[2].value);
    if ( !numKeyframes )
        return 1;

    percent_delta = 15.0 / (double)numKeyframes;
    if ( !sithKeyFrame_New(world, numKeyframes) )
    {
        stdPrintf((int)pSithHS->errorPrint, ".\\Engine\\sithPuppet.c", 1538, "Memory error while reading keyframes, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }

    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_entry.args[0].value, "end", 4u) )
            return 1;
        
        // Weird inline?
        if ( !sithKeyFrame_LoadEntry(stdConffile_entry.args[1].value) )
        {
            stdPrintf(
                (int)pSithHS->errorPrint,
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
        sithWorld_UpdateLoadPercent(load_percent);
    }
    return 1;
}

rdKeyframe* sithKeyFrame_GetByIdx(int idx)
{
    rdKeyframe *result;

    sithWorld* world = sithWorld_pCurWorld;
    if ( (idx & 0x8000) != 0 )
    {
        world = sithWorld_pStatic;
        idx &= 0xFFFF7FFF;
    }

    if ( idx < 0 || idx >= world->numKeyframesLoaded )
        result = 0;
    else
        result = &world->keyframes[idx];

    return result;
}

rdKeyframe* sithKeyFrame_LoadEntry(const char *fpath)
{
    rdKeyframe *keyframe;
    char key_fpath[128];

    sithWorld* world = sithWorld_pLoading;
    if ( !sithWorld_pLoading->keyframes )
        return NULL;

    _sprintf(key_fpath, "%s%c%s", "3do\\key", 92, fpath);
    keyframe = (rdKeyframe *)stdHashTable_GetKeyVal(keyframes_hashmap, fpath);

    // Keyframe already loaded
    if (keyframe)
        return keyframe;

    // No space for another keyframe
    if ( world->numKeyframesLoaded >= world->numKeyframes )
        return NULL;

    // Allocate and load new keyframe
    keyframe = &world->keyframes[world->numKeyframesLoaded];
    if ( !rdKeyframe_LoadEntry(key_fpath, keyframe) )
        return NULL;

    keyframe->id = world->numKeyframesLoaded;
    if (world->level_type_maybe & 1) // static
    {
        keyframe->id |= 0x8000;
    }
    stdHashTable_SetKeyVal(keyframes_hashmap, keyframe->name, keyframe);
    ++world->numKeyframesLoaded;
    return keyframe;
}

int sithKeyFrame_New(sithWorld *world, int numKeyframes)
{
    world->keyframes = (rdKeyframe *)pSithHS->alloc(sizeof(rdKeyframe) * numKeyframes);
    if ( !world->keyframes )
        return 0;
    world->numKeyframes = numKeyframes;
    world->numKeyframesLoaded = 0;
    _memset(world->keyframes, 0, sizeof(rdKeyframe) * numKeyframes);
    return 1;
}

void sithKeyFrame_Free(sithWorld *world)
{
    if (!world->numKeyframes)
        return;

    for (int idx = 0; idx < world->numKeyframesLoaded; idx++)
    {
        stdHashTable_FreeKey(keyframes_hashmap, world->keyframes[idx].name);
        rdKeyframe_FreeJoints(&world->keyframes[idx]);
    }
    
    pSithHS->free(world->keyframes);
    world->keyframes = 0;
    world->numKeyframesLoaded = 0;
    world->numKeyframes = 0;
}
