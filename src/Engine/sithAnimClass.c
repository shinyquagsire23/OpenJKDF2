#include "sithAnimClass.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "Engine/sithPuppet.h"
#include "World/sithWorld.h"
#include "General/stdString.h"
#include "General/stdHashtbl.h"
#include "Win95/std.h"
#include "jk.h"

int sithAnimClass_Load(sithWorld *world, int a2)
{
    int num_animclasses; // ebx
    sithAnimclass *animclasses; // edi
    sithAnimclass *animclass; // esi
    char pup_path[128]; // [esp+10h] [ebp-80h] BYREF

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "puppets") )
        return 0;
    num_animclasses = _atoi(stdConffile_entry.args[2].value);
    if ( !num_animclasses )
        return 1;
#ifdef TARGET_RETRO_HOMEBREW
    // Added: animclass data is all 32-bit fields, written only at parse time and
    // read when animations start -- cold and word-safe, so it can live in
    // word-addressable-only memory (DC VRAM arena / NDS slot-2 RAM).
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
    animclasses = (sithAnimclass *)SITH_ALLOC(sizeof(sithAnimclass) * num_animclasses);
#ifdef TARGET_RETRO_HOMEBREW
    pSithHS->suggestHeap(prevSuggest);
#endif
    world->animclasses = animclasses;
    if ( !animclasses )
        return 0;
    world->numAnimClasses = num_animclasses;
    world->numAnimClassesLoaded = 0;
    stdPlatform_Memzero32(animclasses, sizeof(sithAnimclass) * num_animclasses); // Added: word-safe
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        if ( !stdHashtbl_Find(sithPuppet_pClassHashtable, stdConffile_entry.args[1].value) )
        {
            if ( sithWorld_g_pLastLoadedWorld->numAnimClassesLoaded != sithWorld_g_pLastLoadedWorld->numAnimClasses )
            {
                animclass = &sithWorld_g_pLastLoadedWorld->animclasses[sithWorld_g_pLastLoadedWorld->numAnimClassesLoaded];
                stdPlatform_Memzero32(animclass, sizeof(sithAnimclass)); // Added: word-safe
                const char* name = stdConffile_entry.args[1].value;
#ifdef SITH_DEBUG_STRUCT_NAMES
                stdString_SafeStrCopy(animclass->name, name, 32);
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
                animclass->namecrc = stdCrc32(name, strlen(name));
#endif
                // Added: sprintf -> snprintf
                stdString_snprintf(pup_path, 128, "%s%c%s", "misc\\pup", 92, stdConffile_entry.args[1].value);
                if ( sithAnimClass_LoadPupEntry(animclass, pup_path) )
                {
                    ++sithWorld_g_pLastLoadedWorld->numAnimClassesLoaded;
#ifdef SITH_DEBUG_STRUCT_NAMES
                    // The copies of names are load-bearing, SetKeyVal stores a reference
                    stdHashtbl_Add(sithPuppet_pClassHashtable, animclass->name, animclass);
#else
                    stdHashtbl_Add(sithPuppet_pClassHashtable, name, animclass);
#endif
                }
            }
        }
    }
    return 1;
}

sithAnimclass* sithAnimClass_LoadEntry(char *a1)
{
    sithAnimclass *result; // eax
    int v3; // ecx
    sithAnimclass *v4; // esi
    stdHashTable *v5; // [esp-Ch] [ebp-9Ch]
    char v6[128]; // [esp+10h] [ebp-80h] BYREF
#ifdef STDHASHTABLE_CRC32_KEYS
    char tmp[32];
#endif

    result = (sithAnimclass *)stdHashtbl_Find(sithPuppet_pClassHashtable, a1);
    if ( !result )
    {
        v3 = sithWorld_g_pLastLoadedWorld->numAnimClassesLoaded;
        if ( v3 == sithWorld_g_pLastLoadedWorld->numAnimClasses
          || (v4 = &sithWorld_g_pLastLoadedWorld->animclasses[v3],
              stdPlatform_Memzero32(v4, sizeof(sithAnimclass)), // Added: word-safe
#ifdef SITH_DEBUG_STRUCT_NAMES
              stdString_SafeStrCopy(v4->name, a1, 32),
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
              stdString_SafeStrCopy(tmp, a1, 32),
              v4->namecrc = stdCrc32(a1, strlen(a1)),
#endif
              _sprintf(v6, "%s%c%s", "misc\\pup", 92, a1),
              !sithAnimClass_LoadPupEntry(v4, v6)) )
        {
            result = 0;
        }
        else
        {
            v5 = sithPuppet_pClassHashtable;
            ++sithWorld_g_pLastLoadedWorld->numAnimClassesLoaded;
#ifdef SITH_DEBUG_STRUCT_NAMES
            stdHashtbl_Add(v5, v4->name, v4);
#else
            stdHashtbl_Add(v5, tmp, v4); // Added: tmp thing
#endif
            result = v4;
        }
    }
    return result;
}

int sithAnimClass_LoadPupEntry(sithAnimclass *animclass, char *fpath)
{
    int mode; // ebx
    unsigned int bodypart_idx; // esi
    int joint_idx; // eax
    intptr_t animNameIdx; // ebp
    sithWorld *world; // esi
    char *key_fname; // edi
    rdKeyframe *v10; // eax
    unsigned int v12; // eax
    rdKeyframe *keyframe; // edi
    int lowpri; // [esp+4h] [ebp-8Ch]
    int flags; // [esp+8h] [ebp-88h] BYREF
    int hipri; // [esp+Ch] [ebp-84h]
    char keyframe_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    mode = 0;
    if (!stdConffile_Open(fpath))
        return 0;

    stdPlatform_Memset32(animclass->bodypart_to_joint, 0xFFu, sizeof(animclass->bodypart_to_joint)); // Added: word-safe
    while ( stdConffile_ReadArgs() )
    {
        if ( !stdConffile_entry.numArgs )
            continue;
        if ( !_strcmp(stdConffile_entry.args[0].key, "mode") )
        {
            mode = _atoi(stdConffile_entry.args[0].value);
            if ( stdConffile_entry.numArgs > 1u && !_strcmp(stdConffile_entry.args[1].key, "basedon") )
                stdPlatform_Memcpy32(&animclass->modes[mode], &animclass->modes[_atoi(stdConffile_entry.args[1].value)], sizeof(animclass->modes[mode])); // Added: word-safe
        }
        else if ( !_strcmp(stdConffile_entry.args[0].value, "joints") )
        {
            while ( stdConffile_ReadArgs() )
            {
                if ( !stdConffile_entry.numArgs || !_strcmp(stdConffile_entry.args[0].key, "end") )
                    break;
                bodypart_idx = _atoi(stdConffile_entry.args[0].key);
                joint_idx = _atoi(stdConffile_entry.args[0].value);
                if ( bodypart_idx < 0xA )
                    animclass->bodypart_to_joint[bodypart_idx] = joint_idx;
            }
        }
        else if ( stdConffile_entry.numArgs > 1u )
        {
            animNameIdx = (intptr_t)stdHashtbl_Find(sithPuppet_pHashtblSubmodes, stdConffile_entry.args[0].value);
            if ( animNameIdx )
            {
                if ( stdConffile_entry.numArgs <= 2u )
                    flags = 0;
                else
                    _sscanf(stdConffile_entry.args[2].value, "%x", &flags);
                if ( stdConffile_entry.numArgs <= 3u )
                    lowpri = 0;
                else
                    lowpri = _atoi(stdConffile_entry.args[3].value);
                if ( stdConffile_entry.numArgs <= 4u )
                    hipri = lowpri;
                else
                    hipri = _atoi(stdConffile_entry.args[4].value);
                if ( _strcmp(stdConffile_entry.args[1].value, "none") )
                {
                    world = sithWorld_g_pLastLoadedWorld;
                    key_fname = stdConffile_entry.args[1].value;
                    if ( sithWorld_g_pLastLoadedWorld->keyframes )
                    {
                        _sprintf(keyframe_fpath, "%s%c%s", "3do\\key", 92, stdConffile_entry.args[1].value);
                        v10 = (rdKeyframe *)stdHashtbl_Find(sithPuppet_pKeyHashtable, key_fname);
                        if ( v10 )
                        {
LABEL_39:
                            animclass->modes[mode].keyframe[animNameIdx].keyframe = v10;
                            animclass->modes[mode].keyframe[animNameIdx].flags = flags;
                            animclass->modes[mode].keyframe[animNameIdx].lowPri = lowpri;
                            animclass->modes[mode].keyframe[animNameIdx].highPri = hipri;

                            continue;
                        }
                        v12 = world->numKeyframesLoaded;
                        if ( v12 < world->numKeyframes )
                        {
                            keyframe = &world->keyframes[v12];
                            if ( rdKeyframe_LoadEntry(keyframe_fpath, keyframe) )
                            {
                                keyframe->id = world->numKeyframesLoaded;
                                if ( (world->level_type_maybe & 1) )
                                {
                                    keyframe->id |= 0x8000u;
                                }
#ifdef SITH_DEBUG_STRUCT_NAMES
                                stdHashtbl_Add(sithPuppet_pKeyHashtable, keyframe->name, keyframe);
#else
                                stdHashtbl_Add(sithPuppet_pKeyHashtable, /*keyframe->name*//*key_fname*/stdFileFromPath(keyframe_fpath), keyframe);
#endif
                                v10 = keyframe;
                                ++world->numKeyframesLoaded;
                                goto LABEL_39;
                            }
                        }
                    }
                }
                v10 = NULL;
                goto LABEL_39;
            }
        }
    }
    stdConffile_Close();
    return 1;
}

int sithAnimClass_New(sithWorld *world, int num)
{
    sithAnimclass *animclasses;

#ifdef TARGET_RETRO_HOMEBREW
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE); // Added: see sithAnimClass_Load
#endif
    animclasses = (sithAnimclass *)SITH_ALLOC(sizeof(sithAnimclass) * num);
#ifdef TARGET_RETRO_HOMEBREW
    pSithHS->suggestHeap(prevSuggest);
#endif
    world->animclasses = animclasses;
    if ( !animclasses )
        return 0;
    world->numAnimClasses = num;
    world->numAnimClassesLoaded = 0;
    stdPlatform_Memzero32(animclasses, sizeof(sithAnimclass) * num); // Added: word-safe
    return 1;
}

void sithAnimClass_Free(sithWorld *world)
{
    unsigned int v1; // edi
    int v2; // ebx

    if ( world->numAnimClasses )
    {

        v1 = 0;
        if ( world->numAnimClassesLoaded )
        {
            v2 = 0;
            do
            {
#ifdef SITH_DEBUG_STRUCT_NAMES
                stdHashtbl_Remove(sithPuppet_pClassHashtable, world->animclasses[v2].name);
#elif defined(STDHASHTABLE_CRC32_KEYS)
                stdHashtbl_FreeKeyCrc32(sithPuppet_pClassHashtable, world->animclasses[v2].namecrc);
#endif
                ++v1;
                ++v2;
            }
            while ( v1 < world->numAnimClassesLoaded );
        }

        SITH_FREE(world->animclasses);
        world->animclasses = 0;
        world->numAnimClassesLoaded = 0;
        world->numAnimClasses = 0;
    }
}

