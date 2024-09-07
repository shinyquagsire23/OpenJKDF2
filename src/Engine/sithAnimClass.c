#include "sithAnimClass.h"

#include "Engine/sithPuppet.h"
#include "World/sithWorld.h"
#include "General/stdString.h"
#include "General/stdHashTable.h"
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
    animclasses = (sithAnimclass *)pSithHS->alloc(sizeof(sithAnimclass) * num_animclasses);
    world->animclasses = animclasses;
    if ( !animclasses )
        return 0;
    world->numAnimClasses = num_animclasses;
    world->numAnimClassesLoaded = 0;
    _memset(animclasses, 0, sizeof(sithAnimclass) * num_animclasses);
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        if ( !stdHashTable_GetKeyVal(sithPuppet_hashtable, stdConffile_entry.args[1].value) )
        {
            if ( sithWorld_pLoading->numAnimClassesLoaded != sithWorld_pLoading->numAnimClasses )
            {
                animclass = &sithWorld_pLoading->animclasses[sithWorld_pLoading->numAnimClassesLoaded];
                _memset(animclass, 0, sizeof(sithAnimclass));
                _strncpy(animclass->name, stdConffile_entry.args[1].value, 0x1Fu);
                animclass->name[31] = 0;
                // Added: sprintf -> snprintf
                stdString_snprintf(pup_path, 128, "%s%c%s", "misc\\pup", 92, stdConffile_entry.args[1].value);
                if ( sithAnimClass_LoadPupEntry(animclass, pup_path) )
                {
                    ++sithWorld_pLoading->numAnimClassesLoaded;
                    stdHashTable_SetKeyVal(sithPuppet_hashtable, animclass->name, animclass);
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

    result = (sithAnimclass *)stdHashTable_GetKeyVal(sithPuppet_hashtable, a1);
    if ( !result )
    {
        v3 = sithWorld_pLoading->numAnimClassesLoaded;
        if ( v3 == sithWorld_pLoading->numAnimClasses
          || (v4 = &sithWorld_pLoading->animclasses[v3],
              _memset(v4, 0, sizeof(sithAnimclass)),
              _strncpy(v4->name, a1, 0x1Fu),
              v4->name[31] = 0,
              _sprintf(v6, "%s%c%s", "misc\\pup", 92, a1),
              !sithAnimClass_LoadPupEntry(v4, v6)) )
        {
            result = 0;
        }
        else
        {
            v5 = sithPuppet_hashtable;
            ++sithWorld_pLoading->numAnimClassesLoaded;
            stdHashTable_SetKeyVal(v5, v4->name, v4);
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
    if (!stdConffile_OpenRead(fpath))
        return 0;

    _memset(animclass->bodypart_to_joint, 0xFFu, sizeof(animclass->bodypart_to_joint));
    while ( stdConffile_ReadArgs() )
    {
        if ( !stdConffile_entry.numArgs )
            continue;
        if ( !_strcmp(stdConffile_entry.args[0].key, "mode") )
        {
            mode = _atoi(stdConffile_entry.args[0].value);
            if ( stdConffile_entry.numArgs > 1u && !_strcmp(stdConffile_entry.args[1].key, "basedon") )
                _memcpy(&animclass->modes[mode], &animclass->modes[_atoi(stdConffile_entry.args[1].value)], sizeof(animclass->modes[mode]));
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
            animNameIdx = (intptr_t)stdHashTable_GetKeyVal(sithPuppet_animNamesToIdxHashtable, stdConffile_entry.args[0].value);
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
                    world = sithWorld_pLoading;
                    key_fname = stdConffile_entry.args[1].value;
                    if ( sithWorld_pLoading->keyframes )
                    {
                        _sprintf(keyframe_fpath, "%s%c%s", "3do\\key", 92, stdConffile_entry.args[1].value);
                        v10 = (rdKeyframe *)stdHashTable_GetKeyVal(sithPuppet_keyframesHashtable, key_fname);
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
								#ifdef STATIC_JKL_EXT
									keyframe->id |= world->idx_offset;
								#else
                                    keyframe->id |= 0x8000u;
								#endif
                                }
                                stdHashTable_SetKeyVal(sithPuppet_keyframesHashtable, keyframe->name, keyframe);
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
                stdHashTable_FreeKey(sithPuppet_hashtable, world->animclasses[v2].name);
                ++v1;
                ++v2;
            }
            while ( v1 < world->numAnimClassesLoaded );
        }
        pSithHS->free(world->animclasses);
        world->animclasses = 0;
        world->numAnimClassesLoaded = 0;
        world->numAnimClasses = 0;
    }
}

