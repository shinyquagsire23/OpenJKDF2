#include "sithSoundClass.h"

#include "stdPlatform.h"
#include "General/stdHashTable.h"
#include "Engine/sithNet.h"
#include "Engine/sithSound.h"
#include "World/sithWorld.h"

static const char* sithSoundClass_aKeys[96] = {
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

int sithSoundClass_Startup()
{
    sithSoundClass_hashtable = stdHashTable_New(64);
    sithSoundClass_nameToKeyHashtable = stdHashTable_New(192);
    if ( sithSoundClass_hashtable && sithSoundClass_nameToKeyHashtable )
    {
        for (int i = 1; i < 96; i++)
        {
            stdHashTable_SetKeyVal(sithSoundClass_nameToKeyHashtable, sithSoundClass_aKeys[i], (void *)i);
        }
        return 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithSoundClass.c", 214, "Could not allocate hashtable for soundclasses.\n", 0, 0, 0, 0);
        return 0;
    }
}

int sithSoundClass_Load(sithWorld *world, int a2)
{
    int num_soundclasses; // ebx
    signed int result; // eax
    sithSoundClass *soundclasses; // edi
    int v5; // eax
    char *v6; // ebp
    sithWorld *v7; // ebx
    int idx; // eax
    sithSoundClass *current_soundclass; // esi
    stdHashTable *v10; // [esp-Ch] [ebp-9Ch]
    char soundclass_fname[128]; // [esp+10h] [ebp-80h] BYREF

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "soundclasses") )
        return 0;
    num_soundclasses = _atoi(stdConffile_entry.args[2].value);
    if ( num_soundclasses <= 0 )
        return 1;
    if ( net_isMulti )
        num_soundclasses += 32;
    soundclasses = (sithSoundClass *)pSithHS->alloc(sizeof(sithSoundClass) * num_soundclasses);
    world->soundclasses = soundclasses;
    if ( soundclasses )
    {
        world->numSoundClasses = num_soundclasses;
        world->numSoundClassesLoaded = 0;
        _memset(soundclasses, 0, sizeof(sithSoundClass) * num_soundclasses);
        v5 = 1;
    }
    else
    {
        v5 = 0;
    }
    if ( v5 )
    {
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
                break;
            v6 = stdConffile_entry.args[1].value;
            v7 = sithWorld_pLoading;
            if ( _strcmp(stdConffile_entry.args[1].value, "none") )
            {
                if ( sithWorld_pLoading->soundclasses )
                {
                    _sprintf(soundclass_fname, "%s%c%s", "misc\\snd", 92, stdConffile_entry.args[1].value);
                    if ( !stdHashTable_GetKeyVal(sithSoundClass_hashtable, v6) )
                    {
                        idx = v7->numSoundClassesLoaded;
                        if ( idx != v7->numSoundClasses )
                        {
                            current_soundclass = &v7->soundclasses[idx];
                            _strncpy(current_soundclass->snd_fname, v6, 0x1Fu);
                            current_soundclass->snd_fname[31] = 0;
                            if ( sithSoundClass_LoadEntry(current_soundclass, soundclass_fname) )
                            {
                                v10 = sithSoundClass_hashtable;
                                ++v7->numSoundClassesLoaded;
                                stdHashTable_SetKeyVal(v10, current_soundclass->snd_fname, current_soundclass);
                            }
                        }
                    }
                }
            }
        }
        result = 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithSoundClass.c", 321, "Memory error while reading soundclasses, line %d.\n", stdConffile_linenum);
        result = 0;
    }
    return result;
}

sithSoundClass* sithSoundClass_LoadFile(char *fpath)
{
    sithWorld *v1; // ebx
    sithSoundClass *result; // eax
    int v3; // eax
    sithSoundClass *v4; // esi
    stdHashTable *v5; // [esp-Ch] [ebp-9Ch]
    char v6[128]; // [esp+10h] [ebp-80h] BYREF

    v1 = sithWorld_pLoading;
    if ( !_strcmp(fpath, "none") || !sithWorld_pLoading->soundclasses )
        return 0;
    _sprintf(v6, "%s%c%s", "misc\\snd", '\\', fpath);
    result = (sithSoundClass *)stdHashTable_GetKeyVal(sithSoundClass_hashtable, fpath);
    if ( result )
        return result;
    v3 = v1->numSoundClassesLoaded;
    if ( v3 == v1->numSoundClasses )
        return 0;
    v4 = &v1->soundclasses[v3];
    _strncpy(v4->snd_fname, fpath, 0x1Fu);
    v4->snd_fname[31] = 0;
    if ( !sithSoundClass_LoadEntry(v4, v6) )
        return 0;
    v5 = sithSoundClass_hashtable;
    ++v1->numSoundClassesLoaded;
    stdHashTable_SetKeyVal(v5, v4->snd_fname, v4);
    return v4;
}

int sithSoundClass_LoadEntry(sithSoundClass *soundClass, char *fpath)
{
    uint32_t soundIdx; // ebp
    sithSound *v5; // ebx
    sithSoundClassEntry *newEntry; // esi
    sithSoundClassEntry *v8; // edi
    sithSoundClassEntry *v9; // ecx
    int v10; // edx
    sithSoundClassEntry *i; // eax

    if (!stdConffile_OpenRead(fpath))
        return 0;

    while ( stdConffile_ReadArgs() )
    {
        if ( stdConffile_entry.numArgs >= 2u )
        {
            soundIdx = (uint32_t)stdHashTable_GetKeyVal(sithSoundClass_nameToKeyHashtable, stdConffile_entry.args[0].value);
            if (soundIdx)
            {
                if (soundIdx < 0x60)
                {
                    if ( !_strcmp(stdConffile_entry.args[1].value, "none") )
                    {
                        v5 = 0;
LABEL_9:
                        newEntry = (sithSoundClassEntry *)pSithHS->alloc(sizeof(sithSoundClassEntry));
                        if ( newEntry )
                        {
                            _memset(newEntry, 0, sizeof(sithSoundClassEntry));
                            newEntry->sound = v5;
                            newEntry->playflags = 64;
                            newEntry->minRadius = 0.5;
                            newEntry->maxRadius = 2.5;
                            newEntry->maxVolume = 1.0;
                            if (stdConffile_entry.numArgs > 2u)
                                _sscanf(stdConffile_entry.args[2].value, "%x", &newEntry->playflags);
                            if ( stdConffile_entry.numArgs > 3u )
                                newEntry->minRadius = _atof(stdConffile_entry.args[3].value);
                            if ( stdConffile_entry.numArgs > 4u )
                                newEntry->maxRadius = _atof(stdConffile_entry.args[4].value);
                            if ( stdConffile_entry.numArgs > 5u )
                                newEntry->maxVolume = _atof(stdConffile_entry.args[5].value);
                            if ( (newEntry->playflags & 0x4000) != 0 && newEntry->sound )
                                sithSound_LoadFileData(newEntry->sound);
                            v8 = soundClass->entries[soundIdx];
                            if ( v8 )
                            {
                                v9 = soundClass->entries[soundIdx];
                                v10 = 1;
                                for ( i = v8->nextSound; i; i = i->nextSound )
                                {
                                    v9 = i;
                                    ++v10;
                                }
                                v9->nextSound = newEntry;
                                v8->listIdx = v10 + 1;
                            }
                            else
                            {
                                soundClass->entries[soundIdx] = newEntry;
                                newEntry->listIdx = 1;
                            }
                        }
                        continue;
                    }
                    v5 = sithSound_LoadEntry(stdConffile_entry.args[1].value, 0);
                    if ( v5 )
                        goto LABEL_9;
                }
            }
        }
    }
    stdConffile_Close();

    return 1;
}

#ifdef LINUX
sithSoundClass* sithSoundClass_ThingPlaySoundclass(sithThing *thing, int a2)
{
    return NULL;
}
#endif
