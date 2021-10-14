#include "sithSoundClass.h"

#include "stdPlatform.h"
#include "General/stdHashTable.h"
#include "Engine/sithNet.h"
#include "Engine/sithSound.h"
#include "Engine/sithSoundSys.h"
#include "Win95/stdSound.h"
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

void sithSoundClass_Shutdown()
{
    if ( sithSoundClass_hashtable )
    {
        stdHashTable_Free(sithSoundClass_hashtable);
        sithSoundClass_hashtable = 0;
    }
    if ( sithSoundClass_nameToKeyHashtable )
    {
        stdHashTable_Free(sithSoundClass_nameToKeyHashtable);
        sithSoundClass_nameToKeyHashtable = 0;
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

void sithSoundClass_ThingPlaySoundclass4(sithThing *thing, unsigned int soundclass_id)
{
    sithSoundClass *soundclass; // eax
    sithSoundClassEntry *v3; // eax

    soundclass = thing->soundclass;
    if ( soundclass && soundclass_id < 0x60 )
    {
        v3 = soundclass->entries[soundclass_id];
        if ( v3 )
            sithSoundClass_ThingPlaySoundclass2(thing, v3, 1.0);
    }
}

void sithSoundClass_ThingPlaySoundclass5(sithThing *thing, int sc_id, float a3)
{
    sithSoundClass *v3; // eax
    sithSoundClassEntry *v4; // esi
    unsigned int v5; // edi
    uint32_t v6; // eax
    int v7; // eax

    v3 = thing->soundclass;
    if ( v3 )
    {
        if ( (unsigned int)sc_id < 0x60 )
        {
            v4 = v3->entries[sc_id];
            if ( v4 )
            {
                v5 = v4->listIdx;
                if ( v5 > 1 )
                {
                    v6 = (uint32_t)((double)v5 * a3);
                    if ( v6 > v5 - 1 )
                        v6 = v5 - 1;
                    if ( v6 > 1 )
                    {
                        v7 = v6 - 1;
                        do
                        {
                            v4 = v4->nextSound;
                            --v7;
                        }
                        while ( v7 );
                    }
                }
                sithSoundClass_ThingPlaySoundclass2(thing, v4, 1.0);
            }
        }
    }
}

void sithSoundClass_PlayThingSoundclass(sithThing *thing, int sc_id, float a3)
{
    sithSoundClass *v3; // eax
    sithSoundClassEntry *entry; // eax

    v3 = thing->soundclass;
    if ( v3 && (unsigned int)sc_id < 0x60 )
    {
        entry = v3->entries[sc_id];
        if ( entry )
            sithSoundClass_ThingPlaySoundclass2(thing, entry, a3);
    }
}

void sithSoundClass_ThingPauseSoundclass(sithThing *thing, unsigned int sc_id)
{
    sithSoundClass *v2; // eax
    sithSoundClassEntry *v3; // eax

    v2 = thing->soundclass;
    if ( v2 && sc_id < 0x60 )
    {
        v3 = v2->entries[sc_id];
        if ( v3 )
            sithSoundClass_StopSound(thing, v3->sound);
    }
}

void sithSoundClass_Free2(sithWorld *world)
{
    sithSoundClass *v2; // esi
    sithSoundClassEntry **v3; // edi
    int v4; // ebx
    sithSoundClassEntry *v5; // eax
    sithSoundClassEntry *v6; // esi
    int v8; // [esp+8h] [ebp-4h]

    if ( world->numSoundClasses )
    {
        for (v8 = 0; v8 < world->numSoundClassesLoaded; v8++)
        {
            v2 = &world->soundclasses[v8];
            stdHashTable_FreeKey(sithSoundClass_hashtable, v2->snd_fname);
            v3 = v2->entries;
            v4 = 96;
            do
            {
                v5 = *v3;
                if ( *v3 )
                {
                    do
                    {
                        v6 = v5->nextSound;
                        pSithHS->free(v5);
                        v5 = v6;
                    }
                    while ( v6 );
                }
                ++v3;
                --v4;
            }
            while ( v4 );
        }
        pSithHS->free(world->soundclasses);
        world->soundclasses = 0;
        world->numSoundClasses = 0;
        world->numSoundClassesLoaded = 0;
    }
}

sithSoundClass* sithSoundClass_ThingPlaySoundclass(sithThing *thing, uint32_t a2)
{
    sithSoundClass *v2; // eax
    sithSoundClassEntry *v3; // esi
    uint32_t v5; // rax

    v2 = thing->soundclass;
    if ( v2 )
    {
        if ( a2 < SITH_SC_MAX )
        {
            v3 = v2->entries[a2];
            if ( v3 )
            {
                if ( v3->listIdx > 1u )
                {
                    v5 = (uint32_t)(_frand() * (double)v3->listIdx);
                    if ( v5 > v3->listIdx - 1 )
                        v5 = v3->listIdx - 1;
                    for ( ; v5; v5-- )
                        v3 = v3->nextSound;
                }
                sithSoundClass_ThingPlaySoundclass2(thing, v3, 1.0);
                return v2;
            }
        }
    }
    return 0;
}

void sithSoundClass_ThingPlaySoundclass2(sithThing *thing, sithSoundClassEntry *entry, float a3)
{
    sithSound *v3; // edi
    int v4; // ebx
    int v5; // eax
    float a3a; // [esp+1Ch] [ebp+Ch]

    v3 = entry->sound;
    if ( entry->sound )
    {
        v4 = entry->playflags;
        a3a = entry->maxVolume * a3;
        if ( (v4 & 0x400) != 0 )
        {
            v5 = sithSoundSys_GetThingSoundIdx(0, v3);
        }
        else
        {
            if ( (v4 & 0x800) == 0 )
            {
LABEL_7:
                if ( (v4 & 0x40) != 0 )
                    sithSoundSys_PlaySoundPosAbsolute(v3, &thing->position, thing->sector, a3a, entry->minRadius, entry->maxRadius, v4);
                else
                    sithSoundSys_PlaySoundPosThing(v3, thing, a3a, entry->minRadius, entry->maxRadius, v4);
                return;
            }
            v5 = sithSoundSys_GetThingSoundIdx(thing, v3);
        }
        if ( v5 >= 0 )
            return;
        goto LABEL_7;
    }
}

void sithSoundClass_StopSound(sithThing *thing, sithSound *sound)
{
    unsigned int v2; // ebp
    sithPlayingSound* v3; // esi
    int v4; // eax
    sithPlayingSound *v5; // edi
    int v6; // edx
    int v7; // eax
    IDirectSoundBuffer *v8; // [esp-4h] [ebp-14h]

    if ( sithSoundSys_bOpened )
    {
        v2 = 0;
        if ( sithSoundSys_numSoundsAvailable )
        {
            v3 = &sithSoundSys_aPlayingSounds[0];
            do
            {
                if ( v3->flags & 0x80 && thing == v3->thing && (!sound || v3->sound == sound) )
                {
                    sithSoundSys_StopSound(v3);
                }
                ++v2;
                v3++;
            }
            while ( v2 < sithSoundSys_numSoundsAvailable );
        }
        if ( !sound && thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER )
            thing->actorParams.field_1BC = 0;
    }
}

int sithSoundClass_SetThingSoundClass(sithThing *thing, sithSoundClass *soundclass)
{
    if ( thing->soundclass == soundclass )
        return 0;
    thing->soundclass = soundclass;
    return 1;
}
