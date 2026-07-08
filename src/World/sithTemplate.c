#include "sithTemplate.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "World/sithThing.h"
#include "World/sithWorld.h"
#include "General/stdString.h"
#include "General/stdConffile.h"
#include "General/stdHashtbl.h"

#include "jk.h"

int sithTemplate_Startup()
{
    sithTemplate_pHashtable = stdHashtbl_New(512);
    return sithTemplate_pHashtable != 0;
}

void sithTemplate_Shutdown()
{
    if ( sithTemplate_pHashtable )
    {
        stdHashtbl_Free(sithTemplate_pHashtable);
        sithTemplate_pHashtable = 0;
    }
}

int sithTemplate_AllocWorldTemplates(SithWorld *world, unsigned int sizeThingTemplates)
{
#ifdef TARGET_RETRO_HOMEBREW
    // Added: aThingTemplates are parsed into a stack local and copied in word-safely,
    // then only ever read (spawn copies FROM them; byte reads are fine) -- cold
    // and word-safe, so they can live in word-addressable-only memory.
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
    world->aThingTemplates = (SithThing*)SITH_ALLOC(sizeof(SithThing) * sizeThingTemplates);
#ifdef TARGET_RETRO_HOMEBREW
    pSithHS->suggestHeap(prevSuggest);
#endif
    if (!world->aThingTemplates)
        return 0;

    stdPlatform_Memzero32(world->aThingTemplates, sizeof(SithThing) * sizeThingTemplates); // Added: word-safe
    for (int i = 0; i < sizeThingTemplates; i++)
    {
        sithThing_Reset(&world->aThingTemplates[i]);
        if ( world->level_type_maybe & 1 )
        {
            world->aThingTemplates[i].idx = 0x8000 | i;
        }
        else
        {
            world->aThingTemplates[i].idx = i;
        }
    }

    world->sizeThingTemplates = sizeThingTemplates;
    world->numThingTemplates = 0;
    return 1;
}

SithThing* sithTemplate_GetTemplateByIndex(int idx)
{
    SithWorld* world = sithWorld_g_pCurrentWorld;
    if ( idx & 0x8000 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx > 0 && idx < world->numThingTemplates ) // original doesn't check world, but Cog does?
    {
        return &world->aThingTemplates[idx];
    }

    return NULL;
}

int sithTemplate_ReadThingTemplatesListText(SithWorld *world, int a2)
{
    unsigned int sizeThingTemplates;

    if ( a2 )
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "templates", 0xAu) )
        return 0;

    sizeThingTemplates = _atoi(stdConffile_g_entry.aArgs[2].value);
    if ( !sizeThingTemplates )
        return 1;
    
    sithTemplate_AllocWorldTemplates(world, sizeThingTemplates);
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_g_entry.aArgs[0].value, "end", 4u) )
            break;
        sithTemplate_Parse(world);
    }
    return 1;
}

int sithTemplate_OldNew(char *fpath)
{
    return 0; // TODO unused but interesting
}

void sithTemplate_OldFree()
{
    // TODO unused but interesting
}

void sithTemplate_FreeWorldTemplates(SithWorld *world)
{
    for (int i = 0; i < world->numThingTemplates; i++)
    {
        rdThing_FreeEntry(&world->aThingTemplates[i].renderData);
#ifdef STDHASHTABLE_CRC32_KEYS
        stdHashtbl_FreeKeyCrc32(sithTemplate_pHashtable, world->aThingTemplates[i].templateNameCrc);
#else
        stdHashtbl_Remove(sithTemplate_pHashtable, world->aThingTemplates[i].aName);
#endif
    }

    if ( world->aThingTemplates )
    {
        SITH_FREE(world->aThingTemplates);
        world->aThingTemplates = 0;
        world->sizeThingTemplates = 0;
        world->numThingTemplates = 0;
    }
}

SithThing* sithTemplate_GetTemplate(const char *name)
{
    SithThing *result;

    if ( !_memcmp(name, "none", 5u) )
        return 0;
    result = (SithThing *)stdHashtbl_Find(sithTemplate_pHashtable, name);
    if ( result )
        return result;

    if ( !sithTemplate_masterFileCount )
        return 0;

    // TODO interesting, but this pHashtbl is never initialized
#if 0
    char v6[0x400];
    const char** v3 = (const char **)stdHashtbl_Find(sithTemplate_pMasterHashtable, name);
    if ( !v3 )
        return 0;
    if ( v3[3] )
        sithTemplate_GetTemplate(v3[3]);
    stdConffile_Open("none");

    _strncpy(v6, v3[2], 0x3FFu);
    v6[0x3FF] = 0;

    stdConffile_ReadArgsFromStr(&v6);
    result = sithTemplate_Parse(sithWorld_g_pLastLoadedWorld);
    stdConffile_Close();
    return result;
#endif
    return 0;
}

SithThing* sithTemplate_Parse(SithWorld *world)
{
    SithThing *result;
    SithThing tmp;
    const char* aName;

    result = (SithThing *)stdHashtbl_Find(sithTemplate_pHashtable, (const char*)stdConffile_g_entry.aArgs[0].value);
    if ( result )
        return result;

    // Added: memset for consistent behavior
    memset(&tmp, 0, sizeof(tmp));

    sithThing_Reset(&tmp);
    result = (SithThing *)stdHashtbl_Find(sithTemplate_pHashtable, (const char*)stdConffile_g_entry.aArgs[1].value);
    sithThing_SetThingBasedOn(&tmp, result);

    aName = stdConffile_g_entry.aArgs[0].value;
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(tmp.aName, aName, sizeof(tmp.aName));
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
    tmp.templateNameCrc = stdCrc32(aName, strlen(aName));
#endif

    for (int i = 2; i < stdConffile_g_entry.numArgs; i++)
    {
        sithThing_ParseArg(&stdConffile_g_entry.aArgs[i], &tmp);
    }

    if (!tmp.type )
        return 0;

    if ( world->numThingTemplates >= world->sizeThingTemplates )
        return 0;

    result = &world->aThingTemplates[world->numThingTemplates++];
    tmp.idx = result->idx;
    stdPlatform_Memcpy32(result, &tmp, sizeof(SithThing)); // Added: word-safe (array may be word-addressable-only)
#ifdef SITH_DEBUG_STRUCT_NAMES
    // The copies of names are load-bearing, SetKeyVal stores a reference
    stdHashtbl_Add(sithTemplate_pHashtable, result->aName, result);
#else
    stdHashtbl_Add(sithTemplate_pHashtable, aName, result);
#endif

    return result;
}
