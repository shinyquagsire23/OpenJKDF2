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

int sithTemplate_AllocWorldTemplates(SithWorld *pWorld, unsigned int size)
{
#ifdef TARGET_RETRO_HOMEBREW
    // Added: aThingTemplates are parsed into a stack local and copied in word-safely,
    // then only ever read (spawn copies FROM them; byte reads are fine) -- cold
    // and word-safe, so they can live in word-addressable-only memory.
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
    pWorld->aThingTemplates = (SithThing*)SITH_ALLOC(sizeof(SithThing) * size);
#ifdef TARGET_RETRO_HOMEBREW
    pSithHS->suggestHeap(prevSuggest);
#endif
    if (!pWorld->aThingTemplates)
        return 0;

    stdPlatform_Memzero32(pWorld->aThingTemplates, sizeof(SithThing) * size); // Added: word-safe
    for (int i = 0; i < size; i++)
    {
        sithThing_Reset(&pWorld->aThingTemplates[i]);
        if ( pWorld->level_type_maybe & 1 )
        {
            pWorld->aThingTemplates[i].idx = 0x8000 | i;
        }
        else
        {
            pWorld->aThingTemplates[i].idx = i;
        }
    }

    pWorld->sizeThingTemplates = size;
    pWorld->numThingTemplates = 0;
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

int sithTemplate_ReadThingTemplatesListText(SithWorld *pWorld, int bSkip)
{
    unsigned int sizeThingTemplates;

    if ( bSkip )
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "templates", 0xAu) )
        return 0;

    sizeThingTemplates = _atoi(stdConffile_g_entry.aArgs[2].value);
    if ( !sizeThingTemplates )
        return 1;
    
    sithTemplate_AllocWorldTemplates(pWorld, sizeThingTemplates);
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_g_entry.aArgs[0].value, "end", 4u) )
            break;
        sithTemplate_Parse(pWorld);
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

void sithTemplate_FreeWorldTemplates(SithWorld *pWorld)
{
    for (int i = 0; i < pWorld->numThingTemplates; i++)
    {
        rdThing_FreeEntry(&pWorld->aThingTemplates[i].renderData);
#ifdef STDHASHTABLE_CRC32_KEYS
        stdHashtbl_FreeKeyCrc32(sithTemplate_pHashtable, pWorld->aThingTemplates[i].templateNameCrc);
#else
        stdHashtbl_Remove(sithTemplate_pHashtable, pWorld->aThingTemplates[i].aName);
#endif
    }

    if ( pWorld->aThingTemplates )
    {
        SITH_FREE(pWorld->aThingTemplates);
        pWorld->aThingTemplates = 0;
        pWorld->sizeThingTemplates = 0;
        pWorld->numThingTemplates = 0;
    }
}

SithThing* sithTemplate_GetTemplate(const char *pName)
{
    SithThing *result;

    if ( !_memcmp(pName, "none", 5u) )
        return 0;
    result = (SithThing *)stdHashtbl_Find(sithTemplate_pHashtable, pName);
    if ( result )
        return result;

    if ( !sithTemplate_masterFileCount )
        return 0;

    // TODO interesting, but this pHashtbl is never initialized
#if 0
    char v6[0x400];
    const char** v3 = (const char **)stdHashtbl_Find(sithTemplate_pMasterHashtable, pName);
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

SithThing* sithTemplate_Parse(SithWorld *pWorld)
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

    if ( pWorld->numThingTemplates >= pWorld->sizeThingTemplates )
        return 0;

    result = &pWorld->aThingTemplates[pWorld->numThingTemplates++];
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
