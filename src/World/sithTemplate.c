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
    sithTemplate_hashmap = stdHashtbl_New(512);
    return sithTemplate_hashmap != 0;
}

void sithTemplate_Shutdown()
{
    if ( sithTemplate_hashmap )
    {
        stdHashtbl_Free(sithTemplate_hashmap);
        sithTemplate_hashmap = 0;
    }
}

int sithTemplate_AllocWorldTemplates(sithWorld *world, unsigned int numTemplates)
{
#ifdef TARGET_RETRO_HOMEBREW
    // Added: templates are parsed into a stack local and copied in word-safely,
    // then only ever read (spawn copies FROM them; byte reads are fine) -- cold
    // and word-safe, so they can live in word-addressable-only memory.
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
    world->templates = (sithThing*)SITH_ALLOC(sizeof(sithThing) * numTemplates);
#ifdef TARGET_RETRO_HOMEBREW
    pSithHS->suggestHeap(prevSuggest);
#endif
    if (!world->templates)
        return 0;

    stdPlatform_Memzero32(world->templates, sizeof(sithThing) * numTemplates); // Added: word-safe
    for (int i = 0; i < numTemplates; i++)
    {
        sithThing_Reset(&world->templates[i]);
        if ( world->level_type_maybe & 1 )
        {
            world->templates[i].thingIdx = 0x8000 | i;
        }
        else
        {
            world->templates[i].thingIdx = i;
        }
    }

    world->numTemplates = numTemplates;
    world->numTemplatesLoaded = 0;
    return 1;
}

sithThing* sithTemplate_GetTemplateByIndex(int idx)
{
    sithWorld* world = sithWorld_pCurrentWorld;
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx > 0 && idx < world->numTemplatesLoaded ) // original doesn't check world, but Cog does?
    {
        return &world->templates[idx];
    }

    return NULL;
}

int sithTemplate_ReadThingTemplatesListText(sithWorld *world, int a2)
{
    unsigned int numTemplates;

    if ( a2 )
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_entry.args[0].value, "world", 6u) || _memcmp(stdConffile_entry.args[1].value, "templates", 0xAu) )
        return 0;

    numTemplates = _atoi(stdConffile_entry.args[2].value);
    if ( !numTemplates )
        return 1;
    
    sithTemplate_AllocWorldTemplates(world, numTemplates);
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_entry.args[0].value, "end", 4u) )
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

void sithTemplate_FreeWorldTemplates(sithWorld *world)
{
    for (int i = 0; i < world->numTemplatesLoaded; i++)
    {
        rdThing_FreeEntry(&world->templates[i].rdthing);
#ifdef STDHASHTABLE_CRC32_KEYS
        stdHashtbl_FreeKeyCrc32(sithTemplate_hashmap, world->templates[i].templateNameCrc);
#else
        stdHashtbl_Remove(sithTemplate_hashmap, world->templates[i].template_name);
#endif
    }

    if ( world->templates )
    {
        SITH_FREE(world->templates);
        world->templates = 0;
        world->numTemplates = 0;
        world->numTemplatesLoaded = 0;
    }
}

sithThing* sithTemplate_GetTemplate(const char *name)
{
    sithThing *result;

    if ( !_memcmp(name, "none", 5u) )
        return 0;
    result = (sithThing *)stdHashtbl_Find(sithTemplate_hashmap, name);
    if ( result )
        return result;

    if ( !sithTemplate_count )
        return 0;

    // TODO interesting, but this hashtable is never initialized
#if 0
    char v6[0x400];
    const char** v3 = (const char **)stdHashtbl_Find(sithTemplate_oldHashtable, name);
    if ( !v3 )
        return 0;
    if ( v3[3] )
        sithTemplate_GetTemplate(v3[3]);
    stdConffile_Open("none");

    _strncpy(v6, v3[2], 0x3FFu);
    v6[0x3FF] = 0;

    stdConffile_ReadArgsFromStr(&v6);
    result = sithTemplate_Parse(sithWorld_pLoading);
    stdConffile_Close();
    return result;
#endif
    return 0;
}

sithThing* sithTemplate_Parse(sithWorld *world)
{
    sithThing *result;
    sithThing tmp;
    const char* template_name;

    result = (sithThing *)stdHashtbl_Find(sithTemplate_hashmap, (const char*)stdConffile_entry.args[0].value);
    if ( result )
        return result;

    // Added: memset for consistent behavior
    memset(&tmp, 0, sizeof(tmp));

    sithThing_Reset(&tmp);
    result = (sithThing *)stdHashtbl_Find(sithTemplate_hashmap, (const char*)stdConffile_entry.args[1].value);
    sithThing_SetThingBasedOn(&tmp, result);

    template_name = stdConffile_entry.args[0].value;
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(tmp.template_name, template_name, sizeof(tmp.template_name));
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
    tmp.templateNameCrc = stdCrc32(template_name, strlen(template_name));
#endif

    for (int i = 2; i < stdConffile_entry.numArgs; i++)
    {
        sithThing_ParseArg(&stdConffile_entry.args[i], &tmp);
    }

    if (!tmp.type )
        return 0;

    if ( world->numTemplatesLoaded >= world->numTemplates )
        return 0;

    result = &world->templates[world->numTemplatesLoaded++];
    tmp.thingIdx = result->thingIdx;
    stdPlatform_Memcpy32(result, &tmp, sizeof(sithThing)); // Added: word-safe (array may be word-addressable-only)
#ifdef SITH_DEBUG_STRUCT_NAMES
    // The copies of names are load-bearing, SetKeyVal stores a reference
    stdHashtbl_Add(sithTemplate_hashmap, result->template_name, result);
#else
    stdHashtbl_Add(sithTemplate_hashmap, template_name, result);
#endif

    return result;
}
