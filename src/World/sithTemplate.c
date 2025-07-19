#include "sithTemplate.h"

#include "World/sithThing.h"
#include "World/sithWorld.h"
#include "General/stdString.h"
#include "General/stdConffile.h"
#include "General/stdHashTable.h"

#include "jk.h"

int sithTemplate_Startup()
{
    sithTemplate_hashmap = stdHashTable_New(512);
    return sithTemplate_hashmap != 0;
}

void sithTemplate_Shutdown()
{
    if ( sithTemplate_hashmap )
    {
        stdHashTable_Free(sithTemplate_hashmap);
        sithTemplate_hashmap = 0;
    }
}

int sithTemplate_New(sithWorld *world, unsigned int numTemplates)
{
    world->templates = (sithThing*)pSithHS->alloc(sizeof(sithThing) * numTemplates);
    if (!world->templates)
        return 0;

    _memset(world->templates, 0, sizeof(sithThing) * numTemplates);
    for (int i = 0; i < numTemplates; i++)
    {
        sithThing_DoesRdThingInit(&world->templates[i]);
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

sithThing* sithTemplate_GetEntryByIdx(int idx)
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

int sithTemplate_Load(sithWorld *world, int a2)
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
    
    sithTemplate_New(world, numTemplates);
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_entry.args[0].value, "end", 4u) )
            break;
        sithTemplate_CreateEntry(world);
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

void sithTemplate_FreeWorld(sithWorld *world)
{
    for (int i = 0; i < world->numTemplatesLoaded; i++)
    {
        rdThing_FreeEntry(&world->templates[i].rdthing);
#ifdef STDHASHTABLE_CRC32_KEYS
        stdHashTable_FreeKeyCrc32(sithTemplate_hashmap, world->templates[i].templateNameCrc);
#else
        stdHashTable_FreeKey(sithTemplate_hashmap, world->templates[i].template_name);
#endif
    }

    if ( world->templates )
    {
        pSithHS->free(world->templates);
        world->templates = 0;
        world->numTemplates = 0;
        world->numTemplatesLoaded = 0;
    }
}

sithThing* sithTemplate_GetEntryByName(const char *name)
{
    sithThing *result;

    if ( !_memcmp(name, "none", 5u) )
        return 0;
    result = (sithThing *)stdHashTable_GetKeyVal(sithTemplate_hashmap, name);
    if ( result )
        return result;

    if ( !sithTemplate_count )
        return 0;

    // TODO interesting, but this hashtable is never initialized
#if 0
    char v6[0x400];
    const char** v3 = (const char **)stdHashTable_GetKeyVal(sithTemplate_oldHashtable, name);
    if ( !v3 )
        return 0;
    if ( v3[3] )
        sithTemplate_GetEntryByName(v3[3]);
    stdConffile_OpenRead("none");

    _strncpy(v6, v3[2], 0x3FFu);
    v6[0x3FF] = 0;

    stdConffile_ReadArgsFromStr(&v6);
    result = sithTemplate_CreateEntry(sithWorld_pLoading);
    stdConffile_Close();
    return result;
#endif
    return 0;
}

sithThing* sithTemplate_CreateEntry(sithWorld *world)
{
    sithThing *result;
    sithThing tmp;
    const char* template_name;

    result = (sithThing *)stdHashTable_GetKeyVal(sithTemplate_hashmap, (const char*)stdConffile_entry.args[0].value);
    if ( result )
        return result;

    // Added: memset for consistent behavior
    memset(&tmp, 0, sizeof(tmp));

    sithThing_DoesRdThingInit(&tmp);
    result = (sithThing *)stdHashTable_GetKeyVal(sithTemplate_hashmap, (const char*)stdConffile_entry.args[1].value);
    sithThing_InstantiateFromTemplate(&tmp, result);

    template_name = stdConffile_entry.args[0].value;
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(tmp.template_name, template_name, sizeof(tmp.template_name));
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
    tmp.templateNameCrc = crc32(template_name, strlen(template_name));
#endif

    for (int i = 2; i < stdConffile_entry.numArgs; i++)
    {
        sithThing_ParseArgs(&stdConffile_entry.args[i], &tmp);
    }

    if (!tmp.type )
        return 0;

    if ( world->numTemplatesLoaded >= world->numTemplates )
        return 0;

    result = &world->templates[world->numTemplatesLoaded++];
    tmp.thingIdx = result->thingIdx;
    _memcpy(result, &tmp, sizeof(sithThing));
    stdHashTable_SetKeyVal(sithTemplate_hashmap, template_name, result);

    return result;
}
