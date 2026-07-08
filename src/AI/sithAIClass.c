#include "sithAIClass.h"

#include "General/stdHashtbl.h"
#include "General/stdMath.h"
#include "General/stdString.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "AI/sithAI.h"
#include "stdPlatform.h"
#include "jk.h"

int sithAIClass_Startup()
{
    sithAIClass_g_pHashtable = stdHashtbl_New(64);
    return sithAIClass_g_pHashtable != 0;
}

void sithAIClass_Shutdown()
{
    if (sithAIClass_g_pHashtable)
    {
        stdHashtbl_Free(sithAIClass_g_pHashtable);
        sithAIClass_g_pHashtable = 0;
    }
}

// Unused
int sithAIClass_AllocWorldAIClasses(SithWorld *world, int a2)
{
    intptr_t result; // eax

    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: parsed once, word-width fields (fpath is debug-only)
    result = (intptr_t)SITH_ALLOC(sizeof(SithAIClass) * a2);
    TWL_EXTRAM_RESTORE(pSithHS); }
    world->aAIClasses = (SithAIClass *)result;
    if (result)
    {
        stdPlatform_Memzero32((void *)result, sizeof(SithAIClass) * a2); // Added: word-safe
        world->sizeAIClasses = a2;
        world->numAIClasses = 0;
        result = 1;
    }
    else
    {
        world->sizeAIClasses = 0;
        world->numAIClasses = 0;
    }
    return result;
}

int sithAIClass_ReadStaticAIClassesListText(SithWorld *world, int a2)
{
    int sizeAIClasses; // ebx
    SithAIClass *aAIClasses; // eax

    if (a2) {
        return 0;
    }
    stdConffile_ReadArgs();
    if (_strcmp(stdConffile_g_entry.aArgs[0].value, "world") || _strcmp(stdConffile_g_entry.aArgs[1].value, "aiclasses")) {
        return 0;
    }
    sizeAIClasses = _atoi(stdConffile_g_entry.aArgs[2].value);
    if (!sizeAIClasses) {
        return 1;
    }
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: parsed once, word-width fields (fpath is debug-only)
    aAIClasses = (SithAIClass *)SITH_ALLOC(sizeof(SithAIClass) * sizeAIClasses);
    TWL_EXTRAM_RESTORE(pSithHS); }
    world->aAIClasses = aAIClasses;
    if (!aAIClasses)
    {
        world->sizeAIClasses = 0;
        world->numAIClasses = 0;
        stdPrintf(pSithHS->errorPrint, ".\\Ai\\sithAIClass.c", 176, "Memory error while reading aiclasses, line %d.\n", stdConffile_linenum);
        return 0;
    }
    
    stdPlatform_Memzero32(aAIClasses, sizeof(SithAIClass) * sizeAIClasses); // Added: word-safe
    world->numAIClasses = 0;
    world->sizeAIClasses = sizeAIClasses;
    if ( stdConffile_ReadArgs() )
    {
        while ( _strcmp(stdConffile_g_entry.aArgs[0].value, "end") )
        {
            if ( !sithAIClass_Load(stdConffile_g_entry.aArgs[1].value) )
            {
                stdPrintf(pSithHS->errorPrint, ".\\Ai\\sithAIClass.c", 172, "Parse error while reading aiclasses, line %d.\n", stdConffile_linenum);
                return 0;
            }
            if ( !stdConffile_ReadArgs() )
                break;
        }
    }
    return 1;
}

SithAIClass* sithAIClass_Load(char *fpath)
{
    SithWorld *world; // ebp
    SithAIClass *result; // eax
    unsigned int numLoaded; // ecx
    SithAIClass *aiclass; // ebx
    char fullpath[128]; // [esp+10h] [ebp-80h] BYREF

    world = sithWorld_g_pLastLoadedWorld;
    if ( !sithWorld_g_pLastLoadedWorld->aAIClasses )
        return 0;

    result = (SithAIClass *)stdHashtbl_Find(sithAIClass_g_pHashtable, fpath);
    if ( result )
        return result;

    _sprintf(fullpath, "%s%c%s", "misc\\ai", 92, fpath);

    numLoaded = world->numAIClasses;
    if ( numLoaded >= world->sizeAIClasses )
        return 0;

    aiclass = &world->aAIClasses[numLoaded];

    stdPlatform_Memzero32(aiclass, sizeof(SithAIClass)); // Added: word-safe

#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(aiclass->fpath, fpath, 32);
#endif
#ifdef STDHASHTABLE_CRC32_KEYS
    aiclass->fpathcrc = stdCrc32(fpath, strlen(fpath));
#endif

    if ( sithAIClass_LoadEntry(fullpath, aiclass) )
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
            // The copies of names are load-bearing, SetKeyVal stores a reference
        stdHashtbl_Add(sithAIClass_g_pHashtable, aiclass->fpath, aiclass);
#else
        stdHashtbl_Add(sithAIClass_g_pHashtable, fpath, aiclass);
#endif
        aiclass->index = world->numAIClasses++;
        
        return aiclass;
    }
    if ( !_strcmp(fpath, "default.ai") )
        return 0;

    return sithAIClass_Load("default.ai");
}

int sithAIClass_LoadEntry(char *fpath, SithAIClass *aiclass)
{
    int result; // eax
    SithAIClass *v3; // ebx
    unsigned int nextIdx; // eax
    SithAIInstinct *entry; // esi
    SithAIRegisteredInstinct *instinct; // eax
    uint32_t v11; // eax
    char jkl_fname[128]; // [esp+18h] [ebp-8Ch] BYREF
    flex_t a3; // [esp+98h] [ebp-Ch] BYREF
    flex_t a4; // [esp+A0h] [ebp-4h] BYREF
    flex_t fpathb; // [esp+ACh] [ebp+8h]

    _sprintf(jkl_fname, "%s%1d", fpath, jkPlayer_setDiff);
    if ( stdConffile_Open(jkl_fname) || (result = stdConffile_Open(fpath)) != 0 )
    {
        aiclass->maxStep = 0.5;
        aiclass->sightDistance = 20.0;
        aiclass->heardDistance = 10.0;
        aiclass->fov = 0.0;
        aiclass->accurancy = 0.5;
        if ( stdConffile_ReadArgs() )
        {
            for (int v19 = 0; v19 < stdConffile_g_entry.numArgs; v19++)
            {
                StdConffileArg* arg = &stdConffile_g_entry.aArgs[v19];
                if ( !_strcmp(arg->key, "alignment") )
                {
                    aiclass->alignment = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "rank") )
                {
                    aiclass->rank = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "maxstep") )
                {
                    aiclass->maxStep = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "sightdist") )
                {
                    aiclass->sightDistance = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "heardist") )
                {
                    aiclass->heardDistance = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "wakeupdist") )
                {
                    aiclass->weakupDistance = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "fov") )
                {
                    flex_t fov = _atof(arg->value) * 0.5;
                    stdMath_SinCos(fov, &a3, &a4);
                    aiclass->fov = a4;
                }
                else if ( !_strcmp(arg->key, "accurancy") )
                {
                    aiclass->accurancy = _atof(arg->value);
                }
            }
            while ( stdConffile_ReadArgs() )
            {
                nextIdx = aiclass->numEntries;
                entry = &aiclass->entries[nextIdx];
                if ( nextIdx < 0x10 )
                {
                    instinct = sithAI_FindInstinct(stdConffile_g_entry.aArgs[0].value);
                    if ( instinct )
                    {
                        entry->func = instinct->func;
                        entry->param1 = instinct->param1;
                        entry->param2 = instinct->param2;
                        entry->param3 = instinct->param3;

                        for (v11 = 0; v11 < 16; v11++)
                        {
                            if ( stdConffile_g_entry.numArgs <= v11 + 1 )
                            {
                                entry->fltArg[v11] = 0;
                                entry->intArg[v11] = 0;
                            }
                            else
                            {
                                flex_t v15 = _atof(stdConffile_g_entry.aArgs[1+v11].value);
                                entry->fltArg[v11] = v15;
                                entry->intArg[v11] = (int32_t)v15;
                            }
                        }
                        ++aiclass->numEntries;
                    }
                }
            }
            stdConffile_Close();
            return 1;
        }
        else
        {
            stdConffile_Close();
            return 0;
        }
    }
    return result;
}

void sithAIClass_FreeWorldAIClasses(SithWorld *world)
{
    if (world->aAIClasses)
    {
        for (uint32_t i = 0; i < world->numAIClasses; i++)
        {
#ifdef STDHASHTABLE_CRC32_KEYS
            stdHashtbl_FreeKeyCrc32(sithAIClass_g_pHashtable, world->aAIClasses[i].fpathcrc);
#else
            stdHashtbl_Remove(sithAIClass_g_pHashtable, world->aAIClasses[i].fpath);
#endif
        }
        SITH_FREE(world->aAIClasses);
        world->aAIClasses = 0;
    }
    world->sizeAIClasses = 0;
    world->numAIClasses = 0;
}
