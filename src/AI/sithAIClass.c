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
int sithAIClass_AllocWorldAIClasses(SithWorld *pWorld, int numClasses)
{
    intptr_t result; // eax

    SITH_ASSERTREL(pWorld); // Added: J3D assert
    SITH_ASSERTREL(pWorld->aAIClasses == NULL); // Added: J3D assert
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: parsed once, word-width fields (fpath is debug-only)
    result = (intptr_t)SITH_ALLOC(sizeof(SithAIClass) * numClasses);
    TWL_EXTRAM_RESTORE(pSithHS); }
    pWorld->aAIClasses = (SithAIClass *)result;
    if (result)
    {
        stdPlatform_Memzero32((void *)result, sizeof(SithAIClass) * numClasses); // Added: word-safe
        pWorld->sizeAIClasses = numClasses;
        pWorld->numAIClasses = 0;
        result = 1;
    }
    else
    {
        SITHLOG_ERROR("Memory allocation failure.\n"); // Added: J3D log
        pWorld->sizeAIClasses = 0;
        pWorld->numAIClasses = 0;
    }
    return result;
}

int sithAIClass_ReadStaticAIClassesListText(SithWorld *pWorld, int bSkip)
{
    int sizeAIClasses; // ebx
    SithAIClass *aAIClasses; // eax

    if (bSkip) {
        return 0;
    }
    SITH_ASSERTREL(pWorld != NULL); // Added: J3D assert
    stdConffile_ReadArgs();
    if (_strcmp(stdConffile_g_entry.aArgs[0].value, "world") || _strcmp(stdConffile_g_entry.aArgs[1].value, "aiclasses")) {
        SITHLOG_ERROR("Parse error reading static aiclasses list line %d.\n", stdConffile_linenum); // Added: J3D log
        return 0;
    }
    sizeAIClasses = _atoi(stdConffile_g_entry.aArgs[2].value);
    if (!sizeAIClasses) {
        return 1;
    }
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: parsed once, word-width fields (fpath is debug-only)
    aAIClasses = (SithAIClass *)SITH_ALLOC(sizeof(SithAIClass) * sizeAIClasses);
    TWL_EXTRAM_RESTORE(pSithHS); }
    pWorld->aAIClasses = aAIClasses;
    if (!aAIClasses)
    {
        pWorld->sizeAIClasses = 0;
        pWorld->numAIClasses = 0;
        stdPrintf(pSithHS->errorPrint, ".\\Ai\\sithAIClass.c", 176, "Memory error while reading aiclasses, line %d.\n", stdConffile_linenum);
        return 0;
    }
    
    stdPlatform_Memzero32(aAIClasses, sizeof(SithAIClass) * sizeAIClasses); // Added: word-safe
    pWorld->numAIClasses = 0;
    pWorld->sizeAIClasses = sizeAIClasses;
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
    SITH_ASSERTREL(pWorld->numAIClasses <= pWorld->sizeAIClasses); // Added: J3D assert
    return 1;
}

SithAIClass* sithAIClass_Load(char *fpath)
{
    SithWorld *world; // ebp
    SithAIClass *result; // eax
    unsigned int numLoaded; // ecx
    SithAIClass *aiclass; // ebx
    char fullpath[128]; // [esp+10h] [ebp-80h] BYREF

    SITH_ASSERTREL(sithWorld_g_pLastLoadedWorld && fpath); // Added: J3D assert (pWorld && pName)
    SITH_ASSERTREL(strlen(fpath) < 64); // Added: J3D assert
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

int sithAIClass_LoadEntry(char *pPath, SithAIClass *pClass)
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

    SITH_ASSERTREL(pPath && pClass); // Added: J3D assert
    _sprintf(jkl_fname, "%s%1d", pPath, jkPlayer_setDiff);
    if ( stdConffile_Open(jkl_fname) || (result = stdConffile_Open(pPath)) != 0 )
    {
        pClass->maxStep = 0.5;
        pClass->sightDistance = 20.0;
        pClass->heardDistance = 10.0;
        pClass->fov = 0.0;
        pClass->accurancy = 0.5;
        if ( stdConffile_ReadArgs() )
        {
            for (int v19 = 0; v19 < stdConffile_g_entry.numArgs; v19++)
            {
                StdConffileArg* arg = &stdConffile_g_entry.aArgs[v19];
                if ( !_strcmp(arg->key, "alignment") )
                {
                    pClass->alignment = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "rank") )
                {
                    pClass->rank = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "maxstep") )
                {
                    pClass->maxStep = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "sightdist") )
                {
                    pClass->sightDistance = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "heardist") )
                {
                    pClass->heardDistance = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "wakeupdist") )
                {
                    pClass->weakupDistance = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "fov") )
                {
                    flex_t fov = _atof(arg->value) * 0.5;
                    stdMath_SinCos(fov, &a3, &a4);
                    pClass->fov = a4;
                }
                else if ( !_strcmp(arg->key, "accuracy") )
                {
                    pClass->accurancy = _atof(arg->value);
                }
            }
            while ( stdConffile_ReadArgs() )
            {
                nextIdx = pClass->numEntries;
                entry = &pClass->entries[nextIdx];
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
                        ++pClass->numEntries;
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

void sithAIClass_FreeWorldAIClasses(SithWorld *pWorld)
{
    SITH_ASSERTREL(pWorld); // Added: J3D assert
    if (pWorld->aAIClasses)
    {
        for (uint32_t i = 0; i < pWorld->numAIClasses; i++)
        {
#ifdef STDHASHTABLE_CRC32_KEYS
            stdHashtbl_FreeKeyCrc32(sithAIClass_g_pHashtable, pWorld->aAIClasses[i].fpathcrc);
#else
            stdHashtbl_Remove(sithAIClass_g_pHashtable, pWorld->aAIClasses[i].fpath);
#endif
        }
        SITH_FREE(pWorld->aAIClasses);
        pWorld->aAIClasses = 0;
    }
    pWorld->sizeAIClasses = 0;
    pWorld->numAIClasses = 0;
}
