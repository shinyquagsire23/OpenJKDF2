#include "sithAIClass.h"

#include "General/stdHashTable.h"
#include "General/stdMath.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "AI/sithAI.h"
#include "stdPlatform.h"
#include "jk.h"

int sithAIClass_Startup()
{
    sithAIClass_hashmap = stdHashTable_New(64);
    return sithAIClass_hashmap != 0;
}

void sithAIClass_Shutdown()
{
    if (sithAIClass_hashmap)
    {
        stdHashTable_Free(sithAIClass_hashmap);
        sithAIClass_hashmap = 0;
    }
}

// Unused
int sithAIClass_New(sithWorld *world, int a2)
{
    intptr_t result; // eax

    result = (intptr_t)pSithHS->alloc(sizeof(sithAIClass) * a2);
    world->aiclasses = (sithAIClass *)result;
    if (result)
    {
        _memset((void *)result, 0, sizeof(sithAIClass) * a2);
        world->numAIClasses = a2;
        world->numAIClassesLoaded = 0;
        result = 1;
    }
    else
    {
        world->numAIClasses = 0;
        world->numAIClassesLoaded = 0;
    }
    return result;
}

int sithAIClass_ParseSection(sithWorld *world, int a2)
{
    int numAIClasses; // ebx
    sithAIClass *aiclasses; // eax

    if (a2) {
        return 0;
    }
    stdConffile_ReadArgs();
    if (_strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "aiclasses")) {
        return 0;
    }
    numAIClasses = _atoi(stdConffile_entry.args[2].value);
    if (!numAIClasses) {
        return 1;
    }
    aiclasses = (sithAIClass *)pSithHS->alloc(sizeof(sithAIClass) * numAIClasses);
    world->aiclasses = aiclasses;
    if (!aiclasses)
    {
        world->numAIClasses = 0;
        world->numAIClassesLoaded = 0;
        stdPrintf(pSithHS->errorPrint, ".\\Ai\\sithAIClass.c", 176, "Memory error while reading aiclasses, line %d.\n", stdConffile_linenum);
        return 0;
    }
    
    _memset(aiclasses, 0, sizeof(sithAIClass) * numAIClasses);
    world->numAIClassesLoaded = 0;
    world->numAIClasses = numAIClasses;
    if ( stdConffile_ReadArgs() )
    {
        while ( _strcmp(stdConffile_entry.args[0].value, "end") )
        {
            if ( !sithAIClass_Load(stdConffile_entry.args[1].value) )
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

sithAIClass* sithAIClass_Load(char *fpath)
{
    sithWorld *world; // ebp
    sithAIClass *result; // eax
    unsigned int numLoaded; // ecx
    sithAIClass *aiclass; // ebx
    char fullpath[128]; // [esp+10h] [ebp-80h] BYREF

    world = sithWorld_pLoading;
    if ( !sithWorld_pLoading->aiclasses )
        return 0;

    result = (sithAIClass *)stdHashTable_GetKeyVal(sithAIClass_hashmap, fpath);
    if ( result )
        return result;

    _sprintf(fullpath, "%s%c%s", "misc\\ai", 92, fpath);

    numLoaded = world->numAIClassesLoaded;
    if ( numLoaded >= world->numAIClasses )
        return 0;

    aiclass = &world->aiclasses[numLoaded];

    _memset(aiclass, 0, sizeof(sithAIClass));

    _strncpy(aiclass->fpath, fpath, 0x1Fu);
    aiclass->fpath[31] = 0;

    if ( sithAIClass_LoadEntry(fullpath, aiclass) )
    {
        stdHashTable_SetKeyVal(sithAIClass_hashmap, aiclass->fpath, aiclass);
        aiclass->index = world->numAIClassesLoaded++;
        
        return aiclass;
    }
    if ( !_strcmp(fpath, "default.ai") )
        return 0;

    return sithAIClass_Load("default.ai");
}

int sithAIClass_LoadEntry(char *fpath, sithAIClass *aiclass)
{
    int result; // eax
    sithAIClass *v3; // ebx
    unsigned int nextIdx; // eax
    sithAIClassEntry *entry; // esi
    sithAICommand *instinct; // eax
    uint32_t v11; // eax
    char jkl_fname[128]; // [esp+18h] [ebp-8Ch] BYREF
    flex_t a3; // [esp+98h] [ebp-Ch] BYREF
    flex_t a4; // [esp+A0h] [ebp-4h] BYREF
    flex_t fpathb; // [esp+ACh] [ebp+8h]

    _sprintf(jkl_fname, "%s%1d", fpath, jkPlayer_setDiff);
    if ( stdConffile_OpenRead(jkl_fname) || (result = stdConffile_OpenRead(fpath)) != 0 )
    {
        aiclass->maxStep = 0.5;
        aiclass->sightDist = 20.0;
        aiclass->hearDist = 10.0;
        aiclass->fov = 0.0;
        aiclass->accuracy = 0.5;
        if ( stdConffile_ReadArgs() )
        {
            for (int v19 = 0; v19 < stdConffile_entry.numArgs; v19++)
            {
                stdConffileArg* arg = &stdConffile_entry.args[v19];
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
                    aiclass->sightDist = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "heardist") )
                {
                    aiclass->hearDist = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "wakeupdist") )
                {
                    aiclass->wakeupDist = _atof(arg->value);
                }
                else if ( !_strcmp(arg->key, "fov") )
                {
                    flex_t fov = _atof(arg->value) * 0.5;
                    stdMath_SinCos(fov, &a3, &a4);
                    aiclass->fov = a4;
                }
                else if ( !_strcmp(arg->key, "accuracy") )
                {
                    aiclass->accuracy = _atof(arg->value);
                }
            }
            while ( stdConffile_ReadArgs() )
            {
                nextIdx = aiclass->numEntries;
                entry = &aiclass->entries[nextIdx];
                if ( nextIdx < 0x10 )
                {
                    instinct = sithAI_FindCommand(stdConffile_entry.args[0].value);
                    if ( instinct )
                    {
                        entry->func = instinct->func;
                        entry->param1 = instinct->param1;
                        entry->param2 = instinct->param2;
                        entry->param3 = instinct->param3;

                        for (v11 = 0; v11 < 16; v11++)
                        {
                            if ( stdConffile_entry.numArgs <= v11 + 1 )
                            {
                                entry->argsAsFloat[v11] = 0;
                                entry->argsAsInt[v11] = 0;
                            }
                            else
                            {
                                flex_t v15 = _atof(stdConffile_entry.args[1+v11].value);
                                entry->argsAsFloat[v11] = v15;
                                entry->argsAsInt[v11] = (int)v15;
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

void sithAIClass_Free(sithWorld *world)
{
    if (world->aiclasses)
    {
        for (uint32_t i = 0; i < world->numAIClassesLoaded; i++)
        {
            stdHashTable_FreeKey(sithAIClass_hashmap, world->aiclasses[i].fpath);
        }
        pSithHS->free(world->aiclasses);
        world->aiclasses = 0;
    }
    world->numAIClasses = 0;
    world->numAIClassesLoaded = 0;
}
