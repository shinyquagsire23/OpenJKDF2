#include "sithAI.h"

#include "jk.h"
#include "World/sithThing.h"
#include "AI/sithAICmd.h"
#include "AI/sithAIClass.h"
#include "Engine/sithTime.h"
#include "General/stdHashTable.h"

int sithAI_Startup()
{
    int v0; // ebx
    int v1; // edx
    int *v2; // ebp
    sithActor *v3; // esi
    int v4; // eax
    sithActor *v5; // ecx

    if ( sithAI_bInit )
        return 0;

    sithAI_commandList = (sithAICommand *)pSithHS->alloc(sizeof(sithAICommand) * 32);
    if ( sithAI_commandList )
    {
        sithAI_commandsHashmap = stdHashTable_New(64);
        if ( !sithAI_commandsHashmap )
            pSithHS->free(sithAI_commandList);
    }

    sithAICmd_Startup();

    v0 = sithAI_inittedActors;
    _memset(sithAI_actors, 0, sizeof(sithActor) * 256);

    v1 = 255;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[255];
    sithAI_maxActors = 256;

    do
    {
        _memset(v3, 0, sizeof(sithActor));
        if ( v1 == v0 )
        {
            v4 = v1 - 1;
            if ( v1 - 1 >= 0 )
            {
                v5 = &sithAI_actors[v4];
                do
                {
                    if ( v5->thing )
                        break;
                    --v4;
                    --v5;
                }
                while ( v4 >= 0 );
            }
            v0 = v4;
            sithAI_inittedActors = v4;
        }
        *v2++ = v1;
        v3--;
        --v1;
    }
    while ( (int)v3 >= (int)sithAI_actors );

    sithAI_bInit = 1;
    return 1;
}

int sithAI_Open()
{
    if (!sithAI_bInit)
        return 0;

    if (sithAI_bOpened)
        return 0;

    sithAI_bOpened = 1;
    return 1;
}

void sithAI_Close()
{
    int v0; // ebx
    int v1; // edx
    int *v2; // ebp
    sithActor *v3; // esi
    int v4; // eax
    sithActor *v5; // ecx
    
    if (sithAI_bOpened)
        return;
    
    v0 = sithAI_inittedActors;
    _memset(sithAI_actors, 0, sizeof(sithActor) * 256);

    v1 = 255;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[255];
    sithAI_maxActors = 256;

    do
    {
        _memset(v3, 0, sizeof(sithActor));
        if ( v1 == v0 )
        {
            v4 = v1 - 1;
            if ( v1 - 1 >= 0 )
            {
                v5 = &sithAI_actors[v4];
                do
                {
                    if ( v5->thing )
                        break;
                    --v4;
                    --v5;
                }
                while ( v4 >= 0 );
            }
            v0 = v4;
            sithAI_inittedActors = v4;
        }
        *v2++ = v1;
        v3--;
        --v1;
    }
    while ( (int)v3 >= (int)sithAI_actors );
    
    sithAI_bOpened = 0;
}

void sithAI_NewEntry(sithThing *thing)
{
    sithAIClass *sith_ai; // edx
    int v2; // eax
    int v3; // eax
    sithActor *actor; // eax
    float v5; // esi

    sith_ai = thing->aiclass;
    if ( sith_ai )
    {
        v2 = sithAI_maxActors;
        if ( sithAI_maxActors )
        {
            --sithAI_maxActors;
            v3 = sithAI_actorInitted[v2 - 1];
            if ( v3 > sithAI_inittedActors )
                sithAI_inittedActors = v3;
        }
        else
        {
            v3 = -1;
        }
        if ( v3 >= 0 )
        {
            actor = &sithAI_actors[v3];
            thing->actor = actor;
            actor->position.x = thing->position.x;
            v5 = thing->position.z;
            actor->position.y = thing->position.y;
            actor->position.z = v5;
            actor->lookOrientation = thing->lookOrientation.lvec;
            actor->aiclass = sith_ai;
            actor->thing = thing;
            actor->numAIClassEntries = sith_ai->numEntries;
            actor->mode = 0x1004;
            actor->moveSpeed = 1.5;
        }
        else
        {
            thing->thingtype = THINGTYPE_FREE;
        }
    }
    else
    {
        thing->thingtype = THINGTYPE_FREE;
    }
}

void sithAI_FreeEntry(sithThing *thing)
{
    sithActor *v1; // eax
    int v2; // edx
    int v3; // eax
    sithActor *v4; // ecx
    int v5; // eax

    v1 = thing->actor;
    if ( v1 )
    {
        v2 = v1 - sithAI_actors;
        _memset(&sithAI_actors[v2], 0, sizeof(sithActor));
        if ( v2 == sithAI_inittedActors )
        {
            v3 = v2 - 1;
            if ( v2 - 1 >= 0 )
            {
                v4 = &sithAI_actors[v2];
                do
                {
                    if (v4->thing)
                        break;
                    --v3;
                    v4--;
                }
                while ( v3 >= 0 );
            }
            sithAI_inittedActors = v3;
        }
        v5 = sithAI_maxActors;
        thing->actor = 0;
        sithAI_actorInitted[v5] = v2;
        sithAI_maxActors = v5 + 1;
    }
}

int sithAI_LoadThingActorParams(stdConffileArg *arg, sithThing *thing, int param)
{
    sithActor *v3; // esi
    int result; // eax
    int v5; // ebp
    unsigned int v6; // edi
    rdVector3 *v7; // ecx
    float v9; // [esp+10h] [ebp-Ch] BYREF
    float v10; // [esp+14h] [ebp-8h] BYREF
    float v11; // [esp+18h] [ebp-4h] BYREF

    v3 = thing->actor;
    if ( param == THINGPARAM_FRAME )
    {
        v6 = v3->loadedFrames;
        if ( v6 < v3->numFrames && _sscanf(arg->value, "(%f/%f/%f)", &v9, &v10, &v11) == 3 )
        {
            v7 = &v3->framesAlloc[v6];
            v7->x = v9;
            v7->y = v10;
            v7->z = v11;
            ++v3->loadedFrames;
            return 1;
        }
        return 0;
    }
    if ( param != THINGPARAM_NUMFRAMES )
        return 0;
    if ( v3->numFrames )
        return 0;
    v5 = _atoi(arg->value);
    if ( !v5 )
        return 0;
    result = (int)pSithHS->alloc(sizeof(rdVector3) * v5);
    v3->framesAlloc = (rdVector3 *)result;
    if ( result )
    {
        _memset((void *)result, 0, sizeof(rdVector3) * v5);
        v3->numFrames = v5;
        v3->loadedFrames = 0;
        result = 1;
    }
    return result;
}

void sithAI_RegisterCommand(char *cmdName, void *func, int param1, int param2, int param3)
{
    if ( sithAI_numCommands >= 0x20 )
        return;

    sithAICommand* aiCmd = &sithAI_commandList[sithAI_numCommands];

    _strncpy(aiCmd->name, cmdName, 0x1Fu);
    aiCmd->name[31] = 0;
    
    aiCmd->func = func;
    aiCmd->param1 = param1;
    aiCmd->param2 = param2;
    aiCmd->param3 = param3;
    sithAI_numCommands++;
}

sithAICommand* sithAI_FindCommand(const char *cmdName)
{
    if ( !sithAI_numCommands )
        return NULL;

    for (uint32_t i = 0; i < sithAI_numCommands; i++)
    {
        if (!_strcmp(cmdName, sithAI_commandList[i].name))
            return &sithAI_commandList[i];
    }

    return NULL;
}

void sithAI_TickAll()
{
    int v0; // edi
    sithActor *actor; // esi

    v0 = 0;
    for ( actor = sithAI_actors; v0 <= sithAI_inittedActors; ++actor )
    {
        if ( actor->aiclass
          && (actor->thing->thingflags & 0x202) == 0
          && actor->thing->actorParams.health > 0.0
          && (actor->mode & 0x3000) == 0
          && actor->field_190 <= sithTime_curMs )
        {
            sithAI_TickActor(actor);
        }
        ++v0;
    }
}

void sithAI_TickActor(sithActor *actor)
{
    unsigned int v1; // ebp
    int v3; // ebx
    int *v4; // edi
    int v5; // ecx
    unsigned int v7; // [esp+10h] [ebp-8h]
    int a3; // [esp+14h] [ebp-4h]
    int a1a; // [esp+1Ch] [ebp+4h]

    v1 = sithTime_curMs;
    v7 = sithTime_curMs + 5000;
    a3 = actor->mode;
LABEL_2:
    for ( a1a = 0; a1a < actor->numAIClassEntries; ++a1a )
    {
        if ( (actor->entries[a1a].field_0 & 1) == 0 )
        {
            v5 = actor->mode;
            if ( (v5 & actor->aiclass->entries[a1a].param1) != 0 && (v5 & actor->aiclass->entries[a1a].param2) == 0 )
            {
                if ( actor->entries[a1a].field_4 <= v1 )
                {
                    actor->entries[a1a].field_4 = v1 + 1000;
                    if ( actor->aiclass->entries[a1a].func(actor, &actor->aiclass->entries[a1a], &actor->entries[a1a], 0, 0) && a3 != actor->mode )
                    {
                        sithAI_SetActorFireTarget(actor, 256, a3);
                        v1 = sithTime_curMs;
                        a3 = actor->mode;
                        goto LABEL_2;
                    }
                    v1 = sithTime_curMs;
                }
                if ( actor->entries[a1a].field_4 < v7 )
                    v7 = actor->entries[a1a].field_4;
            }
        }
    }
    actor->field_190 = v7;
}
