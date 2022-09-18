#include "sithAI.h"

#include "General/stdMath.h"
#include "World/sithThing.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "Gameplay/sithPlayerActions.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "World/sithWeapon.h"
#include "AI/sithAICmd.h"
#include "AI/sithAIClass.h"
#include "Main/sithMain.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithRender.h"
#include "Engine/sithPhysics.h"
#include "General/stdHashTable.h"
#include "Main/jkGame.h"
#include "Cog/sithCogExec.h"
#include "Cog/sithCog.h"
#include "stdPlatform.h"
#include "Devices/sithConsole.h"
#include "Dss/sithDSS.h"
#include "Dss/sithMulti.h"
#include "jk.h"

stdHashTable* sithAI_commandsHashmap = NULL;
uint32_t sithAI_maxActors = 0;
int sithAI_actorInitted[256] = {0};
int sithAI_bOpened = 0;
int sithAI_bInit = 0;
sithAICommand* sithAI_commandList = NULL;
uint32_t sithAI_numCommands = 0;
float sithAI_flt_84DE58 = 0.0f;
uint32_t sithAI_dword_84DE5C = 0;
int sithAI_dword_84DE60 = 0;
float sithAI_flt_84DE64 = 0.0f;
sithThing** sithAI_pThing_84DE68 = NULL;
int sithAI_dword_84DE6C = 0;
float sithAI_flt_84DE70 = 0.0f;
int sithAI_dword_84DE74 = 0;

// These are located in a different part of .data?
sithActor sithAI_actors[256] = {0};
int sithAI_inittedActors = 0;

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
    _memset(sithAI_actors, 0, sizeof(sithActor) * 0x100);

    v1 = 255;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[255];
    sithAI_maxActors = 0x100;

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
    while ( (intptr_t)v3 >= (intptr_t)sithAI_actors );

    sithAI_bInit = 1;
    return 1;
}

void sithAI_Shutdown()
{
    if ( sithAI_bInit )
    {
        pSithHS->free(sithAI_commandList);
        stdHashTable_Free(sithAI_commandsHashmap);
        sithAI_bInit = 0;
    }
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
    _memset(sithAI_actors, 0, sizeof(sithActor) * 0x100);

    v1 = 255;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[255];
    sithAI_maxActors = 0x100;

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
    while ( (intptr_t)v3 >= (intptr_t)sithAI_actors );
    
    sithAI_bOpened = 0;
}

void sithAI_NewEntry(sithThing *thing)
{
    sithAIClass *sith_ai; // edx
    int v2; // eax
    int v3; // eax
    sithActor *actor; // eax

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
            actor->position.y = thing->position.y;
            actor->position.z = thing->position.z;
            actor->lookOrientation = thing->lookOrientation.lvec;
            actor->aiclass = sith_ai;
            actor->thing = thing;
            actor->numAIClassEntries = sith_ai->numEntries;
            actor->flags = (SITHAI_MODE_SLEEPING|SITHAI_MODE_SEARCHING);
            actor->moveSpeed = 1.5;
        }
        else
        {
            thing->thingtype = SITH_THING_FREE;
        }
    }
    else
    {
        thing->thingtype = SITH_THING_FREE;
    }
}

void sithAI_FreeEntry(sithThing *thing)
{
    sithActor *v1; // eax
    int v2; // edx
    int v3; // eax
    sithActor *v4; // ecx

    v1 = thing->actor;
    if ( v1 )
    {
        v2 = v1 - sithAI_actors;

        // Added: fix memleak
        if (sithAI_actors[v2].framesAlloc)
        {
            pSithHS->free(sithAI_actors[v2].framesAlloc);
            sithAI_actors[v2].framesAlloc = NULL;
        }

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
        thing->actor = 0;
        sithAI_actorInitted[sithAI_maxActors++] = v2;
    }
}

void sithAI_TickAll()
{
    int v0; // edi
    sithActor *actor; // esi

    v0 = 0;
    for ( actor = sithAI_actors; v0 <= sithAI_inittedActors; ++actor )
    {
        if ( actor->aiclass
          && (actor->thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0
          && actor->thing->actorParams.health > 0.0
          && (actor->flags & (SITHAI_MODE_DISABLED|SITHAI_MODE_SLEEPING)) == 0
          && actor->nextUpdate <= sithTime_curMs )
        {
            sithAI_TickActor(actor);

            if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
                sithThing_SetSyncFlags(actor->thing, THING_SYNC_ALL); // Added
            }
        }

        ++v0;
    }
}

void sithAI_TickActor(sithActor *actor)
{
    int v3; // ebx
    int *v4; // edi
    int a1a; // [esp+1Ch] [ebp+4h]

    uint32_t nextMs = sithTime_curMs + 5000;
    int a3 = actor->flags;
LABEL_2:
    for ( a1a = 0; a1a < actor->numAIClassEntries; ++a1a )
    {
        if ( (actor->instincts[a1a].field_0 & 1) == 0 )
        {
            if ((actor->flags & actor->aiclass->entries[a1a].param1) 
                && !(actor->flags & actor->aiclass->entries[a1a].param2))
            {
                if ( actor->instincts[a1a].nextUpdate <= sithTime_curMs )
                {
                    actor->instincts[a1a].nextUpdate = sithTime_curMs + 1000;
                    if ( actor->aiclass->entries[a1a].func(actor, &actor->aiclass->entries[a1a], &actor->instincts[a1a], 0, 0) && a3 != actor->flags )
                    {
                        sithAI_SetActorFireTarget(actor, SITHAI_MODE_UNK100, a3);
                        a3 = actor->flags;
                        goto LABEL_2;
                    }
                }
                if ( actor->instincts[a1a].nextUpdate < nextMs )
                    nextMs = actor->instincts[a1a].nextUpdate;
            }
        }
    }
    actor->nextUpdate = nextMs;
}

void sithAI_SetActorFireTarget(sithActor *actor, int a2, intptr_t actorFlags)
{
    int v6; // eax
    uint32_t v7; // ebx
    int old_flags; // [esp+14h] [ebp+4h]

    for ( ; actor->aiclass; a2 = SITHAI_MODE_UNK100 )
    {
        if ( !actor->thing )
            break;
        if (actor->thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED))
            break;
        if ( (g_debugmodeFlags & 1) != 0 )
            break;
        if ( actor->thing->actorParams.health <= 0.0 )
            break;
        old_flags = actor->flags;
        if ( (actor->flags & SITHAI_MODE_DISABLED) != 0 )
            break;
        if ( (actor->flags & SITHAI_MODE_SLEEPING) != 0 )
        {
            if ( a2 != SITHAI_MODE_ATTACKING )
                return;
            actor->flags &= ~SITHAI_MODE_SLEEPING;
        }

        if ( a2 == SITHAI_MODE_UNK100 )
            sithCog_SendMessageFromThingEx(actor->thing, 0, SITH_MESSAGE_AIEVENT, (float)SITHAI_EVENTMODECHANGED, 0.0, 0.0, 0.0);

        v7 = 0;
        for (v7 = 0; v7 < actor->numAIClassEntries; v7++)
        {
            sithActorInstinct* entry = &actor->instincts[v7];
            if ( (entry->field_0 & 1) == 0 )
            {
                if ( (actor->aiclass->entries[v7].param3 & a2) != 0 )
                {
                    if ( actor->aiclass->entries[v7].func(actor, &actor->aiclass->entries[v7], entry, a2, actorFlags) )
                        break;
                }
            }
        }
        if ( actor->flags == old_flags )
            break;
        actorFlags = old_flags;
    }
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

int sithAI_PrintThings()
{
    int v1; // edi
    sithActor *i; // esi
    sithAIClass *v3; // ecx

    if ( sithAI_bOpened )
    {
        sithConsole_Print("Active AI things:\n");
        v1 = 0;
        for ( i = sithAI_actors; v1 <= sithAI_inittedActors; ++i )
        {
            v3 = i->aiclass;
            if ( v3 )
            {
                if ( i->thing )
                {
                    _sprintf(
                        std_genBuffer,
                        "Block %2d: Class '%s', Owner '%s' (%d), Flags 0x%x\n",
                        v1,
                        v3->fpath,
                        i->thing->template_name,
                        i->thing->thingIdx,
                        i->flags);
                    sithConsole_Print(std_genBuffer);
                }
            }
            ++v1;
        }
        return 1;
    }
    else
    {
        sithConsole_Print("AI system not open.\n");
        return 0;
    }
}

int sithAI_PrintThingStatus(int a1, char *idxStr)
{
    uint32_t v2; // ebx
    sithThing *v3; // eax
    sithActor *v4; // edi
    int result; // eax
    int v7; // [esp+3Ch] [ebp-8h]
    int actorIdx; // [esp+40h] [ebp-4h] BYREF

    v2 = 0;
    if ( idxStr && sithAI_bOpened && _sscanf(idxStr, "%d", &actorIdx) == 1 && actorIdx <= sithAI_inittedActors )
    {
        v3 = sithAI_actors[actorIdx].thing;
        v4 = &sithAI_actors[actorIdx];
        if ( v3 )
        {
            _sprintf(std_genBuffer, "AI Status dump for thing %d (%s).\n", v3->thingIdx, v3->template_name);
            sithConsole_Print(std_genBuffer);
            _sprintf(
                std_genBuffer,
                "Class '%s', Flags=0x%x, Moods %d/%d/%d, NextUpdate=%d\n",
                v4->aiclass->fpath,
                v4->flags,
                v4->mood0,
                v4->mood1,
                v4->mood2,
                v4->nextUpdate);
            sithConsole_Print(std_genBuffer);
            sithConsole_Print("Current instincts:\n");
            if ( v4->numAIClassEntries )
            {
                v7 = 0;
                sithActorInstinct* v6 = &v4->instincts[0];
                do
                {
                    _sprintf(
                        std_genBuffer,
                        "Instinct %d: Params: %f/%f/%f/%f, nextUpdate=%d, mask=0x%x, mode=0x%x.\n",
                        v2,
                        v6->param0,
                        v6->param1,
                        v6->param2,
                        v6->param3,
                        v6->nextUpdate,
                        v4->aiclass->entries[v7].param3,
                        v4->aiclass->entries[v7].param1);
                    sithConsole_Print(std_genBuffer);
                    ++v2;
                    ++v6;
                    ++v7;
                }
                while ( v2 < v4->numAIClassEntries );
            }
            result = 1;
        }
        else
        {
            sithConsole_Print("That AI block is not currently active.\n");
            result = 1;
        }
    }
    else
    {
        sithConsole_Print("cannot process AIStatus command.\n");
        result = 0;
    }
    return result;
}

int sithAI_LoadThingActorParams(stdConffileArg *arg, sithThing *thing, int param)
{
    sithActor *v3; // esi
    intptr_t result; // eax
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
        if ( v6 < v3->sizeFrames && _sscanf(arg->value, "(%f/%f/%f)", &v9, &v10, &v11) == 3 )
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
    if ( v3->sizeFrames )
        return 0;
    v5 = _atoi(arg->value);
    if ( !v5 )
        return 0;
    result = (intptr_t)pSithHS->alloc(sizeof(rdVector3) * v5);
    v3->framesAlloc = (rdVector3 *)result;
    if ( result )
    {
        _memset((void *)result, 0, sizeof(rdVector3) * v5);
        v3->sizeFrames = v5;
        v3->loadedFrames = 0;
        result = 1;
    }
    return result;
}

// Unused
void sithAI_idkframesalloc(sithThing *a2, sithThing *a3, rdVector3 *a4)
{
    sithThing *v3; // esi
    sithActor *v4; // edi
    uint32_t v5; // eax
    int v6; // ebp
    unsigned int v7; // ebx
    rdVector3 *v8; // esi
    rdVector3 *v9; // eax
    rdVector3 a1; // [esp+10h] [ebp-Ch] BYREF

    v3 = a3;
    v4 = a2->actor;
    v4->framesAlloc = (rdVector3 *)pSithHS->alloc(sizeof(rdVector3) * a3->trackParams.sizeFrames);
    v4->sizeFrames = a3->trackParams.sizeFrames;
    v5 = a3->trackParams.loadedFrames;
    v6 = 0;
    v7 = 0;
    v4->loadedFrames = v5;
    if ( v5 )
    {
        while ( 1 )
        {
            v8 = &v3->trackParams.aFrames[v6].pos;
            rdVector_Rotate3(&a1, a4, v8 + 1);
            v9 = &v4->framesAlloc[v7];
            ++v7;
            ++v6;
            v9->x = v8->x + a1.x;
            v9->y = v8->y + a1.y;
            v9->z = v8->z + a1.z;
            if ( v7 >= v4->loadedFrames )
                break;
            v3 = a3;
        }
    }
}

void sithAI_Tick(sithThing *thing, float deltaSeconds)
{
    if ( thing->type == SITH_THING_ACTOR && thing->actorParams.health > 0.0 )
    {
        if ( (thing->actor->flags & SITHAI_MODE_TURNING) != 0 )
            sithAI_sub_4EA630(thing->actor, deltaSeconds);
        if ( (thing->actor->flags & SITHAI_MODE_MOVING) != 0 )
            sithAI_idk_msgarrived_target(thing->actor, deltaSeconds);
    }
}

void sithAI_sub_4EA630(sithActor *actor, float deltaSeconds)
{
    sithThing *v2; // esi
    rdVector3 *v3; // ebp
    rdMatrix34 *v4; // ebx
    double v5; // st7
    double v6; // st5
    double v7; // st7
    double v8; // st4
    double v9; // st6
    rdVector3 *v10; // edi
    double v11; // st5
    double v12; // st5
    double v13; // st4
    double v14; // st7
    double v15; // st7
    double v16; // st6
    double v17; // st5
    double v18; // st7
    int v19; // eax
    rdVector3 *v20; // [esp-8h] [ebp-14h]

    v2 = actor->thing;
    v3 = &actor->lookVector;
    v4 = &actor->thing->lookOrientation;
    v5 = v4->rvec.x * actor->lookVector.x
       + actor->lookVector.y * actor->thing->lookOrientation.rvec.y
       + actor->lookVector.z * actor->thing->lookOrientation.rvec.z;
    if ( v5 < 0.0 )
        v5 = -v5;
    if ( v5 <= 0.01 )
    {
        v10 = &v2->lookOrientation.lvec;
        if ( v2->lookOrientation.lvec.y * actor->lookVector.y + v2->lookOrientation.lvec.x * v3->x + v2->lookOrientation.lvec.z * actor->lookVector.z >= 0.0 )
        {
            actor->flags &= ~SITHAI_MODE_TURNING;
            return;
        }
        v11 = v2->actorParams.maxRotThrust * 0.1 * deltaSeconds;
        v7 = v2->lookOrientation.rvec.y * v11 + v2->lookOrientation.lvec.y;
        v8 = v4->rvec.x * v11 + v10->x;
        v9 = v2->lookOrientation.rvec.z * v11 + v2->lookOrientation.lvec.z;
        v20 = &v2->lookOrientation.lvec;
    }
    else
    {
        v6 = v2->actorParams.maxRotThrust * 0.1 * deltaSeconds;
        v7 = actor->lookVector.y * v6 + v2->lookOrientation.lvec.y;
        v8 = v3->x * v6 + v2->lookOrientation.lvec.x;
        v9 = actor->lookVector.z * v6 + v2->lookOrientation.lvec.z;
        v10 = &v2->lookOrientation.lvec;
        v20 = &v2->lookOrientation.lvec;
    }
    v10->x = v8;
    v2->lookOrientation.lvec.y = v7;
    v2->lookOrientation.lvec.z = v9;
    if ( rdVector_Normalize3Acc(v20) < 0.01 )
        rdVector_Normalize3(v10, v3);
    v12 = v2->lookOrientation.lvec.z;
    v13 = v10->x;
    v14 = v2->lookOrientation.lvec.y;
    v4->rvec.x = v14 * 1.0 - v12 * 0.0;
    v2->lookOrientation.rvec.y = v12 * 0.0 - v13 * 1.0;
    v2->lookOrientation.rvec.z = v13 * 0.0 - v14 * 0.0;
    rdVector_Normalize3Acc(&v4->rvec);
    v15 = v10->x * v2->lookOrientation.rvec.z;
    v2->lookOrientation.uvec.x = v2->lookOrientation.lvec.z * v2->lookOrientation.rvec.y - v2->lookOrientation.lvec.y * v2->lookOrientation.rvec.z;
    v16 = v2->lookOrientation.lvec.y * v4->rvec.x;
    v17 = v15 - v2->lookOrientation.lvec.z * v4->rvec.x;
    v18 = v10->x * v2->lookOrientation.rvec.y;
    v2->lookOrientation.uvec.y = v17;
    v2->lookOrientation.uvec.z = v16 - v18;
}

void sithAI_idk_msgarrived_target(sithActor *actor, float deltaSeconds)
{
    sithThing *v3; // esi
    double v4; // st5
    double v5; // st6
    float *v6; // ebx
    rdVector3 *v7; // ebp
    double v8; // st7
    long double v9; // st7
    double v10; // st5
    double v11; // st6
    long double v12; // st4
    double v13; // st7
    sithSector *v14; // eax
    char v15; // cl
    rdVector3 *v16; // ebp
    char v17; // al
    sithSector *v18; // eax
    int v19; // eax
    float v20; // [esp+10h] [ebp-20h]
    float v21; // [esp+14h] [ebp-1Ch]
    rdVector3 a4; // [esp+18h] [ebp-18h] BYREF
    float v23; // [esp+24h] [ebp-Ch]
    float v24; // [esp+28h] [ebp-8h]
    float actorb; // [esp+34h] [ebp+4h]
    float actora; // [esp+34h] [ebp+4h]

    v3 = actor->thing;
    if ( (actor->flags & SITHAI_MODE_SLEEPING) == 0 && (v3->actorParams.typeflags & SITH_AF_IMMOBILE) == 0 )
    {
        v4 = actor->movePos.y - v3->position.y;
        v5 = actor->movePos.z - v3->position.z;
        v6 = &v3->position.x;
        v7 = &actor->field_1AC;
        v8 = actor->movePos.x - v3->position.x;
        actorb = v3->actorParams.maxThrust * deltaSeconds * actor->moveSpeed;
        actor->field_1AC.x = v8;
        actor->field_1AC.y = v4;
        actor->field_1AC.z = v5;
        v9 = rdVector_Normalize3Acc(&actor->field_1AC);
        v10 = v7->x * actorb;
        v11 = actor->field_1AC.y * actorb;
        v12 = v9;
        v13 = actor->field_1AC.z * actorb;
        v14 = v3->sector;
        actor->field_1B8 = v12;
        v15 = v14->flags;
        v23 = v10;
        v24 = v11;
        if ( (v15 & SITHAI_MODE_ATTACKING) == 0 && (v3->physicsParams.physflags & SITH_PF_FLY) == 0 )
            v13 = 0.0;
        actora = v23 + v3->physicsParams.vel.x;
        v16 = &v3->physicsParams.vel;
        v17 = actor->flags;
        v20 = v24 + v3->physicsParams.vel.y;
        v21 = v13 + v3->physicsParams.vel.z;
        v3->physicsParams.vel.x = actora;
        v3->physicsParams.vel.y = v20;
        v3->physicsParams.vel.z = v21;
        if ( (v17 & SITHAI_MODE_NO_CHECK_FOR_CLIFF) == 0 && v3->attach_flags )
        {
            if ( (v3->physicsParams.physflags & SITH_PF_FLY) != 0 )
            {
LABEL_15:
                if ( (v3->actorParams.typeflags & SITH_AF_BREATH_UNDER_WATER) == 0 )
                {
                    if ( (v3->thingflags & SITH_TF_WATER) != 0 )
                    {
                        v16->x = 0.0;
                        v3->physicsParams.vel.y = 0.0;
                        v3->physicsParams.vel.z = 0.0;
                    }
                    else
                    {
                        a4.x = deltaSeconds * actora + *v6;
                        a4.y = v3->physicsParams.vel.y * deltaSeconds + v3->position.y;
                        a4.z = v3->physicsParams.vel.z * deltaSeconds + v3->position.z;
                        v18 = sithCollision_GetSectorLookAt(v3->sector, &v3->position, &a4, 0.0);
                        if ( !v18 || (v18->flags & SITH_SECTOR_UNDERWATER) == 0 )
                            goto LABEL_22;
                        v16->x = 0.0;
                        v3->physicsParams.vel.y = 0.0;
                        v3->physicsParams.vel.z = 0.0;
                    }
                    v3->physicsParams.vel.z = v3->physicsParams.vel.z - -0.5;
                }
LABEL_22:
                if ( actor->field_1B8 <= (double)v3->moveSize )
                {
                    v16->x = 0.0;
                    v3->physicsParams.vel.y = 0.0;
                    v3->physicsParams.vel.z = 0.0;
                    actor->flags &= ~SITHAI_MODE_MOVING;
                    sithSoundClass_ThingPauseSoundclass(v3, SITH_SC_MOVING);
                    sithCog_SendMessageFromThing(v3, 0, SITH_MESSAGE_ARRIVED);
                    sithAI_SetActorFireTarget(actor, SITHAI_MODE_FLEEING, 0);
                }
                return;
            }
            if ( actora != 0.0 || v20 != 0.0 || v21 != 0.0 )
            {
                a4.x = deltaSeconds * actora + *v6;
                a4.y = v3->physicsParams.vel.y * deltaSeconds + v3->position.y;
                a4.z = v3->physicsParams.vel.z * deltaSeconds + v3->position.z;
                if ( !sithAI_physidk(actor, &a4, 0) )
                {
                    v16->x = 0.0;
                    v3->physicsParams.vel.y = 0.0;
                    v3->physicsParams.vel.z = 0.0;
                    sithAI_SetActorFireTarget(actor, SITHAI_MODE_TARGET_VISIBLE, 0);
                    return;
                }
                goto LABEL_22;
            }
        }
        if ( (v3->physicsParams.physflags & SITH_PF_FLY) == 0 )
            goto LABEL_22;
        goto LABEL_15;
    }
}

void sithAI_SetLookFrame(sithActor *actor, rdVector3 *lookPos)
{
    sithThing *v2; // eax
    double v3; // rt2
    double v4; // rtt
    sithThingActorParams *v5; // edi
    double v6; // st7
    float v7; // eax
    float v8; // ecx
    sithThing *v9; // eax
    rdVector3 a2a; // [esp+Ch] [ebp-Ch] BYREF

    v2 = actor->thing;
    v3 = lookPos->y - actor->thing->position.y;
    v4 = lookPos->z - actor->thing->position.z;
    actor->lookVector.x = lookPos->x - actor->thing->position.x;
    actor->lookVector.y = v3;
    v5 = &v2->actorParams;
    actor->lookVector.z = v4;
    if ( rdVector_Normalize3Acc(&actor->lookVector) != 0.0 )
    {
        if ( (v5->typeflags & SITH_AF_CAN_ROTATE_HEAD) != 0 )
        {
            v6 = stdMath_ArcSin3(actor->lookVector.z);
            if ( v6 < v5->minHeadPitch )
            {
                v6 = v5->minHeadPitch;
            }
            else if ( v6 > v5->maxHeadPitch )
            {
                v6 = v5->maxHeadPitch;
            }
            if ( v6 != v5->eyePYR.x )
            {
                v7 = v5->eyePYR.y;
                v8 = v5->eyePYR.z;
                a2a.x = v6;
                a2a.y = v7;
                v9 = actor->thing;
                a2a.z = v8;
                sithActor_MoveJointsForEyePYR(v9, &a2a);
            }
        }
        actor->lookVector.z = 0.0;
        rdVector_Normalize3Acc(&actor->lookVector);
        actor->flags |= SITHAI_MODE_TURNING;
    }
}

void sithAI_SetMoveThing(sithActor *actor, rdVector3 *movePos, float moveSpeed)
{
    if ( sithTime_curMs >= actor->field_28C || (actor->flags & SITHAI_MODE_MOVING) == 0 )
    {
        actor->moveSpeed = moveSpeed;
        rdVector_Copy3(&actor->movePos, movePos);
        sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_MOVING);
        actor->flags |= SITHAI_MODE_MOVING;
    }
}

void sithAI_Jump(sithActor *actor, rdVector3 *pos, float vel)
{
    actor->moveSpeed = 2.0;
    rdVector_Copy3(&actor->movePos, pos);

    if ( sithPuppet_PlayMode(actor->thing, SITH_ANIM_JUMP, 0) < 0 )
        sithPlayerActions_JumpWithVel(actor->thing, vel);

    actor->field_28C = sithTime_curMs + 2000;
    actor->flags |= SITHAI_MODE_MOVING;
}

void sithAI_sub_4EAD60(sithActor *actor)
{
    sithThing *v2; // edi
    sithThing *v3; // eax
    sithThing *v4; // eax
    int v5; // eax
    int v6; // eax
    float v7; // eax
    float v8; // edx
    int v9; // [esp+10h] [ebp-4h]
    float actora; // [esp+18h] [ebp+4h]

    v2 = actor->thing;
    v9 = actor->field_1F4;
    if ( actor->field_1E0 != bShowInvisibleThings )
    {
        actor->field_1E0 = bShowInvisibleThings;
        v3 = v2->actorParams.templateWeapon;
        if ( v3 )
            actora = v3->moveSize;
        else
            actora = 0.0;
        rdMatrix_TransformVector34(&actor->blindAimError, &v2->actorParams.fireOffset, &v2->lookOrientation);
        v4 = actor->field_1D0;
        rdVector_Add3Acc(&actor->blindAimError, &v2->position);
        if ( v4 )
        {
            if ( (v4->actorParams.typeflags & SITH_AF_INVISIBLE) || (actor->thing->actorParams.typeflags & SITH_AF_BLIND) != 0 )
                v9 = 3;
            actor->field_1D4 = v4->position;
            v5 = sithAI_sub_4EB090(v2, &actor->blindAimError, v4, actor->aiclass->fov, actor->aiclass->sightDist, actora, &actor->field_1E4, &actor->field_1F0);
            actor->field_1F4 = v5;
            if ( !v5 )
            {
                if ( !v9 || sithAI_sub_4EC140(actor, actor->field_1D0, actor->field_1F0) )
                {
                    actor->field_1F8 = actor->field_1D0->position;
                    actor->field_204 = sithTime_curMs;
                }
                else
                {
                    actor->field_1F4 = 3;
                }
            }
        }
        else
        {
            v6 = sithAI_sub_4EB300(
                     v2,
                     &actor->blindAimError,
                     &actor->field_1D4,
                     actor->aiclass->fov,
                     actor->aiclass->sightDist,
                     actora,
                     &actor->field_1E4,
                     &actor->field_1F0);
            actor->field_1F4 = v6;
            if ( !v6 )
            {
                v7 = actor->field_1D4.y;
                actor->field_1F8.x = actor->field_1D4.x;
                v8 = actor->field_1D4.z;
                actor->field_1F8.y = v7;
                actor->field_204 = sithTime_curMs;
                actor->field_1F8.z = v8;
            }
        }
    }
}

void sithAI_sub_4EAF40(sithActor *actor)
{
    int v1; // ebx
    sithThing *v2; // ecx
    int v3; // eax
    int v4; // eax
    float v5; // ecx
    float v6; // eax

    v1 = actor->field_238;
    if ( actor->field_224 != bShowInvisibleThings )
    {
        v2 = actor->thingidk;
        actor->field_224 = bShowInvisibleThings;
        if ( v2 )
        {
            if ( (v2->actorParams.typeflags & SITH_AF_INVISIBLE) || (actor->thing->actorParams.typeflags & SITH_AF_BLIND) != 0 )
                v1 = 3;
            v3 = sithAI_sub_4EB090(actor->thing, &actor->thing->position, v2, -1.0, actor->aiclass->sightDist, 0.0, &actor->field_228, &actor->field_234);
            actor->field_238 = v3;
            if ( !v3 )
            {
                if ( !v1 || sithAI_sub_4EC140(actor, actor->thingidk, actor->field_234) )
                {
                    actor->field_23C = actor->thingidk->position;
                    actor->field_248 = sithTime_curMs;
                }
                else
                {
                    actor->field_238 = 3;
                }
            }
        }
        else
        {
            v4 = sithAI_sub_4EB300(
                     actor->thing,
                     &actor->thing->position,
                     &actor->movepos,
                     -1.0,
                     actor->aiclass->sightDist,
                     0.0,
                     &actor->field_228,
                     &actor->field_234);
            actor->field_238 = v4;
            if ( !v4 )
            {
                v5 = actor->movepos.y;
                actor->field_23C.x = actor->movepos.x;
                v6 = actor->movepos.z;
                actor->field_23C.y = v5;
                actor->field_248 = sithTime_curMs;
                actor->field_23C.z = v6;
            }
        }
    }
}

int sithAI_sub_4EB090(sithThing *a3, rdVector3 *a4, sithThing *arg8, float argC, float arg10, float a6, rdVector3 *a5, float *a8)
{
    long double v12; // st7
    double v18; // st7
    sithSector *v21; // eax
    sithCollisionSearchEntry *v22; // esi
    sithThing *v23; // eax
    float a4a; // [esp+18h] [ebp+8h]
    float a5a; // [esp+2Ch] [ebp+1Ch]

    rdVector_Sub3(a5, &arg8->position, a4);
    v12 = rdVector_Normalize3Acc(a5) - arg8->collideSize;
    *a8 = v12;
 
    if ( v12 <= 0.0 )
        v12 = 0.0;

    *a8 = v12;
    if ( !(a3->thingflags & SITH_TF_WATER) && (arg8->thingflags & SITH_TF_WATER) != 0 )
    {
        if ( arg8->moveType != SITH_MT_PHYSICS )
            return 3;
        if ( (arg8->physicsParams.physflags & SITH_PF_MIDAIR) == 0 )
            return 3;
    }
    if ( (a3->thingflags & SITH_TF_WATER) && (arg8->thingflags & SITH_TF_WATER) == 0 )
        return 3;
    if ( v12 - arg8->collideSize > arg10 )
        return 1;
    if ( argC > -1.0 )
    {
        v18 = a3->lookOrientation.rvec.y * a5->y + a3->lookOrientation.rvec.z * a5->z + a3->lookOrientation.rvec.x * a5->x;
        a5a = a3->lookOrientation.lvec.z * a5->z + a3->lookOrientation.lvec.y * a5->y + a3->lookOrientation.lvec.x * a5->x;

        if ( v18 < 0.0 )
            v18 = -v18;

        a4a = v18;
        if ( argC >= 0.0 )
        {
            if ( a5a < 0.0 )
                return 2;
            if ( a4a > 1.0 - argC )
                return 2;
        }
        if ( argC < 0.0 && a5a < 0.0 && a4a < argC - -1.0 )
            return 2;
    }
    v21 = sithCollision_GetSectorLookAt(a3->sector, &a3->position, a4, 0.0);
    sithCollision_SearchRadiusForThings(v21, a3, a4, a5, *a8, 0.0, 0x102);
    v22 = sithCollision_NextSearchResult();
    if ( v22 )
    {
        while ( (v22->hitType & SITHCOLLISION_THING) != 0 )
        {
            v23 = v22->receiver;
            if ( v23 != arg8 )
            {
                if ( v23->type == SITH_THING_ACTOR || v23->type == SITH_THING_COG )
                    break;
                v22 = sithCollision_NextSearchResult();
                if ( v22 )
                    continue;
            }
            sithCollision_SearchClose();
            return 0;
        }
    }
    sithCollision_SearchClose();
    return v22 != 0 ? 3 : 0;
}

int sithAI_sub_4EB300(sithThing *a3, rdVector3 *a4, rdVector3 *arg8, float argC, float arg10, float a7, rdVector3 *a5, float *a8)
{
    float v11; // st7
    double v16; // st7
    sithSector *v19; // eax
    sithCollisionSearchEntry *v20; // esi
    float a4a; // [esp+18h] [ebp+8h]
    float arg8a; // [esp+1Ch] [ebp+Ch]
 
    a5->x = arg8->x - a4->x;
    a5->y = arg8->y - a4->y;
    a5->z = arg8->z - a4->z;
    v11 = rdVector_Normalize3Acc(a5);
    *a8 = v11;

    if ( v11 > arg10 )
        return 1;

    if ( argC > -1.0 )
    {
        v16 = a3->lookOrientation.rvec.y * a5->y + a3->lookOrientation.rvec.z * a5->z + a3->lookOrientation.rvec.x * a5->x;
        a4a = a3->lookOrientation.lvec.z * a5->z + a3->lookOrientation.lvec.y * a5->y + a3->lookOrientation.lvec.x * a5->x;

        if ( v16 < 0.0 )
            v16 = -v16;
        arg8a = v16;
        if ( argC >= 0.0 )
        {
            if ( a4a < 0.0 )
                return 2;
            if ( arg8a > 1.0 - argC )
                return 2;
        }
        if ( argC < 0.0 && a4a < 0.0 && arg8a < argC - -1.0 )
            return 2;
    }
    v19 = sithCollision_GetSectorLookAt(a3->sector, &a3->position, a4, 0.0);
    sithCollision_SearchRadiusForThings(v19, a3, a4, a5, *a8, a7, 0x2102);
    v20 = sithCollision_NextSearchResult();
    sithCollision_SearchClose();
    return v20 != 0 ? 3 : 0;
}

// TODO this one has some inlined funcs
int sithAI_physidk(sithActor *a7, rdVector3 *a4, int *arg8)
{
    sithThing *v4; // esi
    intptr_t result; // eax
    sithSector *v6; // edi
    sithCollisionSearchEntry *v7; // eax
    sithSurface *v8; // ecx
    sithThing *v10; // eax
    float a6; // [esp+0h] [ebp-2Ch]
    int v12; // [esp+1Ch] [ebp-10h]
    rdVector3 a5; // [esp+20h] [ebp-Ch] BYREF
    float a7a; // [esp+30h] [ebp+4h]

    v4 = a7->thing;
    a5.x = 0.0;
    a5.y = 0.0;
    a5.z = -1.0;
    a7a = v4->moveSize * 0.25;
    v12 = 0;
    result = (intptr_t)sithCollision_GetSectorLookAt(v4->sector, &v4->position, a4, 0.0);
    v6 = (sithSector *)result;
    if ( !result )
        return result;
    a6 = sithPhysics_ThingGetInsertOffsetZ(v4) + a7->aiclass->maxStep;
    sithCollision_SearchRadiusForThings(v6, v4, a4, &a5, a6, a7a, 0x2002);
    v7 = sithCollision_NextSearchResult();
    if ( !v7 )
        goto LABEL_20;
    while ( (v7->hitType & SITHCOLLISION_WORLD) == 0 )
    {
        if ( (v7->hitType & SITHCOLLISION_THING) != 0 )
        {
            v10 = v7->receiver;
            if ( (v10->thingflags & SITH_TF_STANDABLE) != 0 )
            {
                v12 = 1;
                if ( arg8 )
                {
                    if ( (v4->attach_flags & SITH_ATTACH_THINGSURFACE) != 0 && v4->attachedThing == v10 )
                    {
                        *arg8 = 0;
                        sithCollision_SearchClose();
                        return 1;
                    }
                    *arg8 = 1;
                }
LABEL_20:
                sithCollision_SearchClose();
                return v12;
            }
LABEL_8:
            sithCollision_SearchClose();
            return 0;
        }
        v7 = sithCollision_NextSearchResult();
        if ( !v7 )
            goto LABEL_20;
    }
    v8 = v7->surface;
    if ( (v8->surfaceFlags & SITH_SURFACE_AI_CAN_WALK_ON_FLOOR) != 0 )
        goto LABEL_8;
    v12 = 2 - ((v8->surfaceFlags & SITH_SURFACE_FLOOR) != 0);
    if ( !arg8 )
        goto LABEL_20;
    if ( (v4->attach_flags & SITH_ATTACH_WORLDSURFACE) != 0 && v4->attachedSurface == v8 )
    {
        *arg8 = 0;
        sithCollision_SearchClose();
        result = v12;
    }
    else
    {
        *arg8 = 1;
        sithCollision_SearchClose();
        result = v12;
    }
    return result;
}

int sithAI_sub_4EB640(sithActor *actor, rdVector3 *a4, sithSector *a2, int *out)
{
    sithThing *v4; // edi
    int v5; // ebx
    sithCollisionSearchEntry *v6; // eax
    sithSurface *v7; // ecx
    int result; // eax
    sithThing *v10; // eax
    float a6; // [esp+0h] [ebp-24h]
    float a7; // [esp+4h] [ebp-20h]
    rdVector3 a5; // [esp+18h] [ebp-Ch] BYREF

    a5.x = 0.0;
    a5.y = 0.0;
    v4 = actor->thing;
    a5.z = -1.0;
    v5 = 0;
    a7 = v4->moveSize * 0.25;
    a6 = sithPhysics_ThingGetInsertOffsetZ(v4) + actor->aiclass->maxStep;
    sithCollision_SearchRadiusForThings(a2, v4, a4, &a5, a6, a7, 0x2002);
    v6 = sithCollision_NextSearchResult();
    if ( v6 )
    {
        while ( 1 )
        {
            if ( (v6->hitType & SITHCOLLISION_WORLD) != 0 )
            {
                v7 = v6->surface;
                if ( (v7->surfaceFlags & SITH_SURFACE_AI_CAN_WALK_ON_FLOOR) != 0 )
                    goto LABEL_13;
                v5 = 2 - ((v7->surfaceFlags & SITH_SURFACE_FLOOR) != 0);
                if ( !out )
                    goto LABEL_19;
                if ( (v4->attach_flags & SITH_ATTACH_WORLDSURFACE) != 0 && v4->attachedSurface == v7 )
                {
                    *out = 0;
                    sithCollision_SearchClose();
                    result = v5;
                }
                else
                {
                    *out = 1;
                    sithCollision_SearchClose();
                    result = v5;
                }
                return result;
            }
            if ( (v6->hitType & SITHCOLLISION_THING) != 0 )
                break;
            v6 = sithCollision_NextSearchResult();
            if ( !v6 )
                goto LABEL_13;
        }
        v10 = v6->receiver;
        if ( (v10->thingflags & SITH_TF_STANDABLE) == 0 )
        {
LABEL_13:
            sithCollision_SearchClose();
            return 0;
        }
        v5 = 1;
        if ( out )
        {
            if ( (v4->attach_flags & SITH_ATTACH_THINGSURFACE) != 0 && v4->attachedThing == v10 )
            {
                *out = 0;
                sithCollision_SearchClose();
                return 1;
            }
            *out = 1;
        }
    }
LABEL_19:
    sithCollision_SearchClose();
    return v5;
}

int sithAI_FirstThingInView(sithSector *sector, rdMatrix34 *out, float autoaimFov, float autoaimMaxDist, int a5, sithThing **thingList, int a7, float a8)
{
    float a2; // [esp+0h] [ebp-Ch]
    float a2b; // [esp+0h] [ebp-Ch]

    if ( autoaimFov < 0.0 || autoaimMaxDist < 0.0 )
        return 0;
    sithAI_dword_84DE74 = a7;
    sithAI_dword_84DE6C = a5;
    a2 = 90.0 - autoaimFov * 0.5;
    sithAI_flt_84DE70 = a8;
    sithAI_pThing_84DE68 = thingList;
    stdMath_SinCos(a2, &autoaimFov, &sithAI_flt_84DE64);
    a2b = 90.0 - autoaimMaxDist * 0.5;
    stdMath_SinCos(a2b, &autoaimFov, &sithAI_flt_84DE58);
    sithMain_sub_4C4D80();
    sithAI_dword_84DE60 = 0;
    sithAI_dword_84DE5C = 0;
    sithAI_GetThingsInView(sector, out, 0.0);
    return sithAI_dword_84DE60;
}

int sithAI_sub_4EB860(int a1, float a2)
{
    if ( a2 > 0.0 )
        sithMain_sub_4C4D80();
    return 0;
}

void sithAI_SetRandomThingLook(rdMatrix34 *a1, sithThing *a2, rdVector3 *a3, float a4)
{
    rdVector3 rot; // [esp+4h] [ebp-Ch] BYREF
    float v2; // [esp+1Ch] [ebp+Ch]

    rdMatrix_LookAt(a1, &a2->position, a3, 0.0);
    if ( a4 > 0.0 )
    {
        v2 = a4 + a4;
        rot.x = (_frand() * v2) - a4;
        rot.z = 0.0;
        rot.y = (_frand() * v2) - a4;
        rdMatrix_PreRotate34(a1, &rot);
    }
}

void sithAI_RandomFireVector(rdVector3 *out, float magnitude)
{
    out->x = ((double)_frand() - 0.5) * magnitude + out->x;
    out->y = ((double)_frand() - 0.5) * magnitude + out->y;
    out->z = ((double)_frand() - 0.5) * magnitude + out->z;
    rdVector_Normalize3Acc(out);
}

void sithAI_RandomRotationVector(rdVector3 *out)
{
    rdVector3 tmp;

    tmp.x = _frand() * 360.0;
    tmp.z = 0.0;
    tmp.y = _frand() * 360.0;
    rdVector_Rotate3(out, &rdroid_yVector3, &tmp);
}

int sithAI_FireWeapon(sithActor *actor, float a2, float a3, float a4, float a5, int bAltFire, int a7)
{
    sithThing *v8; // ebp
    sithThing *v9; // edi
    float v10; // edx
    sithThing *v11; // ecx
    double v12; // st6
    double v13; // st7
    double v14; // rt2
    int16_t v15; // bx
    sithThing *v16; // eax
    double v19; // st7
    signed int v20; // [esp+10h] [ebp-20h]
    float v21; // [esp+14h] [ebp-1Ch]
    rdVector3 v1; // [esp+18h] [ebp-18h] BYREF
    rdVector3 a1a; // [esp+24h] [ebp-Ch] BYREF
    float actora; // [esp+34h] [ebp+4h]

    v8 = 0;
    v9 = actor->thing;
    v21 = 1.0;
    v20 = 0;
    if ( (g_debugmodeFlags & 0x80u) != 0
      || (v9->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0
      || (v9->sector->flags & SITH_SECTOR_UNDERWATER) != 0 && (v9->actorParams.typeflags & SITH_AF_CANTSHOOTUNDERWATER) != 0 )
    {
        return 0;
    }
    if ( bAltFire )
    {
        if ( bAltFire == 1 )
        {
            v8 = v9->actorParams.templateWeapon2;
            v20 = SITH_ANIM_FIRE2;
        }
    }
    else
    {
        v8 = v9->actorParams.templateWeapon;
        v20 = SITH_ANIM_FIRE;
    }
    if ( !v8 )
        return 0;
    sithAI_sub_4EAD60(actor);
    v10 = actor->field_1E4.y;
    v1.x = actor->field_1E4.x;
    v1.y = v10;
    v1.z = actor->field_1E4.z;
    if ( (a7 & 8) != 0 )
    {
        v20 = 0;
        goto LABEL_12;
    }
    if ( actor->field_288 > sithTime_curMs || actor->field_1F4 )
        return 0;
    if ( actor->field_1F0 < (double)a2 || actor->field_1F0 > (double)a3 )
        return 0;
    v19 = v9->lookOrientation.rvec.x * v1.x + v9->lookOrientation.rvec.y * v1.y + v9->lookOrientation.rvec.z * v1.z;
    if ( v19 < 0.0 )
        v19 = -v19;
    if ( v19 > 1.0 - a4 )
        return 0;
    if ( (v9->actorParams.typeflags & SITH_AF_DELAYFIRE) != 0 )
    {
        actor->field_268 = a7 | 8;
        actor->field_264 = a5;
        actor->field_26C = bAltFire;
        sithPuppet_PlayMode(v9, v20, 0);

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SetSyncFlags(actor->thing, THING_SYNC_PUPPET);
        }
        return 1;
    }
LABEL_12:
    if ( (a7 & 1) != 0 )
    {
        v11 = actor->field_1D0;
        if ( v11->moveType == SITH_MT_PHYSICS
          && (v11->physicsParams.vel.x != 0.0 || v11->physicsParams.vel.y != 0.0 || v11->physicsParams.vel.z != 0.0) )
        {
            a1a.x = v8->physicsParams.vel.y * v1.x;
            a1a.y = v8->physicsParams.vel.y * v1.y;
            a1a.z = v8->physicsParams.vel.y * v1.z;
            a1a.x = a1a.x + v11->physicsParams.vel.x;
            a1a.y = v11->physicsParams.vel.y + a1a.y;
            a1a.z = v11->physicsParams.vel.z + a1a.z;
            rdVector_Normalize3Acc(&a1a);
            if ( a1a.x * v1.x + a1a.y * v1.y + a1a.z * v1.z > 0.5 )
                v1 = a1a;
        }
    }
    if ( (a7 & 2) != 0 && v8->moveType == SITH_MT_PHYSICS) // Added: physics check
    {
        actora = v8->physicsParams.vel.y;
        v12 = actor->field_1E4.y * actora;
        v13 = actor->field_1E4.z * actora;
        v14 = actor->field_1F0 / actora * 0.5;
        a1a.x = actor->field_1E4.x * actora;
        a1a.y = v12;
        a1a.z = v13;
        a1a.z = v14 * sithWorld_pCurrentWorld->worldGravity + a1a.z;
        v15 = 1;
        v21 = rdVector_Normalize3(&v1, &a1a) / actora;
    }
    else
    {
        v15 = 0;
    }
    if ( a5 != 0.0 && actor->field_1F0 != 0.0 && _frand() > actor->aiclass->accuracy )
    {
        v1.x = (_frand() - 0.5) * a5 + v1.x;
        v1.y = (_frand() - 0.5) * a5 + v1.y;
        v1.z = (_frand() - 0.5) * a5 + v1.z;
        rdVector_Normalize3Acc(&v1);
    }
    sithSoundClass_PlayModeRandom(v9, bAltFire + SITH_SC_FIRE1);
    v16 = sithWeapon_Fire(v9, v8, &v1, &actor->blindAimError, 0, v20, v21, v15, 0.0);
    if ( v16 )
        sithCog_SendMessageFromThing(v9, v16, SITH_MESSAGE_FIRE);
    return 1;
}

void sithAI_GetThingsInView(sithSector *a1, rdMatrix34 *a2, float a3)
{
    sithThing *v4; // esi
    unsigned int v6; // eax
    sithAdjoin *v7; // esi
    rdTexinfo *v8; // ebp
    rdMaterial *v9; // ecx
    uint32_t v10; // edx
    float a3a; // [esp+0h] [ebp-48h]
    float v12; // [esp+14h] [ebp-34h]
    rdVector3 v13; // [esp+18h] [ebp-30h] BYREF
    rdVector3 a1a; // [esp+24h] [ebp-24h] BYREF
    rdVector3 v1; // [esp+30h] [ebp-18h] BYREF
    rdVector3 v16; // [esp+3Ch] [ebp-Ch] BYREF
    float v17; // [esp+4Ch] [ebp+4h]
    float a2a; // [esp+50h] [ebp+8h]

    if ( a1->field_8C != sithRender_lastRenderTick )
    {
        a1->field_8C = sithRender_lastRenderTick;
        if ( sithAI_dword_84DE5C < 0x80 )
        {
            v4 = a1->thingsList;
            ++sithAI_dword_84DE5C;
            if ( v4 )
            {
                v6 = sithAI_dword_84DE60;
                do
                {
                    if ( v6 >= sithAI_dword_84DE6C )
                        break;
                    if ( ((1 << v4->type) & sithAI_dword_84DE74) != 0 && (v4->thingflags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
                    {
                        v13.x = v4->position.x - a2->scale.x;
                        v13.y = v4->position.y - a2->scale.y;
                        v13.z = v4->position.z - a2->scale.z;
                        rdVector_Normalize3Acc(&v13);
                        rdVector_Normalize3(&a1a, &a2->uvec);
                        rdVector_Normalize3(&v1, &a2->rvec);
                        rdVector_Normalize3(&v16, &a2->lvec);
                        v17 = a1a.x * v13.x + a1a.y * v13.y + a1a.z * v13.z;
                        a2a = v1.x * v13.x + v1.y * v13.y + v1.z * v13.z;
                        if ( v17 > (double)sithAI_flt_84DE58
                          || v17 < -sithAI_flt_84DE58
                          || a2a > (double)sithAI_flt_84DE64
                          || a2a < -sithAI_flt_84DE64
                          || (v12 = v16.x * v13.x + v16.y * v13.y + v16.z * v13.z, v12 < 0.0) )
                        {
                            v6 = sithAI_dword_84DE60;
                        }
                        else
                        {
                            if ( sithAI_dword_84DE60 >= (unsigned int)sithAI_dword_84DE6C )
                                return;
                            v6 = sithAI_dword_84DE60 + 1;
                            sithAI_dword_84DE60 = v6;
                            sithAI_pThing_84DE68[v6 - 1] = v4;
                        }
                    }
                    v4 = v4->nextThing;
                }
                while ( v4 );
            }
            if ( a3 <= (double)sithAI_flt_84DE70 )
            {
                v7 = a1->adjoins;
                if ( v7 )
                {
                    v8 = NULL;
                    do
                    {
                        v9 = v7->surface->surfaceInfo.face.material;
                        if ( v9 )
                        {
                            v10 = v7->surface->surfaceInfo.face.wallCel;
                            if ( v10 == -1 )
                                v10 = v9->celIdx;
                            v8 = v9->texinfos[v10];
                        }
                        if ( (v7->flags & 1) != 0
                          && (!v9
                           || !v7->surface->surfaceInfo.face.geometryMode
                           || (v7->surface->surfaceInfo.face.type & 2) != 0
                           || (v8 && (v8->texture_ptr->alpha_en & 1) != 0)) // Added: v8 nullptr check
                          && a2->lvec.y * v7->surface->surfaceInfo.face.normal.y
                           + a2->lvec.z * v7->surface->surfaceInfo.face.normal.z
                           + a2->lvec.x * v7->surface->surfaceInfo.face.normal.x < 0.0 )
                        {
                            a3a = v7->mirror->dist + v7->dist + a3;
                            sithAI_GetThingsInView(v7->sector, a2, a3a);
                        }
                        v7 = v7->next;
                    }
                    while ( v7 );
                }
            }
        }
    }
}

int sithAI_sub_4EC140(sithActor *a1, sithThing *a2, float a3)
{
    sithThing *v3; // esi
    double v5; // st7
    sithSector *v6; // edx
    int result; // eax
    float v8; // [esp+0h] [ebp-4h]

    v8 = 1.0;
    v3 = a1->thing;
    if ( !a2 )
        goto LABEL_34;
    if ( a2->type != SITH_THING_ACTOR && a2->type != SITH_THING_PLAYER )
        goto LABEL_34;
    if ( a3 >= 2.0 )
    {
        if ( (a1->flags & SITHAI_MODE_ACTIVE) == 0 )
            v8 = 0.5;
        if ( (a2->actorParams.typeflags & SITH_AF_FIELDLIGHT) == 0 && (a2->jkFlags & 1) == 0 )
        {
            v5 = (a3 - 2.0) * 0.1;
            if ( v5 < 0.0 )
            {
                v5 = 0.0;
            }
            else if ( v5 > 0.6 )
            {
                v5 = 0.6;
            }
            v8 = (1.0 - v5) * v8;
            if ( (v3->actorParams.typeflags & SITH_AF_CAN_SEE_IN_DARK) == 0 )
            {
                v6 = a2->sector;
                if ( v6->ambientLight < 0.5 )
                    v8 = (v6->ambientLight - -0.2) * v8;
            }
            if ( a2->moveType == SITH_MT_PHYSICS )
            {
                if ( (a2->physicsParams.physflags & SITH_PF_CROUCHING) != 0 )
                    v8 = v8 * 0.75;
                if ( a2->physicsParams.vel.x == 0.0 && a2->physicsParams.vel.y == 0.0 && a2->physicsParams.vel.z == 0.0 )
                    v8 = v8 * 0.5;
            }
        }
    }
    if ( a2->actorParams.typeflags & SITH_AF_INVISIBLE && (v3->actorParams.typeflags & SITH_AF_CAN_SEE_INVISIBLE) == 0 )
        v8 = v8 * 0.05;
    if ( (v3->actorParams.typeflags & SITH_AF_BLIND) != 0 )
        v8 = v8 * 0.05;
    if ( v8 < 0.05 )
    {
        v8 = 0.05;
    }
    else if ( v8 > 1.0 )
    {
        v8 = 1.0;
    }
    if ( _frand() >= v8 )
        result = 0;
    else
LABEL_34:
        result = 1;
    return result;
}
