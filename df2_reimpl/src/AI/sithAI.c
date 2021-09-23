#include "sithAI.h"

#include "jk.h"
#include "General/stdMath.h"
#include "World/sithThing.h"
#include "World/sithUnk4.h"
#include "World/sithActor.h"
#include "AI/sithAICmd.h"
#include "AI/sithAIClass.h"
#include "Engine/sithTime.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithAnimClass.h"
#include "General/stdHashTable.h"
#include "Main/jkGame.h"
#include "Cog/sithCogVm.h"
#include "Cog/sithCog.h"
#include "stdPlatform.h"
#include "Win95/DebugConsole.h"

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
    while ( (int)v3 >= (int)sithAI_actors );

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
    while ( (int)v3 >= (int)sithAI_actors );
    
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
            actor->flags = (SITHAIFLAGS_AT_EASE|SITHAIFLAGS_SEARCHING);
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
          && (actor->flags & (SITHAIFLAGS_DISABLED|SITHAIFLAGS_AT_EASE)) == 0
          && actor->nextUpdate <= sithTime_curMs )
        {
            sithAI_TickActor(actor);
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
                        sithAI_SetActorFireTarget(actor, 0x100, a3);
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

void sithAI_SetActorFireTarget(sithActor *actor, int a2, int a3)
{
    sithThing *v4; // ecx
    int flags; // edi
    int v6; // eax
    uint32_t v7; // ebx
    int old_flags; // [esp+14h] [ebp+4h]

    for ( ; actor->aiclass; a2 = 0x100 )
    {
        v4 = actor->thing;
        if ( !actor->thing )
            break;
        if ( (v4->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0 )
            break;
        if ( (g_debugmodeFlags & 1) != 0 )
            break;
        if ( v4->actorParams.health <= 0.0 )
            break;
        flags = actor->flags;
        old_flags = flags;
        if ( (flags & SITHAIFLAGS_DISABLED) != 0 )
            break;
        if ( (flags & SITHAIFLAGS_AT_EASE) != 0 )
        {
            if ( a2 != 2 )
                return;
            actor->flags &= ~SITHAIFLAGS_AT_EASE;
        }

        if ( a2 == 0x100 )
            sithCog_SendMessageFromThingEx(v4, 0, SITH_MESSAGE_AIEVENT, 256.0, 0.0, 0.0, 0.0);

        v7 = 0;
        for (v7 = 0; v7 < actor->numAIClassEntries; v7++)
        {
            sithActorInstinct* entry = &actor->instincts[v7];
            if ( (entry->field_0 & 1) == 0 )
            {
                if ( (actor->aiclass->entries[v7].param3 & a2) != 0 )
                {
                    if ( actor->aiclass->entries[v7].func(actor, &actor->aiclass->entries[v7], entry, a2, a3) )
                        break;
                }
            }
        }
        flags = old_flags;
        if ( actor->flags == flags )
            break;
        a3 = flags;
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
        DebugConsole_Print("Active AI things:\n");
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
                    DebugConsole_Print(std_genBuffer);
                }
            }
            ++v1;
        }
        return 1;
    }
    else
    {
        DebugConsole_Print("AI system not open.\n");
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
            DebugConsole_Print(std_genBuffer);
            _sprintf(
                std_genBuffer,
                "Class '%s', Flags=0x%x, Moods %d/%d/%d, NextUpdate=%d\n",
                v4->aiclass->fpath,
                v4->flags,
                v4->mood0,
                v4->mood1,
                v4->mood2,
                v4->nextUpdate);
            DebugConsole_Print(std_genBuffer);
            DebugConsole_Print("Current instincts:\n");
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
                    DebugConsole_Print(std_genBuffer);
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
            DebugConsole_Print("That AI block is not currently active.\n");
            result = 1;
        }
    }
    else
    {
        DebugConsole_Print("cannot process AIStatus command.\n");
        result = 0;
    }
    return result;
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

void sithAI_Tick(sithThing *thing, float deltaSeconds)
{
    if ( thing->thingType == THINGTYPE_ACTOR && thing->actorParams.health > 0.0 )
    {
        if ( (thing->actor->flags & SITHAIFLAGS_TURNING_TO_DEST) != 0 )
            sithAI_sub_4EA630(thing->actor, deltaSeconds);
        if ( (thing->actor->flags & SITHAIFLAGS_MOVING_TO_DEST) != 0 )
            sithAI_idk_msgarrived_target(thing->actor, deltaSeconds);
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
        if ( (v5->typeflags & 1) != 0 )
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
                sithUnk4_MoveJointsForEyePYR(v9, &a2a);
            }
        }
        actor->lookVector.z = 0.0;
        rdVector_Normalize3Acc(&actor->lookVector);
        actor->flags |= SITHAIFLAGS_TURNING_TO_DEST;
    }
}

void sithAI_SetMoveThing(sithActor *actor, rdVector3 *movePos, float moveSpeed)
{
    if ( sithTime_curMs >= actor->field_28C || (actor->flags & SITHAIFLAGS_MOVING_TO_DEST) == 0 )
    {
        actor->moveSpeed = moveSpeed;
        rdVector_Copy3(&actor->movePos, movePos);
        sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_MOVING);
        actor->flags |= SITHAIFLAGS_MOVING_TO_DEST;
    }
}

void sithAI_Jump(sithActor *actor, rdVector3 *pos, float vel)
{
    actor->moveSpeed = 2.0;
    rdVector_Copy3(&actor->movePos, pos);

    if ( sithPuppet_PlayMode(actor->thing, SITH_ANIM_JUMP, 0) < 0 )
        sithActor_JumpWithVel(actor->thing, vel);

    actor->field_28C = sithTime_curMs + 2000;
    actor->flags |= SITHAIFLAGS_MOVING_TO_DEST;
}

void sithAI_RandomFireVector(rdVector3 *out, float magnitude)
{
    out->x = ((double)_frand() - 0.5) * magnitude + out->x;
    out->y = ((double)_frand() - 0.5) * magnitude + out->y;
    out->z = ((double)_frand() - 0.5) * magnitude + out->z;
    rdVector_Normalize3Acc(out);
}
