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
#include "World/sithSoundClass.h"
#include "Engine/sithPuppet.h"
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
int sithAI_actorInitted[SITHAI_MAX_ACTORS] = {0};
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
sithAIAlign sithAI_aAlignments[10] = {0}; // MoTS Added
sithActor sithAI_actors[SITHAI_MAX_ACTORS] = {0};
int sithAI_inittedActors = 0;

// This is also in a different part
// MoTS Added
sithThing* sithAI_pDistractor = NULL;

float sithAI_FLOAT_005a79d8 = 1.0;

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

    sithAI_FLOAT_005a79d8 = 1.0; // MoTS added

    sithAI_commandList = (sithAICommand *)pSithHS->alloc(sizeof(sithAICommand) * 32);
    if ( sithAI_commandList )
    {
        sithAI_commandsHashmap = stdHashTable_New(64);
        if ( !sithAI_commandsHashmap )
            pSithHS->free(sithAI_commandList);
    }

    sithAICmd_Startup();

    v0 = sithAI_inittedActors;
    _memset(sithAI_actors, 0, sizeof(sithActor) * SITHAI_MAX_ACTORS);

    v1 = SITHAI_MAX_ACTORS-1;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[SITHAI_MAX_ACTORS-1];
    sithAI_maxActors = SITHAI_MAX_ACTORS;

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

    // Added: Clean reset
    sithAI_commandsHashmap = NULL;
    sithAI_maxActors = 0;
    memset(sithAI_actorInitted, 0, sizeof(sithAI_actorInitted));
    sithAI_bOpened = 0;
    sithAI_bInit = 0;
    sithAI_commandList = NULL;
    sithAI_numCommands = 0;
    sithAI_flt_84DE58 = 0.0f;
    sithAI_dword_84DE5C = 0;
    sithAI_dword_84DE60 = 0;
    sithAI_flt_84DE64 = 0.0f;
    sithAI_pThing_84DE68 = NULL;
    sithAI_dword_84DE6C = 0;
    sithAI_flt_84DE70 = 0.0f;
    sithAI_dword_84DE74 = 0;

    // These are located in a different part of .data?
    memset(sithAI_aAlignments, 0, sizeof(sithAI_aAlignments));
    memset(sithAI_actors, 0, sizeof(sithAI_actors));
    sithAI_inittedActors = 0;

    // This is also in a different part
    // MoTS Added
    sithThing* sithAI_pDistractor = NULL;

    sithAI_FLOAT_005a79d8 = 1.0;
}

int sithAI_Open()
{
    if (!sithAI_bInit)
        return 0;

    if (sithAI_bOpened)
        return 0;

    sithAI_FLOAT_005a79d8 = 1.0; // MoTS added
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
    _memset(sithAI_actors, 0, sizeof(sithActor) * SITHAI_MAX_ACTORS);

    v1 = SITHAI_MAX_ACTORS-1;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[SITHAI_MAX_ACTORS-1];
    sithAI_maxActors = SITHAI_MAX_ACTORS;

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

    sith_ai = thing->pAIClass;
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
            rdVector_Copy3(&actor->position, &thing->position);
            actor->lookOrientation = thing->lookOrientation.lvec;
            actor->pAIClass = sith_ai;
            actor->thing = thing;
            actor->numAIClassEntries = sith_ai->numEntries;
            actor->flags = (SITHAI_MODE_SLEEPING|SITHAI_MODE_SEARCHING);
            actor->moveSpeed = 1.5;

            // MOTS Added
            actor->pInterest = NULL;
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
        if (sithAI_actors[v2].paFrames)
        {
            pSithHS->free(sithAI_actors[v2].paFrames);
            sithAI_actors[v2].paFrames = NULL;
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
        if (Main_bMotsCompat)
        {
            if ( actor->pAIClass
                  && (actor->thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0
                  && actor->thing->actorParams.health > 0.0
                  && (actor->flags & (SITHAI_MODE_DISABLED|SITHAI_MODE_SLEEPING)) == 0 )
            {
                if (actor->thing && actor->pInterest && (actor->pInterest->type == SITH_THING_FREE || actor->pInterest->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED))) {
                    sithCog_SendMessageFromThingEx(actor->thing,NULL,SITH_MESSAGE_AIEVENT,65536.0,0.0,0.0,0.0);
                }
                if (actor->nextUpdate <= sithTime_curMs) {
                    sithAI_TickActor(actor);

                    if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
                        sithThing_SetSyncFlags(actor->thing, THING_SYNC_ALL); // Added
                    }
                }
            }
        }
        else {
            if ( actor->pAIClass
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

    while (1) {
        for ( a1a = 0; a1a < actor->numAIClassEntries; ++a1a )
        {
            if ( (actor->instincts[a1a].field_0 & 1) == 0 )
            {
                if ((actor->flags & actor->pAIClass->entries[a1a].param1) 
                    && !(actor->flags & actor->pAIClass->entries[a1a].param2))
                {
                    if ( actor->instincts[a1a].nextUpdate <= sithTime_curMs )
                    {
                        actor->instincts[a1a].nextUpdate = sithTime_curMs + 1000;
                        if ( actor->pAIClass->entries[a1a].func(actor, &actor->pAIClass->entries[a1a], &actor->instincts[a1a], 0, 0) && a3 != actor->flags )
                        {
                            sithAI_SetActorFireTarget(actor, SITHAI_MODE_UNK100, a3);
                            a3 = actor->flags;
                            continue;
                        }
                    }
                    if ( actor->instincts[a1a].nextUpdate < nextMs ) {
                        nextMs = actor->instincts[a1a].nextUpdate;
                    }
                }
            }
        }
        break;
    }
    
    actor->nextUpdate = nextMs;
}

// MoTS altered
void sithAI_SetActorFireTarget(sithActor *actor, int a2, intptr_t actorFlags)
{
    int v6; // eax
    uint32_t v7; // ebx
    int old_flags; // [esp+14h] [ebp+4h]

    for ( ; actor->pAIClass; a2 = SITHAI_MODE_UNK100 )
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
        if (actor->flags & SITHAI_MODE_DISABLED)
            break;
        if (actor->flags & SITHAI_MODE_SLEEPING)
        {
            if ( a2 != SITHAI_MODE_ATTACKING )
                return;
            actor->flags &= ~SITHAI_MODE_SLEEPING;
        }

        if ( a2 == SITHAI_MODE_UNK100 )
            sithCog_SendMessageFromThingEx(actor->thing, 0, SITH_MESSAGE_AIEVENT, Main_bMotsCompat ? (float)actor->flags : (float)SITHAI_EVENTMODECHANGED, 0.0, 0.0, 0.0);

        v7 = 0;
        for (v7 = 0; v7 < actor->numAIClassEntries; v7++)
        {
            sithActorInstinct* entry = &actor->instincts[v7];
            if ( (entry->field_0 & 1) == 0 )
            {
                if ( (actor->pAIClass->entries[v7].param3 & a2) != 0 )
                {
                    if ( actor->pAIClass->entries[v7].func(actor, &actor->pAIClass->entries[v7], entry, a2, actorFlags) )
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
            v3 = i->pAIClass;
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

int sithAI_PrintThingStatus(stdDebugConsoleCmd* a1, const char *idxStr)
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
                v4->pAIClass->fpath,
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
                        v4->pAIClass->entries[v7].param3,
                        v4->pAIClass->entries[v7].param1);
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
            v7 = &v3->paFrames[v6];
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
    v3->paFrames = (rdVector3 *)result;
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
    v4->paFrames = (rdVector3 *)pSithHS->alloc(sizeof(rdVector3) * a3->trackParams.sizeFrames);
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
            v9 = &v4->paFrames[v7];
            ++v7;
            ++v6;
            rdVector_Add3(v9, v8, &a1);
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
        if (thing->actor->flags & SITHAI_MODE_TURNING)
            sithAI_sub_4EA630(thing->actor, deltaSeconds);
        if (thing->actor->flags & SITHAI_MODE_MOVING)
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
    v5 = fabs(rdVector_Dot3(&v4->rvec, &actor->lookVector));
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

// MoTS altered
void sithAI_idk_msgarrived_target(sithActor *actor, float deltaSeconds)
{
    sithThing *v3; // esi
    long double v9; // st7
    double v10; // st5
    double v11; // st6
    double v13; // st7
    sithSector *v18; // eax
    int v19; // eax
    float v20; // [esp+10h] [ebp-20h]
    float v21; // [esp+14h] [ebp-1Ch]
    rdVector3 a4; // [esp+18h] [ebp-18h] BYREF
    float actorb; // [esp+34h] [ebp+4h]

    // MoTS Added: SITH_AF_FREEZE_MOVEMENT
    v3 = actor->thing;
    if ( (actor->flags & SITHAI_MODE_SLEEPING) == 0 && (v3->actorParams.typeflags & SITH_AF_COMBO_FREEZE) == 0 )
    {
        rdVector3 tmp;
        actorb = v3->actorParams.maxThrust * deltaSeconds * actor->moveSpeed;
        rdVector_Sub3(&actor->field_1AC, &actor->movePos, &v3->position);
        v9 = rdVector_Normalize3Acc(&actor->field_1AC);
        rdVector_Scale3(&tmp, &actor->field_1AC, actorb);
        actor->field_1B8 = v9;
        if ( (v3->sector->flags & SITHAI_MODE_ATTACKING) == 0 && (v3->physicsParams.physflags & SITH_PF_FLY) == 0 )
            tmp.z = 0.0;
        rdVector_Add3Acc(&tmp, &v3->physicsParams.vel);
        rdVector_Copy3(&v3->physicsParams.vel, &tmp);
        if ( (actor->flags & SITHAI_MODE_NO_CHECK_FOR_CLIFF) == 0 && v3->attach_flags )
        {
            if ( (v3->physicsParams.physflags & SITH_PF_FLY) != 0 )
            {
LABEL_15:
                if ( (v3->actorParams.typeflags & SITH_AF_BREATH_UNDER_WATER) == 0 )
                {
                    if ( (v3->thingflags & SITH_TF_WATER) != 0 )
                    {
                        rdVector_Zero3(&v3->physicsParams.vel);
                    }
                    else
                    {
                        rdVector_Copy3(&a4, &v3->position);
                        rdVector_MultAcc3(&a4, &v3->physicsParams.vel, deltaSeconds);
                        v18 = sithCollision_GetSectorLookAt(v3->sector, &v3->position, &a4, 0.0);
                        if ( !v18 || (v18->flags & SITH_SECTOR_UNDERWATER) == 0 )
                            goto LABEL_22;
                        rdVector_Zero3(&v3->physicsParams.vel);
                    }
                    v3->physicsParams.vel.z = v3->physicsParams.vel.z - -0.5;
                }
LABEL_22:
                if ( actor->field_1B8 <= (double)v3->moveSize )
                {
                    rdVector_Zero3(&v3->physicsParams.vel);
                    actor->flags &= ~SITHAI_MODE_MOVING;
                    sithSoundClass_ThingPauseSoundclass(v3, SITH_SC_MOVING);
                    sithCog_SendMessageFromThing(v3, 0, SITH_MESSAGE_ARRIVED);
                    sithAI_SetActorFireTarget(actor, SITHAI_MODE_FLEEING, 0);
                }
                return;
            }
            if (!rdVector_IsZero3(&tmp))
            {
                rdVector_Copy3(&a4, &v3->position);
                rdVector_MultAcc3(&a4, &v3->physicsParams.vel, deltaSeconds);
                if ( !sithAI_physidk(actor, &a4, 0) )
                {
                    rdVector_Zero3(&v3->physicsParams.vel);
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
    sithThingActorParams *v5; // edi
    double v6; // st7
    rdVector3 a2a; // [esp+Ch] [ebp-Ch] BYREF

    rdVector_Sub3(&actor->lookVector, lookPos, &actor->thing->position);
    v5 = &actor->thing->actorParams;
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
                a2a.x = v6;
                a2a.y = v5->eyePYR.y;
                a2a.z = v5->eyePYR.z;
                sithActor_MoveJointsForEyePYR(actor->thing, &a2a);
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
    int v9; // [esp+10h] [ebp-4h]
    float actora; // [esp+18h] [ebp+4h]

    v2 = actor->thing;
    v9 = actor->field_1F4;
    if ( actor->field_1E0 == bShowInvisibleThings )
        return;

    actor->field_1E0 = bShowInvisibleThings;
    v3 = v2->actorParams.templateWeapon;
    if ( v3 )
        actora = v3->moveSize;
    else
        actora = 0.0;
    rdMatrix_TransformVector34(&actor->blindAimError, &v2->actorParams.fireOffset, &v2->lookOrientation);
    v4 = actor->pDistractor;
    rdVector_Add3Acc(&actor->blindAimError, &v2->position);
    if ( v4 )
    {
        if ( (v4->actorParams.typeflags & SITH_AF_INVISIBLE) || (actor->thing->actorParams.typeflags & SITH_AF_COMBO_BLIND) != 0 )
            v9 = 3;
        actor->field_1D4 = v4->position;
        v5 = sithAI_CheckSightThing(v2, &actor->blindAimError, v4, actor->pAIClass->fov, actor->pAIClass->sightDist, actora, &actor->attackError, &actor->attackDistance);
        actor->field_1F4 = v5;

        if ( !v5 )
        {
            if ( !v9 || sithAI_CanDetectSightThing(actor, actor->pDistractor, actor->attackDistance) )
            {
                actor->field_1F8 = actor->pDistractor->position;
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
                 actor->pAIClass->fov,
                 actor->pAIClass->sightDist,
                 actora,
                 &actor->attackError,
                 &actor->attackDistance);
        actor->field_1F4 = v6;
        if ( !v6 )
        {
            rdVector_Copy3(&actor->field_1F8, &actor->field_1D4);
            actor->field_204 = sithTime_curMs;
        }
    }
}

void sithAI_sub_4EAF40(sithActor *actor)
{
    int v1; // ebx
    int v3; // eax
    int v4; // eax

    v1 = actor->field_238;
    if ( actor->field_224 != bShowInvisibleThings )
    {
        actor->field_224 = bShowInvisibleThings;
        if ( actor->pMoveThing )
        {
            if ( (actor->pMoveThing->actorParams.typeflags & SITH_AF_INVISIBLE) || (actor->thing->actorParams.typeflags & SITH_AF_COMBO_BLIND) != 0 )
                v1 = 3;
            v3 = sithAI_CheckSightThing(actor->thing, &actor->thing->position, actor->pMoveThing, -1.0, actor->pAIClass->sightDist, 0.0, &actor->field_228, &actor->currentDistanceFromTarget);
            actor->field_238 = v3;
            if ( !v3 )
            {
                if ( !v1 || sithAI_CanDetectSightThing(actor, actor->pMoveThing, actor->currentDistanceFromTarget) )
                {
                    actor->field_23C = actor->pMoveThing->position;
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
                     actor->pAIClass->sightDist,
                     0.0,
                     &actor->field_228,
                     &actor->currentDistanceFromTarget);
            actor->field_238 = v4;
            if ( !v4 )
            {
                rdVector_Copy3(&actor->field_23C, &actor->movepos);
                actor->field_248 = sithTime_curMs;
            }
        }
    }
}

// MoTS altered
int sithAI_CheckSightThing(sithThing *thing, rdVector3 *targetPosition, sithThing *targetThing, float fov, float maxDistance, float unused, rdVector3 *targetErrorDir, float *targetDistance)
{
    long double v12; // st7
    double v18; // st7
    sithSector *v21; // eax
    sithCollisionSearchEntry *v22; // esi
    sithThing *v23; // eax
    float a4a; // [esp+18h] [ebp+8h]
    float a5a; // [esp+2Ch] [ebp+1Ch]

    rdVector_Sub3(targetErrorDir, &targetThing->position, targetPosition);
    v12 = rdVector_Normalize3Acc(targetErrorDir) - targetThing->collideSize;
    *targetDistance = v12;
 
    if ( v12 <= 0.0 )
        v12 = 0.0;

    *targetDistance = v12;
    if ( !(thing->thingflags & SITH_TF_WATER) && (targetThing->thingflags & SITH_TF_WATER))
    {
        if ( targetThing->moveType != SITH_MT_PHYSICS )
            return 3;
        if ( (targetThing->physicsParams.physflags & SITH_PF_MIDAIR) == 0 )
            return 3;
    }
    if ( (thing->thingflags & SITH_TF_WATER) && !(targetThing->thingflags & SITH_TF_WATER))
        return 3;
    if ( v12 - targetThing->collideSize > maxDistance )
        return 1;
    if ( fov > -1.0 )
    {
        v18 = rdVector_Dot3(&thing->lookOrientation.rvec, targetErrorDir);
        a5a = rdVector_Dot3(&thing->lookOrientation.lvec, targetErrorDir);

        if ( v18 < 0.0 )
            v18 = -v18;

        a4a = v18;
        if ( fov >= 0.0 )
        {
            if ( a5a < 0.0 )
                return 2;
            if ( a4a > 1.0 - fov )
                return 2;
        }
        if ( fov < 0.0 && a5a < 0.0 && a4a < fov - -1.0 )
            return 2;
    }

    // MoTS added
    if (thing->sector == NULL) {
        return 3;
    }

    v21 = sithCollision_GetSectorLookAt(thing->sector, &thing->position, targetPosition, 0.0);
    sithCollision_SearchRadiusForThings(v21, thing, targetPosition, targetErrorDir, *targetDistance, 0.0, 0x102);
    v22 = sithCollision_NextSearchResult();
    if ( v22 )
    {
        while ( (v22->hitType & SITHCOLLISION_THING) != 0 )
        {
            v23 = v22->receiver;
            if ( v23 != targetThing )
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

// MOTS altered
int sithAI_sub_4EB300(sithThing *a3, rdVector3 *a4, rdVector3 *arg8, float argC, float arg10, float a7, rdVector3 *a5, float *a8)
{
    float v11; // st7
    double v16; // st7
    sithSector *v19; // eax
    sithCollisionSearchEntry *v20; // esi
    float a4a; // [esp+18h] [ebp+8h]
    float arg8a; // [esp+1Ch] [ebp+Ch]
 
    rdVector_Sub3(a5, arg8, a4);
    v11 = rdVector_Normalize3Acc(a5);
    *a8 = v11;

    if ( v11 > arg10 )
        return 1;

    if ( argC > -1.0 )
    {
        v16 = rdVector_Dot3(&a3->lookOrientation.rvec, a5);
        a4a = rdVector_Dot3(&a3->lookOrientation.lvec, a5);

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

    // MOTS added
    if (a3->sector == NULL) {
        return 3;
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
    rdVector_Neg3(&a5, &rdroid_zVector3);
    a7a = v4->moveSize * 0.25;
    v12 = 0;
    result = (intptr_t)sithCollision_GetSectorLookAt(v4->sector, &v4->position, a4, 0.0);
    v6 = (sithSector *)result;
    if ( !result )
        return result;
    a6 = sithPhysics_ThingGetInsertOffsetZ(v4) + a7->pAIClass->maxStep;
    sithCollision_SearchRadiusForThings(v6, v4, a4, &a5, a6, a7a, 0x2002);
    v7 = sithCollision_NextSearchResult();
    if ( !v7 )
        goto LABEL_20;
    while (!(v7->hitType & SITHCOLLISION_WORLD))
    {
        if (v7->hitType & SITHCOLLISION_THING)
        {
            v10 = v7->receiver;
            if (v10->thingflags & SITH_TF_STANDABLE)
            {
                v12 = 1;
                if ( arg8 )
                {
                    if ((v4->attach_flags & SITH_ATTACH_THINGSURFACE) && v4->attachedThing == v10 )
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
    if ( (v4->attach_flags & SITH_ATTACH_WORLDSURFACE) && v4->attachedSurface == v8 )
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

    v4 = actor->thing;
    rdVector_Neg3(&a5, &rdroid_zVector3);
    v5 = 0;
    a7 = v4->moveSize * 0.25;
    a6 = sithPhysics_ThingGetInsertOffsetZ(v4) + actor->pAIClass->maxStep;
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
    if ( autoaimFov < 0.0 || autoaimMaxDist < 0.0 )
        return 0;
    sithAI_dword_84DE74 = a7;
    sithAI_dword_84DE6C = a5;
    sithAI_flt_84DE70 = a8;
    sithAI_pThing_84DE68 = thingList;
    stdMath_SinCos(90.0 - autoaimFov * 0.5, &autoaimFov, &sithAI_flt_84DE64);
    stdMath_SinCos(90.0 - autoaimMaxDist * 0.5, &autoaimFov, &sithAI_flt_84DE58);
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
        rot.y = (_frand() * v2) - a4;
        rot.z = 0.0;
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
    tmp.y = _frand() * 360.0;
    tmp.z = 0.0;
    rdVector_Rotate3(out, &rdroid_yVector3, &tmp);
}

// MoTS altered
int sithAI_FireWeapon(sithActor *actor, float minDistToFire, float maxDistToFire, float minDot, float percentageErrorInAim, int bAltFire, int a7)
{
    sithThing *v8; // ebp
    sithThing *v9; // edi
    sithThing *v11; // ecx
    double v14; // rt2
    int16_t v15; // bx
    sithThing *v16; // eax
    double v19; // st7
    signed int v20; // [esp+10h] [ebp-20h]
    float v21; // [esp+14h] [ebp-1Ch]
    rdVector3 v1; // [esp+18h] [ebp-18h] BYREF
    rdVector3 a1a; // [esp+24h] [ebp-Ch] BYREF

    v8 = 0;
    v9 = actor->thing;
    v21 = 1.0;
    v20 = 0;
    if ( (g_debugmodeFlags & 0x80u) != 0
      || (v9->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED))
      || (v9->sector->flags & SITH_SECTOR_UNDERWATER) && (v9->actorParams.typeflags & SITH_AF_CANTSHOOTUNDERWATER) != 0 )
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
    rdVector_Copy3(&v1, &actor->attackError);
    if ( (a7 & 8) != 0 )
    {
        v20 = 0;
        goto LABEL_12;
    }
    if ( actor->field_288 > sithTime_curMs || actor->field_1F4 )
        return 0;
    if ( actor->attackDistance < (double)minDistToFire || actor->attackDistance > (double)maxDistToFire )
        return 0;

    // MoTS added
    if (Main_bMotsCompat && (minDot > 0.0 && rdVector_Dot3(&v9->lookOrientation.lvec, &v1) < 0.0)) {
        return 0;
    }

    v19 = fabs(rdVector_Dot3(&v9->lookOrientation.rvec, &v1));
    if ( v19 > 1.0 - minDot )
        return 0;
    
    if ( (v9->actorParams.typeflags & SITH_AF_DELAYFIRE) != 0 )
    {
        actor->field_268 = a7 | 8;
        actor->field_264 = percentageErrorInAim;
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
        v11 = actor->pDistractor;
        if ( v11->moveType == SITH_MT_PHYSICS
          && !rdVector_IsZero3(&v11->physicsParams.vel) )
        {
            rdVector_Scale3(&a1a, &v1, v8->physicsParams.vel.y);
            rdVector_Add3Acc(&a1a, &v11->physicsParams.vel);
            rdVector_Normalize3Acc(&a1a);
            if ( rdVector_Dot3(&a1a, &v1) > 0.5 )
                v1 = a1a;
        }
    }
    if ( (a7 & 2) != 0 && v8->moveType == SITH_MT_PHYSICS) // Added: physics check
    {
        double yvel = 0.00001;
        // Added: div 0 fix
        if (v8->physicsParams.vel.y != 0.0) {
            yvel = v8->physicsParams.vel.y;
        }

        v14 = actor->attackDistance / yvel * 0.5;
        rdVector_Scale3(&a1a, &actor->attackError, v8->physicsParams.vel.y);
        a1a.z = v14 * sithWorld_pCurrentWorld->worldGravity + a1a.z;
        v15 = 1;
        v21 = rdVector_Normalize3(&v1, &a1a) / yvel;
    }
    else
    {
        v15 = 0;
    }
    if ( percentageErrorInAim != 0.0 && actor->attackDistance != 0.0 && _frand() > actor->pAIClass->accuracy )
    {
        sithAI_RandomFireVector(&v1, percentageErrorInAim);
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

    if ( a1->renderTick == sithRender_lastRenderTick )
        return;

    a1->renderTick = sithRender_lastRenderTick;
    if (sithAI_dword_84DE5C >= 0x80)
        return;

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
                rdVector_Sub3(&v13, &v4->position, &a2->scale);
                rdVector_Normalize3Acc(&v13);
                rdVector_Normalize3(&a1a, &a2->uvec);
                rdVector_Normalize3(&v1, &a2->rvec);
                rdVector_Normalize3(&v16, &a2->lvec);
                v17 = rdVector_Dot3(&a1a, &v13);
                a2a = rdVector_Dot3(&v1, &v13);
                if ( v17 > (double)sithAI_flt_84DE58
                  || v17 < -sithAI_flt_84DE58
                  || a2a > (double)sithAI_flt_84DE64
                  || a2a < -sithAI_flt_84DE64
                  || (v12 = rdVector_Dot3(&v16, &v13), v12 < 0.0) )
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
                   || (v7->surface->surfaceInfo.face.type & 2)
                   || (v8 && (v8->texture_ptr->alpha_en & 1) != 0)) // Added: v8 nullptr check
                  && rdVector_Dot3(&a2->lvec, &v7->surface->surfaceInfo.face.normal) < 0.0 )
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

// MoTS altered
int sithAI_CanDetectSightThing(sithActor *actor, sithThing *targetThing, float distance)
{
    sithThing *actorThing; // esi
    double clampedDistance; // st7
    sithSector *targetSector; // edx
    int result; // eax
    float awareness; // [esp+0h] [ebp-4h]

    awareness = 1.0;
    actorThing = actor->thing;
    if ( !targetThing )
        return 1;
    if ( targetThing->type != SITH_THING_ACTOR && targetThing->type != SITH_THING_PLAYER )
        return 1;
    if ( distance >= 2.0 )
    {
        if (!(actor->flags & SITHAI_MODE_ACTIVE))
            awareness = 0.5;
        if (!(targetThing->actorParams.typeflags & SITH_AF_FIELDLIGHT) && (targetThing->jkFlags & 1) == 0 )
        {
            clampedDistance = stdMath_Clamp((distance - 2.0) * 0.1, 0.0, 0.6);
            awareness = (1.0 - clampedDistance) * awareness;
            if (!(actorThing->actorParams.typeflags & SITH_AF_CAN_SEE_IN_DARK))
            {
                targetSector = targetThing->sector;
                if ( targetSector->ambientLight < 0.5 )
                    awareness = (targetSector->ambientLight - -0.2) * awareness;
            }
            if ( targetThing->moveType == SITH_MT_PHYSICS )
            {
                if (targetThing->physicsParams.physflags & SITH_PF_CROUCHING)
                    awareness = awareness * 0.75;
                if (rdVector_IsZero3(&targetThing->physicsParams.vel))
                    awareness = awareness * 0.5;
            }
        }
    }
    if (targetThing->actorParams.typeflags & SITH_AF_INVISIBLE
        && !(actorThing->actorParams.typeflags & SITH_AF_CAN_SEE_INVISIBLE)) {
        awareness = awareness * 0.05;
    }
    if (actorThing->actorParams.typeflags & SITH_AF_COMBO_BLIND) {
        awareness = awareness * 0.05;
    }
    awareness = stdMath_Clamp(awareness, 0.05, 1.0);
    if ( _frand() >= awareness )
        return 0;
    else
        return 1;
}

// MOTS added
void sithAI_SetDistractor(sithThing *pDistractor)
{
    sithActor *ppsVar1;
    sithThing **ppsVar2;
    sithThing *pPlayer;

    pPlayer = sithPlayer_pLocalPlayerThing;
    if (sithAI_pDistractor) 
    {
        for (int i = 0; i < SITHAI_MAX_ACTORS; i++) {
            if (sithAI_actors[i].pDistractor == sithAI_pDistractor) {
                sithAI_actors[i].pDistractor = pPlayer;
            }
        };
    }

    sithAI_pDistractor = pDistractor;
    if (pDistractor) 
    {
        for (int i = 0; i < SITHAI_MAX_ACTORS; i++) {
            if (sithAI_actors[i].pDistractor == pPlayer) {
                sithAI_actors[i].pDistractor = pDistractor;
            }
        }
    }
}

// MOTS added
void sithAI_AddAlignmentPriority(float param_1)
{
    sithAI_FLOAT_005a79d8 = param_1;
}

void sithAI_GetThingsInCone(sithSector *a1, rdMatrix34 *a2, float a3)
{
    sithThing *v4; // esi
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
    float local_190[100];

    // Added: prevent overflow
    if (sithAI_dword_84DE6C > 100) {
        sithAI_dword_84DE6C = 100;
    }

    for (int iterIdx = sithWorld_pCurrentWorld->numThings; iterIdx >= 0; iterIdx--)
    {
        v4 = &sithWorld_pCurrentWorld->things[iterIdx];
        if ( sithAI_dword_84DE60 >= (unsigned int)sithAI_dword_84DE6C )
            break;
        if ( ((1 << v4->type) & sithAI_dword_84DE74) != 0 && (v4->thingflags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
        {
            rdVector_Sub3(&v13, &v4->position, &a2->scale);
            float dist = rdVector_Normalize3Acc(&v13);
            rdVector_Normalize3(&a1a, &a2->uvec);
            rdVector_Normalize3(&v1, &a2->rvec);
            rdVector_Normalize3(&v16, &a2->lvec);
            v17 = rdVector_Dot3(&a1a, &v13);
            a2a = rdVector_Dot3(&v1, &v13);
            if ( v17 > (double)sithAI_flt_84DE58
              || v17 < -sithAI_flt_84DE58
              || a2a > (double)sithAI_flt_84DE64
              || a2a < -sithAI_flt_84DE64
              || (v12 = rdVector_Dot3(&v16, &v13), v12 < 0.0) )
            {
                ;
            }
            else
            {
                if ( sithAI_dword_84DE60 >= (unsigned int)sithAI_dword_84DE6C )
                    return;
                local_190[sithAI_dword_84DE60] = dist;
                sithAI_pThing_84DE68[sithAI_dword_84DE60] = v4;
                sithAI_dword_84DE60++;
            }
        }
    }

    // Sort the results
    for (int i = 0; i < sithAI_dword_84DE60-1; i++) {
        for (int j = 0; j < sithAI_dword_84DE60 - i - 1; j++) {
            if (local_190[j] > local_190[j+1]) {
                float val_a_1 = local_190[j];
                sithThing* val_a_2 = sithAI_pThing_84DE68[j];

                float val_b_1 = local_190[j+1];
                sithThing* val_b_2 = sithAI_pThing_84DE68[j+1];

                local_190[j] = val_b_1;
                sithAI_pThing_84DE68[j] = val_b_2;

                local_190[j+1] = val_a_1;
                sithAI_pThing_84DE68[j+1] = val_a_2;
            }
        }
    }
}

// MOTS added
int sithAI_FirstThingInCone(sithSector *sector, rdMatrix34 *out, float autoaimFov, float autoaimMaxDist, int a5, sithThing **thingList, int a7, float a8)
{
    if ( autoaimFov < 0.0 || autoaimMaxDist < 0.0 )
        return 0;
    sithAI_dword_84DE74 = a7;
    sithAI_dword_84DE6C = a5;
    sithAI_flt_84DE70 = a8;
    sithAI_pThing_84DE68 = thingList;
    stdMath_SinCos(90.0 - autoaimFov * 0.5, &autoaimFov, &sithAI_flt_84DE64);
    stdMath_SinCos(90.0 - autoaimMaxDist * 0.5, &autoaimFov, &sithAI_flt_84DE58);
    sithMain_sub_4C4D80();
    sithAI_dword_84DE60 = 0;
    sithAI_dword_84DE5C = 0;
    sithAI_GetThingsInCone(sector, out, 0.0); // TODO: Did they actually change this?
    return sithAI_dword_84DE60;
}

// MOTS added
int sithAI_FUN_0053a520(sithActor *pActor,float param_2,float param_3,float param_4,int param_5,
                       float param_6,uint32_t param_7)
{
    sithThing *thing;
    sithThing *psVar1;
    sithThing *psVar2;
    float fVar3;
    float fVar4;
    float fVar5;
    int bVar6;
    int anim;

    anim = 0;
    thing = pActor->thing;

    if (g_debugmodeFlags & 0x80) {
        return 0;
    }
    if (thing->thingflags & 0x202) {
        return 0;
    }
    if (thing->sector && thing->sector->flags & SITH_SECTOR_UNDERWATER) // Added: thing->sector
    {
        return 0;
    }
    if (thing->actorParams.typeflags & SITH_AF_CANTSHOOTUNDERWATER) {
        return 0;
    }

    if ((param_5 == 0) || (param_5 == 1)) {
        anim = SITH_ANIM_CHARGE;
    }
    sithAI_sub_4EAD60(pActor);
    if ((param_7 & 8) != 0) {
LAB_0053a691:
        psVar1 = pActor->pDistractor;
        psVar2 = pActor->thing;
        fVar5 = (psVar1->position).x - (psVar2->position).x;
        fVar3 = (psVar1->position).y - (psVar2->position).y;
        fVar4 = (psVar1->position).z - (psVar2->position).z;
        pActor->field_28C = sithTime_curMs + 2000;
        pActor->moveSpeed = 1313.0;
        pActor->flags &= ~(SITHAI_MODE_TURNING | SITHAI_MODE_MOVING);
        pActor->attackError.x = fVar5;
        thing->physicsParams.vel.x = param_6 * fVar5;
        thing->physicsParams.vel.y = param_6 * fVar3;
        pActor->attackError.y = fVar3;
        pActor->attackError.z = fVar4;
        pActor->attackDistance = stdMath_Sqrt(fVar4 * fVar4 + fVar3 * fVar3 + fVar5 * fVar5);
        thing->physicsParams.vel.z = param_6 * fVar4;
        return 1;
    }
    if (((uint32_t)pActor->field_288 <= sithTime_curMs) &&
            (pActor->field_1F4 == 0)) {
        if ((pActor->attackDistance < param_2) || (pActor->attackDistance > param_3)) {
            bVar6 = 0;
        }
        else {
            bVar6 = 1;
        }
        if (bVar6) {
            fVar3 = (thing->lookOrientation).rvec.z * (pActor->attackError).z +
                    (thing->lookOrientation).rvec.y * (pActor->attackError).y +
                    (thing->lookOrientation).rvec.x * (pActor->attackError).x;
            if (fVar3 < 0.0) {
                fVar3 = -fVar3;
            }
            if (fVar3 <= 1.0 - param_4) {
                if ((thing->actorParams.typeflags & SITH_AF_DELAYFIRE) != 0) {
                    pActor->field_268 = param_7 | 8;
                    pActor->field_264 = param_6;
                    pActor->field_26C = param_5;
                    sithPuppet_PlayMode(thing, anim, (rdPuppetTrackCallback_t)0x0);
                    return 1;
                }
                goto LAB_0053a691;
            }
        }
    }
    return 0;
}

// MOTS added
int sithAI_Leap(sithActor *pActor,float minDist,float maxDist,float minDot,int param_5,
                       float param_6,uint32_t param_7)
{
    float fVar1;
    sithThing *thing;
    sithThing *psVar2;
    sithThing *psVar3;
    int bVar4;
    uint32_t uVar5;
    int anim;
    double fVar6;
    double fVar7;
    double fVar8;
    double fVar9;
    double fVar10;
    int64_t lVar11;

    anim = 0;
    thing = pActor->thing;
    
    if (g_debugmodeFlags & 0x80) {
        return 0;
    }
    if (thing->thingflags & 0x202) {
        return 0;
    }
    if (thing->sector && thing->sector->flags & SITH_SECTOR_UNDERWATER) // Added: thing->sector
    {
        return 0;
    }
    if (thing->actorParams.typeflags & SITH_AF_CANTSHOOTUNDERWATER) {
        return 0;
    }

    if ((param_5 == 0) || (param_5 == 1)) {
        anim = SITH_ANIM_JUMP;
    }
    sithAI_sub_4EAD60(pActor);
    uVar5 = sithTime_curMs;
    if ((param_7 & 8) != 0) 
    {
LAB_0053a3b9:
        psVar2 = pActor->pDistractor;
        psVar3 = pActor->thing;
        fVar6 = (double)(psVar2->position).x - (double)(psVar3->position).x;
        fVar7 = (double)(psVar2->position).y - (double)(psVar3->position).y;
        fVar8 = (double)(psVar2->position).z - (double)(psVar3->position).z;
        fVar9 = stdMath_Sqrt(fVar8 * (double)(float)fVar8 + fVar7 * fVar7 + fVar6 * (double)(float)fVar6);
        fVar10 = fVar9 / (double)param_6 - (double) - 0.2;
        fVar1 = sithWorld_pCurrentWorld->worldGravity;
        (pActor->attackError).x = (float)fVar6;
        (pActor->attackError).y = (float)fVar7;
        (pActor->attackError).z = (float)fVar8;
        pActor->attackDistance = (float)fVar9;
        lVar11 = (int64_t)(fVar10 * 1000.0);
        pActor->field_28C = (int)lVar11 + uVar5;
        pActor->flags &= ~(SITHAI_MODE_TURNING | SITHAI_MODE_MOVING);
        sithThing_DetachThing(thing);
        thing->physicsParams.vel.x = param_6 * (float)fVar6;
        thing->physicsParams.vel.y = param_6 * (float)fVar7;
        thing->physicsParams.vel.z =
            (float)(fVar10 * 0.5 * fVar1 + (float)(param_6 * (float)fVar8));
        sithSoundClass_PlayModeRandom(thing, SITH_SC_JUMP);
        return 1;
    }

    
    if (((uint32_t)pActor->field_288 <= sithTime_curMs) &&
            (pActor->field_1F4 == 0)) 
    {
        if (pActor->attackDistance < minDist || pActor->attackDistance > maxDist) {
            bVar4 = 0;
        }
        else {
            bVar4 = 1;
        }
        if (bVar4) {
            fVar1 = (thing->lookOrientation).rvec.z * (pActor->attackError).z +
                    (thing->lookOrientation).rvec.y * (pActor->attackError).y +
                    (thing->lookOrientation).rvec.x * (pActor->attackError).x;
            if (fVar1 < 0.0) {
                fVar1 = -fVar1;
            }
            
            if (fVar1 <= 1.0 - minDot) {
                if (thing->actorParams.typeflags & SITH_AF_DELAYFIRE) 
                {
                    pActor->field_28C = sithTime_curMs + 300;
                    pActor->field_268 = param_7 | 8;
                    pActor->field_264 = param_6;
                    pActor->field_26C = param_5;
                    sithPuppet_PlayMode(thing, anim, NULL);
                    return 1;
                }
                goto LAB_0053a3b9;
            }
        }
    }
    return 0;
}

// MOTS added
sithThing* sithAI_FUN_00539a60(sithActor *pThing)
{
    sithThing *a3;
    sithAIClass *psVar1;
    float fVar2;
    int iVar3;
    sithThing *psVar4;
    sithThing *arg8;
    int iVar5;
    float local_1c;
    int local_18;
    float local_10;
    rdVector3 local_c;

    psVar4 = (sithThing *)0x0;
    if (pThing->pAIClass->alignment != 0.0) 
    {
        a3 = pThing->thing;
        local_1c = 0.0;
        sithAI_dword_84DE74 = 0x404;
        local_18 = sithWorld_pCurrentWorld->numThings;
        if (-1 < local_18) 
        {
            iVar5 = local_18;
            local_18 = local_18 + 1;
            do 
            {
                arg8 = &sithWorld_pCurrentWorld->things[iVar5];
                if (((sithAI_dword_84DE74 & 1 << (arg8->type & 0x1f)) != 0) &&
                ((arg8->thingflags & 0x80202) == 0)) 
                {
                    if (arg8->thingtype == 2) 
                    {
                        fVar2 = arg8->pAIClass->alignment;
                    }
                    else {
                        fVar2 = 0.0;
                        if (arg8->type == 10) {
                            fVar2 = sithAI_FLOAT_005a79d8;
                        }
                    }
                    if (((fVar2 != 0.0) && (psVar1 = pThing->pAIClass, fVar2 < 0.0 != psVar1->alignment < 0.0))
                            && (iVar3 = sithAI_CheckSightThing(a3, &a3->position, arg8, psVar1->fov, psVar1->sightDist, 0.0,
                                                          &local_c, &local_10), iVar3 == 0)) {
                        local_1c = local_1c - -1.0;
                        fVar2 = _frand() * local_1c;
                        if (fVar2 <= 1.0) {
                            psVar4 = arg8;
                        }
                    }
                }
                iVar5 = iVar5 - 1;
                local_18 = local_18 + -1;
            } while (local_18 != 0);
        }
    }
    return psVar4;
}

