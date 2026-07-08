#include "sithAI.h"

#include "General/stdMath.h"
#include "General/crc32.h"
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
#include "General/stdHashtbl.h"
#include "General/stdString.h"
#include "Main/jkGame.h"
#include "Cog/sithCogExec.h"
#include "Cog/sithCog.h"
#include "stdPlatform.h"
#include "Devices/sithConsole.h"
#include "Dss/sithDSS.h"
#include "Dss/sithMulti.h"
#include "jk.h"

tHashTable* sithAI_commandsHashmap = NULL;
uint32_t sithAI_maxActors = 0;
int sithAI_actorInitted[SITHAI_MAX_ACTORS] = {0};
int sithAI_bOpened = 0;
int sithAI_bInit = 0;
SithAIRegisteredInstinct* sithAI_commandList = NULL;
uint32_t sithAI_numCommands = 0;
flex_t sithAI_flt_84DE58 = 0.0;
uint32_t sithAI_dword_84DE5C = 0;
int sithAI_dword_84DE60 = 0;
flex_t sithAI_flt_84DE64 = 0.0;
SithThing** sithAI_pThing_84DE68 = NULL;
int sithAI_dword_84DE6C = 0;
flex_t sithAI_flt_84DE70 = 0.0;
int sithAI_dword_84DE74 = 0;

// These are located in a different part of .data?
sithAIAlign sithAI_aAlignments[10] = {0}; // MoTS Added
#ifdef TARGET_TWL
// Added: 84KB of .bss -> extram. Allocated once at sithAI_Startup; SithAIControlBlock is
// all word-width fields (audited) and every clear below is word-safe.
SithAIControlBlock* sithAI_actors = NULL;
#else
SithAIControlBlock sithAI_actors[SITHAI_MAX_ACTORS] = {0};
#endif
int sithAI_inittedActors = 0;

// This is also in a different part
// MoTS Added
SithThing* sithAI_pDistractor = NULL;

flex_t sithAI_FLOAT_005a79d8 = 1.0;

int sithAI_Startup()
{
    int v1; // edx
    int *v2; // ebp
    SithAIControlBlock *v3; // esi
    int v4; // eax
    SithAIControlBlock *v5; // ecx

#ifdef TARGET_TWL
    // Added: allocate the actor pool in extram (was 84KB of .bss)
    if ( !sithAI_actors )
    {
        TWL_EXTRAM_SUGGEST(pSithHS);
        sithAI_actors = (SithAIControlBlock*)SITH_ALLOC(sizeof(SithAIControlBlock) * SITHAI_MAX_ACTORS);
        TWL_EXTRAM_RESTORE(pSithHS);
        if ( !sithAI_actors )
            return 0;
    }
#endif
    if ( sithAI_bInit )
    {
        SITHLOG_ERROR("Warning: System already initialized!\n"); // Added: OpenJones3D-style log
        return 0;
    }

    sithAI_FLOAT_005a79d8 = 1.0; // MoTS added

    sithAI_commandList = (SithAIRegisteredInstinct *)SITH_ALLOC(sizeof(SithAIRegisteredInstinct) * 32);
    if ( sithAI_commandList )
    {
        sithAI_commandsHashmap = stdHashtbl_New(64);
        if ( !sithAI_commandsHashmap )
            SITH_FREE(sithAI_commandList);
    }

    sithAICmd_Startup();

    // TODO: what is this inline?
    stdPlatform_Memzero32(sithAI_actors, sizeof(SithAIControlBlock) * SITHAI_MAX_ACTORS); // Added: word-safe

    v1 = SITHAI_MAX_ACTORS-1;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[SITHAI_MAX_ACTORS-1];
    sithAI_maxActors = SITHAI_MAX_ACTORS;

    do
    {
        stdPlatform_Memzero32(v3, sizeof(SithAIControlBlock)); // Added: word-safe
        if ( v1 == sithAI_inittedActors )
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
            sithAI_inittedActors = v4;
        }
        *v2++ = v1;
        v3--;
        --v1;
    }
    while ( (intptr_t)v3 >= (intptr_t)sithAI_actors );
    // end inline

    sithAI_bInit = 1;
    return 1;
}

void sithAI_Shutdown()
{
    if ( sithAI_bInit )
    {
        SITH_FREE(sithAI_commandList);
        stdHashtbl_Free(sithAI_commandsHashmap);
        sithAI_bInit = 0;
    }

    // Added: Clean reset
    sithAI_commandsHashmap = NULL;
    sithAI_maxActors = 0;
    _memset(sithAI_actorInitted, 0, sizeof(sithAI_actorInitted));
    sithAI_bOpened = 0;
    sithAI_bInit = 0;
    sithAI_commandList = NULL;
    sithAI_numCommands = 0;
    sithAI_flt_84DE58 = 0.0;
    sithAI_dword_84DE5C = 0;
    sithAI_dword_84DE60 = 0;
    sithAI_flt_84DE64 = 0.0;
    sithAI_pThing_84DE68 = NULL;
    sithAI_dword_84DE6C = 0;
    sithAI_flt_84DE70 = 0.0;
    sithAI_dword_84DE74 = 0;

    // These are located in a different part of .data?
    _memset(sithAI_aAlignments, 0, sizeof(sithAI_aAlignments));
    stdPlatform_Memzero32(sithAI_actors, sizeof(SithAIControlBlock) * SITHAI_MAX_ACTORS); // Added: word-safe (and pointer-safe sizeof)
    sithAI_inittedActors = 0;

    // This is also in a different part
    // MoTS Added
    SithThing* sithAI_pDistractor = NULL;

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
    SithAIControlBlock *v3; // esi
    int v4; // eax
    SithAIControlBlock *v5; // ecx
    
    if (sithAI_bOpened)
        return;
    
    // TODO: what is this inline?
    v0 = sithAI_inittedActors;
    stdPlatform_Memzero32(sithAI_actors, sizeof(SithAIControlBlock) * SITHAI_MAX_ACTORS); // Added: word-safe

    v1 = SITHAI_MAX_ACTORS-1;
    v2 = sithAI_actorInitted;
    v3 = &sithAI_actors[SITHAI_MAX_ACTORS-1];
    sithAI_maxActors = SITHAI_MAX_ACTORS;

    do
    {
        stdPlatform_Memzero32(v3, sizeof(SithAIControlBlock)); // Added: word-safe
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
    // end inline
    
    sithAI_bOpened = 0;
}

void sithAI_Create(SithThing *pThing)
{
    SithAIClass *sith_ai; // edx
    int v2; // eax
    int v3; // eax
    SithAIControlBlock *actor; // eax

    SITH_ASSERTREL(pThing); // Added: OpenJones3D-style assert
    SITH_ASSERTREL(pThing->controlType == SITH_CT_AI); // Added: OpenJones3D-style assert

    sith_ai = pThing->pClass;
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
            pThing->actor = actor;
            rdVector_Copy3(&actor->position, &pThing->position);
            actor->orient = pThing->orient.lvec;
            actor->pClass = sith_ai;
            actor->thing = pThing;
            actor->numInstincts = sith_ai->numEntries;
            actor->flags = (SITHAI_MODE_SLEEPING|SITHAI_MODE_SEARCHING);
            actor->moveSpeed = 1.5;

            // MOTS Added
            actor->pInterest = NULL;
        }
        else
        {
            pThing->controlType = SITH_CT_PLOT;
        }
    }
    else
    {
        pThing->controlType = SITH_CT_PLOT;
    }
}

void sithAI_Free(SithThing *pThing)
{
    SithAIControlBlock *v1; // eax
    int v2; // edx
    int v3; // eax
    SithAIControlBlock *v4; // ecx

    SithAIControlBlock* pActor = pThing->actor;
    if (!pActor)
        return;

    v2 = pActor - sithAI_actors;

    // Added: fix memleak
    if (sithAI_actors[v2].aFrames)
    {
        SITH_FREE(sithAI_actors[v2].aFrames);
        sithAI_actors[v2].aFrames = NULL;
    }

    stdPlatform_Memzero32(&sithAI_actors[v2], sizeof(SithAIControlBlock)); // Added: word-safe
    if (v2 == sithAI_inittedActors)
    {
        v3 = v2 - 1;
        if ( v2 - 1 >= 0 )
        {
            v4 = &sithAI_actors[v3];
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
    pThing->actor = 0;
    sithAI_actorInitted[sithAI_maxActors++] = v2;
}

void sithAI_Process()
{
    int v0; // edi
    SithAIControlBlock *actor; // esi

    v0 = 0;
    for ( actor = sithAI_actors; v0 <= sithAI_inittedActors; ++actor )
    {
        if (Main_bMotsCompat)
        {
            if ( actor->pClass
                  && (actor->thing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0
                  && actor->thing->actorParams.health > 0.0
                  && (actor->flags & (SITHAI_MODE_DISABLED|SITHAI_MODE_SLEEPING)) == 0 )
            {
                if (actor->thing && actor->pInterest && (actor->pInterest->type == SITH_THING_FREE || actor->pInterest->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED))) {
                    sithCog_ThingSendMessageEx(actor->thing,NULL,SITH_MESSAGE_AIEVENT,65536.0,0.0,0.0,0.0);
                }
                if (actor->nextUpdate <= sithTime_g_msecGameTime) {
                    sithAI_InstinctUpdate(actor);

                    if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
                        sithThing_SyncThing(actor->thing, THING_SYNC_ALL); // Added
                    }
                }
            }
        }
        else {
            if ( actor->pClass
                  && (actor->thing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0
                  && actor->thing->actorParams.health > 0.0
                  && (actor->flags & (SITHAI_MODE_DISABLED|SITHAI_MODE_SLEEPING)) == 0
                  && actor->nextUpdate <= sithTime_g_msecGameTime )
            {
                sithAI_InstinctUpdate(actor);

                if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
                    sithThing_SyncThing(actor->thing, THING_SYNC_ALL); // Added
                }
            }
        }
        

        ++v0;
    }
}

void sithAI_InstinctUpdate(SithAIControlBlock *pLocal)
{
    int v3; // ebx
    int *v4; // edi
    int a1a; // [esp+1Ch] [ebp+4h]

    uint32_t nextMs = sithTime_g_msecGameTime + 5000;
    int a3 = pLocal->flags;

    while (1) {
        int bRestartScan = 0;
        for ( a1a = 0; a1a < pLocal->numInstincts; ++a1a )
        {
            if ( (pLocal->aInstinctStates[a1a].field_0 & 1) == 0 )
            {
                if ((pLocal->flags & pLocal->pClass->entries[a1a].param1)
                    && !(pLocal->flags & pLocal->pClass->entries[a1a].param2))
                {
                    if ( pLocal->aInstinctStates[a1a].nextUpdate <= sithTime_g_msecGameTime )
                    {
                        pLocal->aInstinctStates[a1a].nextUpdate = sithTime_g_msecGameTime + 1000;
                        if ( pLocal->pClass->entries[a1a].func(pLocal, &pLocal->pClass->entries[a1a], &pLocal->aInstinctStates[a1a], 0, 0) && a3 != pLocal->flags )
                        {
                            sithAI_EmitEvent(pLocal, SITHAI_MODE_UNK100, a3);
                            a3 = pLocal->flags;
                            
                            bRestartScan = 1;
                            break;
                        }
                    }
                    if ( pLocal->aInstinctStates[a1a].nextUpdate < nextMs ) {
                        nextMs = pLocal->aInstinctStates[a1a].nextUpdate;
                    }
                }
            }
        }
        if (!bRestartScan)
            break;
    }
    
    pLocal->nextUpdate = nextMs;
}

// MoTS altered
void sithAI_EmitEvent(SithAIControlBlock *pLocal, int event, intptr_t pObject)
{
    int v6; // eax
    uint32_t v7; // ebx
    int old_flags; // [esp+14h] [ebp+4h]

    for ( ; pLocal->pClass; event = SITHAI_MODE_UNK100 )
    {
        if ( !pLocal->thing )
            break;
        if (pLocal->thing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED))
            break;
        if ( (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) != 0 )
            break;
        if ( pLocal->thing->actorParams.health <= 0.0 )
            break;
        old_flags = pLocal->flags;
        if (pLocal->flags & SITHAI_MODE_DISABLED)
            break;
        if (pLocal->flags & SITHAI_MODE_SLEEPING)
        {
            if ( event != SITHAI_MODE_ATTACKING )
                return;
            pLocal->flags &= ~SITHAI_MODE_SLEEPING;
        }

        if ( event == SITHAI_MODE_UNK100 )
            sithCog_ThingSendMessageEx(pLocal->thing, 0, SITH_MESSAGE_AIEVENT, Main_bMotsCompat ? (flex_t)pLocal->flags : (flex_t)SITHAI_EVENTMODECHANGED, 0.0, 0.0, 0.0); // FLEXTODO

        v7 = 0;
        for (v7 = 0; v7 < pLocal->numInstincts; v7++)
        {
            SithAIInstinctState* entry = &pLocal->aInstinctStates[v7];
            if ( (entry->field_0 & 1) == 0 )
            {
                if ( (pLocal->pClass->entries[v7].param3 & event) != 0 )
                {
                    if ( pLocal->pClass->entries[v7].func(pLocal, &pLocal->pClass->entries[v7], entry, event, pObject) )
                        break;
                }
            }
        }
        if ( pLocal->flags == old_flags )
            break;
        pObject = old_flags;
    }
}

void sithAI_RegisterInstinct(const char *pName, sithAICommandFunc_t pfInstinct, int updateModes, int updateBlockModes, int triggerEvents)
{
    if ( sithAI_numCommands >= 0x20 )
        return;

    SithAIRegisteredInstinct* aiCmd = &sithAI_commandList[sithAI_numCommands];

#ifndef SITHAI_CRC32_INSTINCTS
    stdString_SafeStrCopy(aiCmd->name, pName, 32);
#else
    aiCmd->namecrc = stdCrc32(pName, strlen(pName));
#endif

    aiCmd->func = pfInstinct;
    aiCmd->param1 = updateModes;
    aiCmd->param2 = updateBlockModes;
    aiCmd->param3 = triggerEvents;
    sithAI_numCommands++;
}

SithAIRegisteredInstinct* sithAI_FindInstinct(const char *pInstinctName)
{
    if ( !sithAI_numCommands )
        return NULL;

#ifdef SITHAI_CRC32_INSTINCTS
    uint32_t cmdNameCrc = stdCrc32(pInstinctName, strlen(pInstinctName));
#endif

    for (uint32_t i = 0; i < sithAI_numCommands; i++)
    {
#ifndef SITHAI_CRC32_INSTINCTS
        if (!_strcmp(pInstinctName, sithAI_commandList[i].name))
#else
        if (sithAI_commandList[i].namecrc == cmdNameCrc)
#endif
            return &sithAI_commandList[i];
    }

    return NULL;
}

int sithAI_AIList(stdDebugConsoleCmd* pFunc, const char* pArg)
{
    int v1; // edi
    SithAIControlBlock *i; // esi
    SithAIClass *v3; // ecx

#ifdef SITH_DEBUG_STRUCT_NAMES
    if ( sithAI_bOpened )
    {
        sithConsole_PrintString("Active AI things:\n");
        v1 = 0;
        for ( i = sithAI_actors; v1 <= sithAI_inittedActors; ++i )
        {
            v3 = i->pClass;
            if ( v3 )
            {
                if ( i->thing )
                {
                    _sprintf(
                        std_g_genBuffer,
                        "Block %2d: Class '%s', Owner '%s' (%d), Flags 0x%x\n",
                        v1,
                        v3->fpath,
                        i->thing->aName,
                        i->thing->idx,
                        i->flags);
                    sithConsole_PrintString(std_g_genBuffer);
                }
            }
            ++v1;
        }
        return 1;
    }
    else
    {
        sithConsole_PrintString("AI system not open.\n");
        return 0;
    }
#endif
}

int sithAI_AIStatus(stdDebugConsoleCmd* pFunc, const char *pArg)
{
    uint32_t v2; // ebx
    SithThing *v3; // eax
    SithAIControlBlock *v4; // edi
    int result = 1; // eax
    int v7; // [esp+3Ch] [ebp-8h]
    int actorIdx; // [esp+40h] [ebp-4h] BYREF

#ifdef SITH_DEBUG_STRUCT_NAMES
    v2 = 0;
    if ( pArg && sithAI_bOpened && _sscanf(pArg, "%d", &actorIdx) == 1 && actorIdx <= sithAI_inittedActors )
    {
        v3 = sithAI_actors[actorIdx].thing;
        v4 = &sithAI_actors[actorIdx];
        if ( v3 )
        {
            _sprintf(std_g_genBuffer, "AI Status dump for thing %d (%s).\n", v3->idx, v3->aName);
            sithConsole_PrintString(std_g_genBuffer);
            _sprintf(
                std_g_genBuffer,
                "Class '%s', Flags=0x%x, Moods %d/%d/%d, NextUpdate=%d\n",
                v4->pClass->fpath,
                v4->flags,
                v4->mood0,
                v4->mood1,
                v4->mood2,
                v4->nextUpdate);
            sithConsole_PrintString(std_g_genBuffer);
            sithConsole_PrintString("Current instincts:\n");
            if ( v4->numInstincts )
            {
                v7 = 0;
                SithAIInstinctState* v6 = &v4->aInstinctStates[0];
                do
                {
                    _sprintf(
                        std_g_genBuffer,
                        "Instinct %d: Params: %f/%f/%f/%f, nextUpdate=%d, mask=0x%x, mode=0x%x.\n",
                        v2,
                        v6->param0,
                        v6->param1,
                        v6->param2,
                        v6->param3,
                        v6->nextUpdate,
                        v4->pClass->entries[v7].param3,
                        v4->pClass->entries[v7].param1);
                    sithConsole_PrintString(std_g_genBuffer);
                    ++v2;
                    ++v6;
                    ++v7;
                }
                while ( v2 < v4->numInstincts );
            }
            result = 1;
        }
        else
        {
            sithConsole_PrintString("That AI block is not currently active.\n");
            result = 1;
        }
    }
    else
    {
        sithConsole_PrintString("cannot process AIStatus command.\n");
        result = 0;
    }
    return result;
#endif // SITH_DEBUG_STRUCT_NAMES
}

int sithAI_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum)
{
    SithAIControlBlock *v3; // esi
    intptr_t result; // eax
    int v5; // ebp
    unsigned int v6; // edi
    rdVector3 *v7; // ecx
    flex32_t v9; // [esp+10h] [ebp-Ch] BYREF
    flex32_t v10; // [esp+14h] [ebp-8h] BYREF
    flex32_t v11; // [esp+18h] [ebp-4h] BYREF

    v3 = pThing->actor;
    if ( adjNum == THINGPARAM_FRAME )
    {
        v6 = v3->loadedFrames;
        if ( v6 < v3->sizeFrames && _sscanf(pArg->value, "(%f/%f/%f)", &v9, &v10, &v11) == 3 )
        {
            v7 = &v3->aFrames[v6];
            v7->x = v9; // FLEXTODO
            v7->y = v10; // FLEXTODO
            v7->z = v11; // FLEXTODO
            ++v3->loadedFrames;
            return 1;
        }
        return 0;
    }
    if ( adjNum != THINGPARAM_NUMFRAMES )
        return 0;
    if ( v3->sizeFrames )
        return 0;
    v5 = _atoi(pArg->value);
    if ( !v5 )
        return 0;
    result = (intptr_t)SITH_ALLOC(sizeof(rdVector3) * v5);
    v3->aFrames = (rdVector3 *)result;
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
void sithAI_CreateAIFramesFomMarker(SithThing *pNewThing, SithThing *pMarker, rdVector3 *pivot)
{
    SithThing *v3; // esi
    SithAIControlBlock *v4; // edi
    uint32_t v5; // eax
    int v6; // ebp
    unsigned int v7; // ebx
    rdVector3 *v8; // esi
    rdVector3 *v9; // eax
    rdVector3 a1; // [esp+10h] [ebp-Ch] BYREF

    v3 = pMarker;
    v4 = pNewThing->actor;
    v4->aFrames = (rdVector3 *)SITH_ALLOC(sizeof(rdVector3) * pMarker->trackParams.sizeFrames);
    v4->sizeFrames = pMarker->trackParams.sizeFrames;
    v5 = pMarker->trackParams.loadedFrames;
    v6 = 0;
    v7 = 0;
    v4->loadedFrames = v5;
    if ( v5 )
    {
        while ( 1 )
        {
            v8 = &v3->trackParams.aFrames[v6].pos;
            rdVector_Rotate3(&a1, pivot, v8 + 1);
            v9 = &v4->aFrames[v7];
            ++v7;
            ++v6;
            rdVector_Add3(v9, v8, &a1);
            if ( v7 >= v4->loadedFrames )
                break;
            v3 = pMarker;
        }
    }
}

void sithAI_Tick(SithThing *thing, flex_t deltaSeconds)
{
    if ( thing->type == SITH_THING_ACTOR && thing->actorParams.health > 0.0 )
    {
        if (thing->actor->flags & SITHAI_MODE_TURNING)
            sithAI_sub_4EA630(thing->actor, deltaSeconds);
        if (thing->actor->flags & SITHAI_MODE_MOVING)
            sithAI_idk_msgarrived_target(thing->actor, deltaSeconds);
    }
}

void sithAI_sub_4EA630(SithAIControlBlock *actor, flex_t deltaSeconds)
{
    SithThing *v2; // esi
    rdVector3 *v3; // ebp
    rdMatrix34 *v4; // ebx
    flex_d_t v5; // st7
    flex_d_t v6; // st5
    flex_d_t v7; // st7
    flex_d_t v8; // st4
    flex_d_t v9; // st6
    rdVector3 *v10; // edi
    flex_d_t v11; // st5
    flex_d_t v12; // st5
    flex_d_t v13; // st4
    flex_d_t v14; // st7
    flex_d_t v15; // st7
    flex_d_t v16; // st6
    flex_d_t v17; // st5
    flex_d_t v18; // st7
    int v19; // eax
    rdVector3 *v20; // [esp-8h] [ebp-14h]

    v2 = actor->thing;
    v3 = &actor->goalLVec;
    v4 = &actor->thing->orient;
    v5 = stdMath_Fabs(rdVector_Dot3(&v4->rvec, &actor->goalLVec));
    if ( v5 <= 0.01 )
    {
        v10 = &v2->orient.lvec;
        if ( v2->orient.lvec.y * actor->goalLVec.y + v2->orient.lvec.x * v3->x + v2->orient.lvec.z * actor->goalLVec.z >= 0.0 )
        {
            actor->flags &= ~SITHAI_MODE_TURNING;
            return;
        }
        v11 = v2->actorParams.maxRotVelocity * 0.1 * deltaSeconds;
        v7 = v2->orient.rvec.y * v11 + v2->orient.lvec.y;
        v8 = v4->rvec.x * v11 + v10->x;
        v9 = v2->orient.rvec.z * v11 + v2->orient.lvec.z;
        v20 = &v2->orient.lvec;
    }
    else
    {
        v6 = v2->actorParams.maxRotVelocity * 0.1 * deltaSeconds;
        v7 = actor->goalLVec.y * v6 + v2->orient.lvec.y;
        v8 = v3->x * v6 + v2->orient.lvec.x;
        v9 = actor->goalLVec.z * v6 + v2->orient.lvec.z;
        v10 = &v2->orient.lvec;
        v20 = &v2->orient.lvec;
    }
    v10->x = v8;
    v2->orient.lvec.y = v7;
    v2->orient.lvec.z = v9;
    if ( rdVector_Normalize3Acc(v20) < 0.01 )
        rdVector_Normalize3(v10, v3);
    v12 = v2->orient.lvec.z;
    v13 = v10->x;
    v14 = v2->orient.lvec.y;
    v4->rvec.x = v14 * 1.0 - v12 * 0.0;
    v2->orient.rvec.y = v12 * 0.0 - v13 * 1.0;
    v2->orient.rvec.z = v13 * 0.0 - v14 * 0.0;
    rdVector_Normalize3Acc(&v4->rvec);
    v15 = v10->x * v2->orient.rvec.z;
    v2->orient.uvec.x = v2->orient.lvec.z * v2->orient.rvec.y - v2->orient.lvec.y * v2->orient.rvec.z;
    v16 = v2->orient.lvec.y * v4->rvec.x;
    v17 = v15 - v2->orient.lvec.z * v4->rvec.x;
    v18 = v10->x * v2->orient.rvec.y;
    v2->orient.uvec.y = v17;
    v2->orient.uvec.z = v16 - v18;
}

// MoTS altered
void sithAI_idk_msgarrived_target(SithAIControlBlock *actor, flex_t deltaSeconds)
{
    SithThing *v3; // esi
    flex_d_t v9; // st7
    flex_d_t v10; // st5
    flex_d_t v11; // st6
    flex_d_t v13; // st7
    SithSector *v18; // eax
    int v19; // eax
    flex_t v20; // [esp+10h] [ebp-20h]
    flex_t v21; // [esp+14h] [ebp-1Ch]
    rdVector3 a4; // [esp+18h] [ebp-18h] BYREF
    flex_t actorb; // [esp+34h] [ebp+4h]

    // MoTS Added: SITH_AF_FREEZE_MOVEMENT
    v3 = actor->thing;
    if ( (actor->flags & SITHAI_MODE_SLEEPING) == 0 && (v3->actorParams.flags & SITH_AF_COMBO_FREEZE) == 0 )
    {
        rdVector3 tmp;
        actorb = v3->actorParams.maxThrust * deltaSeconds * actor->moveSpeed;
        rdVector_Sub3(&actor->moveDirection, &actor->movePos, &v3->position);
        v9 = rdVector_Normalize3Acc(&actor->moveDirection);
        rdVector_Scale3(&tmp, &actor->moveDirection, actorb);
        actor->moveDistance = v9;
        if ( (v3->sector->flags & SITH_SECTOR_UNDERWATER) == 0 && (v3->physicsParams.flags & SITH_PF_FLY) == 0 )
            tmp.z = 0.0;
        rdVector_Add3Acc(&tmp, &v3->physicsParams.vel);
        rdVector_Copy3(&v3->physicsParams.vel, &tmp);
        if ( (actor->flags & SITHAI_MODE_NOCHECKFORCLIFF) == 0 && v3->attach_flags )
        {
            if ( (v3->physicsParams.flags & SITH_PF_FLY) != 0 )
            {
LABEL_15:
                if ( (v3->actorParams.flags & SITH_AF_BREATHEUNDERWATER) == 0 )
                {
                    if ( (v3->flags & SITH_TF_WATER) != 0 )
                    {
                        rdVector_Zero3(&v3->physicsParams.vel);
                    }
                    else
                    {
                        rdVector_Copy3(&a4, &v3->position);
                        rdVector_ScaleAdd3Acc(&a4, &v3->physicsParams.vel, deltaSeconds);
                        v18 = sithCollision_FindSectorInRadius(v3->sector, &v3->position, &a4, 0.0);
                        if ( !v18 || (v18->flags & SITH_SECTOR_UNDERWATER) == 0 )
                            goto LABEL_22;
                        rdVector_Zero3(&v3->physicsParams.vel);
                    }
                    v3->physicsParams.vel.z = v3->physicsParams.vel.z - (-0.5);
                }
LABEL_22:
                if ( actor->moveDistance <= (flex_d_t)v3->moveSize )
                {
                    rdVector_Zero3(&v3->physicsParams.vel);
                    actor->flags &= ~SITHAI_MODE_MOVING;
                    sithSoundClass_StopMode(v3, SITH_SC_MOVING);
                    sithCog_ThingSendMessage(v3, 0, SITH_MESSAGE_ARRIVED);
                    sithAI_EmitEvent(actor, SITHAI_MODE_FLEEING, 0);
                }
                return;
            }
            if (!rdVector_IsZero3(&tmp))
            {
                rdVector_Copy3(&a4, &v3->position);
                rdVector_ScaleAdd3Acc(&a4, &v3->physicsParams.vel, deltaSeconds);
                if ( !sithAI_CanWalk(actor, &a4, 0) )
                {
                    rdVector_Zero3(&v3->physicsParams.vel);
                    sithAI_EmitEvent(actor, SITHAI_MODE_TARGETVISIBLE, 0);
                    return;
                }
                goto LABEL_22;
            }
        }
        if ( (v3->physicsParams.flags & SITH_PF_FLY) == 0 )
            goto LABEL_22;
        goto LABEL_15;
    }
}

void sithAI_SetLookFrame(SithAIControlBlock *actor, rdVector3 *lookPos)
{
    SithActorInfo *v5; // edi
    flex_d_t v6; // st7
    rdVector3 a2a; // [esp+Ch] [ebp-Ch] BYREF

    rdVector_Sub3(&actor->goalLVec, lookPos, &actor->thing->position);
    v5 = &actor->thing->actorParams;
    if ( rdVector_Normalize3Acc(&actor->goalLVec) != 0.0 )
    {
        if ( (v5->flags & SITH_AF_CANROTATEHEAD) != 0 )
        {
            v6 = stdMath_ArcSin3(actor->goalLVec.z);
            if ( v6 < v5->minHeadPitch )
            {
                v6 = v5->minHeadPitch;
            }
            else if ( v6 > v5->maxHeadPitch )
            {
                v6 = v5->maxHeadPitch;
            }
            if ( v6 != v5->headPYR.x )
            {
                a2a.x = v6;
                a2a.y = v5->headPYR.y;
                a2a.z = v5->headPYR.z;
                sithActor_SetHeadPYR(actor->thing, &a2a);
            }
        }
        actor->goalLVec.z = 0.0;
        rdVector_Normalize3Acc(&actor->goalLVec);
        actor->flags |= SITHAI_MODE_TURNING;
    }
}

void sithAI_SetMoveThing(SithAIControlBlock *actor, rdVector3 *movePos, flex_t moveSpeed)
{
    if ( sithTime_g_msecGameTime >= actor->field_28C || (actor->flags & SITHAI_MODE_MOVING) == 0 )
    {
        actor->moveSpeed = moveSpeed;
        rdVector_Copy3(&actor->movePos, movePos);
        sithSoundClass_PlayModeFirst(actor->thing, SITH_SC_MOVING);
        actor->flags |= SITHAI_MODE_MOVING;
    }
}

void sithAI_Jump(SithAIControlBlock *actor, rdVector3 *pos, flex_t vel)
{
    actor->moveSpeed = 2.0;
    rdVector_Copy3(&actor->movePos, pos);

    if ( sithPuppet_PlayMode(actor->thing, SITH_ANIM_JUMP, 0) < 0 )
        sithPlayerActions_JumpWithVel(actor->thing, vel);

    actor->field_28C = sithTime_g_msecGameTime + 2000;
    actor->flags |= SITHAI_MODE_MOVING;
}

void sithAI_sub_4EAD60(SithAIControlBlock *actor)
{
    SithThing *v2; // edi
    SithThing *v3; // eax
    SithThing *v4; // eax
    int v5; // eax
    int v6; // eax
    int v9; // [esp+10h] [ebp-4h]
    flex_t actora; // [esp+18h] [ebp+4h]

    v2 = actor->thing;
    v9 = actor->field_1F4;
    if ( actor->field_1E0 == jkPlayer_currentTickIdx )
        return;

    actor->field_1E0 = jkPlayer_currentTickIdx;
    v3 = v2->actorParams.pWeaponTemplate;
    if ( v3 )
        actora = v3->moveSize;
    else
        actora = 0.0;
    rdMatrix_TransformVector34(&actor->blindAimError, &v2->actorParams.fireOffset, &v2->orient);
    v4 = actor->pDistractor;
    rdVector_Add3Acc(&actor->blindAimError, &v2->position);
    if ( v4 )
    {
        if ( (v4->actorParams.flags & SITH_AF_INVISIBLE) || (actor->thing->actorParams.flags & SITH_AF_COMBO_BLIND) != 0 )
            v9 = 3;
        actor->field_1D4 = v4->position;
        v5 = sithAI_CheckSightThing(v2, &actor->blindAimError, v4, actor->pClass->fov, actor->pClass->sightDistance, actora, &actor->attackError, &actor->attackDistance);
        actor->field_1F4 = v5;

        if ( !v5 )
        {
            if ( !v9 || sithAI_CanDetectSightThing(actor, actor->pDistractor, actor->attackDistance) )
            {
                actor->field_1F8 = actor->pDistractor->position;
                actor->field_204 = sithTime_g_msecGameTime;
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
                 actor->pClass->fov,
                 actor->pClass->sightDistance,
                 actora,
                 &actor->attackError,
                 &actor->attackDistance);
        actor->field_1F4 = v6;
        if ( !v6 )
        {
            rdVector_Copy3(&actor->field_1F8, &actor->field_1D4);
            actor->field_204 = sithTime_g_msecGameTime;
        }
    }
}

void sithAI_sub_4EAF40(SithAIControlBlock *actor)
{
    int v1; // ebx
    int v3; // eax
    int v4; // eax

    v1 = actor->field_238;
    if ( actor->field_224 != jkPlayer_currentTickIdx )
    {
        actor->field_224 = jkPlayer_currentTickIdx;
        if ( actor->pMoveThing )
        {
            if ( (actor->pMoveThing->actorParams.flags & SITH_AF_INVISIBLE) || (actor->thing->actorParams.flags & SITH_AF_COMBO_BLIND) != 0 )
                v1 = 3;
            v3 = sithAI_CheckSightThing(actor->thing, &actor->thing->position, actor->pMoveThing, -1.0, actor->pClass->sightDistance, 0.0, &actor->field_228, &actor->targetDistance);
            actor->field_238 = v3;
            if ( !v3 )
            {
                if ( !v1 || sithAI_CanDetectSightThing(actor, actor->pMoveThing, actor->targetDistance) )
                {
                    actor->field_23C = actor->pMoveThing->position;
                    actor->field_248 = sithTime_g_msecGameTime;
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
                     actor->pClass->sightDistance,
                     0.0,
                     &actor->field_228,
                     &actor->targetDistance);
            actor->field_238 = v4;
            if ( !v4 )
            {
                rdVector_Copy3(&actor->field_23C, &actor->movepos);
                actor->field_248 = sithTime_g_msecGameTime;
            }
        }
    }
}

// MoTS altered
int sithAI_CheckSightThing(SithThing *thing, rdVector3 *targetPosition, SithThing *targetThing, flex_t fov, flex_t maxDistance, flex_t unused, rdVector3 *targetErrorDir, flex_t *targetDistance)
{
    flex_d_t v12; // st7
    flex_d_t v18; // st7
    SithSector *v21; // eax
    SithCollision *v22; // esi
    SithThing *v23; // eax
    flex_t a4a; // [esp+18h] [ebp+8h]
    flex_t a5a; // [esp+2Ch] [ebp+1Ch]

    rdVector_Sub3(targetErrorDir, &targetThing->position, targetPosition);
    v12 = rdVector_Normalize3Acc(targetErrorDir) - targetThing->collideSize;
    *targetDistance = v12;
 
    if ( v12 <= 0.0 )
        v12 = 0.0;

    *targetDistance = v12;
    if ( !(thing->flags & SITH_TF_WATER) && (targetThing->flags & SITH_TF_WATER))
    {
        if ( targetThing->moveType != SITH_MT_PHYSICS )
            return 3;
        if ( (targetThing->physicsParams.flags & SITH_PF_ONWATERSURFACE) == 0 )
            return 3;
    }
    if ( (thing->flags & SITH_TF_WATER) && !(targetThing->flags & SITH_TF_WATER))
        return 3;
    if ( v12 - targetThing->collideSize > maxDistance )
        return 1;
    if ( fov > -1.0 )
    {
        v18 = rdVector_Dot3(&thing->orient.rvec, targetErrorDir);
        a5a = rdVector_Dot3(&thing->orient.lvec, targetErrorDir);

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

    v21 = sithCollision_FindSectorInRadius(thing->sector, &thing->position, targetPosition, 0.0);
    sithCollision_SearchForCollisions(v21, thing, targetPosition, targetErrorDir, *targetDistance, 0.0, RAYCAST_100 | RAYCAST_2);
    v22 = sithCollision_PopStack();
    if ( v22 )
    {
        while ( (v22->type & SITHCOLLISION_THING) != 0 )
        {
            v23 = v22->pThingCollided;
            if ( v23 != targetThing )
            {
                if ( v23->type == SITH_THING_ACTOR || v23->type == SITH_THING_COG )
                    break;
                v22 = sithCollision_PopStack();
                if ( v22 )
                    continue;
            }
            sithCollision_DecreaseStackLevel();
            return 0;
        }
    }
    sithCollision_DecreaseStackLevel();
    return v22 != 0 ? 3 : 0;
}

// MOTS altered
int sithAI_sub_4EB300(SithThing *a3, rdVector3 *a4, rdVector3 *arg8, flex_t argC, flex_t arg10, flex_t a7, rdVector3 *a5, flex_t *a8)
{
    flex_t v11; // st7
    flex_d_t v16; // st7
    SithSector *v19; // eax
    SithCollision *v20; // esi
    flex_t a4a; // [esp+18h] [ebp+8h]
    flex_t arg8a; // [esp+1Ch] [ebp+Ch]
 
    rdVector_Sub3(a5, arg8, a4);
    v11 = rdVector_Normalize3Acc(a5);
    *a8 = v11;

    if ( v11 > arg10 )
        return 1;

    if ( argC > -1.0 )
    {
        v16 = rdVector_Dot3(&a3->orient.rvec, a5);
        a4a = rdVector_Dot3(&a3->orient.lvec, a5);

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

    v19 = sithCollision_FindSectorInRadius(a3->sector, &a3->position, a4, 0.0);
    sithCollision_SearchForCollisions(v19, a3, a4, a5, *a8, a7, RAYCAST_2000 | RAYCAST_100 | RAYCAST_2);
    v20 = sithCollision_PopStack();
    sithCollision_DecreaseStackLevel();
    return v20 != 0 ? 3 : 0;
}

// TODO this one has some inlined funcs
int sithAI_CanWalk(SithAIControlBlock *actor, rdVector3 *targetPosition, int *out)
{
    SithThing *actorThing; // esi
    intptr_t result; // eax
    SithSector *v6; // edi
    SithCollision *colSearchEntry; // eax
    SithSurface *searchSurface; // ecx
    SithThing *searchThing; // eax
    flex_t searchDist; // [esp+0h] [ebp-2Ch]
    int v12; // [esp+1Ch] [ebp-10h]
    rdVector3 moveNorm; // [esp+20h] [ebp-Ch] BYREF
    flex_t searchRadius; // [esp+30h] [ebp+4h]

    actorThing = actor->thing;
    rdVector_Neg3(&moveNorm, &rdroid_zVector3);
    searchRadius = actorThing->moveSize * 0.25;
    v12 = 0;
    result = (intptr_t)sithCollision_FindSectorInRadius(actorThing->sector, &actorThing->position, targetPosition, 0.0);
    v6 = (SithSector *)result;
    if ( !result )
        return result;
    searchDist = sithPhysics_GetThingHeight(actorThing) + actor->pClass->maxStep;
    sithCollision_SearchForCollisions(v6, actorThing, targetPosition, &moveNorm, searchDist, searchRadius, RAYCAST_2000 | RAYCAST_2);
    colSearchEntry = sithCollision_PopStack();
    if ( !colSearchEntry )
        goto LABEL_20;
    while (!(colSearchEntry->type & SITHCOLLISION_WORLD))
    {
        if (colSearchEntry->type & SITHCOLLISION_THING)
        {
            searchThing = colSearchEntry->pThingCollided;
            if (searchThing->flags & SITH_TF_STANDABLE)
            {
                v12 = 1;
                if ( out )
                {
                    if ((actorThing->attach_flags & SITH_ATTACH_THINGFACE) && actorThing->attachedThing == searchThing )
                    {
                        *out = 0;
                        sithCollision_DecreaseStackLevel();
                        return 1;
                    }
                    *out = 1;
                }
LABEL_20:
                sithCollision_DecreaseStackLevel();
                return v12;
            }
LABEL_8:
            sithCollision_DecreaseStackLevel();
            return 0;
        }
        colSearchEntry = sithCollision_PopStack();
        if ( !colSearchEntry )
            goto LABEL_20;
    }
    searchSurface = colSearchEntry->surface;
    if ( (searchSurface->flags & SITH_SURFACE_AI_CAN_WALK_ON_FLOOR) != 0 )
        goto LABEL_8;
    v12 = 2 - ((searchSurface->flags & SITH_SURFACE_FLOOR) != 0);
    if ( !out )
        goto LABEL_20;
    if ( (actorThing->attach_flags & SITH_ATTACH_SURFACE) && actorThing->attachedSurface == searchSurface )
    {
        *out = 0;
        sithCollision_DecreaseStackLevel();
        result = v12;
    }
    else
    {
        *out = 1;
        sithCollision_DecreaseStackLevel();
        result = v12;
    }
    return result;
}

int sithAI_CanWalk_ExplicitSector(SithAIControlBlock *actor, rdVector3 *targetPosition, SithSector *targetSector, int *out)
{
    SithThing *actorThing; // edi
    int retval; // ebx
    SithCollision *colSearchEntry; // eax
    SithSurface *searchSurface; // ecx
    int result; // eax
    SithThing *searchThing; // eax
    flex_t searchDist; // [esp+0h] [ebp-24h]
    flex_t searchRadius; // [esp+4h] [ebp-20h]
    rdVector3 moveNorm; // [esp+18h] [ebp-Ch] BYREF

    actorThing = actor->thing;
    rdVector_Neg3(&moveNorm, &rdroid_zVector3);
    retval = 0;
    searchRadius = actorThing->moveSize * 0.25;
    searchDist = sithPhysics_GetThingHeight(actorThing) + actor->pClass->maxStep;
    sithCollision_SearchForCollisions(targetSector, actorThing, targetPosition, &moveNorm, searchDist, searchRadius, RAYCAST_2000 | RAYCAST_2);
    colSearchEntry = sithCollision_PopStack();
    if ( colSearchEntry )
    {
        while ( 1 )
        {
            if ( (colSearchEntry->type & SITHCOLLISION_WORLD) != 0 )
            {
                searchSurface = colSearchEntry->surface;
                if ( (searchSurface->flags & SITH_SURFACE_AI_CAN_WALK_ON_FLOOR) != 0 )
                    goto LABEL_13;
                retval = 2 - ((searchSurface->flags & SITH_SURFACE_FLOOR) != 0);
                if ( !out )
                    goto LABEL_19;
                if ( (actorThing->attach_flags & SITH_ATTACH_SURFACE) != 0 && actorThing->attachedSurface == searchSurface )
                {
                    *out = 0;
                    sithCollision_DecreaseStackLevel();
                    result = retval;
                }
                else
                {
                    *out = 1;
                    sithCollision_DecreaseStackLevel();
                    result = retval;
                }
                return result;
            }
            if ( (colSearchEntry->type & SITHCOLLISION_THING) != 0 )
                break;
            colSearchEntry = sithCollision_PopStack();
            if ( !colSearchEntry )
                goto LABEL_13;
        }
        searchThing = colSearchEntry->pThingCollided;
        if ( (searchThing->flags & SITH_TF_STANDABLE) == 0 )
        {
LABEL_13:
            sithCollision_DecreaseStackLevel();
            return 0;
        }
        retval = 1;
        if ( out )
        {
            if ( (actorThing->attach_flags & SITH_ATTACH_THINGFACE) != 0 && actorThing->attachedThing == searchThing )
            {
                *out = 0;
                sithCollision_DecreaseStackLevel();
                return 1;
            }
            *out = 1;
        }
    }
LABEL_19:
    sithCollision_DecreaseStackLevel();
    return retval;
}

int sithAI_FirstThingInView(SithSector *sector, rdMatrix34 *out, flex_t autoaimFov, flex_t autoaimMaxDist, int a5, SithThing **thingList, int a7, flex_t a8)
{
    if ( autoaimFov < 0.0 || autoaimMaxDist < 0.0 )
        return 0;
    sithAI_dword_84DE74 = a7;
    sithAI_dword_84DE6C = a5;
    sithAI_flt_84DE70 = a8;
    sithAI_pThing_84DE68 = thingList;
    stdMath_SinCos(90.0 - autoaimFov * 0.5, &autoaimFov, &sithAI_flt_84DE64);
    stdMath_SinCos(90.0 - autoaimMaxDist * 0.5, &autoaimFov, &sithAI_flt_84DE58);
    sithAdvanceRenderTick();
    sithAI_dword_84DE60 = 0;
    sithAI_dword_84DE5C = 0;
    sithAI_GetThingsInView(sector, out, 0.0);
    return sithAI_dword_84DE60;
}

int sithAI_sub_4EB860(int a1, flex_t a2)
{
    if ( a2 > 0.0 )
        sithAdvanceRenderTick();
    return 0;
}

void sithAI_SetRandomThingLook(rdMatrix34 *a1, SithThing *a2, rdVector3 *a3, flex_t a4)
{
    rdVector3 rot; // [esp+4h] [ebp-Ch] BYREF
    flex_t v2; // [esp+1Ch] [ebp+Ch]

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

MATH_FUNC void sithAI_RandomFireVector(rdVector3 *out, flex_t magnitude)
{
    out->x = ((flex_d_t)_frand() - 0.5) * magnitude + out->x;
    out->y = ((flex_d_t)_frand() - 0.5) * magnitude + out->y;
    out->z = ((flex_d_t)_frand() - 0.5) * magnitude + out->z;
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
int sithAI_FireWeapon(SithAIControlBlock *actor, flex_t minDistToFire, flex_t maxDistToFire, flex_t minDot, flex_t percentageErrorInAim, int bAltFire, int a7)
{
    SithThing *v8; // ebp
    SithThing *v9; // edi
    SithThing *v11; // ecx
    flex_d_t v14; // rt2
    int16_t v15; // bx
    SithThing *v16; // eax
    flex_d_t v19; // st7
    signed int v20; // [esp+10h] [ebp-20h]
    flex_t v21; // [esp+14h] [ebp-1Ch]
    rdVector3 v1; // [esp+18h] [ebp-18h] BYREF
    rdVector3 a1a; // [esp+24h] [ebp-Ch] BYREF

    v8 = 0;
    v9 = actor->thing;
    v21 = 1.0;
    v20 = 0;
    if (g_debugmodeFlags & DEBUGFLAG_NO_AI) {
        return 0;
    }
    if (v9->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) {
        return 0;
    }
    // Bail when underwater and unable to shoot underwater
    if (v9->sector // Added: thing->sector null check
        && (v9->sector->flags & SITH_SECTOR_UNDERWATER)
        && (v9->actorParams.flags & SITH_AF_NOUNDERWATERFIRE))
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
        v8 = v9->actorParams.pWeaponTemplate;
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
    if ( actor->field_288 > sithTime_g_msecGameTime || actor->field_1F4 )
        return 0;
    if ( actor->attackDistance < (flex_d_t)minDistToFire || actor->attackDistance > (flex_d_t)maxDistToFire )
        return 0;

    // MoTS added
    if (Main_bMotsCompat && (minDot > 0.0 && rdVector_Dot3(&v9->orient.lvec, &v1) < 0.0)) {
        return 0;
    }

    v19 = stdMath_Fabs(rdVector_Dot3(&v9->orient.rvec, &v1));
    if ( v19 > 1.0 - minDot )
        return 0;
    
    if ( (v9->actorParams.flags & SITH_AF_DELAYFIRE) != 0 )
    {
        actor->field_268 = a7 | 8;
        actor->field_264 = percentageErrorInAim;
        actor->field_26C = bAltFire;
        sithPuppet_PlayMode(v9, v20, 0);

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SyncThing(actor->thing, THING_SYNC_PUPPET);
        }
        return 1;
    }
LABEL_12:
    if ( (a7 & 1) != 0 )
    {
        v11 = actor->pDistractor;
        // Added: nullptr check
        if ( v11 && v11->moveType == SITH_MT_PHYSICS
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
        flex_d_t yvel = 0.00001;
        // Added: div 0 fix
        if (v8->physicsParams.vel.y != 0.0) {
            yvel = v8->physicsParams.vel.y;
        }

        v14 = actor->attackDistance / yvel * 0.5;
        rdVector_Scale3(&a1a, &actor->attackError, v8->physicsParams.vel.y);
        a1a.z = v14 * sithWorld_g_pCurrentWorld->gravity + a1a.z;
        v15 = 1;
        v21 = rdVector_Normalize3(&v1, &a1a) / yvel;
    }
    else
    {
        v15 = 0;
    }
    if ( percentageErrorInAim != 0.0 && actor->attackDistance != 0.0 && _frand() > actor->pClass->accurancy )
    {
        sithAI_RandomFireVector(&v1, percentageErrorInAim);
    }
    sithSoundClass_PlayModeRandom(v9, bAltFire + SITH_SC_FIRE1);
    v16 = sithWeapon_WeaponFire(v9, v8, &v1, &actor->blindAimError, 0, v20, v21, v15, 0.0);
    if ( v16 )
        sithCog_ThingSendMessage(v9, v16, SITH_MESSAGE_FIRE);
    return 1;
}

void sithAI_GetThingsInView(SithSector *a1, rdMatrix34 *a2, flex_t a3)
{
    SithThing *v4; // esi
    unsigned int v6; // eax
    SithSurfaceAdjoin *v7; // esi
    rdTexinfo *v8; // ebp
    rdMaterial *v9; // ecx
    uint32_t v10; // edx
    flex_t a3a; // [esp+0h] [ebp-48h]
    flex_t v12; // [esp+14h] [ebp-34h]
    rdVector3 v13; // [esp+18h] [ebp-30h] BYREF
    rdVector3 a1a; // [esp+24h] [ebp-24h] BYREF
    rdVector3 v1; // [esp+30h] [ebp-18h] BYREF
    rdVector3 v16; // [esp+3Ch] [ebp-Ch] BYREF
    flex_t v17; // [esp+4Ch] [ebp+4h]
    flex_t a2a; // [esp+50h] [ebp+8h]

    if ( a1->renderTick == sithRender_lastRenderTick )
        return;

    a1->renderTick = sithRender_lastRenderTick;
    if (sithAI_dword_84DE5C >= 0x80)
        return;

    v4 = a1->pFirstThingInSector;
    ++sithAI_dword_84DE5C;
    if ( v4 )
    {
        v6 = sithAI_dword_84DE60;
        do
        {
            if ( v6 >= sithAI_dword_84DE6C )
                break;
            if ( ((1 << v4->type) & sithAI_dword_84DE74) != 0 && (v4->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
            {
                rdVector_Sub3(&v13, &v4->position, &a2->scale);
                rdVector_Normalize3Acc(&v13);
                rdVector_Normalize3(&a1a, &a2->uvec);
                rdVector_Normalize3(&v1, &a2->rvec);
                rdVector_Normalize3(&v16, &a2->lvec);
                v17 = rdVector_Dot3(&a1a, &v13);
                a2a = rdVector_Dot3(&v1, &v13);
                if ( v17 > (flex_d_t)sithAI_flt_84DE58
                  || v17 < -sithAI_flt_84DE58
                  || a2a > (flex_d_t)sithAI_flt_84DE64
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
            v4 = v4->pNextThingInSector;
        }
        while ( v4 );
    }
    if ( a3 <= (flex_d_t)sithAI_flt_84DE70 )
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
                        v10 = v9->curCelNum;
                    v8 = v9->texinfos[v10];
                }
                if ( (v7->flags & 1) != 0
                  && (!v9
                   || !v7->surface->surfaceInfo.face.geometryMode
                   || (v7->surface->surfaceInfo.face.type & 2)
                   || (v8 && v8->texture_ptr && (v8->texture_ptr->alpha_en & 1) != 0)) // Added: searchSurface nullptr check, v8->texture_ptr nullptr check
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
int sithAI_CanDetectSightThing(SithAIControlBlock *actor, SithThing *targetThing, flex_t distance)
{
    SithThing *actorThing; // esi
    flex_d_t clampedDistance; // st7
    SithSector *targetSector; // edx
    int result; // eax
    flex_t awareness; // [esp+0h] [ebp-4h]

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
        if (!(targetThing->actorParams.flags & SITH_AF_HEADLIGHT) && (targetThing->jkFlags & 1) == 0 )
        {
            clampedDistance = stdMath_Clamp((distance - 2.0) * 0.1, 0.0, 0.6);
            awareness = (1.0 - clampedDistance) * awareness;
            if (!(actorThing->actorParams.flags & SITH_AF_SEEINDARK))
            {
                targetSector = targetThing->sector;
                if ( targetSector->ambientLight < 0.5 )
                    awareness = (targetSector->ambientLight - -0.2) * awareness;
            }
            if ( targetThing->moveType == SITH_MT_PHYSICS )
            {
                if (targetThing->physicsParams.flags & SITH_PF_CROUCHING)
                    awareness = awareness * 0.75;
                if (rdVector_IsZero3(&targetThing->physicsParams.vel))
                    awareness = awareness * 0.5;
            }
        }
    }
    if (targetThing->actorParams.flags & SITH_AF_INVISIBLE
        && !(actorThing->actorParams.flags & SITH_AF_SEEINVISIBLE)) {
        awareness = awareness * 0.05;
    }
    if (actorThing->actorParams.flags & SITH_AF_COMBO_BLIND) {
        awareness = awareness * 0.05;
    }
    awareness = stdMath_Clamp(awareness, 0.05, 1.0);
    if ( _frand() >= awareness )
        return 0;
    else
        return 1;
}

// MOTS added
void sithAI_SetDistractor(SithThing *pDistractor)
{
    SithAIControlBlock *ppsVar1;
    SithThing **ppsVar2;
    SithThing *pPlayer;

    pPlayer = sithPlayer_g_pLocalPlayerThing;
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
void sithAI_AddAlignmentPriority(flex_t param_1)
{
    sithAI_FLOAT_005a79d8 = param_1;
}

void sithAI_GetThingsInCone(SithSector *a1, rdMatrix34 *a2, flex_t a3)
{
    SithThing *v4; // esi
    SithSurfaceAdjoin *v7; // esi
    rdTexinfo *v8; // ebp
    rdMaterial *v9; // ecx
    uint32_t v10; // edx
    flex_t a3a; // [esp+0h] [ebp-48h]
    flex_t v12; // [esp+14h] [ebp-34h]
    rdVector3 v13; // [esp+18h] [ebp-30h] BYREF
    rdVector3 a1a; // [esp+24h] [ebp-24h] BYREF
    rdVector3 v1; // [esp+30h] [ebp-18h] BYREF
    rdVector3 v16; // [esp+3Ch] [ebp-Ch] BYREF
    flex_t v17; // [esp+4Ch] [ebp+4h]
    flex_t a2a; // [esp+50h] [ebp+8h]
    flex_t local_190[100];

    // Added: prevent overflow
    if (sithAI_dword_84DE6C > 100) {
        sithAI_dword_84DE6C = 100;
    }

    for (int iterIdx = sithWorld_g_pCurrentWorld->numThings; iterIdx >= 0; iterIdx--)
    {
        v4 = &sithWorld_g_pCurrentWorld->aThings[iterIdx];
        if ( sithAI_dword_84DE60 >= (unsigned int)sithAI_dword_84DE6C )
            break;
        if ( ((1 << v4->type) & sithAI_dword_84DE74) != 0 && (v4->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
        {
            rdVector_Sub3(&v13, &v4->position, &a2->scale);
            flex_t dist = rdVector_Normalize3Acc(&v13);
            rdVector_Normalize3(&a1a, &a2->uvec);
            rdVector_Normalize3(&v1, &a2->rvec);
            rdVector_Normalize3(&v16, &a2->lvec);
            v17 = rdVector_Dot3(&a1a, &v13);
            a2a = rdVector_Dot3(&v1, &v13);
            if ( dist > (flex_d_t)sithAI_flt_84DE70
              || v17 > (flex_d_t)sithAI_flt_84DE58
              || v17 < -sithAI_flt_84DE58
              || a2a > (flex_d_t)sithAI_flt_84DE64
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
                flex_t val_a_1 = local_190[j];
                SithThing* val_a_2 = sithAI_pThing_84DE68[j];

                flex_t val_b_1 = local_190[j+1];
                SithThing* val_b_2 = sithAI_pThing_84DE68[j+1];

                local_190[j] = val_b_1;
                sithAI_pThing_84DE68[j] = val_b_2;

                local_190[j+1] = val_a_1;
                sithAI_pThing_84DE68[j+1] = val_a_2;
            }
        }
    }
}

// MOTS added
int sithAI_FirstThingInCone(SithSector *sector, rdMatrix34 *out, flex_t autoaimFov, flex_t autoaimMaxDist, int a5, SithThing **thingList, int a7, flex_t a8)
{
    if ( autoaimFov < 0.0 || autoaimMaxDist < 0.0 )
        return 0;
    sithAI_dword_84DE74 = a7;
    sithAI_dword_84DE6C = a5;
    sithAI_flt_84DE70 = a8;
    sithAI_pThing_84DE68 = thingList;
    stdMath_SinCos(90.0 - autoaimFov * 0.5, &autoaimFov, &sithAI_flt_84DE64);
    stdMath_SinCos(90.0 - autoaimMaxDist * 0.5, &autoaimFov, &sithAI_flt_84DE58);
    sithAdvanceRenderTick();
    sithAI_dword_84DE60 = 0;
    sithAI_dword_84DE5C = 0;
    sithAI_GetThingsInCone(sector, out, 0.0); // TODO: Did they actually change this?
    return sithAI_dword_84DE60;
}

// MOTS added
int sithAI_Charge(SithAIControlBlock *pActor,flex_t param_2,flex_t param_3,flex_t param_4,int param_5,
                       flex_t param_6,uint32_t param_7)
{
    SithThing *thing;
    SithThing *pDistractorThing;
    SithThing *pActorThing;
    flex_t fVar3;
    flex_t fVar4;
    flex_t xDist;
    int bVar6;
    int anim;

    anim = 0;
    thing = pActor->thing;

    if (g_debugmodeFlags & DEBUGFLAG_NO_AI) {
        return 0;
    }
    if (thing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) {
        return 0;
    }
    // Bail when underwater and unable to shoot underwater
    if (thing->sector // Added: thing->sector null check
        && (thing->sector->flags & SITH_SECTOR_UNDERWATER)
        && (thing->actorParams.flags & SITH_AF_NOUNDERWATERFIRE))
    {
        return 0;
    }

    if ((param_5 == 0) || (param_5 == 1)) {
        anim = SITH_ANIM_CHARGE;
    }
    sithAI_sub_4EAD60(pActor);
    if ((param_7 & 8) != 0) {
LAB_0053a691:
        pDistractorThing = pActor->pDistractor;
        pActorThing = pActor->thing;
        
        xDist = (pDistractorThing->position).x - (pActorThing->position).x;
        fVar3 = (pDistractorThing->position).y - (pActorThing->position).y;
        fVar4 = (pDistractorThing->position).z - (pActorThing->position).z;

        pActor->field_28C = sithTime_g_msecGameTime + 2000;
        pActor->moveSpeed = 1313.0;
        pActor->flags &= ~(SITHAI_MODE_TURNING | SITHAI_MODE_MOVING);
        pActor->attackError.x = xDist;
        thing->physicsParams.vel.x = param_6 * xDist;
        thing->physicsParams.vel.y = param_6 * fVar3;
        pActor->attackError.y = fVar3;
        pActor->attackError.z = fVar4;
        pActor->attackDistance = stdMath_Sqrt(fVar4 * fVar4 + fVar3 * fVar3 + xDist * xDist);
        thing->physicsParams.vel.z = param_6 * fVar4;
        return 1;
    }
    if (((uint32_t)pActor->field_288 <= sithTime_g_msecGameTime) &&
            (pActor->field_1F4 == 0)) {
        if ((pActor->attackDistance < param_2) || (pActor->attackDistance > param_3)) {
            bVar6 = 0;
        }
        else {
            bVar6 = 1;
        }
        if (bVar6) {
            fVar3 = (thing->orient).rvec.z * (pActor->attackError).z +
                    (thing->orient).rvec.y * (pActor->attackError).y +
                    (thing->orient).rvec.x * (pActor->attackError).x;
            if (fVar3 < 0.0) {
                fVar3 = -fVar3;
            }
            if (fVar3 <= 1.0 - param_4) {
                if ((thing->actorParams.flags & SITH_AF_DELAYFIRE) != 0) {
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
int sithAI_Leap(SithAIControlBlock *pActor,flex_t minDist,flex_t maxDist,flex_t minDot,int param_5,
                       flex_t leapSpeed,uint32_t param_7)
{
    flex_t fVar1;
    SithThing *thing;
    SithThing *pDistractorThing;
    SithThing *pActorThing;
    int bVar4;
    int anim;
    flex_d_t xDist;
    flex_d_t fVar7;
    flex_d_t fVar8;
    flex_d_t fVar9;
    flex_d_t fVar10;
    int64_t lVar11;

    anim = 0;
    thing = pActor->thing;
    
    if (g_debugmodeFlags & DEBUGFLAG_NO_AI) {
        return 0;
    }
    if (thing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) {
        return 0;
    }
    // Bail when underwater and unable to shoot underwater
    if (thing->sector // Added: thing->sector null check
        && (thing->sector->flags & SITH_SECTOR_UNDERWATER)
        && (thing->actorParams.flags & SITH_AF_NOUNDERWATERFIRE))
    {
        return 0;
    }

    if ((param_5 == 0) || (param_5 == 1)) {
        anim = SITH_ANIM_JUMP;
    }
    sithAI_sub_4EAD60(pActor);
    if ((param_7 & 8) != 0) 
    {
LAB_0053a3b9:
        pDistractorThing = pActor->pDistractor;
        pActorThing = pActor->thing;
        
        xDist = (flex_d_t)(pDistractorThing->position).x - (flex_d_t)(pActorThing->position).x;
        fVar7 = (flex_d_t)(pDistractorThing->position).y - (flex_d_t)(pActorThing->position).y;
        fVar8 = (flex_d_t)(pDistractorThing->position).z - (flex_d_t)(pActorThing->position).z;
        
        fVar9 = stdMath_Sqrt(fVar8 * (flex_d_t)(flex_t)fVar8 + fVar7 * fVar7 + xDist * (flex_d_t)(flex_t)xDist); // FLEXTODO
        fVar10 = fVar9 / (flex_d_t)leapSpeed - (flex_d_t) - 0.2;
        fVar1 = sithWorld_g_pCurrentWorld->gravity;
        (pActor->attackError).x = (flex_t)xDist; // FLEXTODO
        (pActor->attackError).y = (flex_t)fVar7; // FLEXTODO
        (pActor->attackError).z = (flex_t)fVar8; // FLEXTODO
        pActor->attackDistance = (flex_t)fVar9; // FLEXTODO
        lVar11 = (int64_t)(fVar10 * 1000.0);
        pActor->field_28C = (int)lVar11 + sithTime_g_msecGameTime;
        pActor->flags &= ~(SITHAI_MODE_TURNING | SITHAI_MODE_MOVING);
        sithThing_DetachThing(thing);
        thing->physicsParams.vel.x = leapSpeed * (flex_t)xDist; // FLEXTODO
        thing->physicsParams.vel.y = leapSpeed * (flex_t)fVar7; // FLEXTODO
        thing->physicsParams.vel.z =
            (flex_t)(fVar10 * 0.5 * fVar1 + (flex_t)(leapSpeed * (flex_t)fVar8)); // FLEXTODO
        sithSoundClass_PlayModeRandom(thing, SITH_SC_JUMP);
        return 1;
    }

    
    if (((uint32_t)pActor->field_288 <= sithTime_g_msecGameTime) &&
            (pActor->field_1F4 == 0)) 
    {
        if (pActor->attackDistance < minDist || pActor->attackDistance > maxDist) {
            bVar4 = 0;
        }
        else {
            bVar4 = 1;
        }
        if (bVar4) {
            fVar1 = (thing->orient).rvec.z * (pActor->attackError).z +
                    (thing->orient).rvec.y * (pActor->attackError).y +
                    (thing->orient).rvec.x * (pActor->attackError).x;
            if (fVar1 < 0.0) {
                fVar1 = -fVar1;
            }
            
            if (fVar1 <= 1.0 - minDot) {
                if (thing->actorParams.flags & SITH_AF_DELAYFIRE) 
                {
                    pActor->field_28C = sithTime_g_msecGameTime + 300;
                    pActor->field_268 = param_7 | 8;
                    pActor->field_264 = leapSpeed;
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
SithThing* sithAI_FUN_00539a60(SithAIControlBlock *pThing)
{
    SithThing *a3;
    SithAIClass *psVar1;
    flex_t fVar2;
    int iVar3;
    SithThing *psVar4;
    SithThing *arg8;
    int iVar5;
    flex_t local_1c;
    int local_18;
    flex_t local_10;
    rdVector3 local_c;

    psVar4 = (SithThing *)0x0;
    if (pThing->pClass->alignment != 0.0) 
    {
        a3 = pThing->thing;
        local_1c = 0.0;
        sithAI_dword_84DE74 = 0x404;
        local_18 = sithWorld_g_pCurrentWorld->numThings;
        if (-1 < local_18) 
        {
            iVar5 = local_18;
            local_18 = local_18 + 1;
            do 
            {
                arg8 = &sithWorld_g_pCurrentWorld->aThings[iVar5];
                if (((sithAI_dword_84DE74 & 1 << (arg8->type & 0x1f)) != 0) &&
                ((arg8->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0))
                {
                    if (arg8->controlType == SITH_CT_AI) 
                    {
                        fVar2 = arg8->pClass->alignment;
                    }
                    else {
                        fVar2 = 0.0;
                        if (arg8->type == 10) {
                            fVar2 = sithAI_FLOAT_005a79d8;
                        }
                    }
                    if (((fVar2 != 0.0) && (psVar1 = pThing->pClass, fVar2 < 0.0 != psVar1->alignment < 0.0))
                            && (iVar3 = sithAI_CheckSightThing(a3, &a3->position, arg8, psVar1->fov, psVar1->sightDistance, 0.0,
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

