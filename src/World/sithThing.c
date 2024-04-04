#include "sithThing.h"

#include "General/stdHashTable.h"
#include "General/util.h"
#include "General/stdString.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "Gameplay/sithPlayerActions.h"
#include "World/sithWeapon.h"
#include "World/sithExplosion.h"
#include "World/sithItem.h"
#include "Gameplay/sithPlayer.h"
#include "World/sithSector.h"
#include "World/sithTrackThing.h"
#include "World/sithExplosion.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "World/sithSurface.h"
#include "Devices/sithSoundMixer.h"
#include "Dss/sithMulti.h"
#include "Engine/sithPuppet.h"
#include "World/sithTemplate.h"
#include "Engine/sithParticle.h"
#include "World/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "World/sithModel.h"
#include "World/sithSprite.h"
#include "Main/sithMain.h"
#include "Engine/sithCamera.h"
#include "Engine/sithPhysics.h"
#include "Main/jkGame.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "AI/sithAIAwareness.h"
#include "Cog/sithCog.h"
#include "Dss/sithDSSThing.h"
#include "stdPlatform.h"
#include "Dss/sithDSS.h"
#include "General/stdMath.h"
#include "jk.h"

#define NUM_THING_PARAMS (74) // JK is 72
#define NUM_THING_TYPES (13)

int sithThing_bInitted;
int sithThing_bInitted2;

const char* sithThing_aTypes[NUM_THING_TYPES] = {
    "free",
    "camera",
    "actor",
    "weapon",
    "debris",
    "item",
    "explosion",
    "cog",
    "ghost",
    "corpse",
    "player",
    "particle",
    "--invalid--"
};

const char* sithThing_aParams[NUM_THING_PARAMS] = {
    "type",
    "collide",
#ifdef JKM_PARAMS
    "treesize", // MOTS added
#endif
    "move",
    "size",
    "thingflags",
    "timer",
    "light",
    "attach",
    "soundclass",
    "model3d",
    "sprite",
    "surfdrag",
    "airdrag",
    "staticdrag",
    "mass",
    "height",
    "physflags",
    "maxrotvel",
    "maxvel",
    "vel",
    "angvel",
    "typeflags",
    "health",
    "maxthrust",
    "maxrotthrust",
    "jumpspeed",
    "weapon",
    "weapon2",
    "damage",
    "mindamage",
    "damageclass",
    "explode",
    "frame",
    "numframes",
    "puppet",
    "blasttime",
    "force",
    "maxlight",
    "range",
    "flashrgb",
    "aiclass",
    "cog",
    "respawn",
#ifdef JKM_PARAMS
    "respawnfactor", // MOTS added
#endif
    "material",
    "rate",
    "count",
    "elementsize",
    "particle",
    "maxhealth",
    "movesize",
    "orientspeed",
    "buoyancy",
    "eyeoffset",
    "minheadpitch",
    "maxheadpitch",
    "fireoffset",
    "lightoffset",
    "lightintensity",
    "points",
    "debris",
    "creatething",
    "trailthing",
    "trailcylradius",
    "trailrandangle",
    "minsize",
    "pitchrange",
    "yawrange",
    "error",
    "fov",
    "chance",
    "orient",
    "fleshhit",
};

int sithThing_Startup()
{
    int v1; // edi
    const char **v2; // esi

    if ( !sithThing_bInitted )
    {
        sithThing_paramKeyToParamValMap = stdHashTable_New((NUM_THING_PARAMS+1) * 2);
        if ( sithThing_paramKeyToParamValMap )
        {
            v1 = 1;
            v2 = (const char **)sithThing_aParams;
            while ( 1 )
            {
                stdHashTable_SetKeyVal(sithThing_paramKeyToParamValMap, *v2++, (void *)v1++);
                if ( (intptr_t)v2 >= (intptr_t)&sithThing_aParams[NUM_THING_PARAMS] )
                    break;
            }
            sithThing_bInitted2 = 1;
            sithThing_bInitted = 1;
        }
    }
    return 1;
}

int sithThing_Shutdown()
{
    if ( !sithThing_bInitted )
        return 0;
    stdHashTable_Free(sithThing_paramKeyToParamValMap);
    sithThing_bInitted = 0;
    return 1;
}

void sithThing_SetHandler(sithThing_handler_t handler)
{
    if ( handler )
        sithThing_handler = handler;
}

// MOTS altered?
void sithThing_TickAll(float deltaSeconds, int deltaMs)
{
    sithThing* pThingIter; // esi
    sithWorld *v6; // edi
    int v7; // edx
    int v8; // eax
    int v9; // eax

    if ( sithWorld_pCurrentWorld->numThings < 0 )
        return;

    for (int i = 0; i < sithWorld_pCurrentWorld->numThings+1; i++)
    {
        pThingIter = &sithWorld_pCurrentWorld->things[i];
        if (!pThingIter->type)
            continue;

        if (!(pThingIter->thingflags & SITH_TF_WILLBEREMOVED))
        {

            if ( pThingIter->lifeLeftMs )
            {
                if ( pThingIter->lifeLeftMs > deltaMs )
                {
                    pThingIter->lifeLeftMs -= deltaMs;
                }
                else
                {
                    sithThing_Remove(pThingIter);
                }
            }

            if ( (pThingIter->thingflags & SITH_TF_DISABLED) != 0 )
                continue;

            if ( (pThingIter->thingflags & (SITH_TF_TIMER|SITH_TF_PULSE)) != 0 )
                sithCog_HandleThingTimerPulse(pThingIter);

            switch ( pThingIter->thingtype )
            {
                case SITH_THING_ACTOR:
                    sithAI_Tick(pThingIter, deltaSeconds);
                    break;
                case SITH_THING_EXPLOSION:
                    sithExplosion_Tick(pThingIter);
                    break;
                case SITH_THING_COG:
                    sithParticle_Tick(pThingIter, deltaSeconds);
                    break;
            }

            switch ( pThingIter->type )
            {
                case SITH_THING_PLAYER:
                    sithPlayer_Tick(pThingIter->actorParams.playerinfo, deltaSeconds);
                case SITH_THING_ACTOR:
                    sithActor_Tick(pThingIter, deltaMs);
                    break;
                case SITH_THING_WEAPON:
                    sithWeapon_Tick(pThingIter, deltaSeconds);
                    break;
            }
            if ( sithThing_handler && pThingIter->jkFlags )
                sithThing_handler(pThingIter);
            if ( pThingIter->moveType == SITH_MT_PHYSICS )
            {
                sithPhysics_ThingTick(pThingIter, deltaSeconds);
            }
            else if ( pThingIter->moveType == SITH_MT_PATH )
            {
                sithTrackThing_Tick(pThingIter, deltaSeconds);
            }
            sithThing_TickPhysics(pThingIter, deltaSeconds);

            sithPuppet_Tick(pThingIter, deltaSeconds);
            continue;
        }

        if ( sithNet_isMulti && sithNet_isServer && (pThingIter->thing_id & 0xFFFF0000) == 0 )
            sithMulti_FreeThing(pThingIter->thing_id);

        if ( pThingIter->attach_flags )
            sithThing_DetachThing(pThingIter);

        if ( pThingIter->sector )
            sithThing_LeaveSector(pThingIter);

        if ( pThingIter->moveType == SITH_MT_PATH && pThingIter->trackParams.aFrames )
            pSithHS->free(pThingIter->trackParams.aFrames);

        if ( pThingIter->thingtype == SITH_THING_ACTOR )
            sithAI_FreeEntry(pThingIter);

        if ( pThingIter->type == SITH_THING_PARTICLE )
            sithParticle_FreeEntry(pThingIter);

        if ( pThingIter->animclass )
            sithPuppet_FreeEntry(pThingIter);

        rdThing_FreeEntry(&pThingIter->rdthing);
        sithSoundMixer_FreeThing(pThingIter);

        v7 = pThingIter->thingIdx;
        pThingIter->type = SITH_THING_FREE;
        v8 = sithWorld_pCurrentWorld->numThings;
        pThingIter->signature = 0;
        pThingIter->thing_id = -1;
        if ( v7 == v8 )
        {
            for (v9 = v7 - 1; v9 >= 0; --v9)
            {
                if (sithWorld_pCurrentWorld->things[v9].type)
                    break;
            }
            sithWorld_pCurrentWorld->numThings = v9;
        }
        sithNet_things[1 + sithNet_thingsIdx++] = v7;
    }
}

void sithThing_TickPhysics(sithThing *pThing, float deltaSecs)
{
    int v2; // ebp
    sithSurface *v5; // eax
    rdVector3 v8; // [esp+Ch] [ebp-18h] BYREF
    rdVector3 v1; // [esp+18h] [ebp-Ch] BYREF
    float arg4a; // [esp+2Ch] [ebp+8h]

    v2 = 0;
    if ((pThing->attach_flags & SITH_ATTACH_NO_MOVE))
        return;

    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        rdVector_Copy3(&pThing->field_268, &pThing->physicsParams.velocityMaybe);
    }
    else
    {
        v2 = 4;
        rdVector_Zero3(&pThing->field_268);
    }

    if (pThing->attach_flags && pThing->attach_flags & SITH_ATTACH_WORLDSURFACE)
    {
        v5 = pThing->attachedSurface;
        if ( (v5->surfaceFlags & SITH_SURFACE_SCROLLING) != 0 )
        {
            sithSurface_DetachThing(v5, &v8);
            rdVector_MultAcc3(&pThing->field_268, &v8, deltaSecs);
        }
    }
    
    if (rdVector_IsZero3(&pThing->field_268))
    {
        if ( pThing->moveType == SITH_MT_PHYSICS && (pThing->attach_flags & (SITH_ATTACH_THINGSURFACE|SITH_ATTACH_THING)) != 0 && pThing->attachedThing->moveType == SITH_MT_PATH )
            sithPhysics_FindFloor(pThing, 0);
    }
    else
    {
        arg4a = rdVector_Normalize3(&v1, &pThing->field_268);
        pThing->waggle = sithCollision_UpdateThingCollision(pThing, &v1, arg4a, v2);
    }
}

void sithThing_Remove(sithThing* pThing)
{
    switch ( pThing->type )
    {
        case SITH_THING_ACTOR:
            sithActor_Remove(pThing);
            break;
        case SITH_THING_WEAPON:
            sithWeapon_Remove(pThing);
            break;
        case SITH_THING_ITEM:
            sithItem_Remove(pThing);
            break;
        case SITH_THING_CORPSE:
            sithActor_RemoveCorpse(pThing);
            break;
        case SITH_THING_PLAYER:
            return;
        case SITH_THING_PARTICLE:
            sithParticle_Remove(pThing);
            break;
        default:
            pThing->thingflags |= SITH_TF_WILLBEREMOVED;
            if (pThing->thingflags & SITH_TF_CAPTURED && !(pThing->thingflags & SITH_TF_INVULN))
                sithCog_SendMessageFromThing(pThing, 0, SITH_MESSAGE_REMOVED);
            break;
    }
}

sithThing* sithThing_GetParent(sithThing* pThing)
{
    sithThing *result; // eax
    sithThing *i; // ecx

    result = pThing;
    for ( i = pThing->prev_thing; i; i = i->prev_thing )
    {
        if ( result->child_signature != i->signature )
            break;
        result = i;
    }
    return result;
}

sithThing* sithThing_GetThingByIdx(int idx)
{
    sithThing *result; // eax

    if ( idx < 0 || idx >= sithWorld_pCurrentWorld->numThingsLoaded || (result = &sithWorld_pCurrentWorld->things[idx], result->type == SITH_THING_FREE) )
        result = 0;
    return result;
}

sithThing* sithThing_GetById(int thing_id)
{
    sithThing *result; // eax

    if ( thing_id < 0 )
        return 0;
    if ( (thing_id & 0xFFFF0000) == 0 && thing_id < sithWorld_pCurrentWorld->numThingsLoaded )
    {
        result = &sithWorld_pCurrentWorld->things[thing_id];
        if ( result->type )
            return result;
    }

    if ( sithWorld_pCurrentWorld->numThings < 0 )
        return 0;
    
    for (int i = 0; i < sithWorld_pCurrentWorld->numThings; i++)
    {
        sithThing* iter = &sithWorld_pCurrentWorld->things[i];
        if (iter->thing_id == thing_id && iter->type != SITH_THING_FREE)
            return iter;
    }

    return NULL;
}

void sithThing_Destroy(sithThing* pThing)
{
    pThing->thingflags |= SITH_TF_WILLBEREMOVED;
    if ( (pThing->thingflags & SITH_TF_CAPTURED) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
        sithCog_SendMessageFromThing(pThing, 0, SITH_MESSAGE_REMOVED);
}

float sithThing_Damage(sithThing *sender, sithThing *reciever, float amount, int damageClass)
{
    float param1; // [esp+0h] [ebp-20h]

    // Added: noclip
    if (sender == sithPlayer_pLocalPlayerThing && (g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
        return 0.0;
    }

    if ( amount <= 0.0 )
        return 0.0;
    if ( (sender->thingflags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0 )
        return 0.0;
    if ( (sender->thingflags & SITH_TF_CAPTURED) != 0 && (sender->thingflags & SITH_TF_INVULN) == 0 )
    {
        param1 = (float)(unsigned int)damageClass;
        amount = sithCog_SendMessageFromThingEx(sender, reciever, SITH_MESSAGE_DAMAGED, amount, param1, 0.0, 0.0);
    }
    if ( amount > 0.0 )
    {
        if ( sender->type != SITH_THING_ACTOR )
        {
            if ( sender->type == SITH_THING_WEAPON )
            {
                sithWeapon_SetTimeLeft(sender, reciever, amount);
                return amount;
            }
            if ( sender->type != SITH_THING_PLAYER )
                return amount;
        }
        amount = amount - sithActor_Hit(sender, reciever, amount, damageClass);
    }
    return amount;
}

//sithThing_Create_idk

void sithThing_Free(sithWorld *pWorld)
{
    // Added: !world check
    if (!pWorld || !pWorld->things)
    {
        return;
    }

    sithThing_freestuff(pWorld);

    pSithHS->free(pWorld->things);
    pWorld->things = 0;
    pWorld->numThingsLoaded = 0;
    pWorld->numThings = -1;
}

void sithThing_freestuff(sithWorld *pWorld)
{
    sithThing* pThingIter; // esi
    sithWorld *v3; // edx
    int v4; // esi
    int v5; // eax
    int v7; // eax

    // Added: !world check
    if (!pWorld || !pWorld->things)
        return;

    for (int v9 = 0; v9 < pWorld->numThingsLoaded; v9++)
    {
        pThingIter = &pWorld->things[v9];
        if (!pThingIter->type)
            continue;

        if ( sithNet_isMulti && sithNet_isServer && (pThingIter->thing_id & 0xFFFF0000) == 0 )
            sithMulti_FreeThing(pThingIter->thing_id);
        if ( pThingIter->attach_flags )
            sithThing_DetachThing(pThingIter);
        if ( pThingIter->sector )
            sithThing_LeaveSector(pThingIter);
        if ( pThingIter->moveType == SITH_MT_PATH && pThingIter->trackParams.aFrames )
            pSithHS->free(pThingIter->trackParams.aFrames);
        if ( pThingIter->thingtype == SITH_THING_ACTOR || pThingIter->thingtype == SITH_THING_PLAYER) // Added: SITH_THING_PLAYER
            sithAI_FreeEntry(pThingIter);
        if ( pThingIter->type == SITH_THING_PARTICLE )
            sithParticle_FreeEntry(pThingIter);
        if ( pThingIter->animclass )
            sithPuppet_FreeEntry(pThingIter);
        rdThing_FreeEntry(&pThingIter->rdthing);
        sithSoundMixer_FreeThing(pThingIter);
        v3 = sithWorld_pCurrentWorld;
        pThingIter->type = SITH_THING_FREE;
        pThingIter->signature = 0;
        pThingIter->thing_id = -1;
        v4 = pThingIter->thingIdx;
        if ( v4 == v3->numThings )
        {
            v5 = v4 - 1;
            if ( v4 - 1 >= 0 )
            {
                do
                {
                    if (v3->things[v5].type)
                        break;
                    --v5;
                }
                while ( v5 >= 0 );
            }
            v3->numThings = v5;
        }
        v7 = sithNet_thingsIdx;
        sithNet_things[1 + sithNet_thingsIdx] = v4;
        sithNet_thingsIdx = v7 + 1;
    }
}

//sithThing_idkjkl

void sithThing_sub_4CCE60()
{
    int v1; // edx
    int *v2; // ebp
    int v6; // eax
    int v8; // ecx

    sithNet_thingsIdx = 0;
    sithWorld_pCurrentWorld->numThings = -1;
    v2 = sithNet_things + 1;
    for (v1 = sithWorld_pCurrentWorld->numThingsLoaded - 1; v1 >= 0; v1--)
    {
        if ( sithWorld_pCurrentWorld->things[v1].type )
        {
            if ( v1 > sithWorld_pCurrentWorld->numThings )
                sithWorld_pCurrentWorld->numThings = v1;
        }
        else
        {
            if ( v1 == sithWorld_pCurrentWorld->numThings )
            {
                for (v6 = v1-1; v6 >= 0; v6--)
                {
                    if (sithWorld_pCurrentWorld->things[v6].type)
                        break;
                }
                sithWorld_pCurrentWorld->numThings = v6;
            }
            *v2++ = v1;
            sithNet_thingsIdx++;
        }
    }
}


void sithThing_FreeEverythingNet(sithThing* pThing)
{
    int v2; // esi
    int v3; // eax
    int v5; // eax

    if ( sithNet_isMulti && sithNet_isServer && (pThing->thing_id & 0xFFFF0000) == 0 )
        sithMulti_FreeThing(pThing->thing_id);
    if ( pThing->attach_flags )
        sithThing_DetachThing(pThing);
    if ( pThing->sector )
        sithThing_LeaveSector(pThing);
    if ( pThing->moveType == SITH_MT_PATH && pThing->trackParams.aFrames )
        pSithHS->free(pThing->trackParams.aFrames);
    if ( pThing->thingtype == SITH_THING_ACTOR )
        sithAI_FreeEntry(pThing);
    if ( pThing->type == SITH_THING_PARTICLE )
        sithParticle_FreeEntry(pThing);
    if ( pThing->animclass )
        sithPuppet_FreeEntry(pThing);
    rdThing_FreeEntry(&pThing->rdthing);
    sithSoundMixer_FreeThing(pThing);
    pThing->type = SITH_THING_FREE;
    pThing->signature = 0;
    pThing->thing_id = -1;
    v2 = pThing->thingIdx;
    if ( v2 == sithWorld_pCurrentWorld->numThings )
    {
        v3 = v2 - 1;
        if ( v2 - 1 >= 0 )
        {
            do
            {
                if (sithWorld_pCurrentWorld->things[v3].type)
                    break;
                --v3;
            }
            while ( v3 >= 0 );
        }
        sithWorld_pCurrentWorld->numThings = v3;
    }
    v5 = sithNet_thingsIdx;
    sithNet_things[sithNet_thingsIdx + 1] = v2;
    sithNet_thingsIdx = v5 + 1;
}

void sithThing_FreeEverything(sithThing* pThing)
{
    if ( pThing->attach_flags )
        sithThing_DetachThing(pThing);
    if ( pThing->sector )
        sithThing_LeaveSector(pThing);
    if ( pThing->moveType == SITH_MT_PATH && pThing->trackParams.aFrames )
        pSithHS->free(pThing->trackParams.aFrames);
    if ( pThing->thingtype == SITH_THING_ACTOR )
        sithAI_FreeEntry(pThing);
    if ( pThing->type == SITH_THING_PARTICLE )
        sithParticle_FreeEntry(pThing);
    if ( pThing->animclass )
        sithPuppet_FreeEntry(pThing);
    rdThing_FreeEntry(&pThing->rdthing);
    sithSoundMixer_FreeThing(pThing);
    pThing->type = SITH_THING_FREE;
    pThing->signature = 0;
    pThing->thing_id = -1;
}

void sithThing_sub_4CD100(sithThing* pThing)
{
    switch ( pThing->type )
    {
        case SITH_THING_ITEM:
            sithItem_New(pThing);
            break;
        case SITH_THING_EXPLOSION:
            sithExplosion_CreateThing(pThing);
            break;
        case SITH_THING_PARTICLE:
            sithParticle_CreateThing(pThing);
            break;
    }
    if ( pThing->rdthing.puppet )
        sithPuppet_NewEntry(pThing);
    if ( pThing->thingtype == SITH_THING_ACTOR )
        sithAI_NewEntry(pThing);
    if ( pThing->soundclass )
        sithSoundClass_PlayModeRandom(pThing, SITH_SC_CREATE);

    if ( (sithWorld_pCurrentWorld->level_type_maybe & 2) != 0
      && pThing->moveType == SITH_MT_PHYSICS
      && (pThing->physicsParams.physflags & (SITH_PF_WALLSTICK|SITH_PF_FLOORSTICK)) != 0 )
    {
        sithPhysics_FindFloor(pThing, 1);
    }
}

// MOTS altered
int sithThing_DoesRdThingInit(sithThing* pThing)
{

    int idx = pThing->thingIdx;
    int sig = pThing->signature;

    _memset(pThing, 0, sizeof(sithThing));
    _memcpy(&pThing->lookOrientation, &rdroid_identMatrix34, sizeof(pThing->lookOrientation));

    int out = rdThing_NewEntry(&pThing->rdthing, pThing);
    pThing->thingIdx = idx;
    pThing->signature = sig;

#ifdef JKM_LIGHTING
    pThing->archlightIdx = -1; // MOTS added
#endif

    return out;
}

void sithThing_MoveToSector(sithThing* pThing, sithSector *sector, int a4)
{
    sithSector *v3; // eax

    v3 = pThing->sector;
    if ( v3 )
    {
        if ( v3 == sector )
            return;
        sithThing_LeaveSector(pThing);
    }
    sithThing_EnterSector(pThing, sector, 0, a4);
}

void sithThing_LeaveSector(sithThing* pThing)
{
    sithSector *sector; // eax
    sithThing *prevThing; // ecx
    sithThing *nextThing; // eax
    rdVector3 pos; // [esp+Ch] [ebp-Ch] BYREF

    if (pThing == sithPlayer_pLocalPlayerThing) {
        //jk_printf("OpenJKDF2: Leave sector %p, idx %d\n", pThing->sector, pThing->sector ? pThing->sector->id : -1);
    }

    // Added
    if (!pThing || !pThing->sector) return;

    sector = pThing->sector;
    if ( (sector->flags & 4) == 0 )
        goto LABEL_5;
    pos = pThing->position;
    if ( (pThing->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SendMessageFromSector(sector, pThing, SITH_MESSAGE_EXITED);
    if ( !_memcmp(&pos, &pThing->position, sizeof(rdVector3)) )
    {
LABEL_5:
        prevThing = pThing->prevThing;
        nextThing = pThing->nextThing;
        if ( prevThing )
        {
            prevThing->nextThing = nextThing;
            if ( nextThing )
                nextThing->prevThing = prevThing;
        }
        else
        {
            pThing->sector->thingsList = nextThing;
            if ( nextThing )
            {
                nextThing->prevThing = 0;
                pThing->sector = 0;
                pThing->prevThing = 0;
                pThing->nextThing = 0;
                return;
            }
        }
        pThing->sector = 0;
        pThing->prevThing = 0;
        pThing->nextThing = 0;
    }
}

void sithThing_EnterSector(sithThing* pThing, sithSector *sector, int a3, int a4)
{
    sithSector *v7; // eax
    sithThing* i;

    if (pThing == sithPlayer_pLocalPlayerThing) {
        //jk_printf("OpenJKDF2: Enter sector %p, idx %d\n", sector, sector ? sector->id : -1);
    }

    // Added: Check that sector is non-null
    if (!sector) {
        jk_printf("OpenJKDF2: Tried to enter NULL sector??\n");
        return;
    }

    // Added: Prevent thing getting linked in twice
    for ( i = sector->thingsList; i; i = i->nextThing )
    {
        if (i == pThing) {
            pThing->sector = sector; // just in case?
            jk_printf("OpenJKDF2: Tried to double enter sector??\n");
            return;
        }
    }

    pThing->nextThing = sector->thingsList;
    if ( sector->thingsList )
        sector->thingsList->prevThing = pThing;

    pThing->prevThing = 0;
    sector->thingsList = pThing;
    pThing->sector = sector;

    if (sector->flags & SITH_SECTOR_UNDERWATER)
    {
        if ( pThing->attach_flags && !(pThing->attach_flags & SITH_ATTACH_NO_MOVE) && pThing->moveType == SITH_MT_PHYSICS )
            sithThing_DetachThing(pThing);

        if (!(pThing->thingflags & SITH_TF_WATER))
            sithThing_EnterWater(pThing, a3 | a4);
    }
    else if (pThing->thingflags & SITH_TF_WATER)
    {
        sithThing_ExitWater(pThing, a3 | a4);
    }

    if ( !a4 )
    {
        if ( (pThing->sector->flags & SITH_SECTOR_COGLINKED) != 0 && (pThing->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
            sithCog_SendMessageFromSector(pThing->sector, pThing, SITH_MESSAGE_ENTERED);
    }
}

void sithThing_EnterWater(sithThing* pThing, int a2)
{
    sithThing *v4; // ecx
    sithCog *v5; // eax
    sithCog *v6; // eax

    pThing->thingflags |= SITH_TF_WATER;
    if ( pThing->animclass )
        sithPuppet_sub_4E4760(pThing, 1);
    if ( (pThing->thingflags & SITH_TF_DROWNS) != 0 )
    {
        pThing->thingflags |= SITH_TF_WILLBEREMOVED;
        if ( (pThing->thingflags & SITH_TF_CAPTURED) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
            sithCog_SendMessageFromThing(pThing, 0, SITH_MESSAGE_REMOVED);
    }
    else if ( !a2 )
    {
#ifdef QOL_IMPROVEMENTS
        // Prevent splash sound spam if they're not actually making significant movement
        if ( pThing->soundclass && fabs(pThing->physicsParams.vel.z) > 0.02 )  
#else
        if ( pThing->soundclass )
#endif
        {
            if ( pThing->moveType == SITH_MT_PHYSICS && pThing->physicsParams.vel.z > -1.0 )
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_ENTERWATERSLOW);
            else
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_ENTERWATER);
        }
        v4 = sithPlayer_pLocalPlayerThing;
        if ( sithPlayer_pLocalPlayerThing && (pThing->thingflags & SITH_TF_SPLASHES) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
        {
            v5 = sithPlayer_pLocalPlayerThing->class_cog;
            if ( v5 )
            {
                sithCog_SendMessage(v5, SITH_MESSAGE_SPLASH, SENDERTYPE_THING, pThing->thingIdx, 0, 1, 0);
                v4 = sithPlayer_pLocalPlayerThing;
            }
            v6 = v4->capture_cog;
            if ( v6 )
                sithCog_SendMessage(v6, SITH_MESSAGE_SPLASH, SENDERTYPE_THING, pThing->thingIdx, 0, 1, 0);
        }

        // MOTS added: wtf??
        if (Main_bMotsCompat) {
            if ( pThing->moveType == SITH_MT_PHYSICS ) {
                
                // No water slowdown? Bug??
                int tmp;
                if (tmp = pThing->physicsParams.physflags | SITH_PF_800000, 
                    pThing->physicsParams.physflags = tmp, 
                    tmp == 0) {
                    pThing->physicsParams.vel.z *= 0.25;
                }
            }
        }
        else {
            if ( pThing->moveType == SITH_MT_PHYSICS ) {
                pThing->physicsParams.vel.z *= 0.25;
            }
        }
    }
}

void sithThing_ExitWater(sithThing* pThing, int a2)
{
    pThing->thingflags &= ~SITH_TF_WATER;
    if ( pThing->animclass )
        sithPuppet_sub_4E4760(pThing, 0);

    if ( pThing->soundclass )
    {
        if ( pThing->moveType == SITH_MT_PHYSICS && rdVector_Len3(&pThing->physicsParams.vel) < 1.0 )
            sithSoundClass_PlayModeRandom(pThing, SITH_SC_EXITWATERSLOW);
        else
            sithSoundClass_PlayModeRandom(pThing, SITH_SC_EXITWATER);
    }

    if ( (pThing->thingflags & SITH_TF_WATERCREATURE) != 0 )
    {
        pThing->thingflags |= SITH_TF_WILLBEREMOVED;
        if ( (pThing->thingflags & SITH_TF_CAPTURED) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
            sithCog_SendMessageFromThing(pThing, 0, SITH_MESSAGE_REMOVED);
    }
    else if ( !a2 )
    {
        if ( sithPlayer_pLocalPlayerThing )
        {
            if ( (pThing->thingflags & SITH_TF_SPLASHES) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
            {
                if ( sithPlayer_pLocalPlayerThing->class_cog )
                {
                    sithCog_SendMessage(sithPlayer_pLocalPlayerThing->class_cog, SITH_MESSAGE_SPLASH, 3, pThing->thingIdx, 0, 0, 0);
                }

                if ( sithPlayer_pLocalPlayerThing->capture_cog )
                {
                    sithCog_SendMessage(sithPlayer_pLocalPlayerThing->capture_cog, SITH_MESSAGE_SPLASH, 3, pThing->thingIdx, 0, 0, 0);
                }
            }
        }
    }
}

//sithThing_doesinitidk

void sithThing_SetPosAndRot(sithThing *this, rdVector3 *pos, rdMatrix34 *rot)
{
    rdVector_Copy3(&this->position, pos);
    rdMatrix_Copy34(&this->lookOrientation, rot);
    rdVector_Zero3(&this->lookOrientation.scale);
}

// MOTS altered
int sithThing_SetNewModel(sithThing* pThing, rdModel3 *model)
{
    rdThing *v2; // edi
    rdPuppet *v4; // ebx

    v2 = &pThing->rdthing;
    if ( pThing->rdthing.type == RD_THINGTYPE_MODEL && pThing->rdthing.model3 == model )
        return 0;
    v4 = pThing->rdthing.puppet;
    pThing->rdthing.puppet = 0;
    rdThing_FreeEntry(&pThing->rdthing);
    rdThing_NewEntry(v2, pThing);
    rdThing_SetModel3(v2, model);
    pThing->rdthing.puppet = v4;

    // MOTS added
    if (Main_bMotsCompat)
        pThing->unk = 1;

    return 1;
}

sithThing* sithThing_sub_4CD8A0(sithThing *pThing, sithThing *a2)
{
    sithThing *result; // eax
    int v10; // [esp+10h] [ebp-Ch]
    int v11; // [esp+14h] [ebp-8h]
    sithThing *v12; // [esp+18h] [ebp-4h]
    int thinga; // [esp+20h] [ebp+4h]

    thinga = pThing->thingIdx;
    v11 = pThing->thing_id;
    v10 = pThing->signature;
    v12 = pThing->rdthing.parentSithThing;
    if ( a2 )
    {
        _memcpy(pThing, a2, sizeof(sithThing));
        if ( pThing->rdthing.type == RD_THINGTYPE_MODEL )
        {
            rdThing_SetModel3(&pThing->rdthing, pThing->rdthing.model3);
        }
        else if ( pThing->rdthing.type == RD_THINGTYPE_PARTICLECLOUD )
        {
            rdThing_SetParticleCloud(&pThing->rdthing, pThing->rdthing.particlecloud);
        }
        if ( pThing->animclass )
            rdPuppet_New(&pThing->rdthing);
        if ( pThing->moveType == SITH_MT_PATH && a2->trackParams.aFrames )
        {
            // Added: made this more explicit
            pThing->trackParams.sizeFrames = a2->trackParams.sizeFrames;
            pThing->trackParams.aFrames = (sithThingFrame *)pSithHS->alloc(sizeof(sithThingFrame) * pThing->trackParams.sizeFrames);
            if (pThing->trackParams.aFrames) // Added: nullptr check
                _memcpy(pThing->trackParams.aFrames, a2->trackParams.aFrames, sizeof(sithThingFrame) * pThing->trackParams.sizeFrames);
        }
    }
    else
    {
        sithThing_DoesRdThingInit(pThing);
    }
    pThing->thingIdx = thinga;
    result = v12;
    pThing->templateBase = a2;
    pThing->thing_id = v11;
    pThing->signature = v10;
    pThing->rdthing.parentSithThing = v12;
    return result;
}

sithThing* sithThing_Create(sithThing *templateThing, const rdVector3 *position, const rdMatrix34 *lookOrientation, sithSector *sector, sithThing *prevThing)
{
    int v8; // esi
    sithThing *v10; // esi
    unsigned int v12; // ebp
    unsigned int v13; // edi
    unsigned int v15; // edx
    sithThing *v17; // ebx
    int v19; // eax
    int v20; // ecx
    int v21; // edx
    sithThing *v26; // eax

    if ( sithNet_thingsIdx )
    {
        v8 = sithNet_things[sithNet_thingsIdx];
        --sithNet_thingsIdx;
        if ( v8 > sithWorld_pCurrentWorld->numThings )
            sithWorld_pCurrentWorld->numThings = v8;
    }
    else
    {
        v8 = -1;
    }
    if ( v8 >= 0 )
        goto LABEL_24;

    if ( templateThing->type != SITH_THING_EXPLOSION && templateThing->type != SITH_THING_DEBRIS && templateThing->type != SITH_THING_PARTICLE )
    {
        v10 = sithWorld_pCurrentWorld->things;
        v12 = 0;
        for (v13 = 0; v13 < sithWorld_pCurrentWorld->numThingsLoaded; v13++)
        {
            if ( (v10->thingflags & SITH_TF_WILLBEREMOVED) != 0
              || ((v10->type == SITH_THING_DEBRIS) || v10->type == SITH_THING_PARTICLE) && v10->lifeLeftMs )
            {
                sithThing_FreeEverythingNet(v10);
            }
            v15 = v12++;
            if ( v15 > 0xA )
                break;
            ++v10;
        }
        if ( sithNet_thingsIdx )
        {
            v8 = sithNet_things[sithNet_thingsIdx];
            sithNet_thingsIdx--;
            if ( v8 > sithWorld_pCurrentWorld->numThings )
                sithWorld_pCurrentWorld->numThings = v8;
        }
        else
        {
            v8 = -1;
        }
    }

    if ( v8 >= 0 )
    {
LABEL_24:
        v17 = &sithWorld_pCurrentWorld->things[v8];
        sithThing_DoesRdThingInit(v17);
        v17->thingIdx = v8;
        if ( !sithThing_inittedThings )
            sithThing_inittedThings = 1;
        v19 = sithThing_bInitted2;
        v20 = (playerThingIdx + 1) << 16;
        v21 = sithThing_inittedThings;
        v17->signature = sithThing_bInitted2;
        ++sithThing_inittedThings;
        v17->thing_id = v21 | v20;
        sithThing_bInitted2 = v19 + 1;
        if ( v19 == -1 )
            sithThing_bInitted2 = 1;
    }
    else
    {
        v17 = 0;
    }

    if ( !v17 )
        return 0;

    sithThing_sub_4CD8A0(v17, templateThing);
    v17->position = *position;
    _memcpy(&v17->lookOrientation, lookOrientation, sizeof(v17->lookOrientation));
    rdVector_Zero3(&v17->lookOrientation.scale);
    rdMatrix_PreMultiply34(&v17->lookOrientation, &templateThing->lookOrientation);
    sithThing_EnterSector(v17, sector, 1, 0);
    if ( prevThing )
    {
        v17->prev_thing = prevThing;
        v17->child_signature = prevThing->signature;
    }
    switch ( v17->type )
    {
        case SITH_THING_ITEM:
            sithItem_New(v17);
            break;
        case SITH_THING_EXPLOSION:
            sithExplosion_CreateThing(v17);
            break;
        case SITH_THING_PARTICLE:
            sithParticle_CreateThing(v17);
            break;
    }
    if ( v17->rdthing.puppet )
        sithPuppet_NewEntry(v17);
    if ( v17->thingtype == SITH_THING_ACTOR )
        sithAI_NewEntry(v17);
    if ( v17->soundclass )
        sithSoundClass_PlayModeRandom(v17, SITH_SC_CREATE);
    if ( (sithWorld_pCurrentWorld->level_type_maybe & 2) == 0 )
        goto LABEL_48;
    if ( v17->moveType == SITH_MT_PHYSICS )
    {
        if ( (v17->physicsParams.physflags & (SITH_PF_WALLSTICK|SITH_PF_FLOORSTICK)) != 0 )
            sithPhysics_FindFloor(v17, 1);
LABEL_48:
        if ( v17->moveType == SITH_MT_PHYSICS && (v17->physicsParams.physflags & SITH_PF_20000) == 0 )
            rdMatrix_TransformVector34Acc(&v17->physicsParams.vel, &v17->lookOrientation);
    }
    if ( v17->class_cog )
        sithCog_SendMessage(v17->class_cog, SITH_MESSAGE_CREATED, 3, v17->thingIdx, 0, 0, 0);
    if ( v17->pTemplate )
    {
        v26 = sithThing_Create(v17->pTemplate, position, lookOrientation, sector, prevThing);
        if ( v26 )
        {
            if ( (v17->thingflags & SITH_TF_INVULN) != 0 )
            {
                v26->thingflags |= SITH_TF_INVULN;
            }
        }
    }
    return v17;
}

sithThing* sithThing_SpawnTemplate(sithThing *templateThing, sithThing *spawnThing)
{
    sithSector *v2; // eax
    sithThing *result; // eax
    sithThing *v4; // edi
    rdVector3 diffVec; // [esp+Ch] [ebp-24h] BYREF
    rdVector3 v7; // [esp+18h] [ebp-18h] BYREF
    rdVector3 dstVec; // [esp+24h] [ebp-Ch] BYREF

    if ( templateThing->rdthing.type == RD_THINGTYPE_MODEL )
    {
        diffVec = templateThing->rdthing.model3->insertOffset;
    }
    else if ( templateThing->rdthing.type == RD_THINGTYPE_SPRITE3 )
    {
        diffVec = templateThing->rdthing.sprite3->offset;
    }
    else
    {
        rdVector_Zero3(&diffVec);
    }
    if ( spawnThing->rdthing.type == RD_THINGTYPE_MODEL )
    {
        v7 = spawnThing->rdthing.model3->insertOffset;
    }
    else if ( spawnThing->rdthing.type == RD_THINGTYPE_SPRITE3 )
    {
        v7 = spawnThing->rdthing.sprite3->offset;
    }
    else
    {
        rdVector_Zero3(&v7);
    }
    rdVector_Sub3Acc(&diffVec, &v7);
    rdMatrix_TransformVector34(&dstVec, &diffVec, &spawnThing->lookOrientation);
    rdVector_Add3(&v7, &dstVec, &spawnThing->position);
    v2 = sithCollision_GetSectorLookAt(spawnThing->sector, &spawnThing->position, &v7, 0.0);
    result = sithThing_Create(templateThing, &v7, &spawnThing->lookOrientation, v2, 0);
    v4 = result;
    if ( result )
    {
        if ( result->moveType == SITH_MT_PATH
          && spawnThing->moveType == SITH_MT_PATH
          && spawnThing->trackParams.aFrames
          && !result->trackParams.aFrames )
        {
            sithTrackThing_idkpathmove(result, spawnThing, &diffVec);
        }
        result = v4;
    }
    return result;
}

void sithThing_AttachToSurface(sithThing* pThing, sithSurface *surface, int a3)
{
    int v4; // ebp
    int v5; // eax
    int *v6; // eax
    sithWorld *v7; // edx
    rdVector3 *v8; // ecx
    double v14; // st7
    int v15; // edi
    rdVector3 a2a; // [esp+Ch] [ebp-Ch] BYREF

    v4 = 1;
    v5 = pThing->attach_flags;
    if ( v5 )
    {
        if ( (v5 & 1) != 0 && pThing->attachedSurface == surface )
            return;
        v4 = 0;
        sithThing_DetachThing(pThing);
    }
    v6 = surface->surfaceInfo.face.vertexPosIdx;
    v7 = sithWorld_pCurrentWorld;
    pThing->attach_flags = 1;
    v8 = &v7->vertices[*v6];
    pThing->field_38.x = v8->x;
    pThing->field_38.y = v8->y;
    pThing->attachedSurface = surface;
    pThing->field_38.z = v8->z;
    pThing->attachedSufaceInfo = &surface->surfaceInfo;
    pThing->physicsParams.physflags &= ~SITH_PF_100;
    if ( (surface->surfaceFlags & SITH_SURFACE_SCROLLING) != 0 && pThing->moveType == SITH_MT_PHYSICS )
    {
        sithSurface_DetachThing(surface, &a2a);
        rdVector_Sub3Acc(&pThing->physicsParams.vel, &a2a);
    }
    if ( (surface->surfaceFlags & SITH_SURFACE_COG_LINKED) != 0 && (pThing->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SendMessageFromSurface(surface, pThing, SITH_MESSAGE_ENTERED);
    if ( !a3 && v4 )
    {
        v14 = -rdVector_Dot3(&pThing->physicsParams.vel, &surface->surfaceInfo.face.normal);
        if ( v14 > 2.5 )
        {
            sithCollision_FallHurt(pThing, v14);
            if ( pThing->soundclass )
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDHURT);
            }
            
        }
        if ( pThing->soundclass )
        {
            v15 = surface->surfaceFlags;
            if ( (v15 & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_EARTH|SITH_SURFACE_PUDDLE|SITH_SURFACE_WATER|SITH_SURFACE_METAL)) != 0 )
            {
                if ( (v15 & SITH_SURFACE_METAL) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDMETAL);
                }
                else if ( (v15 & SITH_SURFACE_WATER) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDWATER);
                }
                else if ( (v15 & SITH_SURFACE_PUDDLE) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDPUDDLE);
                }
                else
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDEARTH);
                }
            }
            else
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDHARD);
            }
        }
        if ( pThing->animclass && pThing->moveType == SITH_MT_PHYSICS && (pThing->physicsParams.physflags & SITH_PF_CROUCHING) == 0 )
            sithPuppet_PlayMode(pThing, SITH_ANIM_LAND, 0);
        return;
    }
}

void sithThing_LandThing(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3 *a4, int a5)
{
    int *v7; // eax
    int v8; // eax
    sithThing *v9; // eax
    double v14; // st6
    double downward_velocity; // st7
    int v18; // [esp+10h] [ebp-1Ch]
    rdVector3 a2a; // [esp+14h] [ebp-18h] BYREF
    rdVector3 out; // [esp+20h] [ebp-Ch] BYREF
    float a1a; // [esp+30h] [ebp+4h]

    v18 = 1;
    if ( a1->attach_flags )
    {
        if ( (a1->attach_flags & SITH_ATTACH_THINGSURFACE) != 0 && a1->attachedThing == a2 && (rdFace *)a1->attachedSufaceInfo == a3 )
            return;
        v18 = 0;
        sithThing_DetachThing(a1);
    }
    v7 = a3->vertexPosIdx;
    a1->attach_flags = SITH_ATTACH_THINGSURFACE;
    a1->attachedSufaceInfo = (sithSurfaceInfo *)a3;
    v8 = *v7;
    a1->attachedThing = a2;
    a1->field_38 = a4[v8];
    v9 = a2->attachedParentMaybe;
    a1->childThing = v9;
    if ( v9 )
        v9->parentThing = a1;
    a1->parentThing = 0;
    a2->attachedParentMaybe = a1;
    a1->physicsParams.physflags &= ~SITH_PF_100;
    if ( a2->moveType == SITH_MT_PHYSICS )
    {
        rdVector_Sub3Acc(&a1->physicsParams.vel, &a2->physicsParams.vel);
    }
    else if ( a2->moveType == SITH_MT_PATH )
    {
        rdVector_MultAcc3(&a1->physicsParams.vel, &a2->trackParams.vel, -a2->trackParams.lerpSpeed);
    }
    rdVector_Sub3(&a2a, &a1->position, &a2->position);
    rdMatrix_TransformVector34Acc_0(&a1->field_4C, &a2a, &a2->lookOrientation);
    if ( (a2->thingflags & SITH_TF_CAPTURED) != 0 && (a1->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SendMessageFromThing(a2, a1, SITH_MESSAGE_ENTERED);
    if ( v18 && !a5 )
    {
        rdMatrix_TransformVector34(&out, &a3->normal, &a2->lookOrientation);
        downward_velocity = -rdVector_Dot3(&a1->physicsParams.vel, &out);
        if ( downward_velocity > 2.5 )
        {
            a1a = downward_velocity;
            sithCollision_FallHurt(a1, a1a);
            sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDHURT);
        }
        if ( a1->soundclass )
        {
            if ( (a2->thingflags & SITH_TF_METAL) != 0 )
            {
                sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDMETAL);
            }
            else if ( (SITH_TF_EARTH & a2->thingflags) != 0 )
            {
                sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDEARTH);
            }
            else
            {
                sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDHARD);
            }
        }
    }
}

void sithThing_AttachThing(sithThing *parent, sithThing *child)
{
    int v2; // eax
    sithThing *v3; // eax
    rdVector3 a2; // [esp+8h] [ebp-Ch] BYREF

    v2 = parent->attach_flags;
    if ( v2 )
    {
        if ( (v2 & SITH_ATTACH_THING) != 0 && parent->attachedThing == child )
            return;
        sithThing_DetachThing(parent);
    }
    v3 = child->attachedParentMaybe;
    parent->attach_flags = SITH_ATTACH_THING;
    parent->attachedThing = child;
    parent->childThing = v3;
    if ( v3 )
        v3->parentThing = parent;

    parent->parentThing = 0;
    child->attachedParentMaybe = parent;
    rdVector_Sub3(&a2, &parent->position, &child->position);
    rdMatrix_TransformVector34Acc_0(&parent->field_4C, &a2, &child->lookOrientation);
    if ( (child->thingflags & SITH_TF_CAPTURED) != 0 && (parent->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SendMessageFromThing(child, parent, SITH_MESSAGE_ENTERED);
}

int sithThing_DetachThing(sithThing* pThing)
{
    uint32_t *v2; // edi
    sithThing *v3; // ebx
    double v12; // rt2
    sithThing *v13; // ecx
    sithThing *v14; // eax
    int result; // eax
    sithSurface *attached; // ebx
    rdVector3 a2; // [esp+Ch] [ebp-Ch] BYREF

    v2 = &pThing->attach_flags;
    if ( (pThing->attach_flags & (SITH_ATTACH_THING|SITH_ATTACH_THINGSURFACE)) == 0 )
    {
        if ( (pThing->attach_flags & SITH_ATTACH_WORLDSURFACE) != 0 )
        {
            attached = pThing->attachedSurface;
            if ( (attached->surfaceFlags & SITH_SURFACE_SCROLLING) != 0 && pThing->moveType == SITH_MT_PHYSICS )
            {
                sithSurface_DetachThing(attached, &a2);
                rdVector_Add3Acc(&pThing->physicsParams.vel, &a2);
            }
            if ( (attached->surfaceFlags & SITH_SURFACE_COG_LINKED) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
                sithCog_SendMessageFromSurface(attached, pThing, SITH_MESSAGE_EXITED);
        }
        result = 0;

        _memset(v2, 0, sizeof(uint32_t) + sizeof(rdVector3) + sizeof(sithSurfaceInfo*) + sizeof(float) + sizeof(rdVector3) + sizeof(void*)); // TODO
        return result;
    }
    v3 = pThing->attachedThing;
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        if ( v3->moveType == SITH_MT_PHYSICS )
        {
            rdVector_Add3Acc(&pThing->physicsParams.vel, &v3->physicsParams.vel);
        }
        else
        {
            if ( v3->moveType != SITH_MT_PATH )
                goto LABEL_8;
            pThing->physicsParams.vel.x = (v3->trackParams.vel.x * v3->trackParams.lerpSpeed) + pThing->physicsParams.vel.x;
            pThing->physicsParams.vel.y = (v3->trackParams.vel.y * v3->trackParams.lerpSpeed) + pThing->physicsParams.vel.y;
            pThing->physicsParams.vel.z = (v3->trackParams.vel.z * v3->trackParams.lerpSpeed) + pThing->physicsParams.vel.z;
        }
    }
LABEL_8:
    if ( (v3->thingflags & SITH_TF_CAPTURED) != 0 && (pThing->thingflags & SITH_TF_INVULN) == 0 )
        sithCog_SendMessageFromThing(v3, pThing, SITH_MESSAGE_EXITED);
    v13 = pThing->parentThing;
    v14 = pThing->childThing;
    if ( v13 )
    {
        v13->childThing = v14;
        if ( v14 )
        {
            v14->parentThing = v13;
            result = 0;
            pThing->parentThing = 0;
            pThing->childThing = 0;
            _memset(v2, 0, sizeof(uint32_t) + sizeof(rdVector3) + sizeof(sithSurfaceInfo*) + sizeof(float) + sizeof(rdVector3) + sizeof(void*));// TODO
            return result;
        }
    }
    else
    {
        v3->attachedParentMaybe = v14;
        if ( v14 )
            v14->parentThing = 0;
    }
    result = 0;
    pThing->parentThing = 0;
    pThing->childThing = 0;
    _memset(v2, 0, sizeof(uint32_t) + sizeof(rdVector3) + sizeof(sithSurfaceInfo*) + sizeof(float) + sizeof(rdVector3) + sizeof(void*));// TODO
    return result;
}

void sithThing_detachallchildren(sithThing* pThing)
{
    sithThing *v1; // eax
    sithThing *v2; // esi

    v1 = pThing->attachedParentMaybe;
    if ( v1 )
    {
        do
        {
            v2 = v1->childThing;
            sithThing_DetachThing(v1);
            v1 = v2;
        }
        while ( v2 );
    }
}

//sithThing_IsAttachFlagsAnd6
//sithThing_LotsOfFreeing

// MOTS altered
int sithThing_Load(sithWorld *pWorld, int a2)
{
    sithThing *v4; // esi
    int v5; // esi
    int v6; // eax
    int v10; // ebx
    sithThing* paThings; // eax
    int v13; // ebx
    int v16; // ecx
    sithThing *v17; // ebp
    sithWorld *v18; // edx
    sithThing *v19; // eax
    int v20; // eax
    sithThing *v21; // esi
    sithThing *v22; // ebx
    int v23; // eax
    sithSector *v24; // edi
    int v26; // ecx
    int v27; // edi
    stdConffileArg *v28; // ebx
    rdVector3 a3; // [esp+14h] [ebp-48h] BYREF
    rdVector3 pos; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+2Ch] [ebp-30h] BYREF
    int v36; // [esp+64h] [ebp+8h]
    int v38; // [esp+64h] [ebp+8h]

    sithThing_bInitted2 = 1;
    if ( a2 && pWorld->things )
    {
        for (v36 = 0; v36 < pWorld->numThingsLoaded; v36++)
        {
            v4 = &pWorld->things[v36];
            if ( v4->type )
            {
                if ( sithNet_isMulti && sithNet_isServer && (v4->thing_id & 0xFFFF0000) == 0 )
                    sithMulti_FreeThing(v4->thing_id);
                sithThing_FreeEverything(v4);
                v5 = v4->thingIdx;
                if ( v5 == sithWorld_pCurrentWorld->numThings )
                {
                    for (v6 = v5 - 1; v6 >= 0; v6--)
                    {
                        if (sithWorld_pCurrentWorld->things[v6].type)
                            break;
                    }
                    sithWorld_pCurrentWorld->numThings = v6;
                }
                sithNet_things[1 + sithNet_thingsIdx++] = v5;
            }
        }
        pSithHS->free(pWorld->things);
        pWorld->things = 0;
        pWorld->numThingsLoaded = 0;
        pWorld->numThings = -1;
    }
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") )
        return 0;
    if ( _strcmp(stdConffile_entry.args[1].value, "things") )
        return 0;
    v10 = _atoi(stdConffile_entry.args[2].value);
    paThings = (sithThing *)pSithHS->alloc(sizeof(sithThing) * v10);

    sithWorld_pCurrentWorld->things = paThings;
    if ( !paThings )
        return 0;
    sithWorld_pCurrentWorld->numThingsLoaded = v10;
    sithNet_thingsIdx = 0;
    for ( v13 = v10 - 1; v13 >= 0; v13--)
    {
        v17 = &sithWorld_pCurrentWorld->things[v13];
        v16 = v17->signature;
        int lvlb = v17->thingIdx;
        _memset(v17, 0, sizeof(sithThing));
        _memcpy(&v17->lookOrientation, &rdroid_identMatrix34, sizeof(v17->lookOrientation));
        rdThing_NewEntry(&v17->rdthing, v17);
        v18 = sithWorld_pCurrentWorld;
        v17->thingIdx = lvlb;
        v19 = &v18->things[v13];
        v17->signature = v16;
        v19->thingIdx = v13;
        v19->thing_id = -1;
        sithThing_netidk2(v13);
    }
    v20 = 0x1000 << jkPlayer_setDiff;
    if ( (g_submodeFlags & 1) != 0 )
        v20 |= 0x8000u;
    else
        v20 |= 0x10000u;
    v38 = v20;
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        v21 = &sithWorld_pCurrentWorld->things[_atoi(stdConffile_entry.args[0].value)];
        v22 = sithTemplate_GetEntryByName(stdConffile_entry.args[1].value);
        if ( stdConffile_entry.numArgs >= 0xAu )
        {
            pos.x = _atof(stdConffile_entry.args[3].value);
            pos.y = _atof(stdConffile_entry.args[4].value);
            pos.z = _atof(stdConffile_entry.args[5].value);
            a3.x = _atof(stdConffile_entry.args[6].value);
            a3.y = _atof(stdConffile_entry.args[7].value);
            a3.z = _atof(stdConffile_entry.args[8].value);
            rdMatrix_BuildRotate34(&a, &a3);
            v23 = _atoi(stdConffile_entry.args[9].value);
            if ( v23 >= 0 && v23 < sithWorld_pCurrentWorld->numSectors )
            {
                v24 = &sithWorld_pCurrentWorld->sectors[v23];
                if ( stdConffile_entry.numArgs >= 11 && (stdConffile_entry.args[10].key == stdConffile_entry.args[10].value)) // MOTS added (w/o comparison)
                {
                    // && (!stdConffile_entry.args[10].key || strlen(stdConffile_entry.args[10].key) == 0)
                    v23 = _atoi(stdConffile_entry.args[10].value);
                    v21->archlightIdx = v23;
                    //printf("%p %p %x\n", , v21->archlightIdx);
                }
                sithThing_sub_4CD8A0(v21, v22);
                sithThing_SetPosAndRot(v21, &pos, &a);
                sithThing_EnterSector(v21, v24, 1, 1);
                sithThing_sub_4CD100(v21);
                v26 = v21->thingIdx;
                v21->signature = sithThing_bInitted2++;
                v21->thing_id = v26;
                v27 = 10;
                if ( stdConffile_entry.numArgs > 10 )
                {
                    v28 = &stdConffile_entry.args[10];
                    do
                    {
                        sithThing_ParseArgs(v28, v21);
                        ++v27;
                        ++v28;
                    }
                    while ( v27 < stdConffile_entry.numArgs );
                }
                if ( (v21->thingflags & v38) != 0 )
                {
                    sithThing_FreeEverything(v21);
                }
                else
                {
                    stdString_SafeStrCopy(v21->template_name, stdConffile_entry.args[2].value, 0x20);
                }
            }
        }
    }
    sithThing_sub_4CCE60();
    return 1;
}

int sithThing_ParseArgs(stdConffileArg *arg, sithThing* pThing)
{
    int v2; // ebp
    int param; // eax
    int paramIdx; // edi
    int v7; // eax
    int v8; // eax

    v2 = 0;
    param = (int)stdHashTable_GetKeyVal(sithThing_paramKeyToParamValMap, arg->key);
    paramIdx = param;
    if ( !param )
        return 0;
    if ( sithThing_LoadThingParam(arg, pThing, param) )
        return 1;
    switch ( pThing->type )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_PLAYER:
            v7 = sithActor_LoadParams(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_WEAPON:
            v7 = sithWeapon_LoadParams(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_ITEM:
            v7 = sithItem_LoadThingParams(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_EXPLOSION:
            v7 = sithExplosion_LoadThingParams(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_PARTICLE:
            v7 = sithParticle_LoadThingParams(arg, pThing, paramIdx);
LABEL_10:
            v2 = v7;
            break;
        default:
            break;
    }
    if ( v2 )
        return 1;
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        v8 = sithPhysics_LoadThingParams(arg, pThing, paramIdx);
    }
    else
    {
        if ( pThing->moveType != SITH_MT_PATH )
            goto LABEL_18;
        v8 = sithTrackThing_LoadPathParams(arg, pThing, paramIdx);
    }
    v2 = v8;
LABEL_18:
    if ( v2 )
        return 1;
    return pThing->thingtype == SITH_THING_ACTOR && sithAI_LoadThingActorParams(arg, pThing, paramIdx);
}

// MOTS altered
int sithThing_LoadThingParam(stdConffileArg *arg, sithThing* pThing, int param)
{
    int v3; // ebp
    const char **v4; // edi
    int v5; // eax
    int32_t v6; // eax
    int32_t v7; // eax
    int result; // eax
    sithAIClass *pAIClass; // eax
    sithActor *pActor; // esi
    int collide; // eax
    double size; // st7
    uint32_t thingType; // eax
    double moveSize; // st7
    double light; // st7
    double lifeLeftSec; // st7
    rdModel3 *pModel; // eax
    rdParticle *pParticle; // edi
    rdSprite *pSprite; // eax
    sithAnimclass *pAnimClass; // eax
    sithCog *pCog; // eax
    rdVector3 orientation; // [esp+10h] [ebp-Ch] BYREF
    uint32_t thingFlags;
    float tmpF;

    switch ( param )
    {
        case THINGPARAM_TYPE:
            v3 = SITH_THING_FREE;
            for (int i = 0; i < NUM_THING_TYPES; i++)
            {
                if (!_strcmp(arg->value, sithThing_aTypes[i]))
                {
                    v3 = i;
                    break;
                }
            }
            v5 = v3;

            pThing->type = v5;
            v6 = v5 - 2;
            if ( v6 )
            {
                v7 = v6 - 4;
                if ( v7 )
                {
                    if ( v7 != 5 )
                        goto LABEL_58;
                    pThing->thingtype = SITH_THING_COG;
                    result = 1;
                }
                else
                {
                    pThing->thingtype = SITH_THING_EXPLOSION;
                    result = 1;
                }
            }
            else
            {
                pThing->thingtype = SITH_THING_ACTOR;
                result = 1;
            }
            break;
        case THINGPARAM_COLLIDE:
            collide = _atoi(arg->value);
            if ( collide < 0 || collide > 3 )
                goto LABEL_59;
            pThing->collide = collide;
            result = 1;
            break;
#ifdef JKM_PARAMS
          case THINGPARAM_TREESIZE:
            tmpF = _atof(arg->value);
            if (tmpF < 0.0) {
              return 0;
            }
            pThing->treeSize = tmpF;
            return 1;
#endif
        case THINGPARAM_MOVE:
            if ( !_strcmp(arg->value, "physics") )
            {
                pThing->moveType = SITH_MT_PHYSICS;
                result = 1;
            }
            else if ( !_strcmp(arg->value, "path") )
            {
                pThing->moveType = SITH_MT_PATH;
                result = 1;
            }
            else
            {
                if ( _strcmp(arg->value, "none") )
                    goto LABEL_59;
                pThing->moveType = SITH_MT_NONE;
                result = 1;
            }
            break;
        case THINGPARAM_SIZE:
            size = _atof(arg->value);
            if ( size < 0.0 )
                goto LABEL_56;
            pThing->moveSize = size;
            pThing->collideSize = size;
            result = 1;
            break;
        case THINGPARAM_THINGFLAGS:
            if ( _sscanf(arg->value, "%x", &thingFlags) != 1 )
                goto LABEL_59;
            pThing->thingflags = thingFlags;
            result = 1;
            break;
        case THINGPARAM_TIMER:
            lifeLeftSec = _atof(arg->value);
            if ( lifeLeftSec < 0.0 )
                goto LABEL_56;
            pThing->lifeLeftMs = (__int64)(lifeLeftSec * 1000.0);
            result = 1;
            break;
        case THINGPARAM_LIGHT:
            light = _atof(arg->value);
            if ( light < 0.0 )
                goto LABEL_56;
            pThing->light = light;
            pThing->lightMin = light;
            pThing->thingflags |= SITH_TF_LIGHT;
            result = 1;
            break;
        case THINGPARAM_SOUNDCLASS:
            pThing->soundclass = sithSoundClass_LoadFile(arg->value);
            result = 1;
            break;
        case THINGPARAM_MODEL3D:
            rdThing_FreeEntry(&pThing->rdthing);
            pModel = sithModel_LoadEntry(arg->value, 0);
            if ( pModel )
            {
                rdThing_SetModel3(&pThing->rdthing, pModel);
                if ( pThing->collideSize == 0.0 )
                    pThing->collideSize = pThing->rdthing.model3->radius;
                if ( pThing->moveSize != 0.0 )
                    goto LABEL_58;
                result = 1;
                pThing->moveSize = pThing->rdthing.model3->radius;
            }
            else
            {
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithThing.c",
                    2540,
                    "Could not load model '%s' specified on line %d.\n",
                    arg->value,
                    stdConffile_linenum);
                result = 0;
            }
            break;
        case THINGPARAM_SPRITE:
            rdThing_FreeEntry(&pThing->rdthing);
            pSprite = sithSprite_LoadEntry(arg->value);
            if ( pSprite )
            {
                rdThing_SetSprite3(&pThing->rdthing, pSprite);
                result = 1;
            }
            else
            {
                stdPrintf(pSithHS->errorPrint, ".\\World\\sithThing.c", 2573, "Could not create sprite %s, line %d.\n", arg->value, stdConffile_linenum);
                result = 0;
            }
            break;
        case THINGPARAM_PUPPET:
            pAnimClass = sithAnimClass_LoadEntry(arg->value);
            pThing->animclass = pAnimClass;
            if ( !pAnimClass || pThing->rdthing.puppet )
                goto LABEL_58;
            rdPuppet_New(&pThing->rdthing);
            result = 1;
            break;
        case THINGPARAM_AICLASS:
            pThing->thingtype = SITH_THING_ACTOR;
            pAIClass = sithAIClass_Load(arg->value);
            pThing->pAIClass = pAIClass;
            pActor = pThing->actor;
            if ( !pActor || !pAIClass )
                goto LABEL_58;
            pActor->pAIClass = pAIClass;
            pActor->numAIClassEntries = pAIClass->numEntries;
            result = 1;
            break;
        case THINGPARAM_COG:
            pCog = sithCog_LoadCogscript(arg->value);
            pThing->class_cog = pCog;
            if ( !pCog )
                return 1;

            // MOTS added
            if (Main_bMotsCompat) {
                pCog->flags |= SITH_COG_CLASS;
                if (pCog->flags & SITH_COG_SERVER) {
                    pCog->flags |= SITH_COG_CLASS | SITH_COG_LOCAL;
                }
            }
            else {
                pCog->flags |= SITH_COG_CLASS | SITH_COG_LOCAL;
            }

            pThing->thingflags |= SITH_TF_CAPTURED;
            result = 1;
            break;
        case THINGPARAM_PARTICLE:
            pParticle = sithParticle_LoadEntry(arg->value);
            if ( !pParticle )
                goto LABEL_58;
            rdThing_FreeEntry(&pThing->rdthing);
            rdThing_SetParticleCloud(&pThing->rdthing, pParticle);
            result = 1;
            break;
        case THINGPARAM_MOVESIZE:
            thingType = pThing->type;
            if ( thingType == SITH_THING_ACTOR || thingType == SITH_THING_PLAYER )
                goto LABEL_58;
            moveSize = _atof(arg->value);
            if ( moveSize < 0.0 )
            {
LABEL_56:
                result = 0;
            }
            else
            {
                pThing->moveSize = moveSize;
                result = 1;
            }
            break;
        case THINGPARAM_CREATETHING:
            pThing->pTemplate = sithTemplate_GetEntryByName(arg->value);
            result = 1;
            break;
        case THINGPARAM_ORIENT:
            if ( _sscanf(arg->value, "(%f/%f/%f)", &orientation, &orientation.y, &orientation.z) == 3 )
            {
                rdMatrix_BuildRotate34(&pThing->lookOrientation, &orientation);
LABEL_58:
                result = 1;
            }
            else
            {
                result = 0;
            }
            break;
        default:
LABEL_59:
            result = 0;
            break;
    }
    return result;
}

//sithThing_TypeIdxFromStr

int sithThing_GetIdxFromThing(sithThing* pThing)
{
    unsigned int v1; // ecx
    int result; // eax

    result = 0;
    if ( pThing )
    {
        v1 = pThing->thingIdx;
        if ( v1 == pThing - sithWorld_pCurrentWorld->things && v1 < (SITH_MAX_THINGS-1) )
            result = 1;
    }
    return result;
}

uint32_t sithThing_Checksum(sithThing* pThing, unsigned int last_hash)
{
    uint32_t hash;

    hash = util_Weirdchecksum((uint8_t *)&pThing->thingflags, sizeof(uint32_t), last_hash);
    hash = util_Weirdchecksum((uint8_t *)&pThing->type, sizeof(uint32_t), hash);
    hash = util_Weirdchecksum((uint8_t *)&pThing->moveType, sizeof(uint32_t), hash);
    hash = util_Weirdchecksum((uint8_t *)&pThing->thingtype, sizeof(uint32_t), hash);

    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.physflags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.airDrag, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.surfaceDrag, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.staticDrag, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.mass, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.height, sizeof(float), hash);
    }
    if ( pThing->type == SITH_THING_ACTOR )
    {
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.typeflags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.health, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.maxHealth, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.jumpSpeed, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.maxThrust, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.maxRotThrust, sizeof(float), hash);
    }
    else if ( pThing->type == SITH_THING_WEAPON )
    {
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.typeflags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.damage, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.unk8, sizeof(uint32_t), hash); // ???
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.mindDamage, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.range, sizeof(float), hash);
    }
    return hash;
}

void sithThing_SetSyncFlags(sithThing *pThing, int flags)
{
    if (!sithComm_multiplayerFlags) return;

    for (uint32_t v3 = 0; v3 < sithNet_syncIdx; v3++)
    {
        if (sithNet_aSyncThings[v3] == pThing) {
            sithNet_aSyncFlags[v3] |= flags;
            return;
        }
    }

    if ( sithNet_syncIdx < SITH_MAX_SYNC_THINGS ) // Added: != -> <
    {
        sithNet_aSyncThings[sithNet_syncIdx] = pThing;
        sithNet_aSyncFlags[sithNet_syncIdx] = flags;
        sithNet_syncIdx++;
    }
}

void sithThing_Sync()
{
    uint32_t v0; // esi
    int v1; // eax


    for (v0 = 0; v0 < sithNet_syncIdx; v0++)
    {
        v1 = sithNet_aSyncFlags[v0];
        if ( (v1 & THING_SYNC_FULL) != 0 )
        {
            // Added: this used to be outside the loop?
            sithDSSThing_SendFullDesc(sithNet_aSyncThings[v0], -1, 255);
            //return; // Removed, this used to stop the loop.
        }
        else
        {
            if ( (v1 & THING_SYNC_STATE) != 0 )
                sithDSSThing_SendSyncThing(sithNet_aSyncThings[v0], -1, 255);

            if ( (sithNet_aSyncFlags[v0] & THING_SYNC_POS) != 0 )
                sithDSSThing_SendPos(sithNet_aSyncThings[v0], -1, 0);
        }

        // Added: Co-op
        if (sithMulti_multiModeFlags & MULTIMODEFLAG_COOP && (v1 & THING_SYNC_AI)) {
            if (sithNet_aSyncThings[v0]->actor && sithNet_aSyncThings[v0]->actor->pAIClass)
                sithDSS_SendAIStatus(sithNet_aSyncThings[v0]->actor, -1, 1);
        }

        // Added: Co-op
        if (sithMulti_multiModeFlags & MULTIMODEFLAG_COOP && (v1 & THING_SYNC_PUPPET)) {
            if (sithNet_aSyncThings[v0]->rdthing.puppet)
                sithDSS_SendSyncPuppet(sithNet_aSyncThings[v0], -1, 255);
        }
    }

    sithNet_syncIdx = 0;
    return;
}

int sithThing_ShouldSync(sithThing* pThing)
{
    if ( pThing->type )
        return !pThing->lifeLeftMs || pThing->type != SITH_THING_DEBRIS && pThing->type != SITH_THING_PARTICLE;

    return 0;
}

int sithThing_netidk2(int a1)
{
    int v1; // eax

    if ( a1 == sithWorld_pCurrentWorld->numThings )
    {
        v1 = a1 - 1;
        for (v1 = a1 - 1; v1 >= 0; v1--)
        {
            if (sithWorld_pCurrentWorld->things[v1].type)
                break;
        }
        sithWorld_pCurrentWorld->numThings = v1;
    }
    sithNet_things[1 + sithNet_thingsIdx++] = a1;
    return sithNet_thingsIdx;
}

//sithThing_Release

int sithThing_Release(sithThing *pThing)
{
    sithCogThingLink *v1; // eax
    sithCogThingLink *v2; // ecx

    v1 = sithCog_aThingLinks;
    v2 = &sithCog_aThingLinks[sithCog_numThingLinks];
    if ( v2 <= sithCog_aThingLinks )
        return 0;
    while ( v1->thing != pThing )
    {
        if ( ++v1 >= v2 )
            return 0;
    }
    return 1;
}

// MOTS added
int sithThing_MotsTick(int param_1,int param_2,float param_3)
{
    if (!Main_bMotsCompat) return 1;

    if (sithCog_pActionCog && (sithCog_actionCogIdk & (1 << (param_1 & 0x1f)))) 
    {
        float fVar1 = sithCog_SendMessageEx(sithCog_pActionCog,SITH_MESSAGE_PLAYERACTION,0,0,0,0,0,(float)param_1,(float)param_2,param_3,0.0);
        if (fVar1 == 0.0) {
            return 0;
        }
    }
    return 1;
}

