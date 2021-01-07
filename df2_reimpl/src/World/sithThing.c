#include "sithThing.h"

#include "General/stdHashTable.h"
#include "World/sithWorld.h"
#include "World/sithActor.h"
#include "World/sithWeapon.h"
#include "World/sithExplosion.h"
#include "World/sithItem.h"
#include "World/sithCorpse.h"
#include "World/sithPlayer.h"
#include "World/sithSector.h"
#include "World/sithTrackThing.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithMulti.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithParticle.h"
#include "Engine/sithNet.h"
#include "Engine/sith.h"
#include "AI/sithAI.h"
#include "Cog/sithCog.h"
#include "jk.h"

#define NUM_THING_PARAMS (72)

int sithThing_bInitted;
int sithThing_bInitted2;

char* sithThing_aParams[NUM_THING_PARAMS] = {
    "type",
    "collide",
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

void sithThing_Startup()
{
    int v1; // edi
    const char **v2; // esi

    if ( !sithThing_bInitted )
    {
        sithThing_paramKeyToParamValMap = stdHashTable_New(146);
        if ( sithThing_paramKeyToParamValMap )
        {
            v1 = 1;
            v2 = (const char **)sithThing_aParams;
            while ( 1 )
            {
                stdHashTable_SetKeyVal(sithThing_paramKeyToParamValMap, *v2++, (void *)v1++);
                if ( (int)v2 >= (int)&sithThing_aParams[NUM_THING_PARAMS] )
                    break;
            }
            sithThing_bInitted2 = 1;
            sithThing_bInitted = 1;
        }
    }
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

void sithThing_TickAll(float deltaSeconds, int deltaMs)
{
    sithThing *thingIter; // esi
    sithWorld *v6; // edi
    int v7; // edx
    int v8; // eax
    int v9; // eax
    int v11; // eax

    if ( sithWorld_pCurWorld->numThings < 0 )
        return;

    for (int i = 0; i < sithWorld_pCurWorld->numThings+1; i++)
    {
        thingIter = &sithWorld_pCurWorld->things[i];
        if (!thingIter->thingType)
            continue;

        if (!(thingIter->thingflags & SITH_TF_WILLBEREMOVED))
        {
            if ( thingIter->lifeLeftMs )
            {
                if ( thingIter->lifeLeftMs > deltaMs )
                {
                    thingIter->lifeLeftMs -= deltaMs;
                }
                else
                {
                    sithThing_Remove(thingIter);
                }
            }

            if ( (thingIter->thingflags & SITH_TF_DISABLED) != 0 )
                continue;

            if ( (thingIter->thingflags & (SITH_TF_TIMER|SITH_TF_PULSE)) != 0 )
                sithCog_HandleThingTimerPulse(thingIter);

            switch ( thingIter->thingtype )
            {
                case THINGTYPE_ACTOR:
                    sithAI_Tick(thingIter, deltaSeconds);
                    break;
                case THINGTYPE_EXPLOSION:
                    sithExplosion_Tick(thingIter);
                    break;
                case THINGTYPE_COG:
                    sithParticle_Tick(thingIter, deltaSeconds);
                    break;
            }

            switch ( thingIter->thingType )
            {
                case THINGTYPE_PLAYER:
                    sithPlayer_Tick(thingIter->actorParams.playerinfo, deltaSeconds);
                case THINGTYPE_ACTOR:
                    sithActor_Tick(thingIter, deltaMs);
                    break;
                case THINGTYPE_WEAPON:
                    sithWeapon_Tick(thingIter, deltaSeconds);
                    break;
            }
            if ( sithThing_handler && thingIter->jkFlags )
                sithThing_handler(thingIter);
            if ( thingIter->move_type == MOVETYPE_PHYSICS )
            {
                sithSector_ThingPhysicsTick(thingIter, deltaSeconds);
            }
            else if ( thingIter->move_type == MOVETYPE_PATH )
            {
                sithTrackThing_Tick(thingIter, deltaSeconds);
            }
            sithThing_TickPhysics(thingIter, deltaSeconds);
            sithPuppet_Tick(thingIter, deltaSeconds);
            continue;
        }

        if ( net_isMulti && net_isServer && (thingIter->thing_id & 0xFFFF0000) == 0 )
            sithMulti_FreeThing(thingIter->thing_id);

        if ( thingIter->attach_flags )
            sithThing_DetachThing(thingIter);

        if ( thingIter->sector )
            sithThing_LeaveSector(thingIter);

        if ( thingIter->move_type == MOVETYPE_PATH && thingIter->trackParams.frames )
            pSithHS->free(thingIter->trackParams.frames);

        if ( thingIter->thingtype == THINGTYPE_ACTOR )
            sithAI_FreeEntry(thingIter);

        if ( thingIter->thingType == THINGTYPE_PARTICLE )
            sithParticle_Free(thingIter);

        if ( thingIter->animclass )
            sithPuppet_FreeEntry(thingIter);

        rdThing_FreeEntry(&thingIter->rdthing);
        sithSoundSys_FreeThing(thingIter);

        v7 = thingIter->thingIdx;
        thingIter->thingType = THINGTYPE_FREE;
        v8 = sithWorld_pCurWorld->numThings;
        thingIter->signature = 0;
        thingIter->thing_id = -1;
        if ( v7 == v8 )
        {
            v9 = v7 - 1;
            if ( v7 - 1 >= 0 )
            {
                do
                {
                    if (sithWorld_pCurWorld->things[v9].thingType)
                        break;
                    --v9;
                }
                while ( v9 >= 0 );
            }
            sithWorld_pCurWorld->numThings = v9;
        }
        v11 = net_things_idx;
        net_things[net_things_idx] = v7;
        net_things_idx = v11 + 1;
    }
}

void sithThing_Remove(sithThing *thing)
{
    switch ( thing->thingType )
    {
        case THINGTYPE_ACTOR:
            sithActor_Remove(thing);
            break;
        case THINGTYPE_WEAPON:
            sithWeapon_Remove(thing);
            break;
        case THINGTYPE_ITEM:
            sithItem_Remove(thing);
            break;
        case THINGTYPE_CORPSE:
            sithCorpse_Remove(thing);
            break;
        case THINGTYPE_PLAYER:
            return;
        case THINGTYPE_PARTICLE:
            sithParticle_Remove(thing);
            break;
        default:
            thing->thingflags |= SITH_TF_WILLBEREMOVED;
            if (thing->thingflags & SITH_TF_CAPTURED && !(thing->thingflags & SITH_TF_INVULN))
                sithCog_SendMessageFromThing(thing, 0, SITH_MESSAGE_REMOVED);
            break;
    }
}

sithThing* sithThing_GetParent(sithThing *thing)
{
    sithThing *result; // eax
    sithThing *i; // ecx

    result = thing;
    for ( i = thing->prev_thing; i; i = i->prev_thing )
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

    if ( idx < 0 || idx >= sithWorld_pCurWorld->numThingsLoaded || (result = &sithWorld_pCurWorld->things[idx], result->thingType == THINGTYPE_FREE) )
        result = 0;
    return result;
}
