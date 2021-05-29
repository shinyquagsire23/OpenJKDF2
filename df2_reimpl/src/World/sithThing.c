#include "sithThing.h"

#include "General/stdHashTable.h"
#include "General/util.h"
#include "World/sithWorld.h"
#include "World/sithActor.h"
#include "World/sithWeapon.h"
#include "World/sithExplosion.h"
#include "World/sithItem.h"
#include "World/sithCorpse.h"
#include "World/sithPlayer.h"
#include "World/sithSector.h"
#include "World/sithTrackThing.h"
#include "World/sithExplosion.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithMulti.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithParticle.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithModel.h"
#include "Engine/sithSprite.h"
#include "Engine/sithNet.h"
#include "Engine/sith.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Cog/sithCog.h"
#include "stdPlatform.h"
#include "jk.h"

#define NUM_THING_PARAMS (72)
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

int sithThing_Startup()
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
            sithParticle_FreeEntry(thingIter);

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

int sithThing_DoesRdThingInit(sithThing *thing)
{
    int v2; // ebp
    int result; // eax
    int thinga; // [esp+14h] [ebp+4h]

    v2 = thing->thingIdx;
    thinga = thing->signature;
    _memset(thing, 0, sizeof(sithThing));
    _memcpy(&thing->lookOrientation, &rdroid_identMatrix34, sizeof(thing->lookOrientation));
    result = rdThing_NewEntry(&thing->rdthing, thing);
    thing->thingIdx = v2;
    thing->signature = thinga;
    return result;
}

sithThing* sithThing_sub_4CD8A0(sithThing *thing, sithThing *a2)
{
    int v3; // ecx
    int v4; // edx
    sithThingFrame *v6; // eax
    int v7; // ecx
    sithThingFrame *v8; // esi
    sithThing *result; // eax
    int v10; // [esp+10h] [ebp-Ch]
    int v11; // [esp+14h] [ebp-8h]
    sithThing *v12; // [esp+18h] [ebp-4h]
    sithThing *thinga; // [esp+20h] [ebp+4h]

    v3 = thing->thing_id;
    v4 = thing->signature;
    thinga = (sithThing *)thing->thingIdx;
    v11 = v3;
    v10 = v4;
    v12 = thing->rdthing.parentSithThing;
    if ( a2 )
    {
        _memcpy(thing, a2, sizeof(sithThing));
        if ( thing->rdthing.type == RD_THINGTYPE_MODEL )
        {
            rdThing_SetModel3(&thing->rdthing, thing->rdthing.model3);
        }
        else if ( thing->rdthing.type == RD_THINGTYPE_PARTICLECLOUD )
        {
            rdThing_SetParticleCloud(&thing->rdthing, thing->rdthing.particlecloud);
        }
        if ( thing->animclass )
            rdPuppet_New(&thing->rdthing);
        if ( thing->move_type == MOVETYPE_PATH && thing->trackParams.frames )
        {
            v6 = (sithThingFrame *)pSithHS->alloc(sizeof(sithThingFrame) * thing->trackParams.numFrames);
            v7 = thing->trackParams.numFrames;
            v8 = a2->trackParams.frames;
            thing->trackParams.frames = v6;
            _memcpy(v6, v8, sizeof(sithThingFrame) * v7);
        }
    }
    else
    {
        _memset(thing, 0, sizeof(sithThing));
        _memcpy(&thing->lookOrientation, &rdroid_identMatrix34, sizeof(thing->lookOrientation));
        rdThing_NewEntry(&thing->rdthing, thing);
        thing->thingIdx = (int)thinga;
        thing->signature = v10;
    }
    thing->thingIdx = (int)thinga;
    result = v12;
    thing->templateBase = a2;
    thing->thing_id = v11;
    thing->signature = v10;
    thing->rdthing.parentSithThing = v12;
    return result;
}

int sithThing_ParseArgs(stdConffileArg *arg, sithThing *thing)
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
    if ( sithThing_LoadThingParam(arg, thing, param) )
        return 1;
    switch ( thing->thingType )
    {
        case THINGTYPE_ACTOR:
        case THINGTYPE_PLAYER:
            v7 = sithThing_LoadActorPlayerParams(arg, thing, paramIdx);
            goto LABEL_10;
        case THINGTYPE_WEAPON:
            v7 = sithWeapon_LoadParams(arg, thing, paramIdx);
            goto LABEL_10;
        case THINGTYPE_ITEM:
            v7 = sithItem_LoadThingParams(arg, thing, paramIdx);
            goto LABEL_10;
        case THINGTYPE_EXPLOSION:
            v7 = sithExplosion_LoadThingParams(arg, thing, paramIdx);
            goto LABEL_10;
        case THINGTYPE_PARTICLE:
            v7 = sithParticle_LoadThingParams(arg, thing, paramIdx);
LABEL_10:
            v2 = v7;
            break;
        default:
            break;
    }
    if ( v2 )
        return 1;
    if ( thing->move_type == MOVETYPE_PHYSICS )
    {
        v8 = sithSector_LoadThingPhysicsParams(arg, thing, paramIdx);
    }
    else
    {
        if ( thing->move_type != MOVETYPE_PATH )
            goto LABEL_18;
        v8 = sithTrackThing_LoadPathParams(arg, thing, paramIdx);
    }
    v2 = v8;
LABEL_18:
    if ( v2 )
        return 1;
    return thing->thingtype == THINGTYPE_ACTOR && sithAI_LoadThingActorParams(arg, thing, paramIdx);
}

int sithThing_LoadThingParam(stdConffileArg *arg, sithThing *thing, int param)
{
    int v3; // ebp
    const char **v4; // edi
    int v5; // eax
    int32_t v6; // eax
    int32_t v7; // eax
    int result; // eax
    char *v9; // ecx
    sithAIClass *v10; // eax
    sithActor *v11; // esi
    int v12; // eax
    double v13; // st7
    int v14; // eax
    double v15; // st7
    double v16; // st7
    int v17; // ecx
    double v18; // st7
    void *v19; // eax
    rdParticle *v20; // edi
    rdSprite *v21; // eax
    sithAnimclass *v22; // eax
    sithCog *v23; // eax
    int v24; // eax
    rdVector3 a3a; // [esp+10h] [ebp-Ch] BYREF

    switch ( param )
    {
        case THINGPARAM_TYPE:
            v3 = THINGTYPE_FREE;
            v4 = (const char **)sithThing_aTypes;
            while ( _strcmp(arg->value, *v4) )
            {
                ++v4;
                ++v3;
                if ( (intptr_t)v4 >= (intptr_t)sithThing_aTypes[NUM_THING_TYPES-1])
                {
                    v5 = THINGTYPE_FREE;
                    goto LABEL_6;
                }
            }
            v5 = v3;
LABEL_6:
            thing->thingType = v5;
            v6 = v5 - 2;
            if ( v6 )
            {
                v7 = v6 - 4;
                if ( v7 )
                {
                    if ( v7 != 5 )
                        goto LABEL_58;
                    thing->thingtype = THINGTYPE_COG;
                    result = 1;
                }
                else
                {
                    thing->thingtype = THINGTYPE_EXPLOSION;
                    result = 1;
                }
            }
            else
            {
                thing->thingtype = THINGTYPE_ACTOR;
                result = 1;
            }
            break;
        case THINGPARAM_COLLIDE:
            v12 = _atoi(arg->value);
            if ( v12 < 0 || v12 > 3 )
                goto LABEL_59;
            thing->collide = v12;
            result = 1;
            break;
        case THINGPARAM_MOVE:
            if ( !_strcmp(arg->value, "physics") )
            {
                thing->move_type = MOVETYPE_PHYSICS;
                result = 1;
            }
            else if ( !_strcmp(arg->value, "path") )
            {
                thing->move_type = MOVETYPE_PATH;
                result = 1;
            }
            else
            {
                if ( _strcmp(arg->value, "none") )
                    goto LABEL_59;
                thing->move_type = MOVETYPE_NONE;
                result = 1;
            }
            break;
        case THINGPARAM_SIZE:
            v13 = _atof(arg->value);
            if ( v13 < 0.0 )
                goto LABEL_56;
            thing->moveSize = v13;
            thing->collideSize = v13;
            result = 1;
            break;
        case THINGPARAM_THINGFLAGS:
            if ( _sscanf(arg->value, "%x", &param) != 1 )
                goto LABEL_59;
            thing->thingflags = param;
            result = 1;
            break;
        case THINGPARAM_TIMER:
            v18 = _atof(arg->value);
            if ( v18 < 0.0 )
                goto LABEL_56;
            thing->lifeLeftMs = (__int64)(v18 * 1000.0);
            result = 1;
            break;
        case THINGPARAM_LIGHT:
            v16 = _atof(arg->value);
            if ( v16 < 0.0 )
                goto LABEL_56;
            v17 = thing->thingflags;
            thing->light = v16;
            thing->lightMin = v16;
            thing->thingflags = v17 | 1;
            result = 1;
            break;
        case THINGPARAM_SOUNDCLASS:
            thing->soundclass = sithSoundClass_LoadFile(arg->value);
            result = 1;
            break;
        case THINGPARAM_MODEL3D:
            rdThing_FreeEntry(&thing->rdthing);
            v19 = sithModel_LoadEntry(arg->value, 0);
            if ( v19 )
            {
                rdThing_SetModel3(&thing->rdthing, (rdModel3 *)v19);
                if ( thing->collideSize == 0.0 )
                    thing->collideSize = thing->rdthing.model3->radius;
                if ( thing->moveSize != 0.0 )
                    goto LABEL_58;
                result = 1;
                thing->moveSize = thing->rdthing.model3->radius;
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
            rdThing_FreeEntry(&thing->rdthing);
            v21 = sithSprite_LoadEntry(arg->value);
            if ( v21 )
            {
                rdThing_SetSprite3(&thing->rdthing, v21);
                result = 1;
            }
            else
            {
                stdPrintf(pSithHS->errorPrint, ".\\World\\sithThing.c", 2573, "Could not create sprite %s, line %d.\n", arg->value, stdConffile_linenum);
                result = 0;
            }
            break;
        case THINGPARAM_PUPPET:
            v22 = sithAnimClass_LoadEntry(arg->value);
            thing->animclass = v22;
            if ( !v22 || thing->rdthing.puppet )
                goto LABEL_58;
            rdPuppet_New(&thing->rdthing);
            result = 1;
            break;
        case THINGPARAM_AICLASS:
            v9 = arg->value;
            thing->thingtype = 2;
            v10 = sithAIClass_Load(v9);
            thing->aiclass = v10;
            v11 = thing->actor;
            if ( !v11 || !v10 )
                goto LABEL_58;
            v11->aiclass = v10;
            v11->numAIClassEntries = v10->numEntries;
            result = 1;
            break;
        case THINGPARAM_COG:
            v23 = sithCog_LoadCogscript(arg->value);
            thing->class_cog = v23;
            if ( !v23 )
                goto LABEL_58;
            v23->flags |= 0x60u;
            thing->thingflags |= SITH_TF_CAPTURED;
            result = 1;
            break;
        case THINGPARAM_PARTICLE:
            v20 = sithParticle_LoadEntry(arg->value);
            if ( !v20 )
                goto LABEL_58;
            rdThing_FreeEntry(&thing->rdthing);
            rdThing_SetParticleCloud(&thing->rdthing, v20);
            result = 1;
            break;
        case THINGPARAM_MOVESIZE:
            v14 = thing->thingType;
            if ( v14 == THINGTYPE_ACTOR || v14 == THINGTYPE_PLAYER )
                goto LABEL_58;
            v15 = _atof(arg->value);
            if ( v15 < 0.0 )
            {
LABEL_56:
                result = 0;
            }
            else
            {
                thing->moveSize = v15;
                result = 1;
            }
            break;
        case THINGPARAM_CREATETHING:
            thing->template = sithTemplate_GetEntryByName(arg->value);
            result = 1;
            break;
        case THINGPARAM_ORIENT:
            if ( _sscanf(arg->value, "(%f/%f/%f)", &a3a, &a3a.y, &a3a.z) == 3 )
            {
                rdMatrix_BuildRotate34(&thing->lookOrientation, &a3a);
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

uint32_t sithThing_Checksum(sithThing *thing, unsigned int last_hash)
{
    uint32_t hash;

    hash = util_Weirdchecksum((uint8_t *)&thing->thingflags, sizeof(uint32_t), last_hash);
    hash = util_Weirdchecksum((uint8_t *)&thing->thingType, sizeof(uint32_t), hash);
    hash = util_Weirdchecksum((uint8_t *)&thing->move_type, sizeof(uint32_t), hash);
    hash = util_Weirdchecksum((uint8_t *)&thing->thingtype, sizeof(uint32_t), hash);

    if ( thing->move_type == MOVETYPE_PHYSICS )
    {
        hash = util_Weirdchecksum((uint8_t *)&thing->physicsParams.physflags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->physicsParams.airDrag, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->physicsParams.surfaceDrag, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->physicsParams.staticDrag, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->physicsParams.mass, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->physicsParams.height, sizeof(float), hash);
    }
    if ( thing->thingType == THINGTYPE_ACTOR )
    {
        hash = util_Weirdchecksum((uint8_t *)&thing->actorParams.typeflags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->actorParams.health, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->actorParams.maxHealth, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->actorParams.jumpSpeed, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->actorParams.maxThrust, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->actorParams.maxRotThrust, sizeof(float), hash);
    }
    else if ( thing->thingType == THINGTYPE_WEAPON )
    {
        hash = util_Weirdchecksum((uint8_t *)&thing->weaponParams.typeflags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->weaponParams.damage, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->weaponParams.unk8, sizeof(uint32_t), hash); // ???
        hash = util_Weirdchecksum((uint8_t *)&thing->weaponParams.mindDamage, sizeof(float), hash);
        hash = util_Weirdchecksum((uint8_t *)&thing->weaponParams.range, sizeof(float), hash);
    }
    return hash;
}
