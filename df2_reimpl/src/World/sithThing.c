#include "sithThing.h"

#include "General/stdHashTable.h"
#include "General/util.h"
#include "World/jkPlayer.h"
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
#include "Engine/sithTemplate.h"
#include "Engine/sithParticle.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithModel.h"
#include "Engine/sithSprite.h"
#include "Engine/sithNet.h"
#include "Engine/sith.h"
#include "Main/jkGame.h"
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

void sithThing_sub_4CCE60()
{
    int v1; // edx
    int *v2; // ebp
    int v6; // eax
    int v8; // ecx

    net_things_idx = 0;
    sithWorld_pCurWorld->numThings = -1;
    v2 = net_things;
    for (v1 = sithWorld_pCurWorld->numThingsLoaded - 1; v1 >= 0; v1--)
    {
        if ( sithWorld_pCurWorld->things[v1].thingType )
        {
            if ( v1 > sithWorld_pCurWorld->numThings )
                sithWorld_pCurWorld->numThings = v1;
        }
        else
        {
            if ( v1 == sithWorld_pCurWorld->numThings )
            {
                for (v6 = v1-1; v6 >= 0; v6--)
                {
                    if (sithWorld_pCurWorld->things[v6].thingType)
                        break;
                    --v6;
                }
                sithWorld_pCurWorld->numThings = v6;
            }
            *v2++ = v1;
            net_things_idx++;
        }
    }
}

void sithThing_FreeEverything(sithThing *thing)
{
    if ( thing->attach_flags )
        sithThing_DetachThing(thing);
    if ( thing->sector )
        sithThing_LeaveSector(thing);
    if ( thing->move_type == MOVETYPE_PATH && thing->trackParams.frames )
        pSithHS->free(thing->trackParams.frames);
    if ( thing->thingtype == THINGTYPE_ACTOR )
        sithAI_FreeEntry(thing);
    if ( thing->thingType == THINGTYPE_PARTICLE )
        sithParticle_FreeEntry(thing);
    if ( thing->animclass )
        sithPuppet_FreeEntry(thing);
    rdThing_FreeEntry(&thing->rdthing);
    sithSoundSys_FreeThing(thing);
    thing->thingType = THINGTYPE_FREE;
    thing->signature = 0;
    thing->thing_id = -1;
}

void sithThing_sub_4CD100(sithThing *thing)
{
    switch ( thing->thingType )
    {
        case THINGTYPE_ITEM:
            sithItem_New(thing);
            break;
        case THINGTYPE_EXPLOSION:
            sithExplosion_CreateThing(thing);
            break;
        case THINGTYPE_PARTICLE:
            sithParticle_CreateThing(thing);
            break;
    }
    if ( thing->rdthing.puppet )
        sithPuppet_NewEntry(thing);
    if ( thing->thingtype == THINGTYPE_ACTOR )
        sithAI_NewEntry(thing);
    if ( thing->soundclass )
        sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_CREATE);
    if ( (sithWorld_pCurWorld->level_type_maybe & 2) != 0
      && thing->move_type == MOVETYPE_PHYSICS
      && (thing->physicsParams.physflags & (PHYSFLAGS_WALLSTICK|PHYSFLAGS_FLOORSTICK)) != 0 )
    {
        sithSector_ThingLandIdk(thing, 1);
    }
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

int sithThing_Load(sithWorld *world, int a2)
{
    sithThing *v4; // esi
    int v5; // esi
    int v6; // eax
    int v10; // ebx
    sithThing *things; // eax
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
    int v25; // eax
    int v26; // ecx
    int v27; // edi
    stdConffileArg *v28; // ebx
    rdVector3 a3; // [esp+14h] [ebp-48h] BYREF
    rdVector3 pos; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+2Ch] [ebp-30h] BYREF
    int v36; // [esp+64h] [ebp+8h]
    int v38; // [esp+64h] [ebp+8h]

    sithThing_bInitted2 = 1;
    if ( a2 && world->things )
    {
        for (v36 = 0; v36 < world->numThingsLoaded; v36++)
        {
            v4 = &world->things[v36];
            if ( v4->thingType )
            {
                if ( net_isMulti && net_isServer && (v4->thing_id & 0xFFFF0000) == 0 )
                    sithMulti_FreeThing(v4->thing_id);
                sithThing_FreeEverything(v4);
                v5 = v4->thingIdx;
                if ( v5 == sithWorld_pCurWorld->numThings )
                {
                    for (v6 = v5 - 1; v6 >= 0; v6--)
                    {
                        if (sithWorld_pCurWorld->things[v6].thingType)
                            break;
                    }
                    sithWorld_pCurWorld->numThings = v6;
                }
                net_things[net_things_idx++] = v5;
            }
        }
        pSithHS->free(world->things);
        world->things = 0;
        world->numThingsLoaded = 0;
        world->numThings = -1;
    }
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") )
        return 0;
    if ( _strcmp(stdConffile_entry.args[1].value, "things") )
        return 0;
    v10 = _atoi(stdConffile_entry.args[2].value);
    things = (sithThing *)pSithHS->alloc(sizeof(sithThing) * v10);

    sithWorld_pCurWorld->things = things;
    if ( !things )
        return 0;
    sithWorld_pCurWorld->numThingsLoaded = v10;
    net_things_idx = 0;
    for ( v13 = v10 - 1; v13 >= 0; v13--)
    {
        v17 = &sithWorld_pCurWorld->things[v13];
        v16 = v17->signature;
        int lvlb = v17->thingIdx;
        _memset(v17, 0, sizeof(sithThing));
        _memcpy(&v17->lookOrientation, &rdroid_identMatrix34, sizeof(v17->lookOrientation));
        rdThing_NewEntry(&v17->rdthing, v17);
        v18 = sithWorld_pCurWorld;
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
        v21 = &sithWorld_pCurWorld->things[_atoi(stdConffile_entry.args[0].value)];
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
            if ( v23 >= 0 && v23 < sithWorld_pCurWorld->numSectors )
            {
                v24 = &sithWorld_pCurWorld->sectors[v23];
                sithThing_sub_4CD8A0(v21, v22);
                sithThing_SetPosAndRot(v21, &pos, &a);
                sithThing_EnterSector(v21, v24, 1, 1);
                sithThing_sub_4CD100(v21);
                v25 = sithThing_bInitted2;
                v26 = v21->thingIdx;
                v21->signature = sithThing_bInitted2;
                v21->thing_id = v26;
                sithThing_bInitted2 = v25 + 1;
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
                    _strncpy(v21->template_name, stdConffile_entry.args[2].value, 0x1Fu);
                    v21->template_name[31] = 0;
                }
            }
        }
    }
    sithThing_sub_4CCE60();
    return 1;
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
    double v18; // st7
    void *v19; // eax
    rdParticle *v20; // edi
    rdSprite *v21; // eax
    sithAnimclass *v22; // eax
    sithCog *v23; // eax
    int v24; // eax
    rdVector3 a3a; // [esp+10h] [ebp-Ch] BYREF
    int tmpInt;

    switch ( param )
    {
        case THINGPARAM_TYPE:
            v3 = THINGTYPE_FREE;
            for (int i = 0; i < NUM_THING_TYPES; i++)
            {
                if (!_strcmp(arg->value, sithThing_aTypes[i]))
                {
                    v3 = i;
                    break;
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
            if ( _sscanf(arg->value, "%x", &tmpInt) != 1 )
                goto LABEL_59;
            thing->thingflags = tmpInt;
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
            thing->light = v16;
            thing->lightMin = v16;
            thing->thingflags |= 1;
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

int sithThing_LoadActorPlayerParams(stdConffileArg *arg, sithThing *thing, unsigned int param)
{
    sithThing *v3; // eax
    int result; // eax
    sithThing *v5; // eax
    double v6; // st7
    double v9; // st7
    double v10; // st7
    double v11; // st7
    double v12; // st7
    int v13; // eax
    sithThing *v14; // esi
    sithThing *v16; // eax
    sithThing *v18; // eax
    double v19; // st7
    double v20; // st7
    double v21; // st7
    float tmp;
    int tmpInt;

    switch ( param )
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(arg->value, "%x", &tmpInt) != 1 )
                goto LABEL_38;
            thing->actorParams.typeflags = tmpInt;
            return 1;
        case THINGPARAM_HEALTH:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                goto LABEL_38;

            thing->weaponParams.damageClass = (int)arg;
            if ( tmp < (double)thing->actorParams.maxHealth )
                thing->actorParams.maxHealth = thing->actorParams.maxHealth;
            else
                thing->actorParams.maxHealth = tmp;
            return 1;
        case THINGPARAM_MAXTHRUST:
            v10 = _atof(arg->value);
            if ( v10 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.maxThrust = v10;
            return result;
        case THINGPARAM_MAXROTTHRUST:
            v11 = _atof(arg->value);
            if ( v11 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.maxRotThrust = v11;
            return result;
        case THINGPARAM_JUMPSPEED:
            v12 = _atof(arg->value);
            if ( v12 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.jumpSpeed = v12;
            return result;
        case THINGPARAM_WEAPON:
            v3 = sithTemplate_GetEntryByName(arg->value);
            thing->actorParams.templateWeapon = v3;
            return 1;
        case THINGPARAM_WEAPON2:
            v5 = sithTemplate_GetEntryByName(arg->value);
            thing->actorParams.templateWeapon2 = v5;
            return 1;
        case THINGPARAM_EXPLODE:
            v18 = sithTemplate_GetEntryByName(arg->value);
            thing->actorParams.templateExplode = v18;
            return 1;
        case THINGPARAM_MAXHEALTH:
            v9 = _atof(arg->value);
            if ( v9 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.maxHealth = v9;
            return result;
        case THINGPARAM_EYEOFFSET:
            v13 = _sscanf(
                      arg->value,
                      "(%f/%f/%f)",
                      &thing->actorParams.eyeOffset.x,
                      &thing->actorParams.eyeOffset.y,
                      &thing->actorParams.eyeOffset.z);
            goto LABEL_25;
        case THINGPARAM_MINHEADPITCH:
            result = _sscanf(arg->value, "%f", &tmp);
            if ( result != 1 )
                goto LABEL_38;
            thing->actorParams.minHeadPitch = tmp;
            break;
        case THINGPARAM_MAXHEADPITCH:
            result = _sscanf(arg->value, "%f", &tmp);
            if ( result != 1 )
                goto LABEL_38;
            thing->actorParams.maxHeadPitch = tmp;
            break;
        case THINGPARAM_FIREOFFSET:
            v13 = _sscanf(
                      arg->value,
                      "(%f/%f/%f)",
                      &thing->actorParams.fireOffset.x,
                      &thing->actorParams.fireOffset.y,
                      &thing->actorParams.fireOffset.z);
LABEL_25:
            if ( v13 != 3 )
                goto LABEL_38;
            result = 1;
            break;
        case THINGPARAM_LIGHTOFFSET:
            v14 = thing;
            if ( _sscanf(
                     arg->value,
                     "(%f/%f/%f)",
                     &thing->actorParams.lightOffset.x,
                     &thing->actorParams.lightOffset.y,
                     &thing->actorParams.lightOffset.z) != 3 )
                goto LABEL_38;
            v14->thingflags |= SITH_TF_LIGHT;
            result = 1;
            break;
        case THINGPARAM_LIGHTINTENSITY:
            if ( _sscanf(arg->value, "%f", &tmp) != 1 )
                return 0;
            v16 = thing;
            thing->actorParams.lightIntensity = tmp;
            v16->thingflags |= SITH_TF_LIGHT;
            return 1;
        case THINGPARAM_ERROR:
            v19 = _atof(arg->value);
            thing->actorParams.error = v19;
            return 1;
        case THINGPARAM_FOV:
            v20 = _atof(arg->value);
            thing->actorParams.fov = v20;
            return 1;
        case THINGPARAM_CHANCE:
            v21 = _atof(arg->value);
            thing->actorParams.chance = v21;
            return 1;
        default:
LABEL_38:
            result = 0;
            break;
    }
    return result;
}

void sithThing_SetPosAndRot(sithThing *this, rdVector3 *pos, rdMatrix34 *rot)
{
    rdVector_Copy3(&this->position, pos);
    rdMatrix_Copy34(&this->lookOrientation, rot);
    rdVector_Zero3(&this->lookOrientation.scale);
}

void sithThing_LeaveSector(sithThing *thing)
{
    sithSector *sector; // eax
    sithThing *prevThing; // ecx
    sithThing *nextThing; // eax
    rdVector3 pos; // [esp+Ch] [ebp-Ch] BYREF

    sector = thing->sector;
    if ( (sector->flags & 4) == 0 )
        goto LABEL_5;
    pos = thing->position;
    if ( (thing->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SendMessageFromSector(sector, thing, SITH_MESSAGE_EXITED);
    if ( !_memcmp(&pos, &thing->position, sizeof(rdVector3)) )
    {
LABEL_5:
        prevThing = thing->prevThing;
        nextThing = thing->nextThing;
        if ( prevThing )
        {
            prevThing->nextThing = nextThing;
            if ( nextThing )
                nextThing->prevThing = prevThing;
        }
        else
        {
            thing->sector->thingsList = nextThing;
            if ( nextThing )
            {
                nextThing->prevThing = 0;
                thing->sector = 0;
                thing->prevThing = 0;
                thing->nextThing = 0;
                return;
            }
        }
        thing->sector = 0;
        thing->prevThing = 0;
        thing->nextThing = 0;
    }
}

void sithThing_EnterSector(sithThing *thing, sithSector *sector, int a3, int a4)
{
    sithThing *v4; // ecx
    char v5; // cl
    int v6; // eax
    sithSector *v7; // eax

    v4 = sector->thingsList;
    thing->nextThing = v4;
    if ( v4 )
        v4->prevThing = thing;
    v5 = sector->flags;
    thing->prevThing = 0;
    sector->thingsList = thing;
    thing->sector = sector;
    if ( (v5 & SITH_SF_UNDERWATER) != 0 )
    {
        v6 = thing->attach_flags;
        if ( v6 && (v6 & 8) == 0 && thing->move_type == MOVETYPE_PHYSICS )
            sithThing_DetachThing(thing);
        if ( (thing->thingflags & SITH_TF_WATER) == 0 )
            sithThing_EnterWater(thing, a3 | a4);
    }
    else if ( (thing->thingflags & SITH_TF_WATER) != 0 )
    {
        sithThing_ExitWater(thing, a3 | a4);
    }
    if ( !a4 )
    {
        v7 = thing->sector;
        if ( (v7->flags & SITH_SF_COGLINKED) != 0 && (thing->thingflags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
            sithCog_SendMessageFromSector(v7, thing, SITH_MESSAGE_ENTERED);
    }
}

void sithThing_EnterWater(sithThing *thing, int a2)
{
    sithAnimclass *v2; // eax
    sithThing *v4; // ecx
    sithCog *v5; // eax
    sithCog *v6; // eax

    v2 = thing->animclass;
    thing->thingflags |= SITH_TF_WATER;
    if ( v2 )
        sithPuppet_sub_4E4760(thing, 1);
    if ( (thing->thingflags & SITH_TF_DROWNS) != 0 )
    {
        thing->thingflags |= SITH_TF_WILLBEREMOVED;
        if ( (thing->thingflags & SITH_TF_CAPTURED) != 0 && (thing->thingflags & SITH_TF_INVULN) == 0 )
            sithCog_SendMessageFromThing(thing, 0, SITH_MESSAGE_REMOVED);
    }
    else if ( !a2 )
    {
        if ( thing->soundclass )
        {
            if ( thing->move_type == MOVETYPE_PHYSICS && thing->physicsParams.vel.z > -1.0 )
                sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_ENTERWATERSLOW);
            else
                sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_ENTERWATER);
        }
        v4 = g_localPlayerThing;
        if ( g_localPlayerThing && (thing->thingflags & SITH_TF_SPLASHES) != 0 && (thing->thingflags & SITH_TF_INVULN) == 0 )
        {
            v5 = g_localPlayerThing->class_cog;
            if ( v5 )
            {
                sithCog_SendMessage(v5, SITH_MESSAGE_SPLASH, SENDERTYPE_THING, thing->thingIdx, 0, 1, 0);
                v4 = g_localPlayerThing;
            }
            v6 = v4->capture_cog;
            if ( v6 )
                sithCog_SendMessage(v6, SITH_MESSAGE_SPLASH, SENDERTYPE_THING, thing->thingIdx, 0, 1, 0);
        }
        if ( thing->move_type == MOVETYPE_PHYSICS )
            thing->physicsParams.vel.z = thing->physicsParams.vel.z * 0.25;
    }
}

void sithThing_ExitWater(sithThing *thing, int a2)
{
    thing->thingflags &= ~SITH_TF_WATER;
    if ( thing->animclass )
        sithPuppet_sub_4E4760(thing, 0);

    if ( thing->soundclass )
    {
        if ( thing->move_type == MOVETYPE_PHYSICS && rdVector_Len3(&thing->physicsParams.vel) < 1.0 )
            sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_EXITWATERSLOW);
        else
            sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_EXITWATER);
    }

    if ( (thing->thingflags & SITH_TF_WATERCREATURE) != 0 )
    {
        thing->thingflags |= SITH_TF_WILLBEREMOVED;
        if ( (thing->thingflags & SITH_TF_CAPTURED) != 0 && (thing->thingflags & SITH_TF_INVULN) == 0 )
            sithCog_SendMessageFromThing(thing, 0, SITH_MESSAGE_REMOVED);
    }
    else if ( !a2 )
    {
        if ( g_localPlayerThing )
        {
            if ( (thing->thingflags & SITH_TF_SPLASHES) != 0 && (thing->thingflags & SITH_TF_INVULN) == 0 )
            {
                if ( g_localPlayerThing->class_cog )
                {
                    sithCog_SendMessage(g_localPlayerThing->class_cog, SITH_MESSAGE_SPLASH, 3, thing->thingIdx, 0, 0, 0);
                }

                if ( g_localPlayerThing->capture_cog )
                {
                    sithCog_SendMessage(g_localPlayerThing->capture_cog, SITH_MESSAGE_SPLASH, 3, thing->thingIdx, 0, 0, 0);
                }
            }
        }
    }
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

int sithThing_netidk2(int a1)
{
    int v1; // eax

    if ( a1 == sithWorld_pCurWorld->numThings )
    {
        v1 = a1 - 1;
        for (v1 = a1 - 1; v1 >= 0; v1--)
        {
            if (sithWorld_pCurWorld->things[v1].thingType)
                break;
        }
        sithWorld_pCurWorld->numThings = v1;
    }
    net_things[net_things_idx++] = a1;
    return net_things_idx;
}
