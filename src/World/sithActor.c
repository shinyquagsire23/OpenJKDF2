#include "sithActor.h"

#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "World/jkPlayer.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithNet.h"
#include "Engine/sithPhysics.h"
#include "Cog/sithCogVm.h"
#include "Cog/sithCog.h"
#include "Dss/sithDSSThing.h"
#include "jk.h"

static int lastDoorOpenTime = 0;

void sithActor_Tick(sithThing *thing, int deltaMs)
{
    unsigned int v2; // eax
    unsigned int v3; // eax

    if ( (thing->actorParams.typeflags & THING_TYPEFLAGS_40) == 0 && (thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 || (thing->sector->flags & SITH_SF_UNDERWATER) == 0 )
        {
            v3 = thing->actorParams.msUnderwater;
            if ( v3 )
            {
                if ( v3 <= 18000 )
                {
                    if ( v3 > 10000 )
                        sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_BREATH);
                }
                else
                {
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_GASP);
                }
                thing->actorParams.msUnderwater = 0;
            }
        }
        else
        {
            v2 = deltaMs + thing->actorParams.msUnderwater;
            thing->actorParams.msUnderwater = v2;
            if ( v2 > 20000 )
            {
                sithThing_Damage(thing, thing, 10.0, 32);
                thing->actorParams.msUnderwater -= 2000;
            }
        }
    }
}

void sithActor_JumpWithVel(sithThing *thing, float vel)
{
    double final_vel;
    int isAttached; // zf
    sithSurface *attachedSurface; // eax
    int v12; // eax
    int jumpSound; // edi
    int v14; // eax
    sithSoundClass *v15; // eax

    if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && (thing->actorParams.typeflags & THING_TYPEFLAGS_40000) == 0 )
    {
        final_vel = thing->actorParams.jumpSpeed * vel;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING) != 0 )
            final_vel = final_vel * 0.69999999;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 )
        {
            thing->physicsParams.vel.x = 0.0 * final_vel + thing->physicsParams.vel.x;
            thing->physicsParams.vel.y = 0.0 * final_vel + thing->physicsParams.vel.y;
            thing->physicsParams.vel.z = 1.0 * final_vel + thing->physicsParams.vel.z;
            thing->physicsParams.physflags &= ~PHYSFLAGS_MIDAIR;
        }
        else
        {
            if ( !thing->attach_flags )
                return;
            isAttached = (thing->attach_flags & (ATTACHFLAGS_THING|ATTACHFLAGS_THINGSURFACE)) == 0;
            attachedSurface = thing->attachedSurface;
            thing->physicsParams.vel.x = 0.0 * final_vel + thing->physicsParams.vel.x;
            thing->physicsParams.vel.y = 0.0 * final_vel + thing->physicsParams.vel.y;
            thing->physicsParams.vel.z = 1.0 * final_vel + thing->physicsParams.vel.z;
            if ( isAttached )
            {
                v14 = attachedSurface->surfaceFlags;
                if ( (v14 & (SURFACEFLAGS_100000|SURFACEFLAGS_EARTH|SURFACEFLAGS_PUDDLE|SURFACEFLAGS_WATER|SURFACEFLAGS_METAL)) != 0 )
                {
                    if ( (v14 & SURFACEFLAGS_METAL) != 0 )
                    {
                        jumpSound = SITH_SC_JUMPMETAL;
                    }
                    else if ( (v14 & SURFACEFLAGS_WATER) != 0 )
                    {
                        jumpSound = SITH_SC_JUMPWATER;
                    }
                    else if ( (v14 & SURFACEFLAGS_PUDDLE) != 0 )
                    {
                        jumpSound = SITH_SC_JUMPWATER;
                    }
                    else
                    {
                        jumpSound = (v14 & SURFACEFLAGS_EARTH) != 0 ? SITH_SC_JUMPEARTH : SITH_SC_JUMP;
                    }
                }
                else
                {
                    jumpSound = SITH_SC_JUMP;
                }
            }
            else
            {
                v12 = attachedSurface->field_0;
                if ( (v12 & SITH_TF_METAL) != 0 )
                    jumpSound = SITH_SC_JUMPMETAL;
                else
                    jumpSound = (0x800000 & v12) != 0 ? SITH_SC_JUMPEARTH : SITH_SC_JUMP;
            }
            v15 = sithSoundClass_ThingPlaySoundclass(thing, jumpSound);
            if ( v15 && sithCogVm_multiplayerFlags )
                sithDSSThing_SoundClassPlay(thing, jumpSound, (int)v15->entries[14], -1.0);
            sithThing_DetachThing(thing);
        }
        if ( sithCogVm_multiplayerFlags )
            sithThing_SyncThingPos(thing, 1);
    }
}

void sithActor_cogMsg_OpenDoor(sithThing *thing)
{
    sithSector *v4; // esi
    int v5; // eax
    sithCollisionSearchEntry *searchResult; // eax
    sithThing *v7; // edx
    float a6; // [esp+0h] [ebp-58h]
    rdVector3 thingPos; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+28h] [ebp-30h] BYREF

    if ( !sithNet_isMulti || lastDoorOpenTime + 250 <= sithTime_curMsAbsolute )
    {
        lastDoorOpenTime = sithTime_curMsAbsolute;
        _memcpy(&out, &thing->lookOrientation, sizeof(out));
        thingPos.x = thing->position.x;
        thingPos.y = thing->position.y;
        thingPos.z = thing->position.z;
        if ( thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER )
        {
            rdMatrix_PreRotate34(&out, &thing->actorParams.eyePYR);
            thingPos.x = thing->actorParams.eyeOffset.x + thingPos.x;
            thingPos.y = thing->actorParams.eyeOffset.y + thingPos.y;;
            thingPos.z = thing->actorParams.eyeOffset.z + thingPos.z;
        }
        v4 = sithCollision_GetSectorLookAt(thing->sector, &thing->position, &thingPos, 0.0);
        if ( v4 )
        {
            v5 = sithPuppet_PlayMode(thing, SITH_ANIM_ACTIVATE, 0);
            if ( sithCogVm_multiplayerFlags && v5 >= 0 )
                sithDSSThing_SendOpenDoor(thing, SITH_ANIM_ACTIVATE, thing->rdthing.puppet->tracks[v5].field_130, -1, 255);
            a6 = thing->moveSize - -0.1;
            sithCollision_SearchRadiusForThings(v4, thing, &thingPos, &out.lvec, a6, 0.025, SITH_THING_ACTOR);
            for ( searchResult = sithCollision_NextSearchResult(); searchResult; searchResult = sithCollision_NextSearchResult() )
            {
                if ( (searchResult->collideType & SITH_THING_ACTOR) != 0 )
                {
                    if ( (searchResult->surface->surfaceFlags & SITH_THING_ACTOR) != 0 )
                    {
                        sithCog_SendMessageFromSurface(searchResult->surface, thing, SITH_MESSAGE_ACTIVATE);
                        sithCollision_SearchClose();
                        return;
                    }
                }
                else if ( (searchResult->collideType & 1) != 0 )
                {
                    v7 = searchResult->receiver;
                    if ( v7->type != SITH_THING_ITEM && v7->type != SITH_THING_WEAPON && (v7->thingflags & SITH_TF_CAPTURED) != 0 )
                    {
                        sithCog_SendMessageFromThing(searchResult->receiver, thing, SITH_MESSAGE_ACTIVATE);
                        break;
                    }
                }
            }
            sithCollision_SearchClose();
        }
    }
}

void sithActor_Remove(sithThing *thing)
{
    thing->thingflags |= SITH_TF_DEAD;
    sithThing_detachallchildren(thing);
    thing->type = SITH_THING_CORPSE;
    thing->physicsParams.physflags &= ~(PHYSFLAGS_FLYING|PHYSFLAGS_800|PHYSFLAGS_100|PHYSFLAGS_WALLSTICK);
    thing->physicsParams.physflags |= (PHYSFLAGS_FLOORSTICK|PHYSFLAGS_SURFACEALIGN|PHYSFLAGS_GRAVITY);
    thing->lifeLeftMs = 20000;
    sithPhysics_FindFloor(thing, 0);
}

void sithActor_cogMsg_WarpThingToCheckpoint(sithThing *thing, int idx)
{
    if ( idx < (unsigned int)jkPlayer_maxPlayers )
    {
        if ( (jkPlayer_playerInfos[idx].flags & 2) != 0 )
        {
            _memcpy(&thing->lookOrientation, &jkPlayer_playerInfos[idx].field_135C, sizeof(thing->lookOrientation));
            thing->position = thing->lookOrientation.scale;
            thing->lookOrientation.scale.x = rdroid_zeroVector3.x;
            thing->lookOrientation.scale.y = 0.0;
            thing->lookOrientation.scale.z = 0.0;
            sithThing_MoveToSector(thing, jkPlayer_playerInfos[idx].field_138C, 0);
        }
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            sithPhysics_ThingStop(thing);
            thing->physicsParams.physflags &= ~PHYSFLAGS_100;
            sithPhysics_FindFloor(thing, 1);
        }
    }
}
