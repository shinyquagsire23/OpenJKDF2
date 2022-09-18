#include "sithPlayerActions.h"

#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "World/jkPlayer.h"
#include "World/sithSurface.h"
#include "Engine/sithSoundClass.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithNet.h"
#include "Engine/sithPhysics.h"
#include "Cog/sithCogExec.h"
#include "Cog/sithCog.h"
#include "Dss/sithDSSThing.h"
#include "jk.h"

static int lastDoorOpenTime = 0;

void sithPlayerActions_Activate(sithThing *thing)
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
        rdVector_Copy3(&thingPos, &thing->position);
        if ( thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER )
        {
            rdMatrix_PreRotate34(&out, &thing->actorParams.eyePYR);
            rdVector_Add3Acc(&thingPos, &thing->actorParams.eyeOffset);
        }
        v4 = sithCollision_GetSectorLookAt(thing->sector, &thing->position, &thingPos, 0.0);
        if ( v4 )
        {
            v5 = sithPuppet_PlayMode(thing, SITH_ANIM_ACTIVATE, 0);
            if ( sithComm_multiplayerFlags && v5 >= 0 )
                sithDSSThing_SendPlayKeyMode(thing, SITH_ANIM_ACTIVATE, thing->rdthing.puppet->tracks[v5].field_130, -1, 255);
            a6 = thing->moveSize - -0.1;
            sithCollision_SearchRadiusForThings(v4, thing, &thingPos, &out.lvec, a6, 0.025, SITH_THING_ACTOR);
            for ( searchResult = sithCollision_NextSearchResult(); searchResult; searchResult = sithCollision_NextSearchResult() )
            {
                if ( (searchResult->hitType & SITHCOLLISION_WORLD) != 0 )
                {
                    if ( (searchResult->surface->surfaceFlags & SITH_SURFACE_COG_LINKED) != 0 )
                    {
                        sithCog_SendMessageFromSurface(searchResult->surface, thing, SITH_MESSAGE_ACTIVATE);
                        sithCollision_SearchClose();
                        return;
                    }
                }
                else if ( (searchResult->hitType & SITHCOLLISION_THING) != 0 )
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

void sithPlayerActions_JumpWithVel(sithThing *thing, float vel)
{
    double final_vel;
    int isAttached; // zf
    sithSurface *attachedSurface; // eax
    int v12; // eax
    int jumpSound; // edi
    int v14; // eax
    sithPlayingSound *v15; // eax

    if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && (thing->actorParams.typeflags & SITH_AF_IMMOBILE) == 0 )
    {
        final_vel = thing->actorParams.jumpSpeed * vel;
        if ( (thing->physicsParams.physflags & SITH_PF_CROUCHING) != 0 )
            final_vel = final_vel * 0.7;
        if ( (thing->physicsParams.physflags & SITH_PF_MIDAIR) != 0 )
        {
            rdVector_MultAcc3(&thing->physicsParams.vel, &rdroid_zVector3, final_vel);
            thing->physicsParams.physflags &= ~SITH_PF_MIDAIR;
        }
        else
        {
            if ( !thing->attach_flags )
                return;
            isAttached = (thing->attach_flags & (SITH_ATTACH_THING|SITH_ATTACH_THINGSURFACE)) == 0;
            attachedSurface = thing->attachedSurface;
            rdVector_MultAcc3(&thing->physicsParams.vel, &rdroid_zVector3, final_vel);
            if ( isAttached )
            {
                v14 = attachedSurface->surfaceFlags;
                if ( (v14 & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_EARTH|SITH_SURFACE_PUDDLE|SITH_SURFACE_WATER|SITH_SURFACE_METAL)) != 0 )
                {
                    if ( (v14 & SITH_SURFACE_METAL) != 0 )
                    {
                        jumpSound = SITH_SC_JUMPMETAL;
                    }
                    else if ( (v14 & SITH_SURFACE_WATER) != 0 )
                    {
                        jumpSound = SITH_SC_JUMPWATER;
                    }
                    else if ( (v14 & SITH_SURFACE_PUDDLE) != 0 )
                    {
                        jumpSound = SITH_SC_JUMPWATER;
                    }
                    else
                    {
                        jumpSound = (v14 & SITH_SURFACE_EARTH) != 0 ? SITH_SC_JUMPEARTH : SITH_SC_JUMP;
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
                    jumpSound = (SITH_TF_EARTH & v12) != 0 ? SITH_SC_JUMPEARTH : SITH_SC_JUMP;
            }
            v15 = sithSoundClass_PlayModeRandom(thing, jumpSound);
            if ( v15 && sithComm_multiplayerFlags )
                sithDSSThing_SendPlaySoundMode(thing, jumpSound, v15->refid, -1.0);
            sithThing_DetachThing(thing);
        }
        if ( sithComm_multiplayerFlags )
            sithThing_SetSyncFlags(thing, THING_SYNC_POS);
    }
}

void sithPlayerActions_WarpToCheckpoint(sithThing *thing, int idx)
{
    if ( idx < (unsigned int)jkPlayer_maxPlayers )
    {
        if ( (jkPlayer_playerInfos[idx].flags & 2) != 0 )
        {
            _memcpy(&thing->lookOrientation, &jkPlayer_playerInfos[idx].field_135C, sizeof(thing->lookOrientation));
            thing->position = thing->lookOrientation.scale;
            rdVector_Zero3(&thing->lookOrientation.scale);
            sithThing_MoveToSector(thing, jkPlayer_playerInfos[idx].field_138C, 0);
        }
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            sithPhysics_ThingStop(thing);
            thing->physicsParams.physflags &= ~SITH_PF_100;
            sithPhysics_FindFloor(thing, 1);
        }
    }
}
