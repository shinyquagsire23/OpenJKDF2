#include "sithActor.h"

#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithUnk3.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithNet.h"
#include "Cog/sithCogVm.h"
#include "Cog/sithCog.h"

#include "jk.h"

static int lastDoorOpenTime = 0;

void sithActor_Tick(sithThing *thing, int deltaMs)
{
    unsigned int v2; // eax
    unsigned int v3; // eax

    if ( (thing->actorParams.typeflags & THING_TYPEFLAGS_40) == 0 && (thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( (thing->trackParams.numFrames & PHYSFLAGS_MIDAIR) != 0 || (thing->sector->flags & SITH_SF_UNDERWATER) == 0 )
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
    double final_vel; // st7
    double v5; // st5
    double v6; // st6
    int v7; // eax
    double v8; // st5
    double v9; // st6
    int isAttached; // zf
    sithSurface *attachedSurface; // eax
    int v12; // eax
    int jumpSound; // edi
    int v14; // eax
    sithSoundClass *v15; // eax

    if ( (thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER) && (thing->actorParams.typeflags & THING_TYPEFLAGS_40000) == 0 )
    {
        final_vel = thing->actorParams.jumpSpeed * vel;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING) != 0 )
            final_vel = final_vel * 0.69999999;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 )
        {
            v5 = 0.0 * final_vel + thing->physicsParams.vel.y;
            v6 = 1.0 * final_vel + thing->physicsParams.vel.z;
            thing->physicsParams.vel.x = 0.0 * final_vel + thing->physicsParams.vel.x;
            thing->physicsParams.vel.y = v5;
            thing->physicsParams.vel.z = v6;
            thing->physicsParams.physflags &= ~PHYSFLAGS_MIDAIR;
        }
        else
        {
            v7 = thing->attach_flags;
            if ( !v7 )
                return;
            v8 = 0.0 * final_vel + thing->physicsParams.vel.y;
            v9 = 1.0 * final_vel + thing->physicsParams.vel.z;
            thing->physicsParams.vel.x = 0.0 * final_vel + thing->physicsParams.vel.x;
            isAttached = (v7 & (ATTACHFLAGS_THING|ATTACHFLAGS_THINGSURFACE)) == 0;
            thing->physicsParams.vel.y = v8;
            attachedSurface = thing->attachedSurface;
            thing->physicsParams.vel.z = v9;
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
                sithSector_cogMsg_SoundClassPlay(thing, jumpSound, (int)v15->entries[14], -1.0);
            sithThing_DetachThing(thing);
        }
        if ( sithCogVm_multiplayerFlags )
            sithThing_SyncThingPos(thing, 1);
    }
}

void sithActor_cogMsg_OpenDoor(sithThing *thing)
{
    double v2; // st7
    double v3; // st6
    sithSector *v4; // esi
    int v5; // eax
    sithUnk3SearchEntry *searchResult; // eax
    sithThing *v7; // edx
    float a6; // [esp+0h] [ebp-58h]
    rdVector3 thingPos; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+28h] [ebp-30h] BYREF

    if ( !net_isMulti || lastDoorOpenTime + 250 <= sithTime_curMsAbsolute )
    {
        lastDoorOpenTime = sithTime_curMsAbsolute;
        _memcpy(&out, &thing->lookOrientation, sizeof(out));
        thingPos.x = thing->position.x;
        thingPos.y = thing->position.y;
        thingPos.z = thing->position.z;
        if ( thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER )
        {
            rdMatrix_PreRotate34(&out, &thing->actorParams.eyePYR);
            v2 = thing->actorParams.eyeOffset.y + thingPos.y;
            v3 = thing->actorParams.eyeOffset.z + thingPos.z;
            thingPos.x = thing->actorParams.eyeOffset.x + thingPos.x;
            thingPos.y = v2;
            thingPos.z = v3;
        }
        v4 = sithUnk3_GetSectorLookAt(thing->sector, &thing->position, &thingPos, 0.0);
        if ( v4 )
        {
            v5 = sithPuppet_PlayMode(thing, SITH_ANIM_ACTIVATE, 0);
            if ( sithCogVm_multiplayerFlags && v5 >= 0 )
                sithSector_cogMsg_SendOpenDoor(thing, SITH_ANIM_ACTIVATE, thing->rdthing.puppet->tracks[v5].field_130, -1, 255);
            a6 = thing->moveSize - -0.1;
            sithUnk3_SearchRadiusForThings(v4, thing, &thingPos, &out.lvec, a6, 0.025, THINGTYPE_ACTOR);
            for ( searchResult = sithUnk3_NextSearchResult(); searchResult; searchResult = sithUnk3_NextSearchResult() )
            {
                if ( (searchResult->collideType & THINGTYPE_ACTOR) != 0 )
                {
                    if ( (searchResult->surface->surfaceFlags & THINGTYPE_ACTOR) != 0 )
                    {
                        sithCog_SendMessageFromSurface(searchResult->surface, thing, SITH_MESSAGE_ACTIVATE);
                        sithUnk3_SearchClose();
                        return;
                    }
                }
                else if ( (searchResult->collideType & 1) != 0 )
                {
                    v7 = searchResult->receiver;
                    if ( v7->thingType != THINGTYPE_ITEM && v7->thingType != THINGTYPE_WEAPON && (v7->thingflags & SITH_TF_CAPTURED) != 0 )
                    {
                        sithCog_SendMessageFromThing(searchResult->receiver, thing, SITH_MESSAGE_ACTIVATE);
                        break;
                    }
                }
            }
            sithUnk3_SearchClose();
        }
    }
}
