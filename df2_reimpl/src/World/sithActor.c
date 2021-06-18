#include "sithActor.h"

#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSoundClass.h"
#include "Cog/sithCogVm.h"

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
