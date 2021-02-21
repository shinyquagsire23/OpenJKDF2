#include "sithSector.h"

#include "Primitives/rdMath.h"
#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "World/sithUnk3.h"
#include "jk.h"
#include "Engine/sithNet.h"

#define TARGET_FPS (50.0)
#define DELTA_50FPS (1.0/TARGET_FPS)

void sithSector_Close()
{
}

void sithSector_ApplyDrag(rdVector3 *vec, float drag, float mag, float deltaSecs)
{
    if (mag == 0.0 || rdVector_Len3(vec) >= mag)
    {
        if (drag != 0.0)
        {
            double scaled = deltaSecs * drag;
            if (scaled > 1.0)
                scaled = 1.0;

            rdVector_MultAcc3(vec, vec, -scaled);
            
            rdMath_ClampVector(vec, 0.00001);
        }
    }
    else
    {
        rdVector_Zero3(vec);
    }
}

void sithSector_ThingPhysicsTick(sithThing *thing, float deltaSecs)
{
    if (!thing->sector)
        return;

    rdVector_Zero3(&thing->velocityMaybe);
    rdVector_Zero3(&thing->addedVelocity);

    if ((thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER) 
        && (thing->actorParams.typeflags & SITH_TF_TIMER))
    {
        rdVector_Zero3(&thing->physicsParams.acceleration);
    }

    if (thing->attach_flags & (ATTACHFLAGS_THINGSURFACE | ATTACHFLAGS_WORLDSURFACE))
    {
        sithSector_ThingPhysAttached(thing, deltaSecs);
    }
    else if (thing->sector->flags & SITH_SF_UNDERWATER)
    {
        sithSector_ThingPhysUnderwater(thing, deltaSecs);
    }
#ifdef QOL_IMPROVEMENTS
    else if ( thing->thingType == THINGTYPE_PLAYER && net_isMulti)
    {
        sithSector_ThingPhysPlayer(thing, deltaSecs);
    }
#else
    else if ( thing->thingType == THINGTYPE_PLAYER )
    {
        sithSector_ThingPhysPlayer(thing, deltaSecs);
    }
#endif
    else
    {
        sithSector_ThingPhysGeneral(thing, deltaSecs);
    }
}

void sithSector_ThingPhysGeneral(sithThing *thing, float deltaSeconds)
{
    rdVector3 a1a;
    rdVector3 a3;
    rdMatrix34 a;

    rdVector_Zero3(&thing->addedVelocity);
    rdVector_Zero3(&a1a);

    if (thing->physicsParams.physflags & PHYSFLAGS_ANGTHRUST)
    {
        if (!rdVector_IsZero3(&thing->physicsParams.angVel))
        {
            sithSector_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
        }

        rdVector_MultAcc3(&thing->physicsParams.angVel, &thing->physicsParams.field_1F8, deltaSeconds);
        
        rdMath_ClampVectorRange(&thing->physicsParams.angVel, -thing->physicsParams.maxRotVel, thing->physicsParams.maxRotVel);
        rdMath_ClampVector(&thing->physicsParams.angVel, 0.00001);
    }

    if (rdVector_IsZero3(&thing->physicsParams.angVel))
    {
        rdVector_Zero3(&a3);
    }
    else
    {
        rdVector_Scale3(&a3, &thing->physicsParams.angVel, deltaSeconds);
    }

    if (!rdVector_IsZero3(&a3))
    {
        rdMatrix_BuildRotate34(&a, &a3);
        sithUnk3_sub_4E7670(thing, &a);

        if ( (thing->physicsParams.physflags & PHYSFLAGS_FLYING) != 0 )
            rdMatrix_TransformVector34Acc(&thing->physicsParams.vel, &a);

        if ( ((bShowInvisibleThings + (thing->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&thing->lookOrientation);
    }

    if ( thing->physicsParams.airDrag != 0.0 )
        sithSector_ApplyDrag(&thing->physicsParams.vel, thing->physicsParams.airDrag, 0.0, deltaSeconds);

    if (thing->physicsParams.physflags & PHYSFLAGS_USESTHRUST)
    {
        if (!(thing->physicsParams.physflags & PHYSFLAGS_FLYING))
        {
            rdVector_Scale3Acc(&thing->physicsParams.acceleration, 0.30000001);
        }
        rdVector_Scale3(&a1a, &thing->physicsParams.acceleration, deltaSeconds);
        rdMatrix_TransformVector34Acc(&a1a, &thing->lookOrientation);
    }

    if (thing->physicsParams.mass != 0.0 
        && (thing->sector->flags & SITH_SF_HASTHRUST) 
        && !(thing->physicsParams.physflags & PHYSFLAGS_NOTHRUST))
    {
        rdVector_MultAcc3(&a1a, &thing->sector->thrust, deltaSeconds);
    }

    if (thing->physicsParams.mass != 0.0 
        && thing->physicsParams.physflags & PHYSFLAGS_GRAVITY
        && !(thing->sector->flags & SITH_SF_NOGRAVITY))
    {
        float gravity = sithWorld_pCurWorld->worldGravity * deltaSeconds;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_PARTIALGRAVITY) != 0 )
            gravity *= 0.5;
        a1a.z = a1a.z - gravity;
        thing->addedVelocity.z = -gravity;
    }

    rdVector_Add3Acc(&thing->physicsParams.vel, &a1a);
    rdMath_ClampVector(&thing->physicsParams.vel, 0.00001);

    if (!rdVector_IsZero3(&thing->physicsParams.vel))
    {
        rdVector_Scale3(&thing->velocityMaybe, &thing->physicsParams.vel, deltaSeconds);
    }
}

void sithSector_ThingPhysPlayer(sithThing *player, float deltaSeconds)
{
    rdMatrix34 a;
    rdVector3 a3;
    rdVector3 a1a;

    rdVector_Zero3(&player->addedVelocity);
    if (player->physicsParams.physflags & PHYSFLAGS_ANGTHRUST)
    {
        if (!rdVector_IsZero3(&player->physicsParams.angVel))
        {
            sithSector_ApplyDrag(&player->physicsParams.angVel, player->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
        }

        rdVector_MultAcc3(&player->physicsParams.angVel, &player->physicsParams.field_1F8, deltaSeconds);

        rdMath_ClampVectorRange(&player->physicsParams.angVel, -player->physicsParams.maxRotVel, player->physicsParams.maxRotVel);
        rdMath_ClampVector(&player->physicsParams.angVel, 0.00001);
    }

    if (rdVector_IsZero3(&player->physicsParams.angVel))
    {
        rdVector_Zero3(&a3);
    }
    else
    {
        rdVector_Scale3(&a3, &player->physicsParams.angVel, deltaSeconds);
    }

    if (!rdVector_IsZero3(&a3))
    {
        rdMatrix_BuildRotate34(&a, &a3);
        sithUnk3_sub_4E7670(player, &a);

        if (player->physicsParams.physflags & PHYSFLAGS_FLYING)
            rdMatrix_TransformVector34Acc(&player->physicsParams.vel, &a);

        if ( ((bShowInvisibleThings + (player->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&player->lookOrientation);
    }

    if (!(player->physicsParams.physflags & PHYSFLAGS_FLYING))
    {
        rdVector_Scale3Acc(&player->physicsParams.acceleration, 0.30000001);
    }

    // I think all of this is specifically for multiplayer, so that player things
    // sync better between clients.
    float rolloverCombine = deltaSeconds + player->physicsRolloverFrames;

    float framesToApply = rolloverCombine * TARGET_FPS; // get number of 50FPS steps passed
    player->physicsRolloverFrames = rolloverCombine - (double)(unsigned int)(int)framesToApply * DELTA_50FPS;

    for (int i = (int)framesToApply; i > 0; i--)
    {
        rdVector_Zero3(&a1a);
        if ( player->physicsParams.airDrag != 0.0 )
        {
            sithSector_ApplyDrag(&player->physicsParams.vel, player->physicsParams.airDrag, 0.0, DELTA_50FPS);
        }

        if (player->physicsParams.physflags & PHYSFLAGS_USESTHRUST)
        {
            rdVector_Scale3(&a1a, &player->physicsParams.acceleration, DELTA_50FPS);
            rdMatrix_TransformVector34Acc(&a1a, &player->lookOrientation);
        }

        if ( player->physicsParams.mass != 0.0 )
        {
            if ((player->sector->flags & SITH_SF_HASTHRUST)
                && !(player->physicsParams.physflags & PHYSFLAGS_NOTHRUST))
            {
                rdVector_MultAcc3(&a1a, &player->sector->thrust, DELTA_50FPS);
            }
        }

        if ( player->physicsParams.mass != 0.0 
             && (player->physicsParams.physflags & PHYSFLAGS_GRAVITY) 
             && !(player->sector->flags & SITH_SF_NOGRAVITY) )
        {
            float gravity = sithWorld_pCurWorld->worldGravity * DELTA_50FPS;
            if ( (player->physicsParams.physflags & PHYSFLAGS_PARTIALGRAVITY) != 0 )
                gravity = gravity * 0.5;
            a1a.z = a1a.z - gravity;
            player->addedVelocity.z = -gravity;
        }
        rdVector_Add3Acc(&player->physicsParams.vel, &a1a);
        rdVector_MultAcc3(&player->velocityMaybe, &player->physicsParams.vel, DELTA_50FPS);
    }
}
