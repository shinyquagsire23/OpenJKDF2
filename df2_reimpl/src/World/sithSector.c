#include "sithSector.h"

#include "Primitives/rdMath.h"
#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "World/sithUnk3.h"
#include "jk.h"

#define DELTA_50FPS (0.02)

void sithSector_ApplyDrag(rdVector3 *vec, float drag, float mag, float deltaSecs)
{
    double v4;

    if ( mag == 0.0 || rdVector_Len3(vec) >= mag )
    {
        if ( drag != 0.0 )
        {
            v4 = deltaSecs * drag;
            if ( v4 > 1.0 )
                v4 = 1.0;

            vec->x = vec->x * -v4 + vec->x;
            vec->y = vec->y * -v4 + vec->y;
            vec->z = vec->z * -v4 + vec->z;
            
            rdMath_ClampVector(vec, 0.00001);
        }
    }
    else
    {
        vec->x = 0.0;
        vec->y = 0.0;
        vec->z = 0.0;
    }
}

void sithSector_ThingPhysicsTick(sithThing *thing, float deltaSecs)
{
    if ( thing->sector )
    {
        rdVector_Copy3(&thing->velocityMaybe, &rdroid_zeroVector3);
        rdVector_Copy3(&thing->addedVelocity, &rdroid_zeroVector3);

        if ((thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER) 
            && (thing->actorParams.typeflags & SITH_TF_TIMER))
        {
            rdVector_Copy3(&thing->physicsParams.acceleration, &rdroid_zeroVector3);
        }

        if (thing->attach_flags & (ATTACHFLAGS_THINGSURFACE | ATTACHFLAGS_WORLDSURFACE))
        {
            sithSector_ThingPhysAttached(thing, deltaSecs);
        }
        else if (thing->sector->flags & SITH_SF_UNDERWATER)
        {
            sithSector_ThingPhysUnderwater(thing, deltaSecs);
        }
        else if ( thing->thingType == THINGTYPE_PLAYER )
        {
            sithSector_ThingPhysPlayer(thing, deltaSecs);
        }
        else
        {
            sithSector_ThingPhysGeneral(thing, deltaSecs);
        }
    }
}

void sithSector_ThingPhysPlayer(sithThing *player, float deltaSeconds)
{
    double v6; // st6
    double v7; // st6
    double v22; // st7
    double v23; // st7
    rdMatrix34 a; // [esp+18h] [ebp-54h] BYREF
    rdVector3 a3; // [esp+48h] [ebp-24h] BYREF
    rdVector3 a1a; // [esp+54h] [ebp-18h] BYREF
    float v30; // [esp+64h] [ebp-8h]
    float playerc; // [esp+74h] [ebp+8h]
    float deltaSecondsb; // [esp+78h] [ebp+Ch]

    rdVector_Copy3(&player->addedVelocity, &rdroid_zeroVector3);
    if (player->physicsParams.physflags & PHYSFLAGS_ANGTHRUST)
    {
        if ( player->physicsParams.angVel.x != 0.0
          || player->physicsParams.angVel.y != 0.0
          || player->physicsParams.angVel.z != 0.0 )
        {
            sithSector_ApplyDrag(&player->physicsParams.angVel, player->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
        }

        player->physicsParams.angVel.x = (player->physicsParams.field_1F8.x * deltaSeconds + player->physicsParams.angVel.x);
        player->physicsParams.angVel.y = (player->physicsParams.field_1F8.y * deltaSeconds + player->physicsParams.angVel.y);
        v30 = player->physicsParams.field_1F8.z * deltaSeconds + player->physicsParams.angVel.z;
        player->physicsParams.angVel.z = v30;
        float v5 = -player->physicsParams.maxRotVel;

        if ( player->physicsParams.angVel.x < v5 )
        {
            v6 = v5;
        }
        else if ( player->physicsParams.maxRotVel < (double)player->physicsParams.angVel.x )
        {
            v6 = player->physicsParams.maxRotVel;
        }
        else
        {
            v6 = player->physicsParams.angVel.x;
        }
        player->physicsParams.angVel.x = v6;

        if ( player->physicsParams.angVel.y < v5 )
        {
            v7 = v5;
        }
        else if ( player->physicsParams.maxRotVel < (double)player->physicsParams.angVel.y )
        {
            v7 = player->physicsParams.maxRotVel;
        }
        else
        {
            v7 = player->physicsParams.angVel.y;
        }
        player->physicsParams.angVel.y = v7;

        if ( v30 >= v5 )
        {
            if ( player->physicsParams.maxRotVel < (double)v30 )
                v5 = player->physicsParams.maxRotVel;
            else
                v5 = v30;
        }
        player->physicsParams.angVel.z = v5;

        rdMath_ClampVector(&player->physicsParams.angVel, 0.00001);
    }
    if ( player->physicsParams.angVel.x == 0.0
      && player->physicsParams.angVel.y == 0.0
      && player->physicsParams.angVel.z == 0.0 )
    {
        rdVector_Copy3(&a3, &rdroid_zeroVector3);
    }
    else
    {
        rdVector_Scale3(&a3, &player->physicsParams.angVel, deltaSeconds);
    }

    if ( a3.x != 0.0 || a3.y != 0.0 || a3.z != 0.0 )
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

    deltaSecondsb = deltaSeconds + player->field_240;

    playerc = deltaSecondsb * 50.0; // get number of 50FPS steps passed
    player->field_240 = deltaSecondsb - (double)(unsigned int)(int)playerc * DELTA_50FPS;

    for (int i = (int)playerc; i > 0; i--)
    {
        rdVector_Copy3(&a1a, &rdroid_zeroVector3);
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
            if ( (player->sector->flags & SITH_SF_HASTHRUST) != 0 && !(player->physicsParams.physflags & PHYSFLAGS_NOTHRUST))
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
