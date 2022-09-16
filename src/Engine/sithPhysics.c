#include "sithPhysics.h"

#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "Engine/sithCollision.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithSurface.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/jkPlayer.h"
#include "jk.h"

void sithPhysics_FindFloor(sithThing *thing, int a3)
{
    int v4; // ecx
    sithCollisionSearchEntry *v5; // eax
    double v8; // st7
    double v9; // st7
    sithCollisionSearchEntry *i; // esi
    sithThing *v11; // edi
    rdFace *v12; // eax
    int v14; // [esp+10h] [ebp-20h]
    float range; // [esp+14h] [ebp-1Ch]
    rdVector3 direction; // [esp+18h] [ebp-18h] BYREF
    rdVector3 a1; // [esp+24h] [ebp-Ch] BYREF
    float thinga; // [esp+34h] [ebp+4h]

    range = 0.0;
    v14 = 0;
    if (!thing->sector)
        return;

    if (thing->sector->flags & SITH_SECTOR_UNDERWATER && thing->type == SITH_THING_PLAYER)
    {
        sithCollision_SearchRadiusForThings(thing->sector, thing, &thing->position, &rdroid_zVector3, 0.05, 0.0, 1);
        v5 = sithCollision_NextSearchResult();
        if ( v5 )
        {
            while ( (v5->hitType & SITHCOLLISION_ADJOINCROSS) == 0 || (v5->surface->adjoin->sector->flags & SITH_SECTOR_UNDERWATER) != 0 )
            {
                v5 = sithCollision_NextSearchResult();
                if ( !v5 )
                    goto LABEL_8;
            }
            thing->field_48 = v5->distance;
            thing->physicsParams.physflags |= SITH_PF_MIDAIR;
            sithCollision_SearchClose();
        }
        else
        {
LABEL_8:
            sithCollision_SearchClose();
            thing->physicsParams.physflags &= ~SITH_PF_MIDAIR;
        }
    }
    else
    {
        if ( (thing->physicsParams.physflags & SITH_PF_WALLSTICK) == 0 )
        {
            direction.x = -0.0;
            direction.y = direction.x;
            direction.z = -1.0;
            v14 = 0x10;
        }
        else
        {
            rdVector_Neg3(&direction, &thing->lookOrientation.uvec);
        }

        if ( a3 || thing->attach_flags )
        {
            v9 = thing->physicsParams.height;
            if ( v9 == 0.0 )
            {
                if ( thing->rdthing.type == RD_THINGTYPE_MODEL )
                    v9 = thing->rdthing.model3->insertOffset.z;
                thinga = thing->moveSize - -0.005;
                if ( v9 <= thinga )
                    v9 = thinga;
            }
            if ( (thing->physicsParams.physflags & (SITH_PF_FLOORSTICK|SITH_PF_WALLSTICK)) != 0 )
                v8 = v9 + v9;
            else
                v8 = v9 * 1.1;
        }
        else
        {
            v8 = thing->moveSize - -0.005;
        }

        if ( v8 > 0.0 )
        {
            sithCollision_SearchRadiusForThings(thing->sector, 0, &thing->position, &direction, v8, 0.0, v14 | 0x2802);
            while ( 1 )
            {
                for ( i = sithCollision_NextSearchResult(); i; i = sithCollision_NextSearchResult() )
                {
                    if ( (i->hitType & SITHCOLLISION_WORLD) != 0 )
                    {
                        //printf("Attach to new surface? %x\n", i->surface->field_0);
                        sithThing_AttachToSurface(thing, i->surface, a3);
                        sithCollision_SearchClose();
                        return;
                    }
                    if ( (i->hitType & SITHCOLLISION_THING) != 0 )
                    {
                        v11 = i->receiver;
                        if ( v11 != thing )
                        {
                            v12 = i->face;
                            if ( !v12 || !i->sender )
                            {
                                sithCollision_SearchClose();
                                return;
                            }
                            
                            // Track thing that can move
                            if ( (v14 & 0x10) == 0
                              || (rdMatrix_TransformVector34(&a1, &v12->normal, &v11->lookOrientation), rdVector_Dot3(&a1, &rdroid_zVector3) >= 0.6) )
                            {
                                sithThing_LandThing(thing, v11, i->face, i->sender->vertices, a3);
                                sithCollision_SearchClose();
                                return;
                            }
                        }
                    }
                }
                sithCollision_SearchClose();
                if ( range != 0.0 )
                    break;

                if ( thing->type != SITH_THING_ACTOR && thing->type != SITH_THING_PLAYER )
                    break;
                if ( thing->moveSize == 0.0 )
                    break;
                range = thing->moveSize;
                sithCollision_SearchRadiusForThings(thing->sector, 0, &thing->position, &direction, v8, range, v14 | 0x2802);
            }
        }
        if ( thing->attach_flags )
            sithThing_DetachThing(thing);
    }
}

// Inlined func

void sithPhysics_ThingTick(sithThing *thing, float deltaSecs)
{
    if (!thing->sector)
        return;

    rdVector_Zero3(&thing->physicsParams.velocityMaybe);
    rdVector_Zero3(&thing->physicsParams.addedVelocity);

    if ((thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) 
        && (thing->actorParams.typeflags & SITH_TF_TIMER))
    {
        rdVector_Zero3(&thing->physicsParams.acceleration);
    }

    if (thing->attach_flags & (SITH_ATTACH_THINGSURFACE | SITH_ATTACH_WORLDSURFACE))
    {
        sithPhysics_ThingPhysAttached(thing, deltaSecs);
    }
    else if (thing->sector->flags & SITH_SECTOR_UNDERWATER)
    {
        sithPhysics_ThingPhysUnderwater(thing, deltaSecs);
    }
#ifdef QOL_IMPROVEMENTS
    else if ( thing->type == SITH_THING_PLAYER && sithNet_isMulti)
    {
#ifdef FIXED_TIMESTEP_PHYS
        if (NEEDS_STEPPED_PHYS) {
        // time stepping is handled elsewhere
        sithPhysics_ThingPhysGeneral(thing, deltaSecs);
        }
        else
        {
            sithPhysics_ThingPhysPlayer(thing, deltaSecs);
        }
#else
        sithPhysics_ThingPhysPlayer(thing, deltaSecs);
#endif
    }
#else
    else if ( thing->type == SITH_THING_PLAYER )
    {
        sithPhysics_ThingPhysPlayer(thing, deltaSecs);
    }
#endif
    else
    {
        sithPhysics_ThingPhysGeneral(thing, deltaSecs);
    }
}

void sithPhysics_ThingApplyForce(sithThing *thing, rdVector3 *forceVec)
{
    if ( thing->moveType == SITH_MT_PHYSICS && thing->physicsParams.mass > 0.0 )
    {
        float invMass = 1.0 / thing->physicsParams.mass;

        if ( forceVec->z * invMass > 0.5 ) // TODO verify
            sithThing_DetachThing(thing);

        rdVector_MultAcc3(&thing->physicsParams.vel, forceVec, invMass);
        thing->physicsParams.physflags |= SITH_PF_8000;
    }
}

void sithPhysics_ThingSetLook(sithThing *thing, const rdVector3 *look, float a3)
{
    double v4; // st7
    double v8;
    double v9; // st6
    double v10; // st4
    double v13; // rt0
    double v20; // st7
    double v23; // st4
    double v24; // st7
    double v25; // st5
    double v26; // st6
    double v27; // st4
    double v28; // st6
    double v29; // st7
    double v30; // st6
    double v31; // st5
    double v32; // st7

    v4 = stdMath_ClipPrecision(1.0 - rdVector_Dot3(&thing->lookOrientation.uvec, look));
    if ( v4 == 0.0 )
    {
        thing->physicsParams.physflags |= SITH_PF_100;
    }
    else if ( a3 == 0.0 )
    {
        v10 = thing->lookOrientation.lvec.x;
        v8 = thing->lookOrientation.lvec.y;
        v9 = thing->lookOrientation.lvec.z;

        thing->lookOrientation.uvec.x = look->x;
        thing->lookOrientation.uvec.y = look->y;
        thing->lookOrientation.uvec.z = look->z;

        thing->lookOrientation.rvec.x = v8 * thing->lookOrientation.uvec.z - v9 * thing->lookOrientation.uvec.y;
        thing->lookOrientation.rvec.y = v9 * thing->lookOrientation.uvec.x - v10 * thing->lookOrientation.uvec.z;
        thing->lookOrientation.rvec.z = v10 * thing->lookOrientation.uvec.y - v8 * thing->lookOrientation.uvec.x;
        rdVector_Normalize3Acc(&thing->lookOrientation.rvec);
        thing->lookOrientation.lvec.x = thing->lookOrientation.rvec.z * thing->lookOrientation.uvec.y
                                      - thing->lookOrientation.rvec.y * thing->lookOrientation.uvec.z;
        thing->lookOrientation.lvec.y = (thing->lookOrientation.rvec.x * thing->lookOrientation.uvec.z) - (thing->lookOrientation.rvec.z * thing->lookOrientation.uvec.x);
        thing->lookOrientation.lvec.z = (thing->lookOrientation.rvec.y * thing->lookOrientation.uvec.x) - (thing->lookOrientation.rvec.x * thing->lookOrientation.uvec.y);
        thing->physicsParams.physflags |= SITH_PF_100;
    }
    else
    {
        v20 = a3 * 10.0;
        thing->lookOrientation.uvec.x = look->x * v20 + thing->lookOrientation.uvec.x;
        thing->lookOrientation.uvec.y = look->z * v20 + thing->lookOrientation.uvec.y;
        thing->lookOrientation.uvec.z = look->y * v20 + thing->lookOrientation.uvec.z;
        rdVector_Normalize3Acc(&thing->lookOrientation.uvec);
        v23 = thing->lookOrientation.uvec.z;
        v24 = thing->lookOrientation.uvec.x;
        v25 = thing->lookOrientation.uvec.y;
        v26 = thing->lookOrientation.rvec.x;
        thing->lookOrientation.lvec.x = thing->lookOrientation.rvec.z * v25 - thing->lookOrientation.rvec.y * v23;
        v27 = v26 * v23 - thing->lookOrientation.rvec.z * thing->lookOrientation.uvec.x;
        v28 = thing->lookOrientation.rvec.y;
        thing->lookOrientation.lvec.y = v27;
        thing->lookOrientation.lvec.z = v28 * v24 - thing->lookOrientation.rvec.x * v25;
        rdVector_Normalize3Acc(&thing->lookOrientation.lvec);
        v29 = thing->lookOrientation.lvec.z * thing->lookOrientation.uvec.x;
        thing->lookOrientation.rvec.x = thing->lookOrientation.lvec.y * thing->lookOrientation.uvec.z
                                      - thing->lookOrientation.lvec.z * thing->lookOrientation.uvec.y;
        v30 = thing->lookOrientation.lvec.x * thing->lookOrientation.uvec.y;
        v31 = v29 - thing->lookOrientation.lvec.x * thing->lookOrientation.uvec.z;
        v32 = thing->lookOrientation.lvec.y * thing->lookOrientation.uvec.x;
        thing->lookOrientation.rvec.y = v31;
        thing->lookOrientation.rvec.z = v30 - v32;
    }
}

void sithPhysics_ApplyDrag(rdVector3 *vec, float drag, float mag, float deltaSecs)
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

int sithPhysics_LoadThingParams(stdConffileArg *arg, sithThing *thing, int param)
{
    float tmp;
    int tmpInt;

    switch ( param )
    {
        case THINGPARAM_SURFDRAG:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                return 0;
            thing->physicsParams.surfaceDrag = tmp;
            return 1;
        case THINGPARAM_AIRDRAG:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                return 0;
            thing->physicsParams.airDrag = tmp;
            return 1;
        case THINGPARAM_STATICDRAG:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                return 0;
            thing->physicsParams.staticDrag = tmp;
            return 1;
        case THINGPARAM_MASS:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                return 0;
            thing->physicsParams.mass = tmp;
            return 1;
        case THINGPARAM_HEIGHT:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                return 0;
            thing->physicsParams.height = tmp;
            return 1;
        case THINGPARAM_PHYSFLAGS:
            if ( _sscanf(arg->value, "%x", &tmpInt) != 1 )
                return 0;
            thing->physicsParams.physflags = tmpInt;
            return 1;
        case THINGPARAM_MAXROTVEL:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 || thing->moveType != SITH_MT_PHYSICS )
                return 0;
            thing->physicsParams.maxRotVel = tmp;
            return 1;
        case THINGPARAM_MAXVEL:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 || thing->moveType != SITH_MT_PHYSICS )
                return 0;
            thing->physicsParams.maxVel = tmp;
            return 1;
        case THINGPARAM_VEL:
            if (_sscanf(
                      arg->value,
                      "(%f/%f/%f)",
                      &thing->physicsParams.vel,
                      &thing->physicsParams.vel.y,
                      &thing->physicsParams.vel.z) != 3)
                return 0;
            return 1;
        case THINGPARAM_ANGVEL:
            if (_sscanf(
                      arg->value,
                      "(%f/%f/%f)",
                      &thing->physicsParams.angVel,
                      &thing->physicsParams.angVel.y,
                      &thing->physicsParams.angVel.z) != 3)
                return 0;

            return 1;
        case THINGPARAM_ORIENTSPEED:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 || thing->moveType != SITH_MT_PHYSICS )
                return 0;
            thing->physicsParams.orientSpeed = tmp;
            return 1;
        case THINGPARAM_BUOYANCY:
            tmp = _atof(arg->value);
            thing->physicsParams.buoyancy = tmp;
            return 1;
        default:
            return 0;
    }
}

void sithPhysics_ThingStop(sithThing *thing)
{
    rdVector_Zero3(&thing->physicsParams.vel);
    rdVector_Zero3(&thing->physicsParams.angVel);
    rdVector_Zero3(&thing->physicsParams.field_1F8);
    rdVector_Zero3(&thing->physicsParams.acceleration);
    rdVector_Zero3(&thing->physicsParams.velocityMaybe);
    rdVector_Zero3(&thing->field_268);
}

float sithPhysics_ThingGetInsertOffsetZ(sithThing *thing)
{
    double result; // st7
    float v2; // [esp+4h] [ebp+4h]

    result = thing->physicsParams.height;
    if ( result == 0.0 )
    {
        if ( thing->rdthing.type == RD_THINGTYPE_MODEL )
            result = thing->rdthing.model3->insertOffset.z;
        v2 = thing->moveSize - -0.005;
        if ( result <= v2 )
            result = v2;
    }
    return result;
}

void sithPhysics_ThingPhysGeneral(sithThing *thing, float deltaSeconds)
{
    rdVector3 a1a;
    rdVector3 a3;
    rdMatrix34 a;

    rdVector_Zero3(&thing->physicsParams.addedVelocity);
    rdVector_Zero3(&a1a);

    if (thing->physicsParams.physflags & SITH_PF_ANGTHRUST)
    {
        if (!rdVector_IsZero3(&thing->physicsParams.angVel))
        {
            sithPhysics_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
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
        sithCollision_sub_4E7670(thing, &a);

        if ( (thing->physicsParams.physflags & SITH_PF_FLY) != 0 )
            rdMatrix_TransformVector34Acc(&thing->physicsParams.vel, &a);

        if ( ((bShowInvisibleThings + (thing->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&thing->lookOrientation);
    }

    if ( thing->physicsParams.airDrag != 0.0 )
        sithPhysics_ApplyDrag(&thing->physicsParams.vel, thing->physicsParams.airDrag, 0.0, deltaSeconds);

    if (thing->physicsParams.physflags & SITH_PF_USESTHRUST)
    {
        if (!(thing->physicsParams.physflags & SITH_PF_FLY))
        {
            rdVector_Scale3Acc(&thing->physicsParams.acceleration, 0.3);
        }
        rdVector_Scale3(&a1a, &thing->physicsParams.acceleration, deltaSeconds);
        rdMatrix_TransformVector34Acc(&a1a, &thing->lookOrientation);
    }

    if (thing->physicsParams.mass != 0.0 
        && (thing->sector->flags & SITH_SECTOR_HASTHRUST) 
        && !(thing->physicsParams.physflags & SITH_PF_NOTHRUST))
    {
        rdVector_MultAcc3(&a1a, &thing->sector->thrust, deltaSeconds);
    }

    if (thing->physicsParams.mass != 0.0 
        && thing->physicsParams.physflags & SITH_PF_USEGRAVITY
        && !(thing->sector->flags & SITH_SECTOR_NOGRAVITY))
    {
        float gravity = sithWorld_pCurrentWorld->worldGravity * deltaSeconds;
        if ( (thing->physicsParams.physflags & SITH_PF_PARTIALGRAVITY) != 0 )
            gravity *= 0.5;
        a1a.z = a1a.z - gravity;
        thing->physicsParams.addedVelocity.z = -gravity;
    }

    rdVector_Add3Acc(&thing->physicsParams.vel, &a1a);
    rdMath_ClampVector(&thing->physicsParams.vel, 0.00001);

    if (!rdVector_IsZero3(&thing->physicsParams.vel))
    {
        rdVector_Scale3(&thing->physicsParams.velocityMaybe, &thing->physicsParams.vel, deltaSeconds);
    }
}

void sithPhysics_ThingPhysPlayer(sithThing *player, float deltaSeconds)
{
    rdMatrix34 a;
    rdVector3 a3;
    rdVector3 a1a;

    rdVector_Zero3(&player->physicsParams.addedVelocity);
    if (player->physicsParams.physflags & SITH_PF_ANGTHRUST)
    {
        if (!rdVector_IsZero3(&player->physicsParams.angVel))
        {
            sithPhysics_ApplyDrag(&player->physicsParams.angVel, player->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
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
        sithCollision_sub_4E7670(player, &a);

        if (player->physicsParams.physflags & SITH_PF_FLY)
            rdMatrix_TransformVector34Acc(&player->physicsParams.vel, &a);

        if ( ((bShowInvisibleThings + (player->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&player->lookOrientation);
    }

    if (!(player->physicsParams.physflags & SITH_PF_FLY))
    {
        rdVector_Scale3Acc(&player->physicsParams.acceleration, 0.3);
    }

    // I think all of this is specifically for multiplayer, so that player things
    // sync better between clients.
    float rolloverCombine = deltaSeconds + player->physicsParams.physicsRolloverFrames;

    float framesToApply = rolloverCombine * OLDSTEP_TARGET_FPS; // get number of 50FPS steps passed
    player->physicsParams.physicsRolloverFrames = rolloverCombine - (double)(unsigned int)(int)framesToApply * OLDSTEP_DELTA_50FPS;

    for (int i = (int)framesToApply; i > 0; i--)
    {
        rdVector_Zero3(&a1a);
        if ( player->physicsParams.airDrag != 0.0 )
        {
            sithPhysics_ApplyDrag(&player->physicsParams.vel, player->physicsParams.airDrag, 0.0, OLDSTEP_DELTA_50FPS);
        }

        if (player->physicsParams.physflags & SITH_PF_USESTHRUST)
        {
            rdVector_Scale3(&a1a, &player->physicsParams.acceleration, OLDSTEP_DELTA_50FPS);
            rdMatrix_TransformVector34Acc(&a1a, &player->lookOrientation);
        }

        if ( player->physicsParams.mass != 0.0 )
        {
            if ((player->sector->flags & SITH_SECTOR_HASTHRUST)
                && !(player->physicsParams.physflags & SITH_PF_NOTHRUST))
            {
                rdVector_MultAcc3(&a1a, &player->sector->thrust, OLDSTEP_DELTA_50FPS);
            }
        }

        if ( player->physicsParams.mass != 0.0 
             && (player->physicsParams.physflags & SITH_PF_USEGRAVITY) 
             && !(player->sector->flags & SITH_SECTOR_NOGRAVITY) )
        {
            float gravity = sithWorld_pCurrentWorld->worldGravity * OLDSTEP_DELTA_50FPS;
            if ( (player->physicsParams.physflags & SITH_PF_PARTIALGRAVITY) != 0 )
                gravity = gravity * 0.5;
            a1a.z = a1a.z - gravity;
            player->physicsParams.addedVelocity.z = -gravity;
        }
        rdVector_Add3Acc(&player->physicsParams.vel, &a1a);
        rdVector_MultAcc3(&player->physicsParams.velocityMaybe, &player->physicsParams.vel, OLDSTEP_DELTA_50FPS);
    }
}

void sithPhysics_ThingPhysUnderwater(sithThing *thing, float deltaSeconds)
{
    double v35; // st6
    double v51; // st7
    rdVector3 a1a; // [esp+24h] [ebp-48h] BYREF
    rdVector3 a3; // [esp+30h] [ebp-3Ch] BYREF
    rdMatrix34 tmpMat; // [esp+3Ch] [ebp-30h] BYREF

    rdVector_Zero3(&a1a);
    rdVector_Zero3(&thing->physicsParams.addedVelocity);
    if ( (thing->physicsParams.physflags & SITH_PF_ANGTHRUST) != 0 )
    {
        if ( !rdVector_IsZero3(&thing->physicsParams.angVel) )
        {
            sithPhysics_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
        }
        rdVector_MultAcc3(&thing->physicsParams.angVel, &thing->physicsParams.field_1F8, deltaSeconds);
        rdVector_ClampValue3(&thing->physicsParams.angVel, thing->physicsParams.maxRotVel);
        rdVector_ClipPrecision3(&thing->physicsParams.angVel);
    }
    if ( rdVector_IsZero3(&thing->physicsParams.angVel) )
    {
        rdVector_Zero3(&a3);
    }
    else
    {
        rdVector_Scale3(&a3, &thing->physicsParams.angVel, deltaSeconds);
    }
    if (!rdVector_IsZero3(&a3))
    {
        rdMatrix_BuildRotate34(&tmpMat, &a3);
        sithCollision_sub_4E7670(thing, &tmpMat);
        if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&thing->lookOrientation);
    }
    if ( thing->physicsParams.airDrag != 0.0 )
    {
        sithPhysics_ApplyDrag(&thing->physicsParams.vel, thing->physicsParams.airDrag * 4.0, 0.0, deltaSeconds);
    }
    if ( (thing->physicsParams.physflags & SITH_PF_USESTHRUST) != 0 )
    {
        rdVector_Scale3Acc(&thing->physicsParams.acceleration, 0.6);
        rdVector_Scale3(&a1a, &thing->physicsParams.acceleration, deltaSeconds);
        rdMatrix_TransformVector34Acc(&a1a, &thing->lookOrientation);
    }
    if ( thing->physicsParams.mass != 0.0 && thing->sector && (thing->sector->flags & SITH_SECTOR_HASTHRUST) && !(thing->physicsParams.physflags & SITH_PF_NOTHRUST) )
    {
        rdVector_MultAcc3(&a1a, &thing->sector->thrust, deltaSeconds);
    }

    if ( ((thing->physicsParams.physflags & SITH_PF_MIDAIR) == 0 || (thing->thingflags & SITH_TF_DEAD) != 0) && (thing->physicsParams.physflags & SITH_PF_USEGRAVITY) != 0 )
    {
        v35 = sithWorld_pCurrentWorld->worldGravity * deltaSeconds * thing->physicsParams.buoyancy;
        a1a.z -= v35;
        thing->physicsParams.addedVelocity.z -= v35;
    }
    rdVector_Add3Acc(&thing->physicsParams.vel, &a1a);

    rdVector_ClipPrecision3(&thing->physicsParams.vel);
    if ( !rdVector_IsZero3(&thing->physicsParams.vel) )
    {
        rdVector_Scale3(&thing->physicsParams.velocityMaybe, &thing->physicsParams.vel, deltaSeconds);
    }
    if ( (thing->physicsParams.physflags & SITH_PF_MIDAIR) != 0 && thing->physicsParams.acceleration.z >= 0.0 )
    {
        v51 = thing->field_48 - 0.01;
        if ( thing->physicsParams.velocityMaybe.z > 0.0 && thing->physicsParams.velocityMaybe.z < (double)deltaSeconds * 0.2 ) // verify first
            thing->physicsParams.velocityMaybe.z = 0.0;
        if ( v51 > 0.0 )
        {
            if ( v51 >= deltaSeconds * 0.2 )
                v51 = deltaSeconds * 0.2;
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &rdroid_zVector3, v51);
        }
    }
}

void sithPhysics_ThingPhysAttached(sithThing *thing, float deltaSeconds)
{   
    float a2a; // [esp+0h] [ebp-94h]
    float v144; // [esp+4h] [ebp-90h]
    float possibly_undef_2; // [esp+1Ch] [ebp-78h]
    float new_z; // [esp+20h] [ebp-74h]
    float new_x; // [esp+24h] [ebp-70h]
    float v158; // [esp+28h] [ebp-6Ch]
    float possibly_undef_1; // [esp+2Ch] [ebp-68h]
    float new_y; // [esp+30h] [ebp-64h]
    float new_ya; // [esp+30h] [ebp-64h]
    rdVector3 vel_change; // [esp+34h] [ebp-60h] BYREF
    rdVector3 attachedNormal; // [esp+40h] [ebp-54h] BYREF
    rdVector3 out; // [esp+4Ch] [ebp-48h] BYREF
    rdVector3 a3; // [esp+58h] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+64h] [ebp-30h] BYREF

    possibly_undef_1 = 0.0;
    possibly_undef_2 = 0.0;

    rdVector_Zero3(&vel_change);
    v158 = 1.0;
    thing->physicsParams.physflags &= ~SITH_PF_200000;
    if ( (thing->attach_flags & SITH_ATTACH_WORLDSURFACE) != 0 )
    {
        attachedNormal = thing->attachedSufaceInfo->face.normal;
        possibly_undef_1 = rdMath_DistancePointToPlane(&thing->position, &attachedNormal, &thing->field_38);
        if ( (thing->attachedSurface->surfaceFlags & (SITH_SURFACE_ICY|SITH_SURFACE_VERYICY)) != 0 )
        {
            if ( (thing->attachedSurface->surfaceFlags & SITH_SURFACE_VERYICY) != 0 )
                possibly_undef_2 = 0.1;
            else
                possibly_undef_2 = 0.3;
        }
        else
        {
            possibly_undef_2 = 1.0;
        }
    }
    else if ( (thing->attach_flags & SITH_ATTACH_THINGSURFACE) != 0 )
    {
        rdMatrix_TransformVector34(&attachedNormal, &thing->attachedSufaceInfo->face.normal, &thing->attachedThing->lookOrientation);
        rdMatrix_TransformVector34(&a3, &thing->field_38, &thing->attachedThing->lookOrientation);
        possibly_undef_2 = 1.0;
        rdVector_Add3Acc(&a3, &thing->attachedThing->position);
        possibly_undef_1 = rdMath_DistancePointToPlane(&thing->position, &attachedNormal, &a3);
    }

    if (thing->physicsParams.physflags & SITH_PF_800)
    {
        v158 = rdVector_Dot3(&attachedNormal, &rdroid_zVector3);
        if ( v158 < 1.0 )
            possibly_undef_1 = possibly_undef_1 / v158;
    }

    if (!(thing->physicsParams.physflags & SITH_PF_100))
    {
        if ( (thing->physicsParams.physflags & SITH_PF_SURFACEALIGN) != 0 )
        {
            sithPhysics_ThingSetLook(thing, &attachedNormal, thing->physicsParams.orientSpeed * deltaSeconds);
        }
        else if ( (thing->physicsParams.physflags & SITH_PF_800) != 0 )
        {
            sithPhysics_ThingSetLook(thing, &rdroid_zVector3, thing->physicsParams.orientSpeed * deltaSeconds);
        }
        else
        {
            thing->physicsParams.physflags |= SITH_PF_100;
        }
    }

    if (thing->physicsParams.physflags & SITH_PF_ANGTHRUST)
    {
        if (!rdVector_IsZero3(&thing->physicsParams.angVel))
        {
            sithPhysics_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.surfaceDrag - -0.2, 0.0, deltaSeconds);
        }

        thing->physicsParams.angVel.y = thing->physicsParams.field_1F8.y * deltaSeconds + thing->physicsParams.angVel.y;
        rdVector_ClampValue3(&thing->physicsParams.angVel, thing->physicsParams.maxRotVel);
        rdVector_ClipPrecision3(&thing->physicsParams.angVel);
    }
    if ( thing->physicsParams.angVel.y != 0.0 )
    {
        rdVector_Scale3(&a3, &thing->physicsParams.angVel, deltaSeconds);
        rdMatrix_BuildRotate34(&a, &a3);
        sithCollision_sub_4E7670(thing, &a);
        if ( possibly_undef_2 >= 1.0 )
        {
            rdMatrix_TransformVector34Acc(&thing->physicsParams.vel, &a);
        }
        else
        {
            rdMatrix_TransformVector34(&out, &thing->physicsParams.vel, &a);
            rdVector_Scale3Acc(&thing->physicsParams.vel, 1.0 - possibly_undef_2);
            rdVector_MultAcc3(&thing->physicsParams.vel, &out, possibly_undef_2);
        }
        if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&thing->lookOrientation);
    }
    if ( possibly_undef_2 < 0.25 )
    {
        possibly_undef_2 = 0.25;
    }
    else if ( possibly_undef_2 > 1.0 )
    {
        possibly_undef_2 = 1.0;
    }

    if (!rdVector_IsZero3(&thing->physicsParams.vel) && thing->physicsParams.surfaceDrag != 0.0)
    {
        if ( (thing->physicsParams.physflags & SITH_PF_8000) == 0 )
        {
            if ( rdVector_IsZero3(&thing->physicsParams.acceleration)
              && !(thing->sector->flags & SITH_SECTOR_HASTHRUST)
              && possibly_undef_2 > 0.8 )
            {
                a2a = thing->physicsParams.surfaceDrag * possibly_undef_2;
                v144 = thing->physicsParams.staticDrag * possibly_undef_2;
            }
            else
            {
                a2a = thing->physicsParams.surfaceDrag * possibly_undef_2;
                v144 = 0.0;
            }
            sithPhysics_ApplyDrag(&thing->physicsParams.vel, a2a, v144, deltaSeconds);
        }
        else
        {
            thing->physicsParams.physflags &= ~SITH_PF_8000;
        }
    }

    if ( (thing->physicsParams.physflags & SITH_PF_USESTHRUST) != 0
      && !rdVector_IsZero3(&thing->physicsParams.acceleration) )
    {
        float v44 = possibly_undef_2 * deltaSeconds;
        if ( (thing->physicsParams.physflags & SITH_PF_CROUCHING) != 0 )
            v44 = deltaSeconds * 0.8;
        rdVector_Scale3(&vel_change, &thing->physicsParams.acceleration, v44);
        rdVector_ClipPrecision3(&vel_change);
        if ( !rdVector_IsZero3(&vel_change) )
            rdMatrix_TransformVector34Acc(&vel_change, &thing->lookOrientation);
    }

    if (thing->physicsParams.mass != 0.0 && (thing->sector->flags & SITH_SECTOR_HASTHRUST) && !(thing->physicsParams.physflags & SITH_PF_NOTHRUST))
    {
        if ( thing->sector->thrust.z > sithWorld_pCurrentWorld->worldGravity * thing->physicsParams.mass )
        {
            sithThing_DetachThing(thing);
            rdVector_Zero3(&thing->physicsParams.addedVelocity);
            rdVector_Zero3(&out);
            if ( (thing->physicsParams.physflags & SITH_PF_ANGTHRUST) != 0 )
            {
                if ( !rdVector_IsZero3(&thing->physicsParams.angVel) )
                {
                    sithPhysics_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
                }
                rdVector_MultAcc3(&thing->physicsParams.angVel, &thing->physicsParams.field_1F8, deltaSeconds);

                rdVector_ClampValue3(&thing->physicsParams.angVel, thing->physicsParams.maxRotVel);
                rdVector_ClipPrecision3(&thing->physicsParams.angVel);
            }
            if ( rdVector_IsZero3(&thing->physicsParams.angVel) )
            {
                rdVector_Zero3(&a3);
            }
            else
            {
                rdVector_Scale3(&a3, &thing->physicsParams.angVel, deltaSeconds);
            }
            if ( !rdVector_IsZero3(&a3) )
            {
                rdMatrix_BuildRotate34(&a, &a3);
                sithCollision_sub_4E7670(thing, &a);
                if ( (thing->physicsParams.physflags & SITH_PF_FLY) != 0 )
                    rdMatrix_TransformVector34Acc(&thing->physicsParams.vel, &a);
                if ( ((bShowInvisibleThings + (thing->thingIdx & 0xFF)) & 7) == 0 )
                    rdMatrix_Normalize34(&thing->lookOrientation);
            }

            if ( thing->physicsParams.airDrag != 0.0 )
                sithPhysics_ApplyDrag(&thing->physicsParams.vel, thing->physicsParams.airDrag, 0.0, deltaSeconds);

            if (thing->physicsParams.physflags & SITH_PF_USESTHRUST)
            {
                if (!(thing->physicsParams.physflags & SITH_PF_FLY))
                {
                    rdVector_Scale3Acc(&thing->physicsParams.acceleration, 0.3);
                }
                rdVector_Scale3(&out, &thing->physicsParams.acceleration, deltaSeconds);
            }

            if ( thing->physicsParams.mass != 0.0
              && (thing->sector->flags & SITH_SECTOR_HASTHRUST)
              && !(thing->physicsParams.physflags & SITH_PF_NOTHRUST))
            {
                rdVector_MultAcc3(&out, &thing->sector->thrust, deltaSeconds);
            }

            if ( thing->physicsParams.mass != 0.0 && (thing->physicsParams.physflags & SITH_PF_USEGRAVITY) != 0 && (thing->sector->flags & SITH_PF_USEGRAVITY) == 0 )
            {
                float v91 = sithWorld_pCurrentWorld->worldGravity * deltaSeconds;
                if ( (thing->physicsParams.physflags & SITH_PF_PARTIALGRAVITY) != 0 )
                    v91 = v91 * 0.5;
                out.z -= v91;
                thing->physicsParams.addedVelocity.z = -v91;
            }
            rdVector_Add3Acc(&thing->physicsParams.vel, &out);
            rdVector_ClipPrecision3(&thing->physicsParams.vel);
            if ( !rdVector_IsZero3(&thing->physicsParams.vel) )
            {
                rdVector_Scale3(&thing->physicsParams.velocityMaybe, &thing->physicsParams.vel, deltaSeconds);
            }
            return;
        }
        rdVector_MultAcc3(&vel_change, &thing->sector->thrust, deltaSeconds);
    }
    rdVector_Add3Acc(&thing->physicsParams.vel, &vel_change);
    
    // Is the player climbing up/down a slope?
    if ( thing->type == SITH_THING_PLAYER
      && (thing->physicsParams.physflags & SITH_PF_USEGRAVITY) != 0
      && v158 <= 1.0
      && (possibly_undef_2 < 0.8 || !rdVector_IsZero3(&thing->physicsParams.vel)) )
    {
        float v108 = stdMath_Clamp(1.0 - possibly_undef_2, 0.2, 0.8);
        thing->physicsParams.vel.z -= sithWorld_pCurrentWorld->worldGravity * deltaSeconds * v108;
    }

    if ( !rdVector_IsZero3(&thing->physicsParams.vel) )
    {
        float v109 = rdVector_Dot3(&attachedNormal, &thing->physicsParams.vel);

        if ( stdMath_ClipPrecision(v109) != 0.0 )
        {
#ifdef FIXED_TIMESTEP_PHYS
            // Fix physics being tied to framerate?
            if (NEEDS_STEPPED_PHYS)
                v109 *= (deltaSeconds / (1.0 / 25.0));
#endif
            rdVector_MultAcc3(&thing->physicsParams.vel, &attachedNormal, -v109);
        }
    }

    rdVector_ClipPrecision3(&thing->physicsParams.vel);
    if ( !rdVector_IsZero3(&thing->physicsParams.vel) )
    {
        rdVector_Scale3(&thing->physicsParams.velocityMaybe, &thing->physicsParams.vel, deltaSeconds);
    }

    float v131;
    if (thing->physicsParams.physflags & SITH_PF_CROUCHING)
    {
        v131 = v158 * possibly_undef_1 - (thing->moveSize - -0.01);
    }
    else
    {
        float v132 = thing->physicsParams.height;
        if ( v132 == 0.0 )
        {
            if ( thing->rdthing.type == RD_THINGTYPE_MODEL )
                v132 = thing->rdthing.model3->insertOffset.z;
            new_ya = thing->moveSize - -0.005;
            if ( v132 <= new_ya )
                v132 = new_ya;
        }
        v131 = possibly_undef_1 - v132;
    }

    // Slide down slopes
    v131 = stdMath_ClipPrecision(v131);
    if ( v131 != 0.0 )
    {
        // Fix physics being tied to framerate?
        float orig_v131 = stdMath_ClampValue(v131, deltaSeconds * 0.5);
        float new_v131 = v131 * (deltaSeconds / (1.0 / 25.0));
        new_v131 = stdMath_ClampValue(new_v131, deltaSeconds * 0.5);

#ifdef FIXED_TIMESTEP_PHYS
        if (NEEDS_STEPPED_PHYS)
            v131 = new_v131;
        else
            v131 = orig_v131;
#else
        v131 = orig_v131;
#endif

        if ( (thing->physicsParams.physflags & SITH_PF_800) != 0 )
        {
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &rdroid_zVector3, -v131);
        }
        else
        {
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &attachedNormal, -v131);
        }
    }
}