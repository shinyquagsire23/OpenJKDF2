#include "sithPhysics.h"

#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "Engine/sithCollision.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithSurface.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "jk.h"

#define TARGET_FPS (50.0)
#define DELTA_50FPS (1.0/TARGET_FPS)

void sithPhysics_FindFloor(sithThing *thing, int a3)
{
    sithSector *sector; // eax
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
    float thingb; // [esp+34h] [ebp+4h]

    range = 0.0;
    sector = thing->sector;
    v14 = 0;
    if (!sector)
        return;

    if (sector->flags & SITH_SECTOR_UNDERWATER && thing->type == SITH_THING_PLAYER)
    {
        sithCollision_SearchRadiusForThings(sector, thing, &thing->position, &rdroid_zVector3, 0.050000001, 0.0, 1);
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
                thinga = thing->moveSize - -0.0049999999;
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
            v8 = thing->moveSize - -0.0049999999;
        }
        thingb = v8;
        if ( v8 > 0.0 )
        {
            sithCollision_SearchRadiusForThings(thing->sector, 0, &thing->position, &direction, thingb, 0.0, v14 | 0x2802);
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
                              || (rdMatrix_TransformVector34(&a1, &v12->normal, &v11->lookOrientation), rdVector_Dot3(&a1, &rdroid_zVector3) >= 0.60000002) )
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
                sithCollision_SearchRadiusForThings(thing->sector, 0, &thing->position, &direction, thingb, range, v14 | 0x2802);
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
        sithPhysics_ThingPhysPlayer(thing, deltaSecs);
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
    rdVector3 *v3; // edi
    double v4; // st7
    double v6; // st6
    double v8; // st7
    double v9; // st6
    double v10; // st4
    double v11; // st3
    float v12; // ecx
    double v13; // rt0
    double v14; // st2
    double v15; // st7
    double v16; // st5
    double v17; // st4
    double v19; // st7
    double v20; // st7
    double v21; // st5
    double v22; // st6
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

    v3 = &thing->lookOrientation.uvec;
    v4 = 1.0 - (thing->lookOrientation.uvec.x * look->x + look->y * thing->lookOrientation.uvec.y + look->z * thing->lookOrientation.uvec.z);
    v6 = v4;
    if ( v6 < 0.0 )
        v6 = -v4;
    if ( v6 <= 0.0000099999997 )
        v4 = 0.0;
    if ( v4 == 0.0 )
    {
        thing->physicsParams.physflags |= SITH_PF_100;
    }
    else if ( a3 == 0.0 )
    {
        v8 = thing->lookOrientation.lvec.y;
        v9 = thing->lookOrientation.lvec.z;
        v10 = thing->lookOrientation.lvec.x;
        v11 = v10;
        v3->x = look->x;
        v12 = look->z;
        thing->lookOrientation.uvec.y = look->y;
        thing->lookOrientation.uvec.z = v12;
        v13 = v8;
        v14 = v8 * thing->lookOrientation.uvec.z - v9 * thing->lookOrientation.uvec.y;
        v15 = v3->x;
        thing->lookOrientation.rvec.x = v14;
        v16 = v9 * v15 - v10 * thing->lookOrientation.uvec.z;
        v17 = thing->lookOrientation.uvec.y;
        thing->lookOrientation.rvec.y = v16;
        thing->lookOrientation.rvec.z = v11 * v17 - v13 * v3->x;
        rdVector_Normalize3Acc(&thing->lookOrientation.rvec);
        thing->lookOrientation.lvec.x = thing->lookOrientation.rvec.z * thing->lookOrientation.uvec.y
                                      - thing->lookOrientation.rvec.y * thing->lookOrientation.uvec.z;
        v19 = thing->lookOrientation.rvec.y * v3->x;
        thing->lookOrientation.lvec.y = thing->lookOrientation.rvec.x * thing->lookOrientation.uvec.z - thing->lookOrientation.rvec.z * v3->x;
        thing->lookOrientation.lvec.z = v19 - thing->lookOrientation.rvec.x * thing->lookOrientation.uvec.y;
        thing->physicsParams.physflags |= SITH_PF_100;
    }
    else
    {
        v20 = a3 * 10.0;
        v21 = look->z * v20 + thing->lookOrientation.uvec.y;
        v22 = look->y * v20 + thing->lookOrientation.uvec.z;
        v3->x = look->x * v20 + v3->x;
        thing->lookOrientation.uvec.y = v21;
        thing->lookOrientation.uvec.z = v22;
        rdVector_Normalize3Acc(v3);
        v23 = thing->lookOrientation.uvec.z;
        v24 = v3->x;
        v25 = thing->lookOrientation.uvec.y;
        v26 = thing->lookOrientation.rvec.x;
        thing->lookOrientation.lvec.x = thing->lookOrientation.rvec.z * v25 - thing->lookOrientation.rvec.y * v23;
        v27 = v26 * v23 - thing->lookOrientation.rvec.z * v3->x;
        v28 = thing->lookOrientation.rvec.y;
        thing->lookOrientation.lvec.y = v27;
        thing->lookOrientation.lvec.z = v28 * v24 - thing->lookOrientation.rvec.x * v25;
        rdVector_Normalize3Acc(&thing->lookOrientation.lvec);
        v29 = thing->lookOrientation.lvec.z * v3->x;
        thing->lookOrientation.rvec.x = thing->lookOrientation.lvec.y * thing->lookOrientation.uvec.z
                                      - thing->lookOrientation.lvec.z * thing->lookOrientation.uvec.y;
        v30 = thing->lookOrientation.lvec.x * thing->lookOrientation.uvec.y;
        v31 = v29 - thing->lookOrientation.lvec.x * thing->lookOrientation.uvec.z;
        v32 = thing->lookOrientation.lvec.y * v3->x;
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
        v2 = thing->moveSize - -0.0049999999;
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
            rdVector_Scale3Acc(&thing->physicsParams.acceleration, 0.30000001);
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
        rdVector_Scale3Acc(&player->physicsParams.acceleration, 0.30000001);
    }

    // I think all of this is specifically for multiplayer, so that player things
    // sync better between clients.
    float rolloverCombine = deltaSeconds + player->physicsParams.physicsRolloverFrames;

    float framesToApply = rolloverCombine * TARGET_FPS; // get number of 50FPS steps passed
    player->physicsParams.physicsRolloverFrames = rolloverCombine - (double)(unsigned int)(int)framesToApply * DELTA_50FPS;

    for (int i = (int)framesToApply; i > 0; i--)
    {
        rdVector_Zero3(&a1a);
        if ( player->physicsParams.airDrag != 0.0 )
        {
            sithPhysics_ApplyDrag(&player->physicsParams.vel, player->physicsParams.airDrag, 0.0, DELTA_50FPS);
        }

        if (player->physicsParams.physflags & SITH_PF_USESTHRUST)
        {
            rdVector_Scale3(&a1a, &player->physicsParams.acceleration, DELTA_50FPS);
            rdMatrix_TransformVector34Acc(&a1a, &player->lookOrientation);
        }

        if ( player->physicsParams.mass != 0.0 )
        {
            if ((player->sector->flags & SITH_SECTOR_HASTHRUST)
                && !(player->physicsParams.physflags & SITH_PF_NOTHRUST))
            {
                rdVector_MultAcc3(&a1a, &player->sector->thrust, DELTA_50FPS);
            }
        }

        if ( player->physicsParams.mass != 0.0 
             && (player->physicsParams.physflags & SITH_PF_USEGRAVITY) 
             && !(player->sector->flags & SITH_SECTOR_NOGRAVITY) )
        {
            float gravity = sithWorld_pCurrentWorld->worldGravity * DELTA_50FPS;
            if ( (player->physicsParams.physflags & SITH_PF_PARTIALGRAVITY) != 0 )
                gravity = gravity * 0.5;
            a1a.z = a1a.z - gravity;
            player->physicsParams.addedVelocity.z = -gravity;
        }
        rdVector_Add3Acc(&player->physicsParams.vel, &a1a);
        rdVector_MultAcc3(&player->physicsParams.velocityMaybe, &player->physicsParams.vel, DELTA_50FPS);
    }
}

void sithPhysics_ThingPhysUnderwater(sithThing *thing, float deltaSeconds)
{
    rdVector3 *v4; // edi
    double v5; // st6
    double v6; // st7
    double v8; // rtt
    double v9; // st6
    double v10; // st7
    double v12; // st5
    double v18; // st6
    double v20; // st6
    double v22; // st6
    double v24; // st6
    double v26; // st6
    double v30; // st7
    double v31; // st5
    double v32; // st1
    sithSector *v33; // eax
    double v34; // st7
    double v35; // st6
    double v36; // st5
    double v37; // st7
    double v39; // st6
    double v42; // st6
    double v44; // st6
    double v46; // st5
    double v48; // st5
    double v51; // st7
    double v55; // st5
    double v56; // st6
    double v57; // st7
    float v58; // [esp+0h] [ebp-6Ch]
    float v59; // [esp+0h] [ebp-6Ch]
    float v60; // [esp+1Ch] [ebp-50h]
    float v61; // [esp+1Ch] [ebp-50h]
    float v62; // [esp+20h] [ebp-4Ch]
    float v63; // [esp+20h] [ebp-4Ch]
    rdVector3 a1a; // [esp+24h] [ebp-48h] BYREF
    rdVector3 a3; // [esp+30h] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+3Ch] [ebp-30h] BYREF
    float thinga; // [esp+70h] [ebp+4h]
    float thingb; // [esp+70h] [ebp+4h]
    float thingc; // [esp+70h] [ebp+4h]
    float deltaSecondsa; // [esp+74h] [ebp+8h]

    rdVector_Zero3(&a1a);
    rdVector_Zero3(&thing->physicsParams.addedVelocity);
    if ( (thing->physicsParams.physflags & SITH_PF_ANGTHRUST) != 0 )
    {
        v4 = &thing->physicsParams.angVel;
        if ( !rdVector_IsZero3(&thing->physicsParams.angVel) )
        {
            v58 = thing->physicsParams.airDrag - -0.2;
            sithPhysics_ApplyDrag(&thing->physicsParams.angVel, v58, 0.0, deltaSeconds);
        }
        v5 = thing->physicsParams.maxRotVel;
        thinga = thing->physicsParams.field_1F8.x * deltaSeconds + v4->x;
        v6 = thing->physicsParams.field_1F8.y * deltaSeconds + thing->physicsParams.angVel.y;
        v62 = thing->physicsParams.field_1F8.z * deltaSeconds + thing->physicsParams.angVel.z;
        v4->x = thinga;
        thing->physicsParams.angVel.y = v6;
        thing->physicsParams.angVel.z = v62;
        v8 = -v5;
        v9 = v6;
        v10 = v8;
        if ( thinga < v10 )
        {
            v12 = v10;
        }
        else if ( thinga > (double)thing->physicsParams.maxRotVel )
        {
            v12 = thing->physicsParams.maxRotVel;
        }
        else
        {
            v12 = thinga;
        }
        thingb = v12;
        v4->x = v12;
        if ( v9 < v10 )
        {
            v9 = v10;
        }
        else if ( v9 > thing->physicsParams.maxRotVel )
        {
            v9 = thing->physicsParams.maxRotVel;
        }
        v60 = v9;
        thing->physicsParams.angVel.y = v9;
        if ( v62 < thing->physicsParams.maxRotVel ) // TODO verify
        {
            if ( v62 > (double)thing->physicsParams.maxRotVel )
                v10 = thing->physicsParams.maxRotVel;
            else
                v10 = v62;
        }
        thing->physicsParams.angVel.z = v10;
        v18 = thingb;
        if ( v18 < 0.0 )
            v18 = -v18;
        if ( v18 <= 0.0000099999997 )
            v20 = 0.0;
        else
            v20 = thingb;
        v4->x = v20;
        v22 = v60;
        if ( v22 < 0.0 )
            v22 = -v22;
        if ( v22 <= 0.0000099999997 )
            v24 = 0.0;
        else
            v24 = v60;
        thing->physicsParams.angVel.y = v24;
        v26 = v10;
        if ( v26 < 0.0 )
            v26 = -v10;
        if ( v26 <= 0.0000099999997 )
            v10 = 0.0;
        thing->physicsParams.angVel.z = v10;
    }
    if ( thing->physicsParams.angVel.x == 0.0 && thing->physicsParams.angVel.y == 0.0 && thing->physicsParams.angVel.z == 0.0 )
    {
        a3.x = 0.0;
        a3.y = 0.0;
        a3.z = 0.0;
    }
    else
    {
        a3.x = thing->physicsParams.angVel.x * deltaSeconds;
        a3.y = thing->physicsParams.angVel.y * deltaSeconds;
        a3.z = thing->physicsParams.angVel.z * deltaSeconds;
    }
    if (!rdVector_IsZero3(&a3))
    {
        rdMatrix_BuildRotate34(&a, &a3);
        sithCollision_sub_4E7670(thing, &a);
        if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&thing->lookOrientation);
    }
    if ( thing->physicsParams.airDrag != 0.0 )
    {
        v59 = thing->physicsParams.airDrag * 4.0;
        sithPhysics_ApplyDrag(&thing->physicsParams.vel, v59, 0.0, deltaSeconds);
    }
    if ( (thing->physicsParams.physflags & SITH_PF_USESTHRUST) != 0 )
    {
        v30 = thing->physicsParams.acceleration.y * 0.60000002;
        v31 = thing->physicsParams.acceleration.z * 0.60000002;
        v32 = thing->physicsParams.acceleration.x * 0.60000002;
        thing->physicsParams.acceleration.x = v32;
        v63 = v31;
        thing->physicsParams.acceleration.y = v30;
        thing->physicsParams.acceleration.z = v63;
        a1a.x = deltaSeconds * v32;
        a1a.y = deltaSeconds * v30;
        a1a.z = deltaSeconds * v63;
        rdMatrix_TransformVector34Acc(&a1a, &thing->lookOrientation);
    }
    if ( thing->physicsParams.mass == 0.0 || (v33 = thing->sector, (v33->flags & 8) == 0) || (thing->physicsParams.physflags & SITH_PF_NOTHRUST) != 0 )
    {
        v34 = a1a.z;
    }
    else
    {
        a1a.x = v33->thrust.x * deltaSeconds + a1a.x;
        a1a.y = v33->thrust.y * deltaSeconds + a1a.y;
        a1a.z = v33->thrust.z * deltaSeconds + a1a.z;
        v34 = a1a.z;
    }
    if ( ((thing->physicsParams.physflags & SITH_PF_MIDAIR) == 0 || (thing->thingflags & SITH_TF_DEAD) != 0) && (thing->physicsParams.physflags & SITH_PF_USEGRAVITY) != 0 )
    {
        v35 = sithWorld_pCurrentWorld->worldGravity * deltaSeconds * thing->physicsParams.buoyancy;
        v34 -= v35;
        thing->physicsParams.addedVelocity.z = thing->physicsParams.addedVelocity.z - v35;
    }
    v36 = v34;
    v37 = a1a.x + thing->physicsParams.vel.x;
    thingc = a1a.y + thing->physicsParams.vel.y;
    v61 = v36 + thing->physicsParams.vel.z;
    thing->physicsParams.vel.x = v37;
    thing->physicsParams.vel.y = thingc;
    thing->physicsParams.vel.z = v61;
    v39 = v37;
    if ( v39 < 0.0 )
        v39 = -v37;
    if ( v39 <= 0.0000099999997 )
        v37 = 0.0;
    thing->physicsParams.vel.x = v37;
    v42 = thingc;
    if ( v42 < 0.0 )
        v42 = -v42;
    if ( v42 <= 0.0000099999997 )
        v44 = 0.0;
    else
        v44 = thingc;
    thing->physicsParams.vel.y = v44;
    v46 = v61;
    if ( v46 < 0.0 )
        v46 = -v46;
    if ( v46 <= 0.0000099999997 )
        v48 = 0.0;
    else
        v48 = v61;
    thing->physicsParams.vel.z = v48;
    if ( v37 != 0.0 || v44 != 0.0 || v48 != 0.0 )
    {
        thing->physicsParams.velocityMaybe.x = v37 * deltaSeconds;
        thing->physicsParams.velocityMaybe.y = v44 * deltaSeconds;
        thing->physicsParams.velocityMaybe.z = v48 * deltaSeconds;
    }
    if ( (thing->physicsParams.physflags & SITH_PF_MIDAIR) != 0 && thing->physicsParams.acceleration.z >= 0.0 )
    {
        v51 = thing->field_48 - 0.0099999998;
        deltaSecondsa = deltaSeconds * 0.2;
        if ( thing->physicsParams.velocityMaybe.z > 0.0 && thing->physicsParams.velocityMaybe.z < (double)deltaSecondsa ) // verify first
            thing->physicsParams.velocityMaybe.z = 0.0;
        if ( v51 > 0.0 )
        {
            if ( v51 >= deltaSecondsa )
                v51 = deltaSecondsa;
            v55 = v51 * 0.0;
            v56 = v55 + thing->physicsParams.velocityMaybe.y;
            v57 = v51 * 1.0 + thing->physicsParams.velocityMaybe.z;
            thing->physicsParams.velocityMaybe.x = v55 + thing->physicsParams.velocityMaybe.x;
            thing->physicsParams.velocityMaybe.y = v56;
            thing->physicsParams.velocityMaybe.z = v57;
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
        possibly_undef_1 = rdVector_NormalDot(&thing->position, &thing->field_38, &attachedNormal);
        if ( (thing->attachedSurface->surfaceFlags & (SITH_SURFACE_1000|SITH_SURFACE_2000)) != 0 )
        {
            if ( (thing->attachedSurface->surfaceFlags & SITH_SURFACE_2000) != 0 )
                possibly_undef_2 = 0.1;
            else
                possibly_undef_2 = 0.30000001;
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
        possibly_undef_1 = rdVector_NormalDot(&thing->position, &a3, &attachedNormal);
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
              && possibly_undef_2 > 0.80000001 )
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
            v44 = deltaSeconds * 0.80000001;
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
                    rdVector_Scale3Acc(&thing->physicsParams.acceleration, 0.30000001);
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
      && v158 < 1.0
      && (possibly_undef_2 < 0.80000001 || !rdVector_IsZero3(&thing->physicsParams.vel)) )
    {
        float v108 = stdMath_Clamp(1.0 - possibly_undef_2, 0.2, 0.80000001);
        thing->physicsParams.vel.z = thing->physicsParams.vel.z - sithWorld_pCurrentWorld->worldGravity * deltaSeconds * v108;
    }

    if ( !rdVector_IsZero3(&thing->physicsParams.vel) )
    {
        float v109 = stdMath_ClipPrecision(rdVector_Dot3(&attachedNormal, &thing->physicsParams.vel));
        if ( v109 != 0.0 )
        {
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
        v131 = v158 * possibly_undef_1 - (thing->moveSize - -0.0099999998);
    }
    else
    {
        float v132 = thing->physicsParams.height;
        if ( v132 == 0.0 )
        {
            if ( thing->rdthing.type == RD_THINGTYPE_MODEL )
                v132 = thing->rdthing.model3->insertOffset.z;
            new_ya = thing->moveSize - -0.0049999999;
            if ( v132 <= new_ya )
                v132 = new_ya;
        }
        v131 = possibly_undef_1 - v132;
    }

    // Slide down slopes
    v131 = stdMath_ClipPrecision(v131);
    if ( v131 != 0.0 )
    {
        //if (thing->type == SITH_THING_PLAYER)
        //    printf("%f before\n", v131);
        v131 = stdMath_ClampValue(v131, deltaSeconds * 0.5);
        //if (thing->type == SITH_THING_PLAYER)
        //    printf("%f after\n", v131);

        if ( (thing->physicsParams.physflags & SITH_PF_800) != 0 )
        {
            //if (thing->type == SITH_THING_PLAYER)
            //    printf("a\n");
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &rdroid_zVector3, -v131);
        }
        else
        {
            //if (thing->type == SITH_THING_PLAYER)
            //    printf("b\n");
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &attachedNormal, -v131);
        }
    }
}