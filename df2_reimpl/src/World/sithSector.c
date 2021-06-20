#include "sithSector.h"

#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "Primitives/rdFace.h"
#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "World/sithUnk3.h"
#include "World/sithCollide.h"
#include "jk.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithNet.h"
#include "Engine/sithTimer.h"
#include "Engine/rdColormap.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSound.h"
#include "Engine/sithRender.h"
#include "Engine/rdCache.h"
#include "AI/sithAI.h"

#define TARGET_FPS (50.0)
#define DELTA_50FPS (1.0/TARGET_FPS)

int sithSector_Startup()
{
    sithSector_allocPerSector = (sithSectorAlloc *)pSithHS->alloc(sizeof(sithSectorAlloc) * sithWorld_pCurWorld->numSectors);
    if (sithSector_allocPerSector)
    {
        sithSector_numEntries = 0;
        if ( sithTimer_RegisterFunc(3, sithSector_TimerTick, 1000, 1) )
        {
            sithSector_bInitted = 1;
            return 1;
        }
    }

    return 0;
}

void sithSector_Shutdown()
{
    pSithHS->free(sithSector_allocPerSector);
    sithSector_allocPerSector = 0;
    sithTimer_RegisterFunc(3, NULL, 0, 0);
    sithSector_bInitted = 0;
}

void sithSector_Close()
{
}

int sithSector_Load(sithWorld *world, int tmp)
{
    unsigned int sectors_amt_; // esi
    unsigned int alloc_size; // ebx
    sithSector *v5; // eax
    sithSector *v6; // eax
    unsigned int v7; // ecx
    sithSector *sectors; // esi
    int *sector_vertices; // eax
    int v13; // edi
    unsigned int v15; // eax
    void *v16; // ecx
    int junk; // [esp+10h] [ebp-3Ch] BYREF
    unsigned int num_vertices; // [esp+14h] [ebp-38h] BYREF
    unsigned int amount_2; // [esp+18h] [ebp-34h] BYREF
    unsigned int sectors_amt; // [esp+1Ch] [ebp-30h] BYREF
    int v21; // [esp+20h] [ebp-2Ch]
    int vtx_idx; // [esp+24h] [ebp-28h] BYREF
    int amount_1; // [esp+28h] [ebp-24h] BYREF
    char sound_fname[32]; // [esp+2Ch] [ebp-20h] BYREF

    if ( tmp )
        return 0;
    if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " world sectors %d", &sectors_amt) != 1 )
        return 0;
    sectors_amt_ = sectors_amt;
    alloc_size = sizeof(sithSector) * sectors_amt;
    v5 = (sithSector *)pSithHS->alloc(sizeof(sithSector) * sectors_amt);
    world->sectors = v5;
    if ( v5 )
    {
        _memset(v5, 0, alloc_size);
        v6 = world->sectors;
        v7 = 0;
        for ( world->numSectors = sectors_amt_; v7 < sectors_amt_; ++v7 )
        {
            v6->id = v7;
            v6->numVertices = 0;
            v6->verticeIdxs = 0;
            v6->numSurfaces = 0;
            v6->surfaces = 0;
            v6->thingsList = 0;
            ++v6;
        }
    }
    sectors = world->sectors;
    if ( !sectors )
        return 0;
    v21 = 0;
    if ( sectors_amt )
    {
        while ( stdConffile_ReadLine() )
        {
            if ( _sscanf(stdConffile_aLine, " sector %d", &junk) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " flags %x", &sectors->flags) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " ambient light %f", &sectors->ambientLight) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " extra light %f", &sectors->extraLight) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " colormap %d", &tmp) != 1 )
                break;
            sectors->colormap = &world->colormaps[tmp];
            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " tint %f %f %f", &sectors->tint, &sectors->tint.y, &sectors->tint.z) == 3 && !stdConffile_ReadLine() )
            {
                break;
            }
            if ( _sscanf(
                     stdConffile_aLine,
                     " boundbox %f %f %f %f %f %f ",
                     &sectors->boundingbox_onecorner,
                     &sectors->boundingbox_onecorner.y,
                     &sectors->boundingbox_onecorner.z,
                     &sectors->boundingbox_othercorner,
                     &sectors->boundingbox_othercorner.y,
                     &sectors->boundingbox_othercorner.z) != 6 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(
                     stdConffile_aLine,
                     " collidebox %f %f %f %f %f %f ",
                     &sectors->collidebox_onecorner,
                     &sectors->collidebox_onecorner.y,
                     &sectors->collidebox_onecorner.z,
                     &sectors->collidebox_othercorner,
                     &sectors->collidebox_othercorner.y,
                     &sectors->collidebox_othercorner.z) == 6 )
            {
                sectors->flags |= 0x1000;
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, "sound %s %f", sound_fname, &sectors->field_54) == 2 )
            {
                sectors->field_50 = sithSound_LoadEntry(sound_fname, 0);
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, " center %f %f %f", &sectors->center, &sectors->center.y, &sectors->center.z) != 3 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " radius %f", &sectors->radius) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " vertices %d", &num_vertices) != 1 )
                break;
            sector_vertices = (int *)pSithHS->alloc(4 * num_vertices);
            sectors->verticeIdxs = sector_vertices;
            if ( !sector_vertices )
                break;

            for (v13 = 0; v13 < num_vertices; v13++)
            {
                if (!stdConffile_ReadLine())
                    return 0;
                if (_sscanf(stdConffile_aLine, " %d: %d", &junk, &vtx_idx) != 2)
                    return 0;
                sectors->verticeIdxs[v13] = vtx_idx;
            }

            sectors->numVertices = num_vertices;
            if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " surfaces %d %d", &amount_1, &amount_2) != 2 )
                return 0;
            sectors->numSurfaces = amount_2;

            sectors->surfaces = &world->surfaces[amount_1];
            for (v15 = 0; v15 < amount_2; v15++)
            {
                sectors->surfaces[v15].parent_sector = sectors;
            }
            ++sectors;
            if ( ++v21 >= sectors_amt )
                return 1;
        }
        return 0;
    }
    return 1;
}

int sithSector_LoadThingPhysicsParams(stdConffileArg *arg, sithThing *thing, int param)
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
            if ( tmp < 0.0 || thing->move_type != MOVETYPE_PHYSICS )
                return 0;
            thing->physicsParams.maxRotVel = tmp;
            return 1;
        case THINGPARAM_MAXVEL:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 || thing->move_type != MOVETYPE_PHYSICS )
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
            if ( tmp < 0.0 || thing->move_type != MOVETYPE_PHYSICS )
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

    rdVector_Zero3(&thing->physicsParams.velocityMaybe);
    rdVector_Zero3(&thing->physicsParams.addedVelocity);

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
#ifndef LINUX_TMP
        sithSector_ThingPhysUnderwater(thing, deltaSecs);
#endif
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

    rdVector_Zero3(&thing->physicsParams.addedVelocity);
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
        thing->physicsParams.addedVelocity.z = -gravity;
    }

    rdVector_Add3Acc(&thing->physicsParams.vel, &a1a);
    rdMath_ClampVector(&thing->physicsParams.vel, 0.00001);

    if (!rdVector_IsZero3(&thing->physicsParams.vel))
    {
        rdVector_Scale3(&thing->physicsParams.velocityMaybe, &thing->physicsParams.vel, deltaSeconds);
    }
}

void sithSector_ThingPhysPlayer(sithThing *player, float deltaSeconds)
{
    rdMatrix34 a;
    rdVector3 a3;
    rdVector3 a1a;

    rdVector_Zero3(&player->physicsParams.addedVelocity);
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
    float rolloverCombine = deltaSeconds + player->physicsParams.physicsRolloverFrames;

    float framesToApply = rolloverCombine * TARGET_FPS; // get number of 50FPS steps passed
    player->physicsParams.physicsRolloverFrames = rolloverCombine - (double)(unsigned int)(int)framesToApply * DELTA_50FPS;

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
            player->physicsParams.addedVelocity.z = -gravity;
        }
        rdVector_Add3Acc(&player->physicsParams.vel, &a1a);
        rdVector_MultAcc3(&player->physicsParams.velocityMaybe, &player->physicsParams.vel, DELTA_50FPS);
    }
}

void sithSector_ThingLandIdk(sithThing *thing, int a3)
{
    sithSector *sector; // eax
    int v4; // ecx
    sithUnk3SearchEntry *v5; // eax
    int32_t v6; // ecx
    double v7; // st7
    double v8; // st7
    double v9; // st7
    sithUnk3SearchEntry *i; // esi
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
    v4 = thing->physicsParams.physflags;
    v14 = 0;
    if ( sector )
    {
        if ( (sector->flags & 2) != 0 )
        {
            if ( thing->thingType == THINGTYPE_PLAYER )
            {
                sithUnk3_SearchRadiusForThings(sector, thing, &thing->position, &rdroid_zVector3, 0.050000001, 0.0, 1);
                v5 = sithUnk3_NextSearchResult();
                if ( v5 )
                {
                    while ( (v5->collideType & 0x20) == 0 || (v5->surface->adjoin->sector->flags & 2) != 0 )
                    {
                        v5 = sithUnk3_NextSearchResult();
                        if ( !v5 )
                            goto LABEL_8;
                    }
                    v6 = thing->trackParams.numFrames | PHYSFLAGS_MIDAIR;
                    thing->field_48 = v5->distance;
                    thing->trackParams.numFrames = v6;
                    sithUnk3_SearchClose();
                }
                else
                {
LABEL_8:
                    sithUnk3_SearchClose();
                    thing->trackParams.numFrames &= ~PHYSFLAGS_MIDAIR;
                }
            }
        }
        else
        {
            if ( (v4 & 0x80u) == 0 )
            {
                direction.x = -0.0;
                direction.y = direction.x;
                v7 = 1.0;
                v14 = 16;
            }
            else
            {
                direction.x = -thing->lookOrientation.uvec.x;
                direction.y = -thing->lookOrientation.uvec.y;
                v7 = thing->lookOrientation.uvec.z;
            }
            direction.z = -v7;
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
                if ( (v4 & 0xC0) != 0 )
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
                sithUnk3_SearchRadiusForThings(thing->sector, 0, &thing->position, &direction, thingb, 0.0, v14 | 0x2802);
                while ( 1 )
                {
                    for ( i = sithUnk3_NextSearchResult(); i; i = sithUnk3_NextSearchResult() )
                    {
                        if ( (i->collideType & 2) != 0 )
                        {
                            sithThing_AttachToSurface(thing, i->surface, a3);
                            sithUnk3_SearchClose();
                            return;
                        }
                        if ( (i->collideType & 1) != 0 )
                        {
                            v11 = i->receiver;
                            if ( v11 != thing )
                            {
                                v12 = i->face;
                                if ( !v12 || !i->sender )
                                {
                                    sithUnk3_SearchClose();
                                    return;
                                }
                                if ( (v14 & 0x10) == 0
                                  || (rdMatrix_TransformVector34(&a1, &v12->normal, &v11->lookOrientation), a1.x * 0.0 + a1.y * 0.0 + a1.z * 1.0 >= 0.60000002) )
                                {
                                    sithThing_LandThing(thing, v11, i->face, i->sender->vertices, a3);
                                    sithUnk3_SearchClose();
                                    return;
                                }
                            }
                        }
                    }
                    sithUnk3_SearchClose();
                    if ( range != 0.0 )
                        break;

                    if ( thing->thingType != THINGTYPE_ACTOR && thing->thingType != THINGTYPE_PLAYER )
                        break;
                    if ( thing->moveSize == 0.0 )
                        break;
                    range = thing->moveSize;
                    sithUnk3_SearchRadiusForThings(thing->sector, 0, &thing->position, &direction, thingb, range, v14 | 0x2802);
                }
            }
            if ( thing->attach_flags )
                sithThing_DetachThing(thing);
        }
    }
}

int sithSector_SetSkyParams(float horizontalPixelsPerRev, float horizontalDist, float ceilingSky)
{
    sithSector_horizontalPixelsPerRev_idk = horizontalPixelsPerRev * 0.0027777778;
    sithSector_horizontalDist = horizontalDist;
    sithSector_ceilingSky = ceilingSky;
    sithSector_zMaxVec.x = 0.0;
    sithSector_zMaxVec.y = 0.0;
    sithSector_zMaxVec.z = ceilingSky;
    sithSector_horizontalPixelsPerRev = horizontalPixelsPerRev;
    sithSector_zMinVec.x = 0.0;
    sithSector_zMinVec.y = 0.0;
    sithSector_zMinVec.z = -ceilingSky;
    return 1;
}

void sithSector_UpdateSky()
{
    double v0; // st7
    float v1; // [esp-Ch] [ebp-Ch]

    v1 = sithCamera_currentCamera->vec3_2.z;
    sithSector_flt_8553C0 = sithSector_horizontalDist / rdCamera_pCurCamera->fov_y;
    stdMath_SinCos(v1, &sithSector_flt_8553F4, &sithSector_flt_8553C8);
    v0 = -(sithCamera_currentCamera->vec3_2.x * sithSector_horizontalPixelsPerRev_idk);
    sithSector_flt_8553B8 = -(sithCamera_currentCamera->vec3_2.y * sithSector_horizontalPixelsPerRev_idk);
    sithSector_flt_8553C4 = v0;
}

void sithSector_StopPhysicsThing(sithThing *thing)
{
    rdVector_Zero3(&thing->physicsParams.vel);
    rdVector_Zero3(&thing->physicsParams.angVel);
    rdVector_Zero3(&thing->physicsParams.field_1F8);
    rdVector_Zero3(&thing->physicsParams.acceleration);
    rdVector_Zero3(&thing->physicsParams.velocityMaybe);
    rdVector_Zero3(&thing->field_268);
}

int sithSector_GetIdxFromPtr(sithSector *sector)
{
    return sector && sector->id == sector - sithWorld_pCurWorld->sectors && sector->id < (unsigned int)sithWorld_pCurWorld->numSectors;
}

void sithSector_SetAdjoins(sithSector *sector)
{
    sithAdjoin *i; // esi

    for ( i = sector->adjoins; i; i = i->next )
        sithSurface_SetAdjoins(i);
    sector->flags &= ~0x80;
}

void sithSector_UnsetAdjoins(sithSector *sector)
{
    sithAdjoin *i; // esi

    for ( i = sector->adjoins; i; i = i->next )
        sithSurface_UnsetAdjoins(i);
    sector->flags |= 0x80;
}

int sithSector_GetThingsCount(sithSector *sector)
{
    int result; // eax
    sithThing *i; // ecx

    result = 0;
    for ( i = sector->thingsList; i; ++result )
        i = i->nextThing;
    return result;
}

void sithSector_Free(sithWorld *world)
{
    for (uint32_t i = 0; i < world->numSectors; i++)
    {
        if ( world->sectors[i].verticeIdxs )
            pSithHS->free(world->sectors[i].verticeIdxs);
    }
    pSithHS->free(world->sectors);
    world->sectors = 0;
    world->numSectors = 0;
}

int sithSector_GetNumPlayers(sithSector *sector)
{
    int result; // eax
    sithThing *i; // ecx

    result = 0;
    for ( i = sector->thingsList; i; i = i->nextThing )
    {
        if ( i->thingType == THINGTYPE_PLAYER )
            ++result;
    }
    return result;
}

void sithSector_sub_4F2E30(rdProcEntry *a1, sithSurfaceInfo *a2, int num_vertices)
{
    int v3; // eax
    int v4; // eax
    sithWorld *v5; // edi
    rdCanvas *v6; // esi
    rdVector2 *v7; // eax
    rdVector3 *v8; // edx
    float *v9; // ecx
    double v10; // st7
    double v12; // st5
    double v13; // st6
    double v14; // st7
    rdClipFrustum *v15; // [esp+10h] [ebp-4h]
    float a1a; // [esp+18h] [ebp+4h]

    v3 = sithRender_geoMode;
    if ( sithRender_geoMode > 4 )
        v3 = 4;
    a1->geometryMode = v3;
    v4 = sithRender_texMode;
    a1->lightingMode = sithRender_lightMode > 0 ? 0 : sithRender_lightMode;
    a1->textureMode = v4 > 0 ? 0 : v4;
    if ( num_vertices )
    {
        v5 = sithWorld_pCurWorld;
        v6 = rdCamera_pCurCamera->canvas;
        v7 = a1->vertexUVs;
        v15 = rdCamera_pCurCamera->cameraClipFrustum;
        v8 = a1->vertices;
        do
        {
            ++v8;
            v9 = &v7->y;
            v8[-1].z = v15->field_0.z;
            v10 = (v8[-1].x - v6->screen_height_half) * sithSector_flt_8553C0;
            ++v7;
            v12 = (v8[-1].y - v6->screen_width_half) * sithSector_flt_8553C0;
            a1a = v12;
            --num_vertices;
            v13 = v10 * sithSector_flt_8553C8 - v12 * sithSector_flt_8553F4 + sithSector_flt_8553B8;
            v14 = a1a * sithSector_flt_8553C8 + v10 * sithSector_flt_8553F4 + sithSector_flt_8553C4;
            v7[-1].x = v13;
            *v9 = v14;
            v7[-1].x = v7[-1].x + v5->horizontalSkyOffs.x;
            *v9 = *v9 + v5->horizontalSkyOffs.y;
            v7[-1].x = v7[-1].x + a2->face.clipIdk.x;
            *v9 = *v9 + a2->face.clipIdk.y;
        }
        while (num_vertices != 0);
    }
}

void sithSector_ThingPhysAttached(sithThing *thing, float deltaSeconds)
{
    int v3; // eax
    double v4; // st6
    sithSurface* v5; // eax
    double v6; // st5
    double v7; // st7
    sithThing* v9; // edi
    double v10; // st6
    double v11; // st7
    int v12; // ecx
    double v13; // st7
    rdVector3 *v14; // edi
    double v15; // st7
    double v16; // st6
    double v18; // st5
    double v24; // st6
    double v26; // st6
    double v28; // st6
    double v30; // st6
    double v32; // st6
    double v34; // st7
    double v35; // st6
    double v36; // st5
    double v37; // st4
    double v38; // st7
    double v39; // st6
    rdVector3 *velocity; // edi
    int v41; // eax
    double v42; // st7
    double v44; // st7
    double v45; // st5
    double v46; // st6
    double v48; // st7
    double v51; // st7
    double v54; // st7
    sithWorld *v56; // edx
    sithSector *v57; // ecx
    rdVector3 *v59; // edi
    double v60; // st6
    double v61; // st7
    double v63; // rt1
    double v64; // st6
    double v65; // st7
    double v67; // st5
    double v73; // st6
    double v75; // st6
    double v77; // st6
    double v79; // st6
    double v81; // st6
    double v83; // st7
    double v84; // st6
    double v85; // st7
    double v86; // st6
    double v87; // st7
    double v88; // st6
    sithSector *v89; // eax
    double v90; // st7
    double v91; // st6
    double v92; // st5
    double v93; // st7
    double v95; // st6
    double v98; // st6
    double v100; // st6
    double v102; // st5
    double v104; // st5
    double v108; // st7
    double v109; // st7
    double v111; // st6
    double v113; // st7
    double v114; // st5
    double v115; // st6
    double v117; // st7
    double v119; // st7
    double v121; // st6
    double v123; // st6
    double v125; // st5
    double v127; // st5
    double v131; // st7
    double v132; // st7
    double v134; // st6
    double v136; // st5
    double v137; // st7
    double v138; // st5
    double v139; // st4
    double v140; // st6
    float a2; // [esp+0h] [ebp-94h]
    float a2a; // [esp+0h] [ebp-94h]
    float a2b; // [esp+0h] [ebp-94h]
    float v144; // [esp+4h] [ebp-90h]
    float v145; // [esp+8h] [ebp-8Ch]
    float v146; // [esp+8h] [ebp-8Ch]
    float deltaSeconds_; // [esp+8h] [ebp-8Ch]
    float possibly_undef_2; // [esp+1Ch] [ebp-78h]
    float v149; // [esp+20h] [ebp-74h]
    float v150; // [esp+20h] [ebp-74h]
    float v151; // [esp+20h] [ebp-74h]
    float new_z; // [esp+20h] [ebp-74h]
    float v153; // [esp+24h] [ebp-70h]
    float v154; // [esp+24h] [ebp-70h]
    float v155; // [esp+24h] [ebp-70h]
    float v156; // [esp+24h] [ebp-70h]
    float new_x; // [esp+24h] [ebp-70h]
    float v158; // [esp+28h] [ebp-6Ch]
    float v159; // [esp+28h] [ebp-6Ch]
    float possibly_undef_1; // [esp+2Ch] [ebp-68h]
    float v161; // [esp+2Ch] [ebp-68h]
    float v162; // [esp+2Ch] [ebp-68h]
    float new_y; // [esp+30h] [ebp-64h]
    float new_ya; // [esp+30h] [ebp-64h]
    float new_yb; // [esp+30h] [ebp-64h]
    rdVector3 vel_change; // [esp+34h] [ebp-60h] BYREF
    rdVector3 a1a; // [esp+40h] [ebp-54h] BYREF
    rdVector3 out; // [esp+4Ch] [ebp-48h] BYREF
    rdVector3 a3; // [esp+58h] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+64h] [ebp-30h] BYREF

    possibly_undef_1 = 0.0;
    possibly_undef_2 = 0.0;

    vel_change.x = 0.0;
    vel_change.y = 0.0;
    vel_change.z = 0.0;
    v3 = thing->attach_flags;
    v158 = 1.0;
    thing->physicsParams.physflags &= ~PHYSFLAGS_200000;
    if ( (v3 & ATTACHFLAGS_WORLDSURFACE) != 0 )
    {
        v4 = thing->position.y - thing->field_38.y;
        v5 = thing->attachedSurface;
        v6 = thing->position.x - thing->field_38.x;
        v7 = thing->position.z - thing->field_38.z;
        a1a = thing->attachedSufaceInfo->face.normal;
        possibly_undef_1 = v6 * a1a.x + v4 * a1a.y + v7 * a1a.z;
        if ( (v5->surfaceFlags & 0x3000) != 0 )
        {
            if ( (v5->surfaceFlags & 0x2000) != 0 )
                possibly_undef_2 = 0.1;
            else
                possibly_undef_2 = 0.30000001;
        }
        else
        {
            possibly_undef_2 = 1.0;
        }
    }
    else if ( (v3 & 2) != 0 )
    {
        v9 = thing->attachedThing;
        rdMatrix_TransformVector34(&a1a, &thing->attachedSufaceInfo->face.normal, &v9->lookOrientation);
        rdMatrix_TransformVector34(&a3, &thing->field_38, &v9->lookOrientation);
        v10 = thing->position.x;
        v11 = thing->position.y;
        a3.x = v9->position.x + a3.x;
        possibly_undef_2 = 1.0;
        a3.y = v9->position.y + a3.y;
        possibly_undef_1 = (thing->position.z - (v9->position.z + a3.z)) * a1a.z + (v10 - a3.x) * a1a.x + (v11 - a3.y) * a1a.y;
    }
    v12 = thing->physicsParams.physflags;
    if ( (v12 & PHYSFLAGS_800) != 0 )
    {
        v13 = a1a.x * 0.0 + a1a.y * 0.0 + a1a.z * 1.0;
        v158 = v13;
        if ( v13 < 1.0 )
            possibly_undef_1 = possibly_undef_1 / v158;
    }
    if ( (v12 & PHYSFLAGS_100) == 0 )
    {
        if ( (v12 & PHYSFLAGS_SURFACEALIGN) != 0 )
        {
            v145 = thing->physicsParams.orientSpeed * deltaSeconds;
            sithSector_ThingSetLook(thing, &a1a, v145);
        }
        else if ( (thing->physicsParams.physflags & PHYSFLAGS_800) != 0 )
        {
            v146 = thing->physicsParams.orientSpeed * deltaSeconds;
            sithSector_ThingSetLook(thing, &rdroid_zVector3, v146);
        }
        else
        {
            thing->physicsParams.physflags |= 0x100;
        }
    }
    if ( (thing->physicsParams.physflags & PHYSFLAGS_ANGTHRUST) != 0 )
    {
        v14 = &thing->physicsParams.angVel;
        if ( thing->physicsParams.angVel.x != 0.0
          || thing->physicsParams.angVel.y != 0.0
          || thing->physicsParams.angVel.z != 0.0 )
        {
            a2 = thing->physicsParams.surfaceDrag - -0.2;
            sithSector_ApplyDrag(&thing->physicsParams.angVel, a2, 0.0, deltaSeconds);
        }
        v15 = -thing->physicsParams.maxRotVel;
        v16 = thing->physicsParams.field_1F8.y * deltaSeconds + thing->physicsParams.angVel.y;

        thing->physicsParams.angVel.y = v16;
        if ( v14->x >= v15 )
        {
            if ( thing->physicsParams.maxRotVel < (double)v14->x )
                v18 = thing->physicsParams.maxRotVel;
            else
                v18 = v14->x;
        }
        else
        {
            v18 = v15;
        }
        v149 = v18;
        v14->x = v18;
        if ( v16 < v15 ) // TODO verify
        {
            v16 = v15;
        }
        else if ( v16 > thing->physicsParams.maxRotVel )
        {
            v16 = thing->physicsParams.maxRotVel;
        }
        v153 = v16;
        thing->physicsParams.angVel.y = v16;
        if ( v15 < thing->physicsParams.maxRotVel )
        {
            if ( thing->physicsParams.maxRotVel < (double)thing->physicsParams.angVel.z )
                v15 = thing->physicsParams.maxRotVel;
            else
                v15 = thing->physicsParams.angVel.z;
        }
        thing->physicsParams.angVel.z = v15;
        v24 = v149;
        if ( v24 < 0.0 )
            v24 = -v24;
        if ( v24 <= 0.0000099999997 )
            v26 = 0.0;
        else
            v26 = v149;
        v14->x = v26;
        v28 = v153;
        if ( v28 < 0.0 )
            v28 = -v28;
        if ( v28 <= 0.0000099999997 )
            v30 = 0.0;
        else
            v30 = v153;
        thing->physicsParams.angVel.y = v30;
        v32 = v15;
        if ( v32 < 0.0 )
            v32 = -v15;
        if ( v32 <= 0.0000099999997 )
            v15 = 0.0;
        thing->physicsParams.angVel.z = v15;
    }
    if ( thing->physicsParams.angVel.y != 0.0 )
    {
        v34 = thing->physicsParams.angVel.y * deltaSeconds;
        v35 = thing->physicsParams.angVel.z * deltaSeconds;
        a3.x = thing->physicsParams.angVel.x * deltaSeconds;
        a3.y = v34;
        a3.z = v35;
        rdMatrix_BuildRotate34(&a, &a3);
        sithUnk3_sub_4E7670(thing, &a);
        if ( possibly_undef_2 >= 1.0 )
        {
            rdMatrix_TransformVector34Acc(&thing->physicsParams.vel, &a);
        }
        else
        {
            v154 = 1.0 - possibly_undef_2;
            rdMatrix_TransformVector34(&out, &thing->physicsParams.vel, &a);
            v36 = out.y;
            v37 = out.z;
            v38 = thing->physicsParams.vel.z;
            v39 = thing->physicsParams.vel.y * v154;
            thing->physicsParams.vel.x = thing->physicsParams.vel.x * v154 + out.x * possibly_undef_2;
            thing->physicsParams.vel.y = v39 + v36 * possibly_undef_2;
            thing->physicsParams.vel.z = v38 * v154 + v37 * possibly_undef_2;
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
    velocity = &thing->physicsParams.vel;
    if ( (thing->physicsParams.vel.x != 0.0 || thing->physicsParams.vel.y != 0.0 || thing->physicsParams.vel.z != 0.0)
      && thing->physicsParams.surfaceDrag != 0.0 )
    {
        v41 = thing->physicsParams.physflags;
        if ( (v41 & 0x8000) == 0 )
        {
            if ( thing->physicsParams.acceleration.x == 0.0
              && thing->physicsParams.acceleration.y == 0.0
              && thing->physicsParams.acceleration.z == 0.0
              && (thing->sector->flags & 8) == 0
              && possibly_undef_2 > 0.80000001 )
            {
                v42 = thing->physicsParams.surfaceDrag * possibly_undef_2;
                deltaSeconds_ = deltaSeconds;
                v144 = thing->physicsParams.staticDrag * possibly_undef_2;
            }
            else
            {
                v42 = thing->physicsParams.surfaceDrag * possibly_undef_2;
                deltaSeconds_ = deltaSeconds;
                v144 = 0.0;
            }
            a2a = v42;
            sithSector_ApplyDrag(&thing->physicsParams.vel, a2a, v144, deltaSeconds_);
        }
        else
        {
            thing->physicsParams.physflags &= ~0x8000;
        }
    }

    if ( (thing->physicsParams.physflags & PHYSFLAGS_USESTHRUST) != 0
      && (thing->physicsParams.acceleration.x != 0.0
       || thing->physicsParams.acceleration.y != 0.0
       || thing->physicsParams.acceleration.z != 0.0) )
    {
        v44 = possibly_undef_2 * deltaSeconds;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING) != 0 )
            v44 = deltaSeconds * 0.80000001;
        v45 = thing->physicsParams.acceleration.y;
        v46 = thing->physicsParams.acceleration.z;
        vel_change.x = thing->physicsParams.acceleration.x * v44;
        vel_change.y = v45 * v44;
        vel_change.z = v46 * v44;
        v48 = vel_change.x;
        if ( v48 < 0.0 )
            v48 = -v48;
        if ( v48 <= 0.0000099999997 )
            vel_change.x = 0.0;
        v51 = vel_change.y;
        if ( v51 < 0.0 )
            v51 = -v51;
        if ( v51 <= 0.0000099999997 )
            vel_change.y = 0.0;
        v54 = vel_change.z;
        if ( v54 < 0.0 )
            v54 = -v54;
        if ( v54 <= 0.0000099999997 )
            vel_change.z = 0.0;
        if ( vel_change.x != 0.0 || vel_change.y != 0.0 || vel_change.z != 0.0 )
            rdMatrix_TransformVector34Acc(&vel_change, &thing->lookOrientation);
    }
    v56 = sithWorld_pCurWorld;
    if ( thing->physicsParams.mass != 0.0 )
    {
        v57 = thing->sector;
        if ( (v57->flags & SITH_SF_HASTHRUST) != 0 && (thing->physicsParams.physflags & PHYSFLAGS_NOTHRUST) == 0 )
        {
            if ( v57->thrust.z > sithWorld_pCurWorld->worldGravity * thing->physicsParams.mass )
            {
                sithThing_DetachThing(thing);
                thing->physicsParams.addedVelocity.x = 0.0;
                out.x = 0.0;
                out.y = 0.0;
                thing->physicsParams.addedVelocity.y = 0.0;
                out.z = 0.0;
                thing->physicsParams.addedVelocity.z = 0.0;
                if ( (thing->physicsParams.physflags & PHYSFLAGS_ANGTHRUST) != 0 )
                {
                    v59 = &thing->physicsParams.angVel;
                    if ( thing->physicsParams.angVel.x != 0.0
                      || thing->physicsParams.angVel.y != 0.0
                      || thing->physicsParams.angVel.z != 0.0 )
                    {
                        a2b = thing->physicsParams.airDrag - -0.2;
                        sithSector_ApplyDrag(&thing->physicsParams.angVel, a2b, 0.0, deltaSeconds);
                    }
                    v60 = thing->physicsParams.maxRotVel;
                    v161 = thing->physicsParams.field_1F8.x * deltaSeconds + v59->x;
                    v61 = thing->physicsParams.field_1F8.y * deltaSeconds + thing->physicsParams.angVel.y;
                    v159 = thing->physicsParams.field_1F8.z * deltaSeconds + thing->physicsParams.angVel.z;
                    v59->x = v161;
                    thing->physicsParams.angVel.y = v61;
                    thing->physicsParams.angVel.z = v159;
                    v63 = -v60;
                    v64 = v61;
                    v65 = v63;
                    if ( v161 < v65 )
                    {
                        v67 = v65;
                    }
                    else if ( v161 > (double)thing->physicsParams.maxRotVel )
                    {
                        v67 = thing->physicsParams.maxRotVel;
                    }
                    else
                    {
                        v67 = v161;
                    }
                    v155 = v67;
                    v59->x = v67;
                    if ( v64 < v65 )
                    {
                        v64 = v65;
                    }
                    else if ( v64 > thing->physicsParams.maxRotVel )
                    {
                        v64 = thing->physicsParams.maxRotVel;
                    }
                    v150 = v64;
                    thing->physicsParams.angVel.y = v64;
                    if ( v65 < thing->physicsParams.maxRotVel )
                    {
                        if ( v159 > (double)thing->physicsParams.maxRotVel )
                            v65 = thing->physicsParams.maxRotVel;
                        else
                            v65 = v159;
                    }
                    thing->physicsParams.angVel.z = v65;
                    v73 = v155;
                    if ( v73 < 0.0 )
                        v73 = -v73;
                    if ( v73 <= 0.0000099999997 )
                        v75 = 0.0;
                    else
                        v75 = v155;
                    v59->x = v75;
                    v77 = v150;
                    if ( v77 < 0.0 )
                        v77 = -v77;
                    if ( v77 <= 0.0000099999997 )
                        v79 = 0.0;
                    else
                        v79 = v150;
                    thing->physicsParams.angVel.y = v79;
                    v81 = v65;
                    if ( v81 < 0.0 )
                        v81 = -v65;
                    if ( v81 <= 0.0000099999997 )
                        v65 = 0.0;
                    thing->physicsParams.angVel.z = v65;
                }
                if ( thing->physicsParams.angVel.x == 0.0
                  && thing->physicsParams.angVel.y == 0.0
                  && thing->physicsParams.angVel.z == 0.0 )
                {
                    a3.x = 0.0;
                    a3.y = 0.0;
                    a3.z = 0.0;
                }
                else
                {
                    v83 = thing->physicsParams.angVel.y * deltaSeconds;
                    v84 = thing->physicsParams.angVel.z * deltaSeconds;
                    a3.x = thing->physicsParams.angVel.x * deltaSeconds;
                    a3.y = v83;
                    a3.z = v84;
                }
                if ( a3.x != 0.0 || a3.y != 0.0 || a3.z != 0.0 )
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
                if ( (thing->physicsParams.physflags & PHYSFLAGS_USESTHRUST) != 0 )
                {
                    if ( (thing->physicsParams.physflags & PHYSFLAGS_FLYING) == 0 )
                    {
                        v85 = thing->physicsParams.acceleration.y * 0.30000001;
                        v86 = thing->physicsParams.acceleration.z * 0.30000001;
                        thing->physicsParams.acceleration.x = thing->physicsParams.acceleration.x * 0.30000001;
                        thing->physicsParams.acceleration.y = v85;
                        thing->physicsParams.acceleration.z = v86;
                    }
                    v87 = thing->physicsParams.acceleration.y * deltaSeconds;
                    v88 = thing->physicsParams.acceleration.z * deltaSeconds;
                    out.x = thing->physicsParams.acceleration.x * deltaSeconds;
                    out.y = v87;
                    out.z = v88;
                    rdMatrix_TransformVector34Acc(&out, &thing->lookOrientation);
                }
                if ( thing->physicsParams.mass == 0.0
                  || (v89 = thing->sector, (v89->flags & SITH_SF_HASTHRUST) == 0)
                  || (thing->physicsParams.physflags & PHYSFLAGS_NOTHRUST) != 0 )
                {
                    v90 = out.z;
                }
                else
                {
                    out.x = v89->thrust.x * deltaSeconds + out.x;
                    out.y = v89->thrust.y * deltaSeconds + out.y;
                    v90 = v89->thrust.z * deltaSeconds + out.z;
                    out.z = v90;
                }
                if ( thing->physicsParams.mass != 0.0 && (thing->physicsParams.physflags & PHYSFLAGS_GRAVITY) != 0 && (thing->sector->flags & PHYSFLAGS_GRAVITY) == 0 )
                {
                    v91 = sithWorld_pCurWorld->worldGravity * deltaSeconds;
                    if ( (thing->physicsParams.physflags & PHYSFLAGS_PARTIALGRAVITY) != 0 )
                        v91 = v91 * 0.5;
                    v90 = v90 - v91;
                    thing->physicsParams.addedVelocity.z = -v91;
                }
                v92 = v90;
                v93 = out.x + thing->physicsParams.vel.x;
                v156 = out.y + thing->physicsParams.vel.y;
                v151 = v92 + thing->physicsParams.vel.z;
                thing->physicsParams.vel.x = v93;
                thing->physicsParams.vel.y = v156;
                thing->physicsParams.vel.z = v151;
                v95 = v93;
                if ( v95 < 0.0 )
                    v95 = -v93;
                if ( v95 <= 0.0000099999997 )
                    v93 = 0.0;
                thing->physicsParams.vel.x = v93;
                v98 = v156;
                if ( v98 < 0.0 )
                    v98 = -v98;
                if ( v98 <= 0.0000099999997 )
                    v100 = 0.0;
                else
                    v100 = v156;
                thing->physicsParams.vel.y = v100;
                v102 = v151;
                if ( v102 < 0.0 )
                    v102 = -v102;
                if ( v102 <= 0.0000099999997 )
                    v104 = 0.0;
                else
                    v104 = v151;
                thing->physicsParams.vel.z = v104;
                if ( v93 != 0.0 || v100 != 0.0 || v104 != 0.0 )
                {
                    thing->physicsParams.velocityMaybe.x = v93 * deltaSeconds;
                    thing->physicsParams.velocityMaybe.y = v100 * deltaSeconds;
                    thing->physicsParams.velocityMaybe.z = v104 * deltaSeconds;
                }
                return;
            }
            vel_change.x = v57->thrust.x * deltaSeconds + vel_change.x;
            vel_change.y = v57->thrust.y * deltaSeconds + vel_change.y;
            vel_change.z = v57->thrust.z * deltaSeconds + vel_change.z;
        }
    }
    new_x = vel_change.x + velocity->x;
    new_y = vel_change.z + thing->physicsParams.vel.z;
    new_z = vel_change.y + thing->physicsParams.vel.y;
    thing->physicsParams.vel.z = new_y;

    velocity->x = new_x;
    thing->physicsParams.vel.y = new_z;
    if ( thing->thingType == THINGTYPE_PLAYER
      && (thing->physicsParams.physflags & PHYSFLAGS_GRAVITY) != 0
      && v158 < 1.0
      && (possibly_undef_2 < 0.80000001 || new_x != 0.0 || new_z != 0.0 || new_y != 0.0) )
    {
        v108 = 1.0 - possibly_undef_2;
        if ( v108 < 0.2 )
        {
            v108 = 0.2;
        }
        else if ( v108 > 0.80000001 )
        {
            v108 = 0.80000001;
        }
        thing->physicsParams.vel.z = new_y - v56->worldGravity * deltaSeconds * v108;
    }
    if ( new_x != 0.0 || new_z != 0.0 || thing->physicsParams.vel.z != 0.0 )
    {
        v109 = a1a.x * new_x + a1a.y * new_z + thing->physicsParams.vel.z * a1a.z;
        v111 = v109;
        if ( v111 < 0.0 )
            v111 = -v109;
        if ( v111 <= 0.0000099999997 )
            v109 = 0.0;
        if ( v109 != 0.0 )
        {
            v113 = -v109;
            v114 = a1a.y * v113 + new_z;
            v115 = a1a.z * v113 + thing->physicsParams.vel.z;
            velocity->x = a1a.x * v113 + new_x;
            thing->physicsParams.vel.y = v114;
            thing->physicsParams.vel.z = v115;
        }
    }
    v117 = velocity->x;
    if ( v117 < 0.0 )
        v117 = -v117;
    if ( v117 <= 0.0000099999997 )
        v119 = 0.0;
    else
        v119 = velocity->x;
    velocity->x = v119;
    v121 = thing->physicsParams.vel.y;
    if ( v121 < 0.0 )
        v121 = -v121;
    if ( v121 <= 0.0000099999997 )
        v123 = 0.0;
    else
        v123 = thing->physicsParams.vel.y;
    thing->physicsParams.vel.y = v123;
    v125 = thing->physicsParams.vel.z;
    if ( v125 < 0.0 )
        v125 = -v125;
    if ( v125 <= 0.0000099999997 )
        v127 = 0.0;
    else
        v127 = thing->physicsParams.vel.z;
    thing->physicsParams.vel.z = v127;
    if ( v119 != 0.0 || v123 != 0.0 || v127 != 0.0 )
    {
        thing->physicsParams.velocityMaybe.x = v119 * deltaSeconds;
        thing->physicsParams.velocityMaybe.y = v123 * deltaSeconds;
        thing->physicsParams.velocityMaybe.z = v127 * deltaSeconds;
    }
    if ( (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING) != 0 )
    {
        v131 = v158 * possibly_undef_1 - (thing->moveSize - -0.0099999998);
    }
    else
    {
        v132 = thing->physicsParams.height;
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
    v134 = v131;
    if ( v134 < 0.0 )
        v134 = -v131;
    if ( v134 <= 0.0000099999997 )
        v131 = 0.0;
    if ( v131 != 0.0 )
    {
        v136 = deltaSeconds * 0.5;
        new_yb = v136;
        v162 = -v136;
        if ( v131 < v162 )
        {
            v131 = v162;
        }
        else if ( v131 > new_yb )
        {
            v131 = new_yb;
        }
        v137 = -v131;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_800) != 0 )
        {
            v138 = 0.0 * v137 + thing->physicsParams.velocityMaybe.y;
            v139 = 0.0 * v137 + thing->physicsParams.velocityMaybe.x;
            v140 = 1.0 * v137 + thing->physicsParams.velocityMaybe.z;
        }
        else
        {
            v138 = a1a.y * v137 + thing->physicsParams.velocityMaybe.y;
            v139 = a1a.x * v137 + thing->physicsParams.velocityMaybe.x;
            v140 = a1a.z * v137 + thing->physicsParams.velocityMaybe.z;
        }
        thing->physicsParams.velocityMaybe.x = v139;
        thing->physicsParams.velocityMaybe.y = v138;
        thing->physicsParams.velocityMaybe.z = v140;
    }
}

void sithSector_ThingSetLook(sithThing *thing, rdVector3 *look, float a3)
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
        thing->physicsParams.physflags |= PHYSFLAGS_100;
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
        thing->physicsParams.physflags |= PHYSFLAGS_100;
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

void sithSector_ThingApplyForce(sithThing *thing, rdVector3 *forceVec)
{
    double v2; // st7
    double v6; // st7
    double v7; // st6
    int v8; // eax
    float v9; // [esp+4h] [ebp-Ch]
    float v10; // [esp+8h] [ebp-8h]
    float v11; // [esp+Ch] [ebp-4h]

    if ( thing->move_type == MOVETYPE_PHYSICS && thing->physicsParams.mass > 0.0 )
    {
        v2 = 1.0 / thing->physicsParams.mass;
        v11 = forceVec->z * v2;
        v9 = forceVec->x * v2;
        v10 = forceVec->y * v2;
        if ( v11 > 0.5 ) // TODO verify
            sithThing_DetachThing(thing);
        v6 = v10 + thing->physicsParams.vel.y;
        v7 = v11 + thing->physicsParams.vel.z;
        thing->physicsParams.vel.x = v9 + thing->physicsParams.vel.x;
        thing->physicsParams.vel.y = v6;
        thing->physicsParams.vel.z = v7;
        thing->physicsParams.physflags |= PHYSFLAGS_8000;
    }
}

void sithSector_sub_4F2F60(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4)
{
    int v4; // eax
    rdProcEntry *v5; // ebx
    unsigned int v6; // edi
    int v8; // esi
    rdVector2 *v9; // eax
    rdVector2 *v10; // eax
    double v11; // st7
    sithWorld *v12; // ecx
    double v13; // st5
    double v14; // st6
    sithSurfaceInfo *v15; // ecx
    unsigned int v16; // eax
    rdMatrix34 *v17; // [esp-4h] [ebp-38h]
    rdVector3 a1a; // [esp+10h] [ebp-24h] BYREF
    rdVector3 a2a; // [esp+1Ch] [ebp-18h] BYREF
    rdVector3 vertex_out; // [esp+28h] [ebp-Ch] BYREF

    v4 = sithRender_geoMode;
    if ( sithRender_geoMode > 4 )
        v4 = 4;
    v5 = a1;
    a1->geometryMode = v4;
    v6 = 0;
    v5->lightingMode = sithRender_lightMode > 0 ? 0 : sithRender_lightMode;
    if ( a4 != 0 )
    {
        v8 = 0;
        do
        {
            rdMatrix_TransformPoint34(&a2a, &a3[v8], &rdCamera_camMatrix);
            a2a.x = a2a.x - sithCamera_currentCamera->vec3_1.x;
            a2a.y = a2a.y - sithCamera_currentCamera->vec3_1.y;
            a2a.z = a2a.z - sithCamera_currentCamera->vec3_1.z;
            rdVector_Normalize3(&a1a, &a2a);
            
            float tmp = 0.0;
            if ( !sithCollide_sub_508BE0(&sithCamera_currentCamera->vec3_1, &a1a, 1000.0, 0.0, &sithSector_surfaceNormal, &sithSector_zMaxVec, &tmp, 0) )
                tmp = 1000.0;
            v9 = v5->vertexUVs;
            a1a.x = tmp * a1a.x;
            a1a.y = tmp * a1a.y;
            a1a.z = tmp * a1a.z;
            v10 = &v9[v6];
            v17 = &sithCamera_currentCamera->rdCam.view_matrix;
            v11 = a2->face.clipIdk.x;
            a1a.x = sithCamera_currentCamera->vec3_1.x + a1a.x;
            a1a.y = sithCamera_currentCamera->vec3_1.y + a1a.y;
            v12 = sithWorld_pCurWorld;
            a1a.z = sithCamera_currentCamera->vec3_1.z + a1a.z;
            v10->x = a1a.x * 16.0;
            v13 = v12->ceilingSkyOffs.x;
            v14 = v12->ceilingSkyOffs.y;
            v10->y = a1a.y * 16.0;
            v15 = a2;
            v10->x = v13 + v10->x;
            v10->y = v14 + v10->y;
            v10->x = v11 + v10->x;
            v10->y = v10->y + v15->face.clipIdk.y;
            rdMatrix_TransformPoint34(&vertex_out, &a1a, v17);
            v16 = a4;
            ++v6;
            v5->vertices[v8++].z = vertex_out.y;
        }
        while ( v6 < v16 );
    }
}

int sithSector_AddEntry(sithSector *sector, rdVector3 *pos, int a3, float a4, sithThing *thing)
{
    int v6; // ecx
    int v7; // eax
    rdVector3 *v8; // edx

    if ( !sithAI_bOpened )
        return 0;
    v6 = sithSector_numEntries;
    if ( sithSector_numEntries == 32 )
        return 0;
    v7 = sithSector_numEntries;
    sithSector_aEntries[v7].sector = sector;
    v8 = &sithSector_aEntries[v6].pos;
    v8->x = pos->x;
    sithSector_numEntries = v6 + 1;
    v8->y = pos->y;
    v8->z = pos->z;
    sithSector_aEntries[v7].field_14 = a3;
    sithSector_aEntries[v7].field_18 = a4;
    sithSector_aEntries[v7].thing = thing;
    return 1;
}
