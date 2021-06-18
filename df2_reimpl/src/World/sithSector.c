#include "sithSector.h"

#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "World/sithUnk3.h"
#include "Engine/sithAdjoin.h"
#include "jk.h"
#include "Engine/sithNet.h"
#include "Engine/sithTimer.h"
#include "Engine/rdColormap.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSound.h"
#include "Primitives/rdFace.h"
#include "Engine/sithRender.h"
#include "Engine/rdCache.h"

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

    rdVector_Zero3(&thing->velocityMaybe);
    rdVector_Zero3(&thing->addedVelocity);

    if ((thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER) 
        && (thing->actorParams.typeflags & SITH_TF_TIMER))
    {
        rdVector_Zero3(&thing->physicsParams.acceleration);
    }

    if (thing->attach_flags & (ATTACHFLAGS_THINGSURFACE | ATTACHFLAGS_WORLDSURFACE))
    {
#ifndef LINUX_TMP
        sithSector_ThingPhysAttached(thing, deltaSecs);
#endif
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
    rdVector_Zero3(&thing->velocityMaybe);
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
