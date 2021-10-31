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
#include "Engine/sithSoundSys.h"
#include "Engine/sithRender.h"
#include "Engine/rdCache.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithSurface.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"

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
                sectors->flags |= SITH_SF_COLLIDEBOX;
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, "sound %s %f", sound_fname, &sectors->sectorSoundVol) == 2 )
            {
                sectors->sectorSound = sithSound_LoadEntry(sound_fname, 0);
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
        sithSector_ThingPhysUnderwater(thing, deltaSecs);
    }
#ifdef QOL_IMPROVEMENTS
    else if ( thing->thingType == THINGTYPE_PLAYER && sithNet_isMulti)
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
    v14 = 0;
    if (!sector)
        return;

    if (sector->flags & SITH_SF_UNDERWATER && thing->thingType == THINGTYPE_PLAYER)
    {
        sithUnk3_SearchRadiusForThings(sector, thing, &thing->position, &rdroid_zVector3, 0.050000001, 0.0, 1);
        v5 = sithUnk3_NextSearchResult();
        if ( v5 )
        {
            while ( (v5->collideType & 0x20) == 0 || (v5->surface->adjoin->sector->flags & SITH_SF_UNDERWATER) != 0 )
            {
                v5 = sithUnk3_NextSearchResult();
                if ( !v5 )
                    goto LABEL_8;
            }
            thing->field_48 = v5->distance;
            thing->physicsParams.physflags |= PHYSFLAGS_MIDAIR;
            sithUnk3_SearchClose();
        }
        else
        {
LABEL_8:
            sithUnk3_SearchClose();
            thing->physicsParams.physflags &= ~PHYSFLAGS_MIDAIR;
        }
    }
    else
    {
        if ( (thing->physicsParams.physflags & PHYSFLAGS_WALLSTICK) == 0 )
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
            if ( (thing->physicsParams.physflags & (PHYSFLAGS_FLOORSTICK|PHYSFLAGS_WALLSTICK)) != 0 )
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
                        //printf("Attach to new surface? %x\n", i->surface->field_0);
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
                            
                            // Track thing that can move
                            if ( (v14 & 0x10) == 0
                              || (rdMatrix_TransformVector34(&a1, &v12->normal, &v11->lookOrientation), rdVector_Dot3(&a1, &rdroid_zVector3) >= 0.60000002) )
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
    sector->flags &= ~SITH_SF_80;
}

void sithSector_UnsetAdjoins(sithSector *sector)
{
    sithAdjoin *i; // esi

    for ( i = sector->adjoins; i; i = i->next )
        sithSurface_UnsetAdjoins(i);
    sector->flags |= SITH_SF_80;
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
    thing->physicsParams.physflags &= ~PHYSFLAGS_200000;
    if ( (thing->attach_flags & ATTACHFLAGS_WORLDSURFACE) != 0 )
    {
        attachedNormal = thing->attachedSufaceInfo->face.normal;
        possibly_undef_1 = rdVector_NormalDot(&thing->position, &thing->field_38, &attachedNormal);
        if ( (thing->attachedSurface->surfaceFlags & (SURFACEFLAGS_1000|SURFACEFLAGS_2000)) != 0 )
        {
            if ( (thing->attachedSurface->surfaceFlags & SURFACEFLAGS_2000) != 0 )
                possibly_undef_2 = 0.1;
            else
                possibly_undef_2 = 0.30000001;
        }
        else
        {
            possibly_undef_2 = 1.0;
        }
    }
    else if ( (thing->attach_flags & ATTACHFLAGS_THINGSURFACE) != 0 )
    {
        rdMatrix_TransformVector34(&attachedNormal, &thing->attachedSufaceInfo->face.normal, &thing->attachedThing->lookOrientation);
        rdMatrix_TransformVector34(&a3, &thing->field_38, &thing->attachedThing->lookOrientation);
        possibly_undef_2 = 1.0;
        rdVector_Add3Acc(&a3, &thing->attachedThing->position);
        possibly_undef_1 = rdVector_NormalDot(&thing->position, &a3, &attachedNormal);
    }

    if (thing->physicsParams.physflags & PHYSFLAGS_800)
    {
        v158 = rdVector_Dot3(&attachedNormal, &rdroid_zVector3);
        if ( v158 < 1.0 )
            possibly_undef_1 = possibly_undef_1 / v158;
    }

    if (!(thing->physicsParams.physflags & PHYSFLAGS_100))
    {
        if ( (thing->physicsParams.physflags & PHYSFLAGS_SURFACEALIGN) != 0 )
        {
            sithSector_ThingSetLook(thing, &attachedNormal, thing->physicsParams.orientSpeed * deltaSeconds);
        }
        else if ( (thing->physicsParams.physflags & PHYSFLAGS_800) != 0 )
        {
            sithSector_ThingSetLook(thing, &rdroid_zVector3, thing->physicsParams.orientSpeed * deltaSeconds);
        }
        else
        {
            thing->physicsParams.physflags |= PHYSFLAGS_100;
        }
    }

    if (thing->physicsParams.physflags & PHYSFLAGS_ANGTHRUST)
    {
        if (!rdVector_IsZero3(&thing->physicsParams.angVel))
        {
            sithSector_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.surfaceDrag - -0.2, 0.0, deltaSeconds);
        }

        thing->physicsParams.angVel.y = thing->physicsParams.field_1F8.y * deltaSeconds + thing->physicsParams.angVel.y;
        rdVector_ClampValue3(&thing->physicsParams.angVel, thing->physicsParams.maxRotVel);
        rdVector_ClipPrecision3(&thing->physicsParams.angVel);
    }
    if ( thing->physicsParams.angVel.y != 0.0 )
    {
        rdVector_Scale3(&a3, &thing->physicsParams.angVel, deltaSeconds);
        rdMatrix_BuildRotate34(&a, &a3);
        sithUnk3_sub_4E7670(thing, &a);
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
        if ( (thing->physicsParams.physflags & PHYSFLAGS_8000) == 0 )
        {
            if ( rdVector_IsZero3(&thing->physicsParams.acceleration)
              && !(thing->sector->flags & SITH_SF_HASTHRUST)
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
            sithSector_ApplyDrag(&thing->physicsParams.vel, a2a, v144, deltaSeconds);
        }
        else
        {
            thing->physicsParams.physflags &= ~PHYSFLAGS_8000;
        }
    }

    if ( (thing->physicsParams.physflags & PHYSFLAGS_USESTHRUST) != 0
      && !rdVector_IsZero3(&thing->physicsParams.acceleration) )
    {
        float v44 = possibly_undef_2 * deltaSeconds;
        if ( (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING) != 0 )
            v44 = deltaSeconds * 0.80000001;
        rdVector_Scale3(&vel_change, &thing->physicsParams.acceleration, v44);
        rdVector_ClipPrecision3(&vel_change);
        if ( !rdVector_IsZero3(&vel_change) )
            rdMatrix_TransformVector34Acc(&vel_change, &thing->lookOrientation);
    }

    if (thing->physicsParams.mass != 0.0 && (thing->sector->flags & SITH_SF_HASTHRUST) && !(thing->physicsParams.physflags & PHYSFLAGS_NOTHRUST))
    {
        if ( thing->sector->thrust.z > sithWorld_pCurWorld->worldGravity * thing->physicsParams.mass )
        {
            sithThing_DetachThing(thing);
            rdVector_Zero3(&thing->physicsParams.addedVelocity);
            rdVector_Zero3(&out);
            if ( (thing->physicsParams.physflags & PHYSFLAGS_ANGTHRUST) != 0 )
            {
                if ( !rdVector_IsZero3(&thing->physicsParams.angVel) )
                {
                    sithSector_ApplyDrag(&thing->physicsParams.angVel, thing->physicsParams.airDrag - -0.2, 0.0, deltaSeconds);
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
                rdVector_Scale3(&out, &thing->physicsParams.acceleration, deltaSeconds);
            }

            if ( thing->physicsParams.mass != 0.0
              && (thing->sector->flags & SITH_SF_HASTHRUST)
              && !(thing->physicsParams.physflags & PHYSFLAGS_NOTHRUST))
            {
                rdVector_MultAcc3(&out, &thing->sector->thrust, deltaSeconds);
            }

            if ( thing->physicsParams.mass != 0.0 && (thing->physicsParams.physflags & PHYSFLAGS_GRAVITY) != 0 && (thing->sector->flags & PHYSFLAGS_GRAVITY) == 0 )
            {
                float v91 = sithWorld_pCurWorld->worldGravity * deltaSeconds;
                if ( (thing->physicsParams.physflags & PHYSFLAGS_PARTIALGRAVITY) != 0 )
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
    if ( thing->thingType == THINGTYPE_PLAYER
      && (thing->physicsParams.physflags & PHYSFLAGS_GRAVITY) != 0
      && v158 < 1.0
      && (possibly_undef_2 < 0.80000001 || !rdVector_IsZero3(&thing->physicsParams.vel)) )
    {
        float v108 = stdMath_Clamp(1.0 - possibly_undef_2, 0.2, 0.80000001);
        thing->physicsParams.vel.z = thing->physicsParams.vel.z - sithWorld_pCurWorld->worldGravity * deltaSeconds * v108;
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
    if (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING)
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
        //if (thing->thingType == THINGTYPE_PLAYER)
        //    printf("%f before\n", v131);
        v131 = stdMath_ClampValue(v131, deltaSeconds * 0.5);
        //if (thing->thingType == THINGTYPE_PLAYER)
        //    printf("%f after\n", v131);

        if ( (thing->physicsParams.physflags & PHYSFLAGS_800) != 0 )
        {
            //if (thing->thingType == THINGTYPE_PLAYER)
            //    printf("a\n");
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &rdroid_zVector3, -v131);
        }
        else
        {
            //if (thing->thingType == THINGTYPE_PLAYER)
            //    printf("b\n");
            rdVector_MultAcc3(&thing->physicsParams.velocityMaybe, &attachedNormal, -v131);
        }
    }
}

void sithSector_ThingSetLook(sithThing *thing, const rdVector3 *look, float a3)
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
    if ( thing->move_type == MOVETYPE_PHYSICS && thing->physicsParams.mass > 0.0 )
    {
        float invMass = 1.0 / thing->physicsParams.mass;

        if ( forceVec->z * invMass > 0.5 ) // TODO verify
            sithThing_DetachThing(thing);

        rdVector_MultAcc3(&thing->physicsParams.vel, forceVec, invMass);
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

void sithSector_ThingPhysUnderwater(sithThing *thing, float deltaSeconds)
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
    if ( (thing->physicsParams.physflags & PHYSFLAGS_ANGTHRUST) != 0 )
    {
        v4 = &thing->physicsParams.angVel;
        if ( !rdVector_IsZero3(&thing->physicsParams.angVel) )
        {
            v58 = thing->physicsParams.airDrag - -0.2;
            sithSector_ApplyDrag(&thing->physicsParams.angVel, v58, 0.0, deltaSeconds);
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
        sithUnk3_sub_4E7670(thing, &a);
        if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 7) == 0 )
            rdMatrix_Normalize34(&thing->lookOrientation);
    }
    if ( thing->physicsParams.airDrag != 0.0 )
    {
        v59 = thing->physicsParams.airDrag * 4.0;
        sithSector_ApplyDrag(&thing->physicsParams.vel, v59, 0.0, deltaSeconds);
    }
    if ( (thing->physicsParams.physflags & PHYSFLAGS_USESTHRUST) != 0 )
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
    if ( thing->physicsParams.mass == 0.0 || (v33 = thing->sector, (v33->flags & 8) == 0) || (thing->physicsParams.physflags & PHYSFLAGS_NOTHRUST) != 0 )
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
    if ( ((thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) == 0 || (thing->thingflags & SITH_TF_DEAD) != 0) && (thing->physicsParams.physflags & PHYSFLAGS_GRAVITY) != 0 )
    {
        v35 = sithWorld_pCurWorld->worldGravity * deltaSeconds * thing->physicsParams.buoyancy;
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
    if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 && thing->physicsParams.acceleration.z >= 0.0 )
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

float sithSector_ThingGetInsertOffsetZ(sithThing *thing)
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

int sithSector_TimerTick()
{
    ++sithSector_timerTicks;
    if ( !sithSector_numEntries )
        return 1;

    for (size_t v1 = 0; v1 < sithSector_numEntries; v1++)
    {
        sithSectorEntry* v2 = (sithSectorEntry *)&sithSector_aEntries[v1];
        sithSector_sub_4F2C30(v2, v2->sector, &v2->pos, &v2->pos, v2->field_18, v2->field_18, v2->thing);
    }
    
    for (size_t v3 = 0; v3 <= sithAI_inittedActors; ++v3 )
    {
        sithActor* i = &sithAI_actors[v3];

        if ( i->aiclass )
        {
            if ( i->thing )
            {
                if ( (i->thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
                {
                    sithSector* v6 = i->thing->sector;
                    if ( v6 )
                    {
                        if ( sithSector_allocPerSector[v6->id].field_0 == sithSector_timerTicks )
                            sithAI_SetActorFireTarget(i, SITHAIFLAGS_ATTACKING_TARGET, 0);
                    }
                }
            }
        }
    }
    sithSector_numEntries = 0;
    return 1;
}

void sithSector_sub_4F2C30(sithSectorEntry *sectorEntry, sithSector *sector, rdVector3 *pos1, rdVector3 *pos2, float a5, float a6, sithThing *thing)
{
    int v7; // esi
    sithSectorAlloc *v8; // edx
    int v9; // ecx
    sithAdjoin *i; // esi
    sithAdjoin *v13; // ecx
    float a6a; // [esp+24h] [ebp+14h]

    v7 = sithSector_timerTicks;
    v8 = &sithSector_allocPerSector[sector->id];
    if ( v8->field_0 != sithSector_timerTicks )
    {
        _memset(v8, 0, sizeof(sithSectorAlloc));
        v8->field_0 = v7;
    }
    v9 = sectorEntry->field_14;
    if ( v8->field_4[v9] < (double)a5 )
    {
        v8->field_4[v9] = a5;
        v8->field_10[v9] = *pos1;
        v8->field_34[v9] = *pos2;
        v8->field_58[v9] = thing;
        if ( a6 > 0.0 )
        {
            for ( i = sector->adjoins; i; i = i->next )
            {
                v13 = i->mirror;
                if ( v13 )
                    a6a = a6 - v13->dist;
                else
                    a6a = a6;
                sithSector_sub_4F2C30(sectorEntry, i->sector, pos1, &i->field_1C, a6, a6a, thing);
            }
        }
    }
}

sithSector* sithSector_GetPtrFromIdx(int idx)
{
    sithSector *result; // eax

    if ( sithWorld_pCurWorld && idx >= 0 && idx < sithWorld_pCurWorld->numSectors )
        result = &sithWorld_pCurWorld->sectors[idx];
    else
        result = 0;
    return result;
}

void sithSector_cogMsg_SendSyncThingFull(sithThing *thing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHU16(thing->thingIdx);
    NETMSG_PUSHU16(thing->thingType);
    if ( thing->thingType )
    {
        NETMSG_PUSHU16(thing->templateBase->thingIdx);
        NETMSG_PUSHU32(thing->signature);
        NETMSG_PUSHU32(thing->thing_id);
        NETMSG_PUSHVEC3(thing->position);
        NETMSG_PUSHVEC3(thing->lookOrientation.rvec);
        NETMSG_PUSHVEC3(thing->lookOrientation.lvec);
        NETMSG_PUSHVEC3(thing->lookOrientation.uvec);
        if ( thing->sector ) {
            NETMSG_PUSHU16(thing->sector->id);
        }
        else {
            NETMSG_PUSHU16(-1);
        }
        NETMSG_PUSHU32(thing->thingflags);
        NETMSG_PUSHU32(thing->lifeLeftMs);
        NETMSG_PUSHU32(thing->timer);
        NETMSG_PUSHU32(thing->pulse_end_ms);
        NETMSG_PUSHU32(thing->pulse_ms);
        NETMSG_PUSHF32(thing->userdata);
        NETMSG_PUSHU8(thing->rdthing.geometryMode);
        NETMSG_PUSHU16(thing->collide);
        NETMSG_PUSHF32(thing->collideSize);
        NETMSG_PUSHF32(thing->light);
        NETMSG_PUSHU32(thing->jkFlags);
        if ( (thing->thingflags & SITH_TF_CAPTURED) != 0 )
        {
            if ( thing->class_cog ) {
                NETMSG_PUSHU16(thing->class_cog->selfCog);
            }
            else {
                NETMSG_PUSHU16(-1);
            }
            if ( thing->capture_cog ) {
                NETMSG_PUSHU16(thing->capture_cog->selfCog);
            }
            else {
                NETMSG_PUSHU16(-1);
            }
        }
        switch ( thing->thingType )
        {
            case THINGTYPE_ACTOR:
            case THINGTYPE_CORPSE:
            case THINGTYPE_PLAYER:
                NETMSG_PUSHU32(thing->actorParams.typeflags);
                NETMSG_PUSHF32(thing->actorParams.health);
                NETMSG_PUSHF32(thing->actorParams.extraSpeed);
                NETMSG_PUSHVEC3(thing->actorParams.eyePYR);
                
                NETMSG_PUSHF32(thing->actorParams.timeLeftLengthChange);
                NETMSG_PUSHF32(thing->actorParams.lightIntensity);
                NETMSG_PUSHU32(thing->actorParams.field_1BC);
                if ( thing->actorParams.playerinfo )
                {
                    NETMSG_PUSHU32(thing->actorParams.playerinfo - jkPlayer_playerInfos);
                    NETMSG_PUSHU32(thing->actorParams.playerinfo->palEffectsIdx1);
                    NETMSG_PUSHU32(thing->actorParams.playerinfo->palEffectsIdx2);
                }
                else
                {
                    NETMSG_PUSHU32(-1);
                }
                break;
            case THINGTYPE_WEAPON:
                NETMSG_PUSHU32(thing->weaponParams.typeflags);
                NETMSG_PUSHF32(thing->weaponParams.unk8);
                NETMSG_PUSHU16(thing->weaponParams.field_18);
                break;
            case THINGTYPE_EXPLOSION:
                NETMSG_PUSHU32(thing->explosionParams.typeflags);
                break;
            default:
                break;
        }
        if ( thing->move_type == MOVETYPE_PHYSICS )
        {
            NETMSG_PUSHU32(thing->physicsParams.physflags);
            NETMSG_PUSHVEC3(thing->physicsParams.vel);
            NETMSG_PUSHVEC3(thing->physicsParams.angVel);
        }
        else if ( thing->move_type == MOVETYPE_PATH )
        {
            NETMSG_PUSHU16(thing->trackParams.field_C);
            NETMSG_PUSHVEC3(thing->trackParams.vel);
            NETMSG_PUSHF32(thing->trackParams.field_1C);
            NETMSG_PUSHF32(thing->trackParams.field_20);
            NETMSG_PUSHF32(thing->trackParams.field_54);
            NETMSG_PUSHVEC3(thing->trackParams.field_58);
            NETMSG_PUSHVEC3(thing->trackParams.field_64);
            NETMSG_PUSHF32(thing->field_24C);
            NETMSG_PUSHU16(thing->field_250);
            NETMSG_PUSHU16(thing->curframe);
            NETMSG_PUSHU16(thing->field_258);
            NETMSG_PUSHU16(thing->goalframe);
            NETMSG_PUSHMAT34(thing->trackParams.field_24);
            NETMSG_PUSHVEC3(thing->trackParams.orientation);
            NETMSG_PUSHU16(thing->trackParams.loadedFrames);

            for (int i = 0; i < thing->trackParams.loadedFrames; i++)
            {
                NETMSG_PUSHVEC3(thing->trackParams.frames[i].pos);
                NETMSG_PUSHVEC3(thing->trackParams.frames[i].rot);
            }
        }
    }
    
    NETMSG_END(COGMSG_SYNCTHINGFULL);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncThingFull(sithCogMsg *msg)
{
    int16_t thingIdx; // ebp
    uint32_t v8; // ecx
    sithThing* thing;
    sithSector* v11;
    int thingType;


    NETMSG_IN_START(msg);

    if ( sithNet_isMulti && (g_submodeFlags & 8) == 0 )
        return 0;

    thingIdx = NETMSG_POPU16();
    if ( thingIdx >= sithWorld_pCurWorld->numThingsLoaded )
        return 0;

    if ( sithWorld_pCurWorld->things[thingIdx].thingType )
        sithThing_FreeEverythingNet(&sithWorld_pCurWorld->things[thingIdx]);

    if ( sithWorld_pCurWorld->numThings > thingIdx )
        thingIdx = sithWorld_pCurWorld->numThings;

    sithWorld_pCurWorld->numThings = thingIdx;

    thingType = NETMSG_POPU16();
    if ( !thingType )
        return 1;

    thing = &sithWorld_pCurWorld->things[thingIdx];
    sithThing_DoesRdThingInit(thing);
    v8 = NETMSG_POPU16();

    if ( v8 >= sithWorld_pCurWorld->numTemplatesLoaded )
        return 0;

    sithThing_sub_4CD8A0(thing, &sithWorld_pCurWorld->templates[v8]);

    thing->signature = NETMSG_POPU32();
    thing->thing_id = NETMSG_POPU32();
    thing->thingType = thingType;
    thing->position = NETMSG_POPVEC3();
    thing->lookOrientation.rvec = NETMSG_POPVEC3();
    thing->lookOrientation.lvec = NETMSG_POPVEC3();
    thing->lookOrientation.uvec = NETMSG_POPVEC3();
    v11 = sithSector_GetPtrFromIdx(NETMSG_POPS16());
    if ( v11 )
        sithThing_MoveToSector(thing, v11, 1);

    thing->thingflags = NETMSG_POPU32();
    thing->lifeLeftMs = NETMSG_POPU32();
    thing->timer = NETMSG_POPU32();
    thing->pulse_end_ms = NETMSG_POPU32();
    thing->pulse_ms = NETMSG_POPU32();
    thing->userdata = NETMSG_POPF32();
    thing->rdthing.geometryMode = NETMSG_POPU8();
    thing->collide = NETMSG_POPU16();
    thing->collideSize = NETMSG_POPF32();
    thing->light = NETMSG_POPF32();
    thing->jkFlags = NETMSG_POPU32();

    if ( thing->thingflags & SITH_TF_CAPTURED )
    {
        thing->class_cog = sithCog_GetByIdx(NETMSG_POPU16());
        thing->capture_cog = sithCog_GetByIdx(NETMSG_POPU16());
    }
    switch ( thing->thingType )
    {
        case THINGTYPE_ACTOR:
        case THINGTYPE_CORPSE:
        case THINGTYPE_PLAYER:
            thing->actorParams.typeflags = NETMSG_POPU32();
            thing->actorParams.health = NETMSG_POPF32();
            thing->actorParams.extraSpeed = NETMSG_POPF32();
            thing->actorParams.eyePYR = NETMSG_POPVEC3();
            
            thing->actorParams.timeLeftLengthChange = NETMSG_POPF32();
            thing->actorParams.lightIntensity = NETMSG_POPF32();
            thing->actorParams.field_1BC = NETMSG_POPU32();
            
            int playerInfo_idx = NETMSG_POPU32();
            
            if ( playerInfo_idx >= 0 && playerInfo_idx < 32 )
            {
                thing->actorParams.playerinfo = &jkPlayer_playerInfos[playerInfo_idx];
                thing->actorParams.playerinfo->palEffectsIdx1 = NETMSG_POPU32();
                thing->actorParams.playerinfo->palEffectsIdx2 = NETMSG_POPU32();
            }
            break;
        case THINGTYPE_WEAPON:
            thing->weaponParams.typeflags = NETMSG_POPU32();
            thing->weaponParams.unk8 = NETMSG_POPF32();
            thing->weaponParams.field_18 = NETMSG_POPU16();
            break;
        case THINGTYPE_EXPLOSION:
            thing->explosionParams.typeflags = NETMSG_POPU32();
            break;
        default:
            break;
    }
    if ( thing->move_type == MOVETYPE_PHYSICS )
    {
        thing->physicsParams.physflags = NETMSG_POPU32();
        thing->physicsParams.vel = NETMSG_POPVEC3();
        thing->physicsParams.angVel = NETMSG_POPVEC3();
    }
    else if ( thing->move_type == MOVETYPE_PATH )
    {
        thing->trackParams.field_C = NETMSG_POPU16();
        thing->trackParams.vel = NETMSG_POPVEC3();
        thing->trackParams.field_1C = NETMSG_POPF32();
        thing->trackParams.field_20 = NETMSG_POPF32();
        thing->trackParams.field_54 = NETMSG_POPF32();
        thing->trackParams.field_58 = NETMSG_POPVEC3();
        thing->trackParams.field_64 = NETMSG_POPVEC3();
        thing->field_24C = NETMSG_POPF32();
        thing->field_250 = NETMSG_POPU16();
        thing->curframe = NETMSG_POPU16();
        thing->field_258 = NETMSG_POPU16();
        thing->goalframe = NETMSG_POPU16();
        thing->trackParams.field_24 = NETMSG_POPMAT34();
        thing->trackParams.orientation = NETMSG_POPVEC3();
        thing->trackParams.loadedFrames = NETMSG_POPU16();

        if ( thing->trackParams.loadedFrames )
        {
            // TODO: verify this doesn't leak memory
            thing->trackParams.numFrames = thing->trackParams.loadedFrames;
            thing->trackParams.frames = pSithHS->alloc(sizeof(sithThingFrame) * thing->trackParams.numFrames);
        }

        for (int i = 0; i < thing->trackParams.loadedFrames; i++)
        {
            thing->trackParams.frames[i].pos = NETMSG_POPVEC3();
            thing->trackParams.frames[i].rot = NETMSG_POPVEC3();
        }
    }
    sithThing_sub_4CD100(thing);
    return 1;
}

void sithSector_cogMsg_SendSyncPuppet(sithThing *thing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    rdPuppet* puppet = thing->rdthing.puppet;

    NETMSG_PUSHU32(thing->thingIdx);
    for (int i = 0; i < 4; i++)
    {
        NETMSG_PUSHU32(puppet->tracks[i].status);
        if ( puppet->tracks[i].status )
        {
            NETMSG_PUSHS32(puppet->tracks[i].keyframe->id);
            NETMSG_PUSHS32(puppet->tracks[i].field_4);
            NETMSG_PUSHS16(puppet->tracks[i].lowPri);
            NETMSG_PUSHS16(puppet->tracks[i].highPri);
            NETMSG_PUSHF32(puppet->tracks[i].speed);
            NETMSG_PUSHF32(puppet->tracks[i].playSpeed);
            NETMSG_PUSHF32(puppet->tracks[i].field_120);
            NETMSG_PUSHF32(puppet->tracks[i].field_124);
        }
    }
    if ( thing->puppet )
    {
        NETMSG_PUSHS32(thing->puppet->otherTrack);
        NETMSG_PUSHS16(thing->puppet->field_0);
        NETMSG_PUSHS16(thing->puppet->field_4);
    }
    
    NETMSG_END(COGMSG_SYNCPUPPET);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncPuppet(sithCogMsg *msg)
{
    sithThing *thing; // eax
    rdPuppet *rdpuppet; // edi

    NETMSG_IN_START(msg);

    thing = sithThing_GetThingByIdx(NETMSG_POPS32());

    if ( !thing )
        return 0;

    if ( !thing->animclass )
        return 0;

    if ( !thing->puppet )
        return 0;

    rdpuppet = thing->rdthing.puppet;
    if ( !rdpuppet )
        return 0;

    rdPuppet_RemoveTrack(rdpuppet, &thing->rdthing);

    for (int i = 0; i < 4; i++)
    {
        rdpuppet->tracks[i].status = NETMSG_POPS32();
        if ( rdpuppet->tracks[i].status )
        {
            rdpuppet->tracks[i].keyframe = sithKeyFrame_GetByIdx(NETMSG_POPS32());
            rdpuppet->tracks[i].field_4 = NETMSG_POPS32();
            rdpuppet->tracks[i].lowPri = (int)NETMSG_POPS16();
            rdpuppet->tracks[i].highPri = (int)NETMSG_POPS16();
            rdpuppet->tracks[i].speed = NETMSG_POPF32();
            rdpuppet->tracks[i].playSpeed = NETMSG_POPF32();
            rdpuppet->tracks[i].field_120 = NETMSG_POPF32();
            rdpuppet->tracks[i].field_124 = NETMSG_POPF32();
        }
    }

    if ( thing->puppet )
    {
        thing->puppet->otherTrack = NETMSG_POPS32();
        
        sithPuppet_SetArmedMode(thing, NETMSG_POPS16());
        sithPuppet_sub_4E4760(thing, NETMSG_POPS16());
    }
    return 1;
}

void sithSector_cogMsg_SendSyncAI(sithActor *actor, int sendto_id, int idx)
{    
    NETMSG_START;

    NETMSG_PUSHS16(actor->thing->thingIdx);
    NETMSG_PUSHU16((uint16_t)(((intptr_t)actor->aiclass - (intptr_t)sithWorld_pCurWorld->aiclasses) / sizeof(sithAIClass)));
    NETMSG_PUSHU32(actor->flags);
    NETMSG_PUSHU32(actor->nextUpdate);
    if ( actor->thingidk ) {
        NETMSG_PUSHS16(actor->thingidk->thingIdx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    NETMSG_PUSHVEC3(actor->movepos);
    NETMSG_PUSHVEC3(actor->field_23C);
    NETMSG_PUSHU32(actor->field_248);
    if ( actor->field_1D0 ) {
        NETMSG_PUSHS16(actor->field_1D0->thingIdx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    NETMSG_PUSHVEC3(actor->field_1D4);
    NETMSG_PUSHVEC3(actor->field_1F8);
    NETMSG_PUSHU32(actor->field_204);
    NETMSG_PUSHF32(actor->moveSpeed);

    if (actor->flags & SITHAIFLAGS_MOVING_TO_DEST)
    {
        NETMSG_PUSHVEC3(actor->movePos);
    }
    if (actor->flags & SITHAIFLAGS_TURNING_TO_DEST)
    {
        NETMSG_PUSHVEC3(actor->lookVector);
    }
    if (actor->flags & SITHAIFLAGS_FLEEING)
    {
        if ( actor->field_1C0 ) {
            NETMSG_PUSHS16(actor->field_1C0->thingIdx);
        }
        else {
            NETMSG_PUSHS16(-1);
        }
    }
    NETMSG_PUSHVEC3(actor->position);
    NETMSG_PUSHVEC3(actor->lookOrientation);
    for (int i = 0; i < actor->numAIClassEntries; i++)
    {
        NETMSG_PUSHU32(actor->instincts[i].nextUpdate);
        NETMSG_PUSHF32(actor->instincts[i].param0);
        NETMSG_PUSHF32(actor->instincts[i].param1);
        NETMSG_PUSHF32(actor->instincts[i].param2);
        NETMSG_PUSHF32(actor->instincts[i].param3);
    }
    NETMSG_PUSHU32(actor->field_288);
    NETMSG_PUSHU32(actor->field_28C);
    NETMSG_PUSHU32(actor->loadedFrames);
    for (int i = 0; i < actor->loadedFrames; i++)
    {
        NETMSG_PUSHVEC3(actor->framesAlloc[i]);
    }
    
    NETMSG_END(COGMSG_SYNCAI);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, idx, 1);
}

int sithSector_cogMsg_HandleSyncAI(sithCogMsg *msg)
{
    sithThing *thing;
    sithActor *actor;
    
    NETMSG_IN_START(msg);

    thing = sithThing_GetThingByIdx(NETMSG_POPS16());
    if ( !thing )
        return 0;
    if ( thing->thingtype != THINGTYPE_ACTOR )
        return 0;
    actor = thing->actor;
    if ( !actor )
        return 0;
    
    int16_t idx = NETMSG_POPU16();
    if ( idx >= sithWorld_pCurWorld->numAIClassesLoaded )
        return 0;

    actor->aiclass = &sithWorld_pCurWorld->aiclasses[idx];
    actor->numAIClassEntries = sithWorld_pCurWorld->aiclasses[idx].numEntries;
    actor->flags = NETMSG_POPU32();
    actor->nextUpdate = NETMSG_POPU32();
    actor->thingidk = sithThing_GetThingByIdx(NETMSG_POPS16());
    actor->field_224 = 0; // interesting?
    
    actor->movepos = NETMSG_POPVEC3();
    actor->field_23C = NETMSG_POPVEC3();
    actor->field_248 = NETMSG_POPU32();

    actor->field_1D0 = sithThing_GetThingByIdx(NETMSG_POPS16());
    
    actor->field_1D4 = NETMSG_POPVEC3();
    actor->field_1E0 = 0; // interesting?
    actor->field_1F8 = NETMSG_POPVEC3();
    actor->field_204 = NETMSG_POPU32();
    actor->moveSpeed = NETMSG_POPF32();

    if (actor->flags & SITHAIFLAGS_MOVING_TO_DEST)
    {
        actor->movePos = NETMSG_POPVEC3();
    }
    if (actor->flags & SITHAIFLAGS_TURNING_TO_DEST)
    {
        actor->lookVector = NETMSG_POPVEC3();
    }
    if (actor->flags & SITHAIFLAGS_FLEEING)
    {
        actor->field_1C0 = sithThing_GetThingByIdx(NETMSG_POPS16());
    }
    actor->position = NETMSG_POPVEC3();
    actor->lookOrientation = NETMSG_POPVEC3();

    for (int i = 0; i < actor->numAIClassEntries; i++)
    {
        actor->instincts[i].nextUpdate = NETMSG_POPU32();
        actor->instincts[i].param0 = NETMSG_POPF32();
        actor->instincts[i].param1 = NETMSG_POPF32();
        actor->instincts[i].param2 = NETMSG_POPF32();
        actor->instincts[i].param3 = NETMSG_POPF32();
    }
    
    actor->field_288 = NETMSG_POPU32();
    actor->field_28C = NETMSG_POPU32();
    actor->loadedFrames = NETMSG_POPU32();
    
    if ( actor->loadedFrames)
    {
        actor->framesAlloc = (rdVector3 *)pSithHS->alloc(sizeof(rdVector3) * actor->loadedFrames);
        actor->numFrames = actor->loadedFrames;
        if ( actor->framesAlloc )
        {
            for (int i = 0; i < actor->loadedFrames; i++)
            {
                actor->framesAlloc[i] = NETMSG_POPVEC3();
            }
            return 1;
        }
    }
    else
    {
        actor->numFrames = 0;
        actor->loadedFrames = 0;
        actor->framesAlloc = NULL; // Added
    }
    return 1;
}

void sithSector_cogMsg_SendSyncSurface(sithSurface *surface, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(surface->field_0);
    NETMSG_PUSHU32(surface->surfaceFlags);
    if ( surface->surfaceInfo.face.material ) {
        NETMSG_PUSHS32(surface->surfaceInfo.face.material->id);
    }
    else {
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHS16(surface->surfaceInfo.face.wallCel);
    NETMSG_PUSHVEC2(surface->surfaceInfo.face.clipIdk);
    NETMSG_PUSHF32(surface->surfaceInfo.face.extraLight);
    NETMSG_PUSHU32(surface->surfaceInfo.face.type);
    NETMSG_PUSHU32(surface->surfaceInfo.face.geometryMode);
    NETMSG_PUSHU32(surface->surfaceInfo.face.lightingMode);
    NETMSG_PUSHU32(surface->surfaceInfo.face.textureMode);
    if ( surface->adjoin )
    {
        NETMSG_PUSHU32(surface->adjoin->flags);
    }
    
    NETMSG_END(COGMSG_SYNCSURFACE);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncSurface(sithCogMsg *msg)
{
    unsigned int v1; // eax
    sithSurface *surface; // edi
    signed int v4; // ecx
    
    NETMSG_IN_START(msg);

    v1 = NETMSG_POPS16();
    if ( v1 >= sithWorld_pCurWorld->numSurfaces )
        return 0;

    surface = &sithWorld_pCurWorld->surfaces[v1];

    surface->surfaceFlags = NETMSG_POPU32();
    surface->surfaceInfo.face.material = sithMaterial_GetByIdx(NETMSG_POPS32());;

    v4 = NETMSG_POPS16();
    if ( v4 == -1 || !surface->surfaceInfo.face.material || v4 >= surface->surfaceInfo.face.material->num_texinfo )
        surface->surfaceInfo.face.wallCel = -1;
    else
        surface->surfaceInfo.face.wallCel = v4;

    surface->surfaceInfo.face.clipIdk = NETMSG_POPVEC2();
    surface->surfaceInfo.face.extraLight = NETMSG_POPF32();
    surface->surfaceInfo.face.type = NETMSG_POPU32();
    surface->surfaceInfo.face.geometryMode = NETMSG_POPU32();
    surface->surfaceInfo.face.lightingMode = NETMSG_POPU32();
    surface->surfaceInfo.face.textureMode = NETMSG_POPU32();

    if ( surface->adjoin )
        surface->adjoin->flags = NETMSG_POPU32();

    return 1;
}

void sithSector_cogMsg_SendSyncSector(sithSector *sector, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(sector->id);
    NETMSG_PUSHS16(((intptr_t)sector->colormap - (intptr_t)sithWorld_pCurWorld->colormaps) / sizeof(rdColormap));
    NETMSG_PUSHU32(sector->flags);
    NETMSG_PUSHF32(sector->ambientLight);
    NETMSG_PUSHF32(sector->extraLight);
    
    if (sector->flags & SITH_SF_HASTHRUST)
    {
        NETMSG_PUSHVEC3(sector->thrust);
    }
    NETMSG_PUSHVEC3(sector->tint);
    
    NETMSG_END(COGMSG_SYNCSECTOR);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncSector(sithCogMsg *msg)
{
    uint32_t idx; // eax
    sithSector *sector; // edi
    uint32_t colormapIdx = 0; // eax
    int oldSectorFlags = 0;

    NETMSG_IN_START(msg);

    idx = NETMSG_POPS16();
    if ( idx >= sithWorld_pCurWorld->numSectors )
        return 0;
    sector = &sithWorld_pCurWorld->sectors[idx];

    colormapIdx = NETMSG_POPS16();
    if ( colormapIdx >= sithWorld_pCurWorld->numColormaps )
        return 0;
    sector->colormap = &sithWorld_pCurWorld->colormaps[colormapIdx];

    oldSectorFlags = sector->flags;
    sector->flags = NETMSG_POPU32();

    // TODO: untangle this
    if (!(sector->flags & SITH_SF_80))
    {
        if ( (oldSectorFlags & SITH_SF_80) == 0 )
            goto LABEL_11;
LABEL_9:
        if ( (sector->flags & SITH_SF_80) == 0 )
            sithSector_SetAdjoins(sector);
        goto LABEL_11;
    }
    if (oldSectorFlags & SITH_SF_80)
        goto LABEL_9;
    sithSector_UnsetAdjoins(sector);
LABEL_11:

    sector->ambientLight = NETMSG_POPF32();
    sector->extraLight = NETMSG_POPF32();

    if ( (sector->flags & SITH_SF_HASTHRUST) != 0 )
    {
        sector->thrust = NETMSG_POPVEC3();
    }
    else
    {
        rdVector_Zero3(&sector->thrust);
    }

    sector->tint = NETMSG_POPVEC3();

    return 1;
}

void sithSector_cogMsg_SendSyncItemDesc(sithThing *thing, int binIdx, int sendto_id, int mpFlags)
{
    if ( thing->thingType == THINGTYPE_PLAYER || thing->thingType == THINGTYPE_ACTOR )
    {
        sithPlayerInfo* v5 = thing->actorParams.playerinfo;
        if ( v5 )
        {
            NETMSG_START;
        
            NETMSG_PUSHS16(thing->thingIdx);
            NETMSG_PUSHS16(binIdx);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].ammoAmt);
            NETMSG_PUSHU32(v5->iteminfo[binIdx].state);
            NETMSG_PUSHU32(v5->iteminfo[binIdx].field_4);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].activatedTimeSecs);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].activationDelaySecs);
            NETMSG_PUSHF32(v5->iteminfo[binIdx].binWait);
            
            NETMSG_END(COGMSG_SYNCITEMDESC);
            
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
        }
    }
}

int sithSector_cogMsg_HandleSyncItemDesc(sithCogMsg *msg)
{
    int thingIdx; // edx
    sithThing *thing; // ecx
    sithPlayerInfo *playerInfo; // edx
    int binIdx; // ecx
    sithItemInfo *iteminfo; // ecx
    
    NETMSG_IN_START(msg);

    thingIdx = NETMSG_POPS16();
    if ( thingIdx < 0 )
        return 0;
    if ( thingIdx >= sithWorld_pCurWorld->numThingsLoaded )
        return 0;

    thing = &sithWorld_pCurWorld->things[thingIdx];
    if ( thing->thingType != THINGTYPE_ACTOR && thing->thingType != THINGTYPE_PLAYER )
        return 0;

    playerInfo = thing->actorParams.playerinfo;
    if ( !playerInfo )
        return 0;

    binIdx = NETMSG_POPS16();
    if ( binIdx < 0 || binIdx >= 200 )
        return 0;

    iteminfo = &playerInfo->iteminfo[binIdx];
    iteminfo->ammoAmt = NETMSG_POPF32();
    iteminfo->state = NETMSG_POPU32();
    iteminfo->field_4 = NETMSG_POPU32();
    iteminfo->activatedTimeSecs = NETMSG_POPF32();
    iteminfo->activationDelaySecs = NETMSG_POPF32();
    iteminfo->binWait = NETMSG_POPF32();

    return 1;
}

void sithSector_cogMsg_SendStopAnim(rdSurface *surface, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(surface->index);
    NETMSG_PUSHU32(surface->flags);
    if (surface->flags & 0xC0000)
    {
        NETMSG_PUSHS32(surface->parent_thing->thingIdx);
        NETMSG_PUSHU32(surface->signature);
    }
    if (surface->flags & 0x20000)
        NETMSG_PUSHU32(surface->sithSurfaceParent->field_0);
    if (surface->flags & 0x100000)
    {
        NETMSG_PUSHVEC3(surface->field_24);
        NETMSG_PUSHVEC2(surface->field_1C);
    }
    if (surface->flags & 0x200000)
    {
        NETMSG_PUSHU32(surface->field_30);
        NETMSG_PUSHU32(surface->field_34);
        NETMSG_PUSHU32(surface->wallCel);
    }
    if (surface->flags & 0x400000)
    {
        NETMSG_PUSHF32(surface->field_44);
        NETMSG_PUSHF32(surface->field_48);
        NETMSG_PUSHF32(surface->field_40);
        NETMSG_PUSHF32(surface->field_3C);
    }
    if (surface->flags & 0x10000)
        NETMSG_PUSHS32(surface->material->id);
    if (surface->flags & 0x2000000)
        NETMSG_PUSHS32(surface->sector->id);
    
    NETMSG_END(COGMSG_STOPANIM);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleStopAnim(sithCogMsg *msg)
{
    rdSurface *rdsurface; // edi
    rdSurface *surface; // eax
    int v7; // eax

    NETMSG_IN_START(msg);

    rdsurface = sithSurface_GetByIdx(NETMSG_POPS32());
    if ( rdsurface || (surface = sithSurface_Alloc(), (rdsurface = surface) != 0) )
    {
        rdsurface->flags = NETMSG_POPU32();
        if (!rdsurface->flags )
        {
            sithSurface_StopAnim(rdsurface);
            return 1;
        }
        
        if ( (rdsurface->flags & 0xC0000) != 0 )
        {
            rdsurface->parent_thing = sithThing_GetThingByIdx(NETMSG_POPS32());
            if ( rdsurface->parent_thing && rdsurface->parent_thing->rdthing.type == RD_THINGTYPE_SPRITE3 )
                rdsurface->material = rdsurface->parent_thing->rdthing.sprite3->face.material;
            rdsurface->signature = NETMSG_POPU32();
        }

        if ( (rdsurface->flags & 0x20000) != 0 )
        {
            v7 = NETMSG_POPS32();
            if ( v7 >= 0 && v7 < sithWorld_pCurWorld->numSurfaces )
            {
                rdsurface->sithSurfaceParent = &sithWorld_pCurWorld->surfaces[v7];
                rdsurface->material = sithWorld_pCurWorld->surfaces[v7].surfaceInfo.face.material;
            }
        }

        if ( (rdsurface->flags & 0x100000) != 0 )
        {
            rdsurface->field_24 = NETMSG_POPVEC3();
            rdsurface->field_1C = NETMSG_POPVEC2();
        }

        if ( (rdsurface->flags & 0x200000) != 0 )
        {
            rdsurface->field_30 = NETMSG_POPU32();
            rdsurface->field_34 = NETMSG_POPU32();
            rdsurface->wallCel = NETMSG_POPU32();
        }

        if ( (rdsurface->flags & 0x400000) != 0 )
        {
            rdsurface->field_44 = NETMSG_POPF32();
            rdsurface->field_48 = NETMSG_POPF32();
            rdsurface->field_40 = NETMSG_POPF32();
            rdsurface->field_3C = NETMSG_POPF32();
        }

        if ( (rdsurface->flags & 0x10000) != 0 )
        {
            rdsurface->material = sithMaterial_GetByIdx(NETMSG_POPS32());
        }

        if ( (rdsurface->flags & 0x2000000) != 0 )
            rdsurface->sector = sithSector_GetPtrFromIdx(NETMSG_POPS32());

        return 1;
    }
    return 0;
}

void sithSector_cogMsg_SendSyncTimers(sithTimer *timer, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHU32(timer->endMs - sithTime_curMs);
    NETMSG_PUSHU32(timer->timerInfo.cogIdx);
    NETMSG_PUSHU32(timer->timerInfo.timerIdx);
    NETMSG_PUSHF32(timer->timerInfo.field_10);
    NETMSG_PUSHF32(timer->timerInfo.field_14);
    NETMSG_PUSHU16(timer->field_4);
    
    NETMSG_END(COGMSG_SYNCTIMERS);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncTimers(sithCogMsg *msg)
{
    int deltaMs;
    int16_t field_4;
    sithTimerInfo info;

    NETMSG_IN_START(msg);

    deltaMs = NETMSG_POPU32();
    info.cogIdx = NETMSG_POPU32();
    info.timerIdx = NETMSG_POPU32();
    info.field_10 = NETMSG_POPF32();
    info.field_14 = NETMSG_POPF32();
    field_4 = NETMSG_POPS16();
    sithTimer_Set(field_4, &info, deltaMs);
    return 1;
}

void sithSector_cogMsg_SendSyncPalEffects(int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(stdPalEffects_numEffectRequests);
    NETMSG_PUSHU8(stdPalEffects_state.field_4);
    NETMSG_PUSHU8(stdPalEffects_state.field_8);
    
    NETMSG_PUSHU8(stdPalEffects_state.field_C);
    NETMSG_PUSHU8(stdPalEffects_state.field_10);
    
    stdPalEffectRequest* iter = &stdPalEffects_aEffects[0];
    for (int i = 0; i < 32; i++)
    {
        NETMSG_PUSHU16(iter->isValid);
        if ( iter->isValid )
        {
            uint16_t v5 = 0;
            if ( iter->effect.filter.x )
                v5 |= 1;
            if ( iter->effect.filter.y )
                v5 |= 2u;
            if ( iter->effect.filter.z )
                v5 |= 4u;

            NETMSG_PUSHU16(v5);
            NETMSG_PUSHVEC3(iter->effect.tint);
            NETMSG_PUSHVEC3I(iter->effect.add)
            NETMSG_PUSHF32(iter->effect.fade);
            NETMSG_PUSHS16(iter->idx);
        }
        ++iter;
    }
    
    NETMSG_END(COGMSG_SYNCPALEFFECTS);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncPalEffects(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    stdPalEffects_numEffectRequests = NETMSG_POPS16();
    stdPalEffects_state.field_4 = NETMSG_POPU8();
    stdPalEffects_state.field_8 = NETMSG_POPU8();
    stdPalEffects_state.field_C = NETMSG_POPU8();
    stdPalEffects_state.field_10 = NETMSG_POPU8();
    
    stdPalEffectRequest* iter = &stdPalEffects_aEffects[0];
    for (int i = 0; i < 32; i++)
    {
        iter->isValid = NETMSG_POPS16();
        if ( iter->isValid )
        {
            uint16_t v5 = NETMSG_POPU16();
            if ( v5 & 1 )
                iter->effect.filter.x = 1;
            if ( v5 & 2 )
                iter->effect.filter.y = 1;
            if ( v5 & 4 )
                iter->effect.filter.z = 1;

            iter->effect.tint = NETMSG_POPVEC3();
            iter->effect.add = NETMSG_POPVEC3I();
            iter->effect.fade = NETMSG_POPF32();
            iter->idx = NETMSG_POPS16();
        }
        ++iter;
    }
    
    stdPalEffects_RefreshPalette();
    return 1;
}

void sithSector_cogMsg_SendSyncCameras(int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(sithCamera_currentCamera - sithCamera_cameras);
    NETMSG_PUSHU32(sithCamera_dword_8EE5A0);
    NETMSG_PUSHU32(sithCamera_curCameraIdx);
    NETMSG_PUSHVEC3(sithCamera_povShakeVector1);
    NETMSG_PUSHVEC3(sithCamera_povShakeVector2);
    NETMSG_PUSHF32(sithCamera_povShakeF1);
    NETMSG_PUSHF32(sithCamera_povShakeF2);

    for (int i = 0; i < 7; i++) // TODO define this maximum
    {
        if ( sithCamera_cameras[i].primaryFocus ) {
            NETMSG_PUSHS32(sithCamera_cameras[i].primaryFocus->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        if ( sithCamera_cameras[i].secondaryFocus ) {
            NETMSG_PUSHS32(sithCamera_cameras[i].secondaryFocus->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        NETMSG_PUSHF32(sithCamera_cameras[i].fov);
    }

    NETMSG_PUSHU16(g_selfPlayerInfo->palEffectsIdx1);
    NETMSG_PUSHU16(g_selfPlayerInfo->palEffectsIdx2);
    
    NETMSG_END(COGMSG_SYNCCAMERAS);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleSyncCameras(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);
    
    sithCamera_currentCamera = &sithCamera_cameras[NETMSG_POPS16()];
    sithCamera_dword_8EE5A0 = NETMSG_POPU32();
    sithCamera_curCameraIdx = NETMSG_POPU32();
    sithCamera_povShakeVector1 = NETMSG_POPVEC3();
    sithCamera_povShakeVector2 = NETMSG_POPVEC3();
    sithCamera_povShakeF1 = NETMSG_POPF32();
    sithCamera_povShakeF2 = NETMSG_POPF32();

    for (int i = 0; i < 7; i++) // TODO define this maximum
    {
        // Added: shifted around the -1 checks
        int primaryIdx = NETMSG_POPS32();
        int secondaryIdx = NETMSG_POPS32();
        sithCamera_cameras[i].primaryFocus = sithThing_GetThingByIdx(primaryIdx);
        if (!sithCamera_cameras[i].primaryFocus && primaryIdx != -1) return 0;

        sithCamera_cameras[i].secondaryFocus = sithThing_GetThingByIdx(secondaryIdx);
        if (!sithCamera_cameras[i].secondaryFocus && secondaryIdx != -1) return 0;

        sithCamera_cameras[i].fov = NETMSG_POPF32();
    }

    g_selfPlayerInfo->palEffectsIdx1 = NETMSG_POPU16();
    g_selfPlayerInfo->palEffectsIdx2 = NETMSG_POPU16();

    return 1;
}

void sithSector_cogMsg_SendMisc(int sendto_id, int mpFlags)
{
    NETMSG_START;

    if ( sithCog_masterCog ) {
        NETMSG_PUSHS32(sithCog_masterCog->selfCog);
    }
    else {
        NETMSG_PUSHS32(-1);
    }

    for (int i = 0; i < 2; i++)
    {
        NETMSG_PUSHU32(sithWeapon_a8BD030[i]);
        NETMSG_PUSHU32(sithWeapon_8BD0A0[i]);
    }
    NETMSG_PUSHU32(sithWeapon_8BD05C[1]);
    NETMSG_PUSHF32(sithWeapon_LastFireTimeSecs);
    NETMSG_PUSHF32(sithWeapon_fireWait);
    NETMSG_PUSHF32(sithWeapon_mountWait);
    NETMSG_PUSHF32(sithWeapon_8BD05C[0]);
    NETMSG_PUSHF32(sithWeapon_fireRate);
    NETMSG_PUSHU32(sithWeapon_CurWeaponMode);
    NETMSG_PUSHU32(sithWeapon_8BD024);
    NETMSG_PUSHU32(g_selfPlayerInfo->curItem);
    NETMSG_PUSHU32(g_selfPlayerInfo->curWeapon);
    NETMSG_PUSHU32(g_selfPlayerInfo->curPower);

    for (int i = 0; i < 20; i++)
    {
        NETMSG_PUSHU32(sithInventory_powerKeybinds[i].idk);
    }

    NETMSG_PUSHU32(sithInventory_bUnk);
    NETMSG_PUSHU32(sithInventory_bUnkPower);
    NETMSG_PUSHU32(sithInventory_549FA0);
    NETMSG_PUSHU32(sithInventory_8339EC);
    NETMSG_PUSHU32(sithInventory_bRendIsHidden);
    NETMSG_PUSHU32(sithInventory_8339F4);
    NETMSG_PUSHU32(sithRender_lightingIRMode);
    NETMSG_PUSHF32(sithRender_f_83198C);
    NETMSG_PUSHF32(sithRender_f_831990);
    NETMSG_PUSHU32(sithRender_needsAspectReset);
    NETMSG_PUSHU8(sithSoundSys_bPlayingMci);
    NETMSG_PUSHF32(sithSoundSys_musicVolume);

    if ( sithSoundSys_bPlayingMci )
    {
        NETMSG_PUSHU8(sithSoundSys_dword_835FCC);
        NETMSG_PUSHU8(sithSoundSys_trackTo);
        NETMSG_PUSHU8(sithSoundSys_trackFrom);
    }
    
    NETMSG_END(COGMSG_ID_1F);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithSector_cogMsg_HandleMisc(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithCog_masterCog = sithCog_GetByIdx(NETMSG_POPS32());

    for (int i = 0; i < 2; i++)
    {
        sithWeapon_a8BD030[i] = NETMSG_POPU32();
        sithWeapon_8BD0A0[i] = NETMSG_POPU32();
    }
    sithWeapon_8BD05C[1] = NETMSG_POPU32();
    sithWeapon_LastFireTimeSecs = NETMSG_POPF32();
    sithWeapon_fireWait = NETMSG_POPF32();
    sithWeapon_mountWait = NETMSG_POPF32();
    sithWeapon_8BD05C[0] = NETMSG_POPF32();
    sithWeapon_fireRate = NETMSG_POPF32();
    sithWeapon_CurWeaponMode = NETMSG_POPU32();
    sithWeapon_8BD024 = NETMSG_POPU32();
    g_selfPlayerInfo->curItem = NETMSG_POPU32();
    g_selfPlayerInfo->curWeapon = NETMSG_POPU32();
    g_selfPlayerInfo->curPower = NETMSG_POPU32();

    for (int i = 0; i < 20; i++)
    {
        sithInventory_powerKeybinds[i].idk = NETMSG_POPU32();
    }

    sithInventory_bUnk = NETMSG_POPU32();
    sithInventory_bUnkPower = NETMSG_POPU32();
    sithInventory_549FA0 = NETMSG_POPU32();
    sithInventory_8339EC = NETMSG_POPU32();
    sithInventory_bRendIsHidden = NETMSG_POPU32();
    sithInventory_8339F4 = NETMSG_POPU32();
    sithRender_lightingIRMode = NETMSG_POPU32();
    sithRender_f_83198C = NETMSG_POPF32();
    sithRender_f_831990 = NETMSG_POPF32();
    sithRender_needsAspectReset = NETMSG_POPU32();
    sithSoundSys_bPlayingMci = NETMSG_POPU8();

    sithSoundSys_SetMusicVol(NETMSG_POPF32());
    if ( sithSoundSys_bPlayingMci )
    {
        sithSoundSys_dword_835FCC = NETMSG_POPU8();
        sithSoundSys_trackTo = NETMSG_POPU8();
        sithSoundSys_trackFrom = NETMSG_POPU8();
        sithSoundSys_ResumeMusic(1);
    }

    return 1;
}

void sithSector_cogMsg_SendPlaySoundPos(sithThing *followThing, rdVector3 *pos, sithSound *sound, float volume, float a5, int flags, int refid, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHU32(flags);
    NETMSG_PUSHF32(volume);
    NETMSG_PUSHF32(a5);
    NETMSG_PUSHU16(sound->id);
    if ( (flags & SITHSOUNDFLAG_FOLLOWSTHING) == 0 )
    {
        if ( (flags & SITHSOUNDFLAG_ABSOLUTE) != 0 )
        {
            NETMSG_PUSHVEC3(*pos);
        }
    }
    else
    {
        NETMSG_PUSHS32(followThing->thing_id);
    }
    NETMSG_PUSHU32(refid);
    
    NETMSG_END(COGMSG_PLAYSOUNDPOS);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 0);
}

int sithSector_cogMsg_HandlePlaySoundPos(sithCogMsg *msg)
{
    sithPlayingSound* out = NULL;

    NETMSG_IN_START(msg);

    int flags = NETMSG_POPU32();
    float volume = NETMSG_POPF32();
    float a5 = NETMSG_POPF32();
    int16_t soundIdx = NETMSG_POPS16();
    sithSound* sound = sithSound_GetFromIdx(soundIdx);

    if (!sound)
        return 0;

    if ( (flags & SITHSOUNDFLAG_FOLLOWSTHING) == 0 )
    {
        if ( (flags & SITHSOUNDFLAG_ABSOLUTE) != 0 )
        {
            rdVector3 pos = NETMSG_POPVEC3();
            out = sithSoundSys_PlaySoundPosAbsolute(sound, &pos, 0, 1.0, volume, a5, flags);
        }
        else
        {
            out = sithSoundSys_cog_playsound_internal(sound, volume, a5, flags);
        }
    }
    else
    {
        sithThing* thing = sithThing_GetById(NETMSG_POPS32());
        if ( !thing )
            return 0;
        out = sithSoundSys_PlaySoundPosThing(sound, thing, 1.0, volume, a5, flags);
    }

    if ( out )
        out->refid = NETMSG_POPU32();

    return 1;
}

void sithSector_cogMsg_SendDeath(sithThing *sender, sithThing *receiver, char cause, int sendto_id, int mpFlags)
{
    NETMSG_START;
    
    NETMSG_PUSHS32(sender->thing_id);
    if ( receiver ) {
        NETMSG_PUSHS32(receiver->thing_id);
    }
    else {
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHU8(cause);
    
    NETMSG_END(COGMSG_DEATH);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

void sithSector_cogMsg_SendSyncThingAttachment(sithThing *thing, int sendto_id, int mpFlags, int a4)
{
    NETMSG_START;
    
    NETMSG_PUSHS32(thing->thing_id);
    NETMSG_PUSHU16(thing->attach_flags);

    if (thing->attach_flags & ATTACHFLAGS_WORLDSURFACE)
    {
        NETMSG_PUSHU16(thing->attachedSurface->field_0);
    }
    else if (thing->attach_flags & (ATTACHFLAGS_THING|ATTACHFLAGS_THINGSURFACE))
    {
        sithThing* v7 = (sithThing *)thing->attachedThing;
        NETMSG_PUSHS32(v7->thing_id)
        if ( (thing->attach_flags & ATTACHFLAGS_THINGSURFACE) != 0 )
        {
            NETMSG_PUSHS16(((intptr_t)thing->attachedSufaceInfo - (intptr_t)v7->rdthing.model3->geosets[0].meshes->faces) / sizeof(sithSurfaceInfo));
        }
        else
        {
           NETMSG_PUSHVEC3(thing->field_4C);
        }
    }
    
    NETMSG_END(COGMSG_SYNCTHINGATTACHMENT);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, a4);
}

int sithSector_cogMsg_HandleSyncThingAttachment(sithCogMsg *msg)
{    
    NETMSG_IN_START(msg);

    sithThing* v1 = sithThing_GetById(NETMSG_POPS32());
    if ( !v1 )
        return 0;
    int v3 = NETMSG_POPS16();
    if (v3 & ATTACHFLAGS_WORLDSURFACE)
    {
        sithSurface* v5 = sithSurface_sub_4E63B0(NETMSG_POPS16());
        if ( v5 )
        {
            sithThing_AttachToSurface(v1, v5, 1);
            v1->attach_flags = v3;
            return 1;
        }
        return 0;
    }
    if (v3 & (ATTACHFLAGS_THING|ATTACHFLAGS_THINGSURFACE))
    {
        sithThing* v9 = sithThing_GetById(NETMSG_POPS32());
        if ( !v9 )
            return 0;
        if (v3 & ATTACHFLAGS_THINGSURFACE)
        {
            sithThing_LandThing(
                v1,
                v9,
                &v9->rdthing.model3->geosets[0].meshes->faces[NETMSG_POPS16()],
                v9->rdthing.model3->geosets[0].meshes->vertices,
                1);
            v1->attach_flags = v3;
            return 1;
        }
        else
        {
            sithThing_AttachThing(v1, v9);
            v1->attach_flags = v3;
            v1->field_4C = NETMSG_POPVEC3();
            return 1;
        }
    }
    else
    {
        if ( v1->attach_flags )
            sithThing_DetachThing(v1);
        return 1;
    }
    return 0;
}
