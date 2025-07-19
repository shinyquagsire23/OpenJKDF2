#include "sithPlayerActions.h"

#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "World/jkPlayer.h"
#include "World/sithSurface.h"
#include "World/sithSoundClass.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithPhysics.h"
#include "Cog/sithCogExec.h"
#include "Cog/sithCog.h"
#include "Dss/sithDSSThing.h"
#include "World/sithWeapon.h"
#include "jk.h"

static int lastDoorOpenTime = 0;

void sithPlayerActions_Activate(sithThing *thing)
{
    sithSector *v4; // esi
    int v5; // eax
    sithCollisionSearchEntry *searchResult; // eax
    sithThing *v7; // edx
    flex_t a6; // [esp+0h] [ebp-58h]
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
            sithCollision_SearchRadiusForThings(v4, thing, &thingPos, &out.lvec, a6, 0.025, /*SITH_THING_ACTOR*/RAYCAST_2);
            for ( searchResult = sithCollision_NextSearchResult(); searchResult; searchResult = sithCollision_NextSearchResult() )
            {
                if ( (searchResult->hitType & SITHCOLLISION_WORLD) != 0 )
                {
#ifdef DEBUG_QOL_CHEATS
                    if (searchResult->surface && searchResult->surface->surfaceInfo.face.material && thing == sithPlayer_pLocalPlayerThing)
                        jk_printf("OpenJKDF2: Debug surf %s\n", searchResult->surface->surfaceInfo.face.material->mat_fpath);
#endif
                    if (searchResult->surface->surfaceFlags & SITH_SURFACE_COG_LINKED)
                    {
                        sithCog_SendMessageFromSurface(searchResult->surface, thing, SITH_MESSAGE_ACTIVATE);
                        sithCollision_SearchClose();
                        return;
                    }
                }
                else if ( (searchResult->hitType & SITHCOLLISION_THING) != 0 )
                {
                    v7 = searchResult->receiver;
#ifdef DEBUG_QOL_CHEATS
#ifdef SITH_DEBUG_STRUCT_NAMES
                    if (v7 && thing == sithPlayer_pLocalPlayerThing)
                        jk_printf("OpenJKDF2: Debug thing %s\n", v7->template_name);
#endif
#endif
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

// MoTS altered
void sithPlayerActions_JumpWithVel(sithThing *thing, flex_t vel)
{
    flex_d_t final_vel;
    int isAttachedAndIsSurface; // zf
    int v12; // eax
    int jumpSound; // edi
    int v14; // eax
    sithPlayingSound *v15; // eax

    // MoTS Added: SITH_AF_FREEZE_MOVEMENT
    if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && (thing->actorParams.typeflags & SITH_AF_COMBO_FREEZE) == 0 )
    {
        final_vel = thing->actorParams.jumpSpeed * vel;
        if ( (thing->physicsParams.physflags & SITH_PF_CROUCHING) != 0 )
            final_vel = final_vel * 0.7;
        if ( (thing->physicsParams.physflags & SITH_PF_WATERSURFACE) != 0 )
        {
            rdVector_MultAcc3(&thing->physicsParams.vel, &rdroid_zVector3, final_vel);
            thing->physicsParams.physflags &= ~SITH_PF_WATERSURFACE;
        }
        else
        {
            if ( !thing->attach_flags )
                return;
            isAttachedAndIsSurface = (thing->attach_flags & (SITH_ATTACH_THING|SITH_ATTACH_THINGSURFACE)) == 0;
            
            rdVector_MultAcc3(&thing->physicsParams.vel, &rdroid_zVector3, final_vel);
            if ( isAttachedAndIsSurface )
            {
                sithSurface* pAttachedSurface = thing->attachedSurface;
                v14 = pAttachedSurface->surfaceFlags;
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
                sithThing* pAttachedThing = thing->attachedThing;
                v12 = pAttachedThing->thingflags;
                if ( (v12 & SITH_TF_METAL) != 0 ) // wtf??
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
    if (idx < (unsigned int)jkPlayer_maxPlayers && idx >= 0) // Added: >=0 check
    {
        if ( (jkPlayer_playerInfos[idx].flags & 2) != 0 )
        {
            _memcpy(&thing->lookOrientation, &jkPlayer_playerInfos[idx].spawnPosOrient, sizeof(thing->lookOrientation));
            thing->position = thing->lookOrientation.scale;
            rdVector_Zero3(&thing->lookOrientation.scale);
            sithThing_MoveToSector(thing, jkPlayer_playerInfos[idx].pSpawnSector, 0);
        }
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            sithPhysics_ThingStop(thing);
            thing->physicsParams.physflags &= ~SITH_PF_100;
            sithPhysics_FindFloor(thing, 1);
        }
    }
}

// Added
sithThing* sithPlayerActions_SpawnThingAtLookAt(sithThing *pPlayerThing, sithThing* pTemplate)
{
    sithSector *v4; // esi
    int v5; // eax
    sithCollisionSearchEntry *searchResult; // eax
    sithThing *v7; // edx
    flex_t a6; // [esp+0h] [ebp-58h]
    rdVector3 thingPos; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+28h] [ebp-30h] BYREF

    _memcpy(&out, &pPlayerThing->lookOrientation, sizeof(out));
    rdVector_Copy3(&thingPos, &pPlayerThing->position);
    if ( pPlayerThing->type == SITH_THING_ACTOR || pPlayerThing->type == SITH_THING_PLAYER )
    {
        rdMatrix_PreRotate34(&out, &pPlayerThing->actorParams.eyePYR);
        rdVector_Add3Acc(&thingPos, &pPlayerThing->actorParams.eyeOffset);
    }

    if (pTemplate->type == SITH_THING_WEAPON) {
        rdVector3 tmp1, tmp2;
        rdVector_Zero3(&tmp1);
        rdVector_Zero3(&tmp2);
        return sithWeapon_FireProjectile(pPlayerThing, pTemplate, NULL, -1, &tmp1, &tmp2, 1.0, 0, 90.0, 90.0, 0);
    }

    sithThing* pSpawned = sithThing_SpawnTemplate(pTemplate, pPlayerThing);
    if (!pSpawned) {
        return NULL;
    }

    sithSector* pSectorIter = sithCollision_GetSectorLookAt(pPlayerThing->sector, &pPlayerThing->position, &thingPos, 0.0);
    if ( pSectorIter )
    {
        a6 = pPlayerThing->moveSize*10;//pPlayerThing->moveSize - -0.1;
        sithCollision_SearchRadiusForThings(pSectorIter, pPlayerThing, &thingPos, &out.lvec, a6, 0.025, 0);
        for ( searchResult = sithCollision_NextSearchResult(); searchResult; searchResult = sithCollision_NextSearchResult() )
        {
            if (searchResult->hitType & SITHCOLLISION_ADJOINCROSS)
            {
                if (searchResult && searchResult->surface && searchResult->surface->adjoin && searchResult->surface->adjoin->sector)
                {
                    pSectorIter = searchResult->surface->adjoin->sector;
                    sithThing_MoveToSector(pSpawned, pSectorIter, 0);
                }
            }
            else if ( (searchResult->hitType & SITHCOLLISION_WORLD) != 0 )
            {
                pSectorIter = searchResult->surface->parent_sector;
                //sithCog_SendMessageFromSurface(searchResult->surface, pPlayerThing, SITH_MESSAGE_ACTIVATE);
                if (pSectorIter)
                    sithThing_MoveToSector(pSpawned, pSectorIter, 0);

                rdVector3 tmp, tmp2;
                rdVector_Copy3(&tmp, &thingPos);
                rdVector_Copy3(&tmp2, &searchResult->surface->surfaceInfo.face.normal);
                rdVector_Scale3Acc(&tmp2, pTemplate->moveSize / 2);
                rdVector_MultAcc3(&tmp, &out.lvec, searchResult->distance - 0.001);
                rdVector_Add3Acc(&tmp, &tmp2);
                pSpawned->position = tmp;

                sithCollision_SearchClose();
                return pSpawned;
            }
            /*else if ( (searchResult->hitType & SITHCOLLISION_THING) != 0 )
            {
                v7 = searchResult->receiver;

                if ( v7->type != SITH_THING_ITEM && v7->type != SITH_THING_WEAPON && (v7->thingflags & SITH_TF_CAPTURED) != 0 )
                {
                    sithThing_MoveToSector(i, v5->sector, 0);

                    //sithCog_SendMessageFromThing(searchResult->receiver, pPlayerThing, SITH_MESSAGE_ACTIVATE);
                    sithCollision_SearchClose();
                    return pSpawned;
                }
            }*/
        }

        rdVector3 tmp;
        rdVector_Copy3(&tmp, &pPlayerThing->position);
        rdVector_MultAcc3(&tmp, &out.lvec, a6);
        pSpawned->position = tmp;
    }

    sithCollision_SearchClose();
    return pSpawned;
}
