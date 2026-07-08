#include "sithPlayerActions.h"
#include "stdPlatform.h" // Added

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

void sithPlayerActions_Activate(SithThing *thing)
{
    SithSector *v4; // esi
    int v5; // eax
    SithCollision *searchResult; // eax
    SithThing *v7; // edx
    flex_t a6; // [esp+0h] [ebp-58h]
    rdVector3 thingPos; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+28h] [ebp-30h] BYREF

    if ( !sithNet_isMulti || lastDoorOpenTime + 250 <= sithTime_g_clockTime )
    {
        lastDoorOpenTime = sithTime_g_clockTime;
        _memcpy(&out, &thing->orient, sizeof(out));
        rdVector_Copy3(&thingPos, &thing->position);
        if ( thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER )
        {
            rdMatrix_PreRotate34(&out, &thing->actorParams.headPYR);
            rdVector_Add3Acc(&thingPos, &thing->actorParams.eyeOffset);
        }
        v4 = sithCollision_FindSectorInRadius(thing->sector, &thing->position, &thingPos, 0.0);
        if ( v4 )
        {
            v5 = sithPuppet_PlayMode(thing, SITH_ANIM_ACTIVATE, 0);
            if ( sithMessage_g_outputstream && v5 >= 0 )
                sithDSSThing_PlayKeyMode(thing, SITH_ANIM_ACTIVATE, thing->renderData.puppet->tracks[v5].field_130, -1, 255);
            a6 = thing->moveSize - -0.1;
            sithCollision_SearchForCollisions(v4, thing, &thingPos, &out.lvec, a6, 0.025, /*SITH_THING_ACTOR*/RAYCAST_2);
            for ( searchResult = sithCollision_PopStack(); searchResult; searchResult = sithCollision_PopStack() )
            {
                if ( (searchResult->hitType & SITHCOLLISION_WORLD) != 0 )
                {
#ifdef DEBUG_QOL_CHEATS
                    if (searchResult->surface && searchResult->surface->surfaceInfo.face.material && thing == sithPlayer_g_pLocalPlayerThing)
                        jk_printf("OpenJKDF2: Debug surf %s\n", searchResult->surface->surfaceInfo.face.material->mat_fpath);
#endif
                    if (searchResult->surface->flags & SITH_SURFACE_COG_LINKED)
                    {
                        sithCog_SurfaceSendMessage(searchResult->surface, thing, SITH_MESSAGE_ACTIVATE);
                        sithCollision_DecreaseStackLevel();
                        return;
                    }
                }
                else if ( (searchResult->hitType & SITHCOLLISION_THING) != 0 )
                {
                    v7 = searchResult->receiver;
#ifdef DEBUG_QOL_CHEATS
#ifdef SITH_DEBUG_STRUCT_NAMES
                    if (v7 && thing == sithPlayer_g_pLocalPlayerThing)
                        jk_printf("OpenJKDF2: Debug thing %s\n", v7->aName);
#endif
#endif
                    if ( v7->type != SITH_THING_ITEM && v7->type != SITH_THING_WEAPON && (v7->flags & SITH_TF_CAPTURED) != 0 )
                    {
                        sithCog_ThingSendMessage(searchResult->receiver, thing, SITH_MESSAGE_ACTIVATE);
                        break;
                    }
                }
            }
            sithCollision_DecreaseStackLevel();
        }
    }
}

// MoTS altered
void sithPlayerActions_JumpWithVel(SithThing *thing, flex_t vel)
{
    flex_d_t final_vel;
    int isAttachedAndIsSurface; // zf
    int v12; // eax
    int jumpSound; // edi
    int v14; // eax
    sithPlayingSound *v15; // eax

    // MoTS Added: SITH_AF_FREEZE_MOVEMENT
    if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && (thing->actorParams.flags & SITH_AF_COMBO_FREEZE) == 0 )
    {
        final_vel = thing->actorParams.jumpSpeed * vel;
        if ( (thing->physicsParams.flags & SITH_PF_CROUCHING) != 0 )
            final_vel = final_vel * 0.7;
        if ( (thing->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 )
        {
            rdVector_ScaleAdd3Acc(&thing->physicsParams.vel, &rdroid_zVector3, final_vel);
            thing->physicsParams.flags &= ~SITH_PF_ONWATERSURFACE;
        }
        else
        {
            if ( !thing->attach_flags )
                return;
            isAttachedAndIsSurface = (thing->attach_flags & (SITH_ATTACH_THING|SITH_ATTACH_THINGFACE)) == 0;
            
            rdVector_ScaleAdd3Acc(&thing->physicsParams.vel, &rdroid_zVector3, final_vel);
            if ( isAttachedAndIsSurface )
            {
                SithSurface* pAttachedSurface = thing->attachedSurface;
                v14 = pAttachedSurface->flags;
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
                SithThing* pAttachedThing = thing->attachedThing;
                v12 = pAttachedThing->flags;
                if ( (v12 & SITH_TF_METAL) != 0 ) // wtf??
                    jumpSound = SITH_SC_JUMPMETAL;
                else
                    jumpSound = (SITH_TF_EARTH & v12) != 0 ? SITH_SC_JUMPEARTH : SITH_SC_JUMP;
            }
            v15 = sithSoundClass_PlayModeRandom(thing, jumpSound);
            if ( v15 && sithMessage_g_outputstream )
                sithDSSThing_PlaySoundMode(thing, jumpSound, v15->refid, -1.0);
            sithThing_DetachThing(thing);
        }
        if ( sithMessage_g_outputstream )
            sithThing_SyncThing(thing, SITHTHING_SYNC_POS);
    }
}

void sithPlayerActions_MoveToPlayerPosition(SithThing *thing, int idx)
{
    if (idx < (unsigned int)jkPlayer_maxPlayers && idx >= 0) // Added: >=0 check
    {
        if ( (jkPlayer_playerInfos[idx].flags & 2) != 0 )
        {
            stdPlatform_Memcpy32(&thing->orient, &jkPlayer_playerInfos[idx].orient, sizeof(thing->orient)); // Added: word-safe (aThings may be in extram)
            thing->position = thing->orient.scale;
            rdVector_Zero3(&thing->orient.scale);
            sithThing_SetSector(thing, jkPlayer_playerInfos[idx].pInSector, 0);
        }
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            sithPhysics_ResetThingMovement(thing);
            thing->physicsParams.flags &= ~SITH_PF_100;
            sithPhysics_FindFloor(thing, 1);
        }
    }
}

// Added
SithThing* sithPlayerActions_SpawnThingAtLookAt(SithThing *pPlayerThing, SithThing* pCreateThingTemplate)
{
    SithSector *v4; // esi
    int v5; // eax
    SithCollision *searchResult; // eax
    SithThing *v7; // edx
    flex_t a6; // [esp+0h] [ebp-58h]
    rdVector3 thingPos; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+28h] [ebp-30h] BYREF

    _memcpy(&out, &pPlayerThing->orient, sizeof(out));
    rdVector_Copy3(&thingPos, &pPlayerThing->position);
    if ( pPlayerThing->type == SITH_THING_ACTOR || pPlayerThing->type == SITH_THING_PLAYER )
    {
        rdMatrix_PreRotate34(&out, &pPlayerThing->actorParams.headPYR);
        rdVector_Add3Acc(&thingPos, &pPlayerThing->actorParams.eyeOffset);
    }

    if (pCreateThingTemplate->type == SITH_THING_WEAPON) {
        rdVector3 tmp1, tmp2;
        rdVector_Zero3(&tmp1);
        rdVector_Zero3(&tmp2);
        return sithWeapon_FireProjectile(pPlayerThing, pCreateThingTemplate, NULL, -1, &tmp1, &tmp2, 1.0, 0, 90.0, 90.0, 0);
    }

    SithThing* pSpawned = sithThing_CreateThing(pCreateThingTemplate, pPlayerThing);
    if (!pSpawned) {
        return NULL;
    }

    SithSector* pSectorIter = sithCollision_FindSectorInRadius(pPlayerThing->sector, &pPlayerThing->position, &thingPos, 0.0);
    if ( pSectorIter )
    {
        a6 = pPlayerThing->moveSize*10;//pPlayerThing->moveSize - -0.1;
        sithCollision_SearchForCollisions(pSectorIter, pPlayerThing, &thingPos, &out.lvec, a6, 0.025, 0);
        for ( searchResult = sithCollision_PopStack(); searchResult; searchResult = sithCollision_PopStack() )
        {
            if (searchResult->hitType & SITHCOLLISION_ADJOINCROSS)
            {
                if (searchResult && searchResult->surface && searchResult->surface->pAdjoin && searchResult->surface->pAdjoin->sector)
                {
                    pSectorIter = searchResult->surface->pAdjoin->sector;
                    sithThing_SetSector(pSpawned, pSectorIter, 0);
                }
            }
            else if ( (searchResult->hitType & SITHCOLLISION_WORLD) != 0 )
            {
                pSectorIter = searchResult->surface->pSector;
                //sithCog_SurfaceSendMessage(searchResult->surface, pPlayerThing, SITH_MESSAGE_ACTIVATE);
                if (pSectorIter)
                    sithThing_SetSector(pSpawned, pSectorIter, 0);

                rdVector3 tmp, tmp2;
                rdVector_Copy3(&tmp, &thingPos);
                rdVector_Copy3(&tmp2, &searchResult->surface->surfaceInfo.face.normal);
                rdVector_Scale3Acc(&tmp2, pCreateThingTemplate->moveSize / 2);
                rdVector_ScaleAdd3Acc(&tmp, &out.lvec, searchResult->distance - 0.001);
                rdVector_Add3Acc(&tmp, &tmp2);
                pSpawned->position = tmp;

                sithCollision_DecreaseStackLevel();
                return pSpawned;
            }
            /*else if ( (searchResult->hitType & SITHCOLLISION_THING) != 0 )
            {
                v7 = searchResult->receiver;

                if ( v7->type != SITH_THING_ITEM && v7->type != SITH_THING_WEAPON && (v7->flags & SITH_TF_CAPTURED) != 0 )
                {
                    sithThing_SetSector(i, v5->sector, 0);

                    //sithCog_ThingSendMessage(searchResult->receiver, pPlayerThing, SITH_MESSAGE_ACTIVATE);
                    sithCollision_DecreaseStackLevel();
                    return pSpawned;
                }
            }*/
        }

        rdVector3 tmp;
        rdVector_Copy3(&tmp, &pPlayerThing->position);
        rdVector_ScaleAdd3Acc(&tmp, &out.lvec, a6);
        pSpawned->position = tmp;
    }

    sithCollision_DecreaseStackLevel();
    return pSpawned;
}
