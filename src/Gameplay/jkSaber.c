#include "jkSaber.h"

#include "World/jkPlayer.h"
#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithSoundClass.h"
#include "Gameplay/sithTime.h"
#include "World/sithSurface.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithPuppet.h"
#include "Dss/sithMulti.h"
#include "World/sithTemplate.h"
#include "World/sithModel.h"
#include "Engine/sithKeyFrame.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "Main/jkSmack.h"
#include "General/stdString.h"

#include "jk.h"

#define JKSABER_EXTENDTIME (0.3000000)

void jkSaber_InitializeSaberInfo(sithThing *thing, char *material_side_fname, char *material_tip_fname, float base_rad, float tip_rad, float len, sithThing *wall_sparks, sithThing *blood_sparks, sithThing *saber_sparks)
{
    float length = 0.0;
    jkPlayerInfo* saberinfo = thing->playerInfo;
    if ( saberinfo->polylineThing.polyline )
    {
        length = saberinfo->polyline.length;
        rdThing_FreeEntry(&saberinfo->polylineThing);
        rdPolyLine_FreeEntry(&saberinfo->polyline);
        saberinfo->polylineThing.polyline = 0;
    }

#ifdef DEBUG_QOL_CHEATS
    if (thing == sithPlayer_pLocalPlayerThing && !sithNet_isMulti) {
        material_tip_fname = "saberpurple0.mat";
        material_side_fname = "saberpurple1.mat";
    }
    if (thing == sithPlayer_pLocalPlayerThing) {
        //thing->jkFlags |= JKFLAG_DUALSABERS;
    }
#endif

    rdPolyLine_FreeEntry(&saberinfo->polyline); // Added: fix memleak
    rdPolyLine_NewEntry(&saberinfo->polyline, "Saber", material_side_fname, material_tip_fname, length, base_rad, tip_rad, 4, 0, 0, 0.0);
    rdThing_NewEntry(&saberinfo->polylineThing, thing);
    rdThing_SetPolyline(&saberinfo->polylineThing, &saberinfo->polyline);
    saberinfo->wall_sparks = wall_sparks;
    saberinfo->blood_sparks = blood_sparks;
    saberinfo->saber_sparks = saber_sparks;
    saberinfo->length = len;
}

void jkSaber_PolylineRand(rdThing *thing)
{
    rdPolyLine* line = thing->polyline;
    if ( line )
    {
        if ( !(bShowInvisibleThings & 0xF) )
            line->edgeFace.clipIdk.y = 0.0;
        line->edgeFace.clipIdk.y = (_frand() - 0.8) * 80.0 + line->edgeFace.clipIdk.y;
    }
}

void jkSaber_Draw(rdMatrix34 *posRotMat)
{
    if ( playerThings[playerThingIdx].actorThing->jkFlags & JKFLAG_SABERON
      && playerThings[playerThingIdx].povModel.model3
      && playerThings[playerThingIdx].polylineThing.model3 )
    {
        if ( playerThings[playerThingIdx].povModel.frameTrue != rdroid_frameTrue )
        {
            rdPuppet_BuildJointMatrices(&playerThings[playerThingIdx].povModel, posRotMat);
        }

        jkSaber_PolylineRand(&playerThings[playerThingIdx].polylineThing);
        rdThing_Draw(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[5]); // aaaaa hardcoded K_Rhand
        if (playerThings[playerThingIdx].actorThing->jkFlags & JKFLAG_DUALSABERS)
            rdThing_Draw(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[2]); // K_Lhand
    }
}

void jkSaber_UpdateLength(sithThing *thing)
{
    jkPlayerInfo* playerInfo = thing->playerInfo;
    if (!playerInfo )
    {
        thing->jkFlags &= ~JKFLAG_SABERON;
        return;
    }
    
    if (thing->thingflags & SITH_TF_DEAD || thing->type == SITH_THING_CORPSE)
    {
        thing->jkFlags |= JKFLAG_SABERRETRACT;
    }

    // Added: HACK fix a bug where the saber gets stuck extended.
    if ((thing->jkFlags & (JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT)) == (JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT))
    {
        thing->jkFlags &= ~JKFLAG_SABERRETRACT;
        playerInfo->polyline.length = 0;
    }

    if ( thing->jkFlags & JKFLAG_SABEREXTEND)
    {
        float newLength = playerInfo->polyline.length + (sithTime_deltaSeconds * JKSABER_EXTENDTIME);
        float deltaLen = newLength / playerInfo->length;

        thing->jkFlags &= ~JKFLAG_SABERRETRACT;

        playerInfo->polyline.length = newLength;
        thing->actorParams.timeLeftLengthChange = deltaLen * (1.0 - JKSABER_EXTENDTIME);
        if (newLength >= playerInfo->length) // ? verify, IDA crapped out on this comparison
        {
            playerInfo->polyline.length = playerInfo->length;
            thing->actorParams.timeLeftLengthChange = (1.0 - JKSABER_EXTENDTIME);
            thing->jkFlags &= ~(JKFLAG_SABERRETRACT | JKFLAG_SABEREXTEND);
        }
    }
    else if ( thing->jkFlags & JKFLAG_SABERRETRACT )
    {
        float newLength = playerInfo->polyline.length - (sithTime_deltaSeconds * JKSABER_EXTENDTIME);
        float deltaLen = newLength / playerInfo->length;

        thing->jkFlags &= ~JKFLAG_SABEREXTEND;

        playerInfo->polyline.length = newLength;
        thing->actorParams.timeLeftLengthChange = deltaLen * (1.0 - JKSABER_EXTENDTIME);
        if ( deltaLen < 0.0 ) // ? verify, IDA crapped out on this comparison
        {
            playerInfo->polyline.length = 0.0;
            thing->jkFlags &= ~(JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT | JKFLAG_SABERON);
            thing->actorParams.timeLeftLengthChange = 0.0;
        }
    }
    else if (thing->jkFlags & JKFLAG_SABERFORCEON)
    {
        playerInfo->polyline.length = playerInfo->length;
        thing->actorParams.timeLeftLengthChange = (1.0 - JKSABER_EXTENDTIME);
        thing->jkFlags &= ~(JKFLAG_SABERRETRACT | JKFLAG_SABEREXTEND);
        thing->jkFlags |= JKFLAG_SABERON;
    }

    if ( thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP] >= 0 )
    {
        jkSaber_UpdateCollision(thing, thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP]);
        if ( thing->jkFlags & JKFLAG_DUALSABERS )
        {
            if ( thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP] >= 0 )
                jkSaber_UpdateCollision(thing, thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP]);
        }
    }
}

void jkSaber_UpdateCollision(sithThing *player, int joint)
{
    jkPlayerInfo *playerInfo; // ebx
    sithCollisionSearchEntry *searchResult; // edi
    sithThing *resultThing; // ebp

    sithSector *sector;
    rdVector3 a2a;
    rdVector3 a1;
    rdMatrix34 jointMat;
    rdMatrix34 matrix;
    rdMatrix34 tmpMat;

    rdMatrix_Copy34(&matrix, &player->lookOrientation);
    playerInfo = player->playerInfo;
    matrix.scale.x = player->position.x;
    matrix.scale.y = player->position.y;
    matrix.scale.z = player->position.z;
    if ( jkSmack_GetCurrentGuiState() == 6 )
        rdPuppet_BuildJointMatrices(&player->rdthing, &matrix);
    if ( !rdModel3_GetMeshMatrix(&player->rdthing, &matrix, joint, &jointMat) )
        return;

    player->actorParams.saberBladePos.x = playerInfo->polyline.length * jointMat.lvec.x + jointMat.scale.x;
    player->actorParams.saberBladePos.y = playerInfo->polyline.length * jointMat.lvec.y + jointMat.scale.y;
    player->actorParams.saberBladePos.z = playerInfo->polyline.length * jointMat.lvec.z + jointMat.scale.z;
    if ( player->jkFlags & JKFLAG_40 )
    {
        player->jkFlags &= ~JKFLAG_40;
        playerInfo->numDamagedThings = 0;
        playerInfo->numDamagedSurfaces = 0;
    }
    if ( !(player->jkFlags & JKFLAG_SABERNODAMAGE) )
        return;
    if ( !playerInfo->field_1A4 )
        return;
    sector = sithCollision_GetSectorLookAt(player->sector, &player->position, &jointMat.scale, 0.0);
    if ( !sector )
        return;
    sithCollision_SearchRadiusForThings(sector, player, &jointMat.scale, &jointMat.lvec, playerInfo->field_1AC, 0.0, 0);

    while ( 1 )
    {
        searchResult = sithCollision_NextSearchResult();
        if ( !searchResult )
            break;
    
        if ( searchResult->hitType & SITHCOLLISION_ADJOINCROSS )
        {
            sector = searchResult->surface->adjoin->sector;
        }
        else if ( searchResult->hitType & SITHCOLLISION_THING )
        {
            resultThing = searchResult->receiver;
    
            // TODO is this a matrix function
            a2a.x = searchResult->distance * jointMat.lvec.x + jointMat.scale.x;
            a2a.y = searchResult->distance * jointMat.lvec.y + jointMat.scale.y;
            a2a.z = searchResult->distance * jointMat.lvec.z + jointMat.scale.z;
            if ( resultThing->type == SITH_THING_ITEM || resultThing->type == SITH_THING_EXPLOSION || resultThing->type == SITH_THING_PARTICLE )
            {
                continue;
            }
            if (resultThing->actorParams.typeflags & SITH_AF_DROID 
                || resultThing->type != SITH_THING_ACTOR && resultThing->type != SITH_THING_PLAYER )
            {
                if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->wall_sparks)
                {
                    // TODO is this inlined?
                    sithThing* actorThing = sithThing_Create(playerInfo->wall_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                    if ( actorThing )
                    {
                        actorThing->prev_thing = playerInfo->actorThing;
                        playerInfo->lastSparkSpawnMs = sithTime_curMs;
                        actorThing->child_signature = playerInfo->actorThing->signature;
                    }
                }
            }
            if ( playerInfo->numDamagedThings == 6 )
            {
                break;
            }
            
            int foundIdx = 0;
            for (foundIdx = 0; foundIdx < playerInfo->numDamagedThings; foundIdx++ )
            {
                if ( searchResult->receiver == playerInfo->damagedThings[foundIdx] )
                    break;
            }

            if ( foundIdx < playerInfo->numDamagedThings )
            {
                break;
            }
            
            if ( resultThing->type != SITH_THING_ACTOR 
                 && resultThing->type != SITH_THING_PLAYER 
                 || !(resultThing->actorParams.typeflags & SITH_AF_BLEEDS) )
            {
                if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->blood_sparks)
                {
                    sithThing* actorThing = sithThing_Create(playerInfo->blood_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                    if ( actorThing )
                    {
                        actorThing->prev_thing = playerInfo->actorThing;
                        actorThing->child_signature = playerInfo->actorThing->signature;
                        playerInfo->lastSparkSpawnMs = sithTime_curMs;
                    }
                }

                sithThing_Damage(searchResult->receiver, player, playerInfo->damage, SITH_DAMAGE_SABER);
                playerInfo->damagedThings[playerInfo->numDamagedThings++] = searchResult->receiver;
                break;
            }
            
            // TODO is this a vector func?
            rdVector_Sub3(&a1, &a2a, &resultThing->position);
            rdVector_Normalize3Acc(&a1);
            rdMatrix_Copy34(&tmpMat, &resultThing->lookOrientation);
            if ( resultThing->type == SITH_THING_ACTOR || resultThing->type == SITH_THING_PLAYER )
                rdMatrix_PreRotate34(&tmpMat, &resultThing->actorParams.eyePYR);
                
            // TODO: is this a vector func?
            rdVector3 v52 = tmpMat.lvec;
            rdVector_Normalize3Acc(&v52);
            if ( rdVector_Dot3(&v52, &a1) >= resultThing->actorParams.fov
              && (_frand() < resultThing->actorParams.chance) )
            {
                if (!(player->actorParams.typeflags & SITH_AF_INVISIBLE)) // verify
                {
                    sithSoundClass_PlayModeRandom(player, SITH_SC_DEFLECTED);

                    if ( _frand() >= 0.5 )
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK2, 0);
                    else
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK, 0);

                    if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->saber_sparks)
                    {
                        sithThing* actorThing = sithThing_Create(playerInfo->saber_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                        if ( actorThing )
                        {
                            actorThing->prev_thing = playerInfo->actorThing;
                            playerInfo->lastSparkSpawnMs = sithTime_curMs;
                            actorThing->child_signature = playerInfo->actorThing->signature;
                        }
                    }

                    sithCog_SendMessageFromThing(resultThing, 0, SITH_MESSAGE_BLOCKED);
                    playerInfo->damagedThings[playerInfo->numDamagedThings++] = searchResult->receiver;
                    break;
                }
            }

            if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->blood_sparks)
            {
                sithThing* actorThing = sithThing_Create(playerInfo->blood_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                if ( actorThing )
                {
                    actorThing->prev_thing = playerInfo->actorThing;
                    playerInfo->lastSparkSpawnMs = sithTime_curMs;
                    actorThing->child_signature = playerInfo->actorThing->signature;
                }
            }

            sithThing_Damage(resultThing, player, playerInfo->damage, SITH_DAMAGE_SABER);
            playerInfo->damagedThings[playerInfo->numDamagedThings++] = searchResult->receiver;            
            break;
        }
        else if ( searchResult->hitType & SITHCOLLISION_WORLD )
        {
            a2a.x = (searchResult->distance - 0.001) * jointMat.lvec.x + jointMat.scale.x;
            a2a.y = (searchResult->distance - 0.001) * jointMat.lvec.y + jointMat.scale.y;
            a2a.z = (searchResult->distance - 0.001) * jointMat.lvec.z + jointMat.scale.z;
            if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 )
            {
                if ( playerInfo->wall_sparks )
                {
                    sithThing* actorThing = sithThing_Create(playerInfo->wall_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                    if ( actorThing )
                    {
                        actorThing->prev_thing = playerInfo->actorThing;
                        playerInfo->lastSparkSpawnMs = sithTime_curMs;
                        actorThing->child_signature = playerInfo->actorThing->signature;
                    }
                }
            }

            if ( playerInfo->numDamagedSurfaces < 6 )
            {
                int surfaceNum = 0;
                for ( surfaceNum = 0; surfaceNum < playerInfo->numDamagedSurfaces; surfaceNum++ )
                {
                    if ( searchResult->surface == playerInfo->damagedSurfaces[surfaceNum] )
                        break;
                }
                if ( surfaceNum >= playerInfo->numDamagedSurfaces )
                {
                    sithSurface_SendDamageToThing(searchResult->surface, player, playerInfo->damage, SITH_DAMAGE_SABER);
                    playerInfo->damagedSurfaces[playerInfo->numDamagedSurfaces++] = searchResult->surface;
                }
            }
            break;
        }
    }
    
    sithCollision_SearchClose();
    return;
}

void jkSaber_SpawnSparks(jkPlayerInfo *pPlayerInfo, rdVector3 *pPos, sithSector *psector, int sparkType)
{
    sithThing *pTemplate; // eax
    sithThing *v5; // eax
    sithThing *pActor; // ecx
    int v7; // edx

    if ( sithTime_curMs >= pPlayerInfo->lastSparkSpawnMs + 200 )
    {
        if ( sparkType == 1 )
        {
            pTemplate = pPlayerInfo->blood_sparks;
        }
        else if ( sparkType == 2 )
        {
            pTemplate = pPlayerInfo->saber_sparks;
        }
        else
        {
            pTemplate = pPlayerInfo->wall_sparks;
        }
        if ( pTemplate )
        {
            v5 = sithThing_Create(pTemplate, pPos, &rdroid_identMatrix34, psector, 0);
            if ( v5 )
            {
                pActor = pPlayerInfo->actorThing;
                v7 = sithTime_curMs;
                v5->prev_thing = pActor;
                pPlayerInfo->lastSparkSpawnMs = v7;
                v5->child_signature = pActor->signature;
            }
        }
    }
}

void jkSaber_Enable(sithThing *a1, float a2, float a3, float a4)
{
    a1->playerInfo->damage = a2;
    a1->playerInfo->field_1AC = a3;
    a1->playerInfo->field_1B0 = a4;
    a1->playerInfo->field_1A4 = 1;
    a1->playerInfo->numDamagedThings = 0;
    a1->playerInfo->numDamagedSurfaces = 0;

    _memset(a1->playerInfo->damagedThings, 0, sizeof(a1->playerInfo->damagedThings));
    _memset(a1->playerInfo->damagedSurfaces, 0, sizeof(a1->playerInfo->damagedSurfaces));
    
    a1->playerInfo->lastSparkSpawnMs = 0;
}

void jkSaber_Disable(sithThing *player)
{
    player->playerInfo->field_1A4 = 0;
}