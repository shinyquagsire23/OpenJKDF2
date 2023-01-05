#include "jkSaber.h"

#include "World/jkPlayer.h"
#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithAnimClass.h"
#include "World/sithSoundClass.h"
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
    if (!thing) return; // Added: Fix nullptr deref in Mots cutscenes

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
        //material_tip_fname = "saberpurple0.mat";
        //material_side_fname = "saberpurple1.mat";
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
        line->edgeFace.clipIdk.y += (_frand() - 0.8) * 80.0;
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
        
        // Added: Dual sabers
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

#if 0
    printf("Saber state: ");
    if (thing->jkFlags & JKFLAG_SABERON) {
        printf("ON ");
    }
    if (thing->jkFlags & JKFLAG_SABERDAMAGE) {
        printf("DAMAGE ");
    }
    if (thing->jkFlags & JKFLAG_SABEREXTEND) {
        printf("EXTEND ");
    }
    if (thing->jkFlags & JKFLAG_SABERRETRACT) {
        printf("RETRACT ");
    }
    if (thing->jkFlags & JKFLAG_DUALSABERS) {
        printf("DUALSABERS ");
    }
    if (thing->jkFlags & JKFLAG_SABERFORCEON) {
        printf("FORCEON ");
    }
    printf(" len=%f %f\n", playerInfo->polyline.length, thing->actorParams.timeLeftLengthChange);
#endif

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
        if ( newLength <= 0.0 ) // ? verify, IDA crapped out on this comparison
        {
            playerInfo->polyline.length = 0.0;
            thing->jkFlags &= ~(JKFLAG_SABEREXTEND | JKFLAG_SABERRETRACT | JKFLAG_SABERON);
            thing->actorParams.timeLeftLengthChange = 0.0;
        }
    }
    else if (thing->jkFlags & JKFLAG_SABERFORCEON) // Used for starting a level with the saber on, ie DF2 lv4
    {
        playerInfo->polyline.length = playerInfo->length;
        thing->actorParams.timeLeftLengthChange = (1.0 - JKSABER_EXTENDTIME);
        thing->jkFlags &= ~(JKFLAG_SABERRETRACT | JKFLAG_SABEREXTEND);
        thing->jkFlags |= JKFLAG_SABERON;

        // Added? I think my RETRACT | EXTEND fix inavertently exposed a bug
        thing->jkFlags &= ~JKFLAG_SABERFORCEON;
    }

    if ( thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP] >= 0 )
    {
        jkSaber_UpdateCollision(thing, thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP], 0); // MOTS added: last arg
        if ( thing->jkFlags & JKFLAG_DUALSABERS )
        {
            if ( thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP] >= 0 )
                jkSaber_UpdateCollision(thing, thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP], 1); // MOTS added: last arg
        }
    }
}

// MOTS added: split into its own func
void  jkSaber_UpdateCollision2(sithThing *pPlayerThing,rdVector3 *pSaberPos,rdVector3 *pSaberDir,jkSaberCollide *pCollideInfo)
{
    sithSector *pSector;
    sithCollisionSearchEntry *searchResult;
    sithThing *resultThing;
    rdVector3 local_54;
    rdVector3 local_3c;
    jkPlayerInfo *playerInfo;
    rdMatrix34 tmpMat;
    
    playerInfo = pPlayerThing->playerInfo;
    pSector = sithCollision_GetSectorLookAt(pPlayerThing->sector,&pPlayerThing->position,pSaberPos,0.0);
    if (!pSector) {
        return;
    }
    sithCollision_SearchRadiusForThings(pSector,pPlayerThing,pSaberPos,pSaberDir,pCollideInfo->field_1AC,0.0,0);
    

    sithSector* pSectorIter = pSector;
    while (1) 
    {
        searchResult = sithCollision_NextSearchResult();
        if (!searchResult)
            break;

        if (searchResult->hitType & SITHCOLLISION_ADJOINCROSS)
        {
            pSectorIter = searchResult->surface->adjoin->sector;
        }
        else if (searchResult->hitType & SITHCOLLISION_THING) 
        {
            rdVector_Copy3(&local_54, pSaberPos);
            rdVector_MultAcc3(&local_54, pSaberDir, searchResult->distance);

            resultThing = searchResult->receiver;

            if ( resultThing->type == SITH_THING_ITEM || resultThing->type == SITH_THING_EXPLOSION || resultThing->type == SITH_THING_PARTICLE )
            {
                continue;
            }
            if (resultThing->actorParams.typeflags & SITH_AF_DROID 
                || resultThing->type != SITH_THING_ACTOR && resultThing->type != SITH_THING_PLAYER )
            {
                jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_WALL);
            }
            if ( pCollideInfo->numDamagedThings == 6 )
            {
                break;
            }

            int foundIdx = 0;
            for (foundIdx = 0; foundIdx < pCollideInfo->numDamagedThings; foundIdx++ )
            {
                if ( searchResult->receiver == pCollideInfo->damagedThings[foundIdx] )
                    break;
            }

            if ( foundIdx < pCollideInfo->numDamagedThings )
            {
                break;
            }

            if ( resultThing->type != SITH_THING_ACTOR 
                 && resultThing->type != SITH_THING_PLAYER 
                 || !(resultThing->actorParams.typeflags & SITH_AF_BLEEDS) )
            {
                jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_BLOOD);

                sithThing_Damage(searchResult->receiver, pPlayerThing, pCollideInfo->damage, SITH_DAMAGE_SABER);
                pCollideInfo->damagedThings[pCollideInfo->numDamagedThings++] = searchResult->receiver;
                break;
            }

            // TODO is this a vector func?
            rdVector_Sub3(&local_3c, &local_54, &resultThing->position);
            rdVector_Normalize3Acc(&local_3c);
            rdMatrix_Copy34(&tmpMat, &resultThing->lookOrientation);
            if ( resultThing->type == SITH_THING_ACTOR || resultThing->type == SITH_THING_PLAYER )
                rdMatrix_PreRotate34(&tmpMat, &resultThing->actorParams.eyePYR);
                
            // TODO: is this a vector func?
            rdVector3 v52 = tmpMat.lvec;
            rdVector_Normalize3Acc(&v52);
            if ( rdVector_Dot3(&v52, &local_3c) >= resultThing->actorParams.fov
              && (_frand() < resultThing->actorParams.chance) )
            {
                if (!(pPlayerThing->actorParams.typeflags & SITH_AF_INVISIBLE)) // verify
                {
                    sithSoundClass_PlayModeRandom(pPlayerThing, SITH_SC_DEFLECTED);

                    if ( _frand() >= 0.5 )
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK2, 0);
                    else
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK, 0);

                    jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_SABER);

                    sithCog_SendMessageFromThing(resultThing, 0, SITH_MESSAGE_BLOCKED);
                    pCollideInfo->damagedThings[pCollideInfo->numDamagedThings++] = searchResult->receiver;
                    break;
                }
            }

            jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_BLOOD);

            sithThing_Damage(resultThing, pPlayerThing, pCollideInfo->damage, SITH_DAMAGE_SABER);
            pCollideInfo->damagedThings[pCollideInfo->numDamagedThings++] = searchResult->receiver;
            break;
        }
        else if (searchResult->hitType & SITHCOLLISION_WORLD)
        {
            rdVector_Copy3(&local_54, pSaberPos);
            rdVector_MultAcc3(&local_54, pSaberDir, searchResult->distance - 0.001);
            
            jkSaber_SpawnSparks(playerInfo, &local_54, pSectorIter, SPARKTYPE_WALL);

            if ( pCollideInfo->numDamagedSurfaces < 6 )
            {
                int surfaceNum = 0;
                for ( surfaceNum = 0; surfaceNum < pCollideInfo->numDamagedSurfaces; surfaceNum++ )
                {
                    if ( searchResult->surface == pCollideInfo->damagedSurfaces[surfaceNum] )
                        break;
                }
                if ( surfaceNum >= pCollideInfo->numDamagedSurfaces )
                {
                    sithSurface_SendDamageToThing(searchResult->surface, pPlayerThing, pCollideInfo->damage, SITH_DAMAGE_SABER);
                    pCollideInfo->damagedSurfaces[pCollideInfo->numDamagedSurfaces++] = searchResult->surface;
                }
            }
            break;
        }
    }
    sithCollision_SearchClose();
}

// MOTS altered: interpolation and multiple blades
void jkSaber_UpdateCollision(sithThing *player, int joint, int bSecondary)
{
    jkPlayerInfo *playerInfo; // ebx
    rdVector3 a2a;
    rdMatrix34 jointMat;
    rdVector3 jointPos;
    rdMatrix34 matrix;
    rdMatrix34 tmpMat;
    rdMatrix34 local_60;
    rdVector3 lerpSaberDir;
    rdVector3 lerpSaberPos;
    rdVector3 lerpPosDelta;
    rdVector3 lerpDirDelta;
    rdMatrix34 *storeOrientMat;

    playerInfo = player->playerInfo;

    rdMatrix_Copy34(&matrix, &player->lookOrientation);
    rdVector_Copy3(&matrix.scale, &player->position);
    if ( jkSmack_GetCurrentGuiState() == 6 ) {
        rdPuppet_BuildJointMatrices(&player->rdthing, &matrix);
    }

    if ( !rdModel3_GetMeshMatrix(&player->rdthing, &matrix, joint, &jointMat) )
        return;

    rdVector_Copy3(&player->actorParams.saberBladePos, &jointMat.scale);
    rdVector_MultAcc3(&player->actorParams.saberBladePos, &jointMat.lvec, playerInfo->polyline.length);

    if ( player->jkFlags & JKFLAG_40 )
    {
        player->jkFlags &= ~JKFLAG_40;
        playerInfo->saberCollideInfo.numDamagedThings = 0;
        playerInfo->saberCollideInfo.numDamagedSurfaces = 0;
    }
    if ( !(player->jkFlags & JKFLAG_SABERDAMAGE) )
        return;
    if ( !playerInfo->saberCollideInfo.field_1A4 )
        return;
    
    if (!Main_bMotsCompat) {
        jkSaber_UpdateCollision2(player,&jointMat.scale, &jointMat.lvec, &playerInfo->saberCollideInfo);
        return;
    }
    
    // MOTS added: interpolation at low FPS
    rdVector_Copy3(&jointPos, &jointMat.scale);
    rdVector_Copy3(&a2a, &jointMat.lvec);
    if (sithTime_deltaSeconds > 0.05 && playerInfo->jkmUnk1) 
    {
        storeOrientMat = &playerInfo->jkmSaberUnk1;
        if (bSecondary != 0) {
            storeOrientMat = &playerInfo->jkmSaberUnk2;
        }
        float fVar1 = sithTime_TickHz * 0.05;
        rdMatrix_Copy34(&local_60, storeOrientMat);

        rdVector_Sub3(&lerpPosDelta, &jointMat.scale, &local_60.scale);
        rdVector_Sub3(&lerpDirDelta, &jointMat.lvec, &local_60.lvec);
        float local_b8 = fVar1;
        for (; fVar1 < 1.0; fVar1 = local_b8 + fVar1) {
            rdVector_Copy3(&lerpSaberPos, &local_60.scale);
            rdVector_MultAcc3(&lerpSaberPos, &lerpPosDelta, fVar1);

            rdVector_Copy3(&lerpSaberDir, &local_60.lvec);
            rdVector_MultAcc3(&lerpSaberDir, &lerpDirDelta, fVar1);

            jkSaber_UpdateCollision2(player,&lerpSaberPos,&lerpSaberDir,&playerInfo->saberCollideInfo);
        }
    }
    jkSaber_UpdateCollision2(player,&jointPos,&a2a,&playerInfo->saberCollideInfo);
    storeOrientMat = &playerInfo->jkmSaberUnk1;
    if (bSecondary != 0) {
        storeOrientMat = &playerInfo->jkmSaberUnk2;
    }
    rdMatrix_Copy34(storeOrientMat, &jointMat);
    playerInfo->jkmUnk1 = 1;
}

void jkSaber_SpawnSparks(jkPlayerInfo *pPlayerInfo, rdVector3 *pPos, sithSector *psector, int sparkType)
{
    sithThing *pTemplate; // eax
    sithThing *pSpawned; // eax

    if ( sithTime_curMs < pPlayerInfo->lastSparkSpawnMs + 200 )
        return;

    if ( sparkType == SPARKTYPE_BLOOD )
    {
        pTemplate = pPlayerInfo->blood_sparks;
    }
    else if ( sparkType == SPARKTYPE_SABER )
    {
        pTemplate = pPlayerInfo->saber_sparks;
    }
    else // SPARKTYPE_WALL
    {
        pTemplate = pPlayerInfo->wall_sparks;
    }
    if ( pTemplate )
    {
        pSpawned = sithThing_Create(pTemplate, pPos, &rdroid_identMatrix34, psector, 0);
        if ( pSpawned )
        {
            pSpawned->prev_thing = pPlayerInfo->actorThing;
            pPlayerInfo->lastSparkSpawnMs = sithTime_curMs;
            pSpawned->child_signature = pPlayerInfo->actorThing->signature;
        }
    }
}

// MOTS altered
void jkSaber_Enable(sithThing *a1, float a2, float a3, float a4)
{
    if (!a1 || !a1->playerInfo) return; // MOTS added

    a1->playerInfo->saberCollideInfo.damage = a2;
    a1->playerInfo->saberCollideInfo.field_1AC = a3;
    a1->playerInfo->saberCollideInfo.field_1B0 = a4;
    a1->playerInfo->saberCollideInfo.field_1A4 = 1;
    a1->playerInfo->saberCollideInfo.numDamagedThings = 0;
    a1->playerInfo->saberCollideInfo.numDamagedSurfaces = 0;

    _memset(a1->playerInfo->saberCollideInfo.damagedThings, 0, sizeof(a1->playerInfo->saberCollideInfo.damagedThings));
    _memset(a1->playerInfo->saberCollideInfo.damagedSurfaces, 0, sizeof(a1->playerInfo->saberCollideInfo.damagedSurfaces));
    
    a1->playerInfo->lastSparkSpawnMs = 0;

#ifdef JKM_SABER
    a1->playerInfo->jkmUnk1 = 0; // MOTS added
#endif
}

// MOTS altered
void jkSaber_Disable(sithThing *player)
{
    //MOTS added:
    if (!player || !player->playerInfo) return;

    player->playerInfo->saberCollideInfo.field_1A4 = 0;
#ifdef JKM_SABER
    player->playerInfo->jkmUnk1 = 0; // MOTS added
#endif
}