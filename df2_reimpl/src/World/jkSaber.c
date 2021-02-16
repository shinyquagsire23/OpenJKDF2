#include "jkSaber.h"

#include "jkPlayer.h"
#include "Cog/sithCog.h"
#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithAnimclass.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithTime.h"
#include "Engine/sithSurface.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithPuppet.h"
#include "World/sithSector.h"
#include "World/sithUnk3.h"
#include "Main/jkMain.h"
#include "Main/jkSmack.h"
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
    rdModel3* model = thing->model3;
    if ( model )
    {
        if ( !(bShowInvisibleThings & 0xF) )
            model->field_64 = 0.0;
        model->field_64 = (_frand() - 0.80000001) * 80.0 + model->field_64;
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
        //if (thing->jkFlags & JKFLAG_DUALSABERS)
        //    rdThing_Draw(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[2]); // K_Lhand
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
    
    if (thing->thingflags & SITH_TF_DEAD || thing->thingType == THINGTYPE_CORPSE)
    {
        thing->jkFlags |= JKFLAG_SABERRETRACT;
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
        if ( newLength < 0.0 || deltaLen < 0.0 ) // ? verify, IDA crapped out on this comparison
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
    sithUnk3SearchEntry *searchResult; // edi
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
    if ( player->jkFlags & 0x40 )
    {
        player->jkFlags &= ~0x40;
        playerInfo->numDamagedThings = 0;
        playerInfo->numDamagedSurfaces = 0;
    }
    if ( !(player->jkFlags & JKFLAG_SABERNODAMAGE) )
        return;
    if ( !playerInfo->field_1A4 )
        return;
    sector = sithUnk3_GetSectorLookAt(player->sector, &player->position, &jointMat.scale, 0.0);
    if ( !sector )
        return;
    sithUnk3_SearchRadiusForThings(sector, player, &jointMat.scale, &jointMat.lvec, playerInfo->field_1AC, 0.0, 0);

    while ( 1 )
    {
        searchResult = sithUnk3_NextSearchResult();
        if ( !searchResult )
            break;
    
        if ( searchResult->collideType & 0x20 )
        {
            sector = searchResult->surface->adjoin->sector;
        }
        else if ( searchResult->collideType & 1 )
        {
            resultThing = searchResult->receiver;
    
            // TODO is this a matrix function
            a2a.x = searchResult->distance * jointMat.lvec.x + jointMat.scale.x;
            a2a.y = searchResult->distance * jointMat.lvec.y + jointMat.scale.y;
            a2a.z = searchResult->distance * jointMat.lvec.z + jointMat.scale.z;
            if ( resultThing->thingType == THINGTYPE_ITEM || resultThing->thingType == THINGTYPE_EXPLOSION || resultThing->thingType == THINGTYPE_PARTICLE )
            {
                continue;
            }
            if (resultThing->actorParams.typeflags & 0x100 
                || resultThing->thingType != THINGTYPE_ACTOR && resultThing->thingType != THINGTYPE_PLAYER )
            {
                if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->wall_sparks)
                {
                    // TODO is this inlined?
                    sithThing* actorThing = sithThing_SpawnThingInSector(playerInfo->wall_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
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
            
            if ( resultThing->thingType != THINGTYPE_ACTOR 
                 && resultThing->thingType != THINGTYPE_PLAYER 
                 || !(resultThing->actorParams.typeflags & 0x2000) )
            {
                if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->blood_sparks)
                {
                    sithThing* actorThing = sithThing_SpawnThingInSector(playerInfo->blood_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                    if ( actorThing )
                    {
                        actorThing->prev_thing = playerInfo->actorThing;
                        actorThing->child_signature = playerInfo->actorThing->signature;
                        playerInfo->lastSparkSpawnMs = sithTime_curMs;
                    }
                }

                sithThing_Damage(searchResult->receiver, player, playerInfo->damage, SITH_DT_SABER);
                playerInfo->damagedThings[playerInfo->numDamagedThings++] = searchResult->receiver;
                break;
            }
            
            // TODO is this a vector func?
            rdVector_Sub3(&a1, &a2a, &resultThing->position);
            rdVector_Normalize3Acc(&a1);
            rdMatrix_Copy34(&tmpMat, &resultThing->lookOrientation);
            if ( resultThing->thingType == THINGTYPE_ACTOR || resultThing->thingType == THINGTYPE_PLAYER )
                rdMatrix_PreRotate34(&tmpMat, &resultThing->actorParams.eyePYR);
                
            // TODO: is this a vector func?
            rdVector3 v52 = tmpMat.lvec;
            rdVector_Normalize3Acc(&v52);
            if ( rdVector_Dot3(&v52, &a1) >= resultThing->actorParams.fov
              && (_frand() < resultThing->actorParams.chance) )
            {
                if (!(player->actorParams.typeflags & THING_TYPEFLAGS_80)) // verify
                {
                    sithSoundClass_ThingPlaySoundclass(player, SITH_SC_DEFLECTED);

                    if ( _frand() >= 0.5 )
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK2, 0);
                    else
                        sithPuppet_PlayMode(resultThing, SITH_ANIM_BLOCK, 0);

                    if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 && playerInfo->saber_sparks)
                    {
                        sithThing* actorThing = sithThing_SpawnThingInSector(playerInfo->saber_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
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
                sithThing* actorThing = sithThing_SpawnThingInSector(playerInfo->blood_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
                if ( actorThing )
                {
                    actorThing->prev_thing = playerInfo->actorThing;
                    playerInfo->lastSparkSpawnMs = sithTime_curMs;
                    actorThing->child_signature = playerInfo->actorThing->signature;
                }
            }

            sithThing_Damage(resultThing, player, playerInfo->damage, SITH_DT_SABER);
            playerInfo->damagedThings[playerInfo->numDamagedThings++] = searchResult->receiver;            
            break;
        }
        else if ( searchResult->collideType & 2 )
        {
            a2a.x = (searchResult->distance - 0.001) * jointMat.lvec.x + jointMat.scale.x;
            a2a.y = (searchResult->distance - 0.001) * jointMat.lvec.y + jointMat.scale.y;
            a2a.z = (searchResult->distance - 0.001) * jointMat.lvec.z + jointMat.scale.z;
            if ( sithTime_curMs >= playerInfo->lastSparkSpawnMs + 200 )
            {
                if ( playerInfo->wall_sparks )
                {
                    sithThing* actorThing = sithThing_SpawnThingInSector(playerInfo->wall_sparks, &a2a, &rdroid_identMatrix34, sector, 0);
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
                    sithSurface_SendDamageToThing(searchResult->surface, player, playerInfo->damage, SITH_DT_SABER);
                    playerInfo->damagedSurfaces[playerInfo->numDamagedSurfaces++] = searchResult->surface;
                }
            }
            break;
        }
    }
    
    sithUnk3_SearchClose();
    return;
}
