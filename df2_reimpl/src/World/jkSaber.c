#include "jkSaber.h"

#include "jkPlayer.h"
#include "Cog/sithCog.h"
#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithTime.h"
#include "Engine/sithSurface.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithMulti.h"
#include "Engine/sithSave.h"
#include "World/sithSector.h"
#include "World/sithUnk3.h"
#include "Main/jkMain.h"
#include "Main/jkSmack.h"
#include "Main/jkEpisode.h"
#include "Main/jkRes.h"
#include "Gui/jkGUINet.h"
#include "jk.h"

#define JKSABER_EXTENDTIME (0.3000000)

#define jkSaber_cogMsg_HandleJKEnableSaber ((void*)jkSaber_cogMsg_HandleJKEnableSaber_ADDR)
#define jkSaber_cogMsg_HandleSetSaberInfo2 ((void*)jkSaber_cogMsg_HandleSetSaberInfo2_ADDR)
#define jkSaber_cogMsg_HandleJKSetWeaponMesh ((void*)jkSaber_cogMsg_HandleJKSetWeaponMesh_ADDR)
#define jkSaber_cogMsg_Handlex32 ((void*)jkSaber_cogMsg_Handlex32_ADDR)
#define jkSaber_cogMsg_Handlex33 ((void*)jkSaber_cogMsg_Handlex33_ADDR)
#define jkSaber_cogMsg_HandleHudTarget ((void*)jkSaber_cogMsg_HandleHudTarget_ADDR)
#define jkSaber_cogMsg_Handlex36_setwaggle ((void*)jkSaber_cogMsg_Handlex36_setwaggle_ADDR)
#define jkSaber_cogMsg_HandleJKPrintUniString ((void*)jkSaber_cogMsg_HandleJKPrintUniString_ADDR)
#define jkSaber_cogMsg_HandleEndLevel ((void*)jkSaber_cogMsg_HandleEndLevel_ADDR)
#define jkSaber_cogMsg_HandleSetSaberInfo ((void*)jkSaber_cogMsg_HandleSetSaberInfo_ADDR)
#define jkSaber_cogMsg_HandleSetTeam ((void*)jkSaber_cogMsg_HandleSetTeam_ADDR)
#define jkSaber_idk4 ((void*)jkSaber_idk4_ADDR)

int jkSaber_Startup()
{
    sithCogVm_SetMsgFunc(COGMSG_JKENABLESABER, jkSaber_cogMsg_HandleJKEnableSaber);
    sithCogVm_SetMsgFunc(COGMSG_SABERINFO3, jkSaber_cogMsg_HandleSetSaberInfo2);
    sithCogVm_SetMsgFunc(COGMSG_JKSETWEAPONMESH, jkSaber_cogMsg_HandleJKSetWeaponMesh);
    sithCogVm_SetMsgFunc(COGMSG_ID_32, jkSaber_cogMsg_Handlex32);
    sithCogVm_SetMsgFunc(COGMSG_ID_33, jkSaber_cogMsg_Handlex33);
    sithCogVm_SetMsgFunc(COGMSG_HUDTARGET, jkSaber_cogMsg_HandleHudTarget);
    sithCogVm_SetMsgFunc(COGMSG_ID_36, jkSaber_cogMsg_Handlex36_setwaggle);
    sithCogVm_SetMsgFunc(COGMSG_JKPRINTUNISTRING, jkSaber_cogMsg_HandleJKPrintUniString);
    sithCogVm_SetMsgFunc(COGMSG_ENDLEVEL, jkSaber_cogMsg_HandleEndLevel);
    sithCogVm_SetMsgFunc(COGMSG_SABERINFO1, jkSaber_cogMsg_HandleSetSaberInfo);
    sithCogVm_SetMsgFunc(COGMSG_SABERINFO2, jkSaber_cogMsg_HandleSetSaberInfo);
    sithCogVm_SetMsgFunc(COGMSG_SETTEAM, jkSaber_cogMsg_HandleSetTeam);
    sithCogVm_SetMsgFunc(COGMSG_JOINING, jkGuiNet_CogMsgHandleJoining);
    sithSave_Setidk(jkSaber_playerconfig_idksync, jkSaber_player_thingsidkfunc, jkSaber_nullsub_2, jkSaber_Write, jkSaber_Load);
    sithMulti_SetHandleridk(jkSaber_idk4);
    return 1;
}

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
    rdPolyLine* line = thing->polyline;
    if ( line )
    {
        if ( !(bShowInvisibleThings & 0xF) )
            line->edgeFace.clipIdk.y = 0.0;
        line->edgeFace.clipIdk.y = (_frand() - 0.80000001) * 80.0 + line->edgeFace.clipIdk.y;
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

int jkSaber_Load()
{
    char a1[32]; // [esp+0h] [ebp-20h] BYREF

    stdConffile_Read(a1, 32);
    jkRes_LoadGob(a1);
    return stdConffile_Read(&jkEpisode_mLoad.field_8, 4);
}

int jkSaber_Write()
{
    stdConffile_Write(jkRes_episodeGobName, 32);
    return stdConffile_Write((const char*)&jkEpisode_mLoad.field_8, 4);
}

void jkSaber_player_thingsidkfunc()
{
    int v0; // eax

    v0 = jkSmack_GetCurrentGuiState();
    if ( v0 == 6 || v0 == 5 )
        jkPlayer_Shutdown();
}

void jkSaber_nullsub_2()
{
}

void jkSaber_Disable(sithThing *player)
{
    player->playerInfo->field_1A4 = 0;
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

void jkSaber_playerconfig_idksync()
{
    jkSaber_cogMsg_SendSetSaberInfo2(g_localPlayerThing);
    jkSaber_cogMsg_SendSetSaberInfo(g_localPlayerThing);
    jkSaber_cogMsg_Sendx32(&playerThings[playerThingIdx]);


    {
        NETMSG_START;

        NETMSG_PUSHVEC3(jkPlayer_waggleVec);
        NETMSG_PUSHF32(jkPlayer_waggleMag);

        NETMSG_END(COGMSG_ID_36);

        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 4, 1);
    }

    for (int i = 0; i < jkPlayer_numOtherThings; i++)
    {
        jkSaber_cogMsg_SendSetSaberInfo2(jkPlayer_otherThings[i].actorThing);
    }
    
    {
        NETMSG_START;

        NETMSG_PUSHU16(jkHud_bHasTarget);

        if ( jkHud_pTargetThing ) {
            NETMSG_PUSHU16(jkHud_pTargetThing->thingIdx);
        }
        else {
            NETMSG_PUSHU16(-1);
        }

        NETMSG_PUSHU16(jkHud_targetRed);
        NETMSG_PUSHU16(jkHud_targetBlue);
        NETMSG_PUSHU16(jkHud_targetGreen);
        
        NETMSG_END(COGMSG_HUDTARGET);
        
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 4, 1);
    }
}

void jkSaber_cogMsg_SendSetSaberInfo2(sithThing *thing)
{
    if ( thing->playerInfo )
    {
        NETMSG_START;

        NETMSG_PUSHU16(thing->thingType != THINGTYPE_PLAYER);
        NETMSG_PUSHU16((thing->thingType != THINGTYPE_PLAYER) ? thing->playerInfo - jkPlayer_otherThings : thing->playerInfo - playerThings);
        NETMSG_PUSHU32(thing->thing_id);
        if ( thing->playerInfo->rd_thing.model3 ) {
            NETMSG_PUSHU32(thing->playerInfo->rd_thing.model3->id);
        }
        else {
            NETMSG_PUSHU32(-1);
        }
        
        NETMSG_PUSHU16(thing->playerInfo->maxTwinkles);
        NETMSG_PUSHU16(thing->playerInfo->twinkleSpawnRate);
        NETMSG_PUSHF32(thing->playerInfo->length);
        if ( thing->playerInfo->polylineThing.polyline )
        {
            NETMSG_PUSHF32(thing->playerInfo->polylineThing.polyline->baseRadius);
            NETMSG_PUSHF32(thing->playerInfo->polylineThing.polyline->tipRadius);
            NETMSG_PUSHSTR(thing->playerInfo->polylineThing.polyline->edgeFace.material->mat_fpath, 0x20);
            NETMSG_PUSHSTR(thing->playerInfo->polylineThing.polyline->tipFace.material->mat_fpath, 0x20);
            NETMSG_PUSHF32(thing->playerInfo->polylineThing.polyline->length);
        }
        else
        {
            NETMSG_PUSHU32(0);
        }

        if ( thing->playerInfo->wall_sparks ) {
            NETMSG_PUSHU32(thing->playerInfo->wall_sparks->thingIdx);
        }
        else {
            NETMSG_PUSHU32(-1);
        }

        if ( thing->playerInfo->blood_sparks ) {
            NETMSG_PUSHU32(thing->playerInfo->blood_sparks->thingIdx);
        }
        else {
            NETMSG_PUSHU32(-1);
        }

        if ( thing->playerInfo->saber_sparks ) {
            NETMSG_PUSHU32(thing->playerInfo->saber_sparks->thingIdx);
        }
        else {
            NETMSG_PUSHU32(-1);
        }

        NETMSG_PUSHU32(thing->playerInfo->field_21C);
        NETMSG_PUSHU32(thing->playerInfo->shields);
        NETMSG_PUSHU32(thing->playerInfo->field_224);
        
        NETMSG_END(COGMSG_SABERINFO3);
        
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 255, 1);
    }
}

void jkSaber_cogMsg_SendSetSaberInfo(sithThing *thing)
{
    NETMSG_START;

    NETMSG_PUSHU32(thing->thing_id);
    NETMSG_PUSHSTR(thing->rdthing.model3->filename, 0x20);
    NETMSG_PUSHSTR(thing->soundclass->snd_fname, 0x20);
    NETMSG_PUSHSTR(thing->playerInfo->polyline.edgeFace.material->mat_fpath, 0x20);
    NETMSG_PUSHSTR(thing->playerInfo->polyline.tipFace.material->mat_fpath, 0x20);

    NETMSG_END(COGMSG_SABERINFO2);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 255, 1);
}

void jkSaber_cogMsg_Sendx32(jkPlayerInfo *playerInfo)
{
    rdPuppetTrack *trackIter; // ecx
    
    NETMSG_START;

    NETMSG_PUSHU32(playerInfo - playerThings);

    rdModel3* model3 = playerInfo->povModel.model3;
    if ( model3 ) {
        NETMSG_PUSHU32(model3->id);
    }
    else {
        NETMSG_PUSHU32(-1);
    }

    rdPuppet* puppet = playerInfo->povModel.puppet;
    if ( puppet )
    {
        trackIter = puppet->tracks;

        for (int i = 0; i < 4; i++)
        {
            NETMSG_PUSHU32(trackIter->status);
            if ( trackIter->status )
            {
                NETMSG_PUSHU32(trackIter->keyframe->id);
                NETMSG_PUSHU32(trackIter->field_4);
                NETMSG_PUSHU16(trackIter->lowPri);
                NETMSG_PUSHU16(trackIter->highPri);
                NETMSG_PUSHF32(trackIter->speed);
                NETMSG_PUSHF32(trackIter->playSpeed);
                NETMSG_PUSHF32(trackIter->field_120);
                NETMSG_PUSHF32(trackIter->field_124);
            }
            ++trackIter;
        }
    }

    NETMSG_END(COGMSG_ID_32);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 255, 1);
}
