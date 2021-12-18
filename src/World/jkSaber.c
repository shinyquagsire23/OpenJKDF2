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
#include "Dss/sithGamesave.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithModel.h"
#include "Engine/sithKeyFrame.h"
#include "World/sithSector.h"
#include "Engine/sithCollision.h"
#include "Main/jkMain.h"
#include "Main/jkSmack.h"
#include "Main/jkEpisode.h"
#include "Main/jkRes.h"
#include "Gui/jkGUINet.h"
#include "jk.h"

#define JKSABER_EXTENDTIME (0.3000000)

#define jkSaber_cogMsg_HandleJKEnableSaber ((void*)jkSaber_cogMsg_HandleJKEnableSaber_ADDR)
#define jkSaber_cogMsg_HandleJKSetWeaponMesh ((void*)jkSaber_cogMsg_HandleJKSetWeaponMesh_ADDR)
#define jkSaber_cogMsg_Handlex33 ((void*)jkSaber_cogMsg_Handlex33_ADDR)
#define jkSaber_cogMsg_HandleJKPrintUniString ((void*)jkSaber_cogMsg_HandleJKPrintUniString_ADDR)
#define jkSaber_cogMsg_HandleEndLevel ((void*)jkSaber_cogMsg_HandleEndLevel_ADDR)
#define jkSaber_idk4 ((void*)jkSaber_idk4_ADDR)

const char* jkSaber_aKyTeamModels[5] = {
    "ky.3do",
    "kyX0.3do",
    "kyU0.3do",
    "kyV0.3do",
    "kyT0.3do",
};


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
    sithGamesave_Setidk(jkSaber_playerconfig_idksync, jkSaber_player_thingsidkfunc, jkSaber_nullsub_2, jkSaber_Write, jkSaber_Load);
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

#ifdef DEBUG_QOL_CHEATS
    if (thing == g_localPlayerThing) {
        material_tip_fname = "saberpurple0.mat";
        material_side_fname = "saberpurple1.mat";
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
    
    if (thing->thingflags & SITH_TF_DEAD || thing->type == SITH_THING_CORPSE)
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
    sector = sithCollision_GetSectorLookAt(player->sector, &player->position, &jointMat.scale, 0.0);
    if ( !sector )
        return;
    sithCollision_SearchRadiusForThings(sector, player, &jointMat.scale, &jointMat.lvec, playerInfo->field_1AC, 0.0, 0);

    while ( 1 )
    {
        searchResult = sithCollision_NextSearchResult();
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
            if ( resultThing->type == SITH_THING_ITEM || resultThing->type == SITH_THING_EXPLOSION || resultThing->type == SITH_THING_PARTICLE )
            {
                continue;
            }
            if (resultThing->actorParams.typeflags & 0x100 
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
                 || !(resultThing->actorParams.typeflags & 0x2000) )
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

                sithThing_Damage(searchResult->receiver, player, playerInfo->damage, SITH_DT_SABER);
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
                if (!(player->actorParams.typeflags & THING_TYPEFLAGS_80)) // verify
                {
                    sithSoundClass_ThingPlaySoundclass(player, SITH_SC_DEFLECTED);

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
                    sithSurface_SendDamageToThing(searchResult->surface, player, playerInfo->damage, SITH_DT_SABER);
                    playerInfo->damagedSurfaces[playerInfo->numDamagedSurfaces++] = searchResult->surface;
                }
            }
            break;
        }
    }
    
    sithCollision_SearchClose();
    return;
}

void jkSaber_Load()
{
    char a1[32]; // [esp+0h] [ebp-20h] BYREF

    stdConffile_Read(a1, 32);
    jkRes_LoadGob(a1);
    stdConffile_Read(&jkEpisode_mLoad.field_8, 4);
}

void jkSaber_Write()
{
    stdConffile_Write(jkRes_episodeGobName, 32);
    stdConffile_Write((const char*)&jkEpisode_mLoad.field_8, 4);
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

        NETMSG_PUSHU16(thing->type != SITH_THING_PLAYER);
        NETMSG_PUSHU16((thing->type != SITH_THING_PLAYER) ? thing->playerInfo - jkPlayer_otherThings : thing->playerInfo - playerThings);
        NETMSG_PUSHU32(thing->thing_id);
        if ( thing->playerInfo->rd_thing.model3 ) {
            NETMSG_PUSHS32(thing->playerInfo->rd_thing.model3->id);
        }
        else {
            NETMSG_PUSHS32(-1);
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
            NETMSG_PUSHF32(0.0);
        }

        if ( thing->playerInfo->wall_sparks ) {
            NETMSG_PUSHS32(thing->playerInfo->wall_sparks->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        if ( thing->playerInfo->blood_sparks ) {
            NETMSG_PUSHS32(thing->playerInfo->blood_sparks->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        if ( thing->playerInfo->saber_sparks ) {
            NETMSG_PUSHS32(thing->playerInfo->saber_sparks->thingIdx);
        }
        else {
            NETMSG_PUSHS32(-1);
        }

        NETMSG_PUSHU32(thing->playerInfo->field_21C);
        NETMSG_PUSHU32(thing->playerInfo->shields);
        NETMSG_PUSHU32(thing->playerInfo->field_224);
        
        NETMSG_END(COGMSG_SABERINFO3);
        
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 255, 1);
    }
}

int jkSaber_cogMsg_HandleSetSaberInfo2(sithCogMsg *msg)
{
    char material_tip_fname[32];
    char material_side_fname[32];
    
    jkPlayerInfo *playerInfo = NULL;
    
    NETMSG_IN_START(msg);

    int isNotPlayer = NETMSG_POPU16();
    int playerInfoIdx = NETMSG_POPS16();
    if ( isNotPlayer )
        playerInfo = &jkPlayer_otherThings[playerInfoIdx];
    else
        playerInfo = &playerThings[playerInfoIdx];

    sithThing* thing = sithThing_GetById(NETMSG_POPS32());
    if (!thing)
        return 0;

    int modelIdx = NETMSG_POPS32();
    thing->playerInfo = playerInfo;
    playerInfo->actorThing = thing;
    rdModel3* model = sithModel_GetByIdx(modelIdx);
    if (model)
    {
        rdThing_NewEntry(&playerInfo->rd_thing, 0);
        rdThing_SetModel3(&playerInfo->rd_thing, model);
    }

    playerInfo->maxTwinkles = NETMSG_POPS16();
    playerInfo->twinkleSpawnRate = NETMSG_POPS16();
    playerInfo->length = NETMSG_POPF32();
    float baseRadius = NETMSG_POPF32();
    if ( baseRadius != 0.0 )
    {
        float tipRadius = NETMSG_POPF32();
        
        NETMSG_POPSTR(material_side_fname, 0x20);
        NETMSG_POPSTR(material_tip_fname, 0x20);

        jkSaber_InitializeSaberInfo(thing, material_side_fname, material_tip_fname, baseRadius, tipRadius, playerInfo->length, 0, 0, 0);
        thing->playerInfo->polylineThing.polyline->length = NETMSG_POPF32();
    }
    playerInfo->wall_sparks = sithTemplate_GetEntryByIdx(NETMSG_POPS32());
    playerInfo->blood_sparks = sithTemplate_GetEntryByIdx(NETMSG_POPS32());
    playerInfo->saber_sparks = sithTemplate_GetEntryByIdx(NETMSG_POPS32());
    playerInfo->field_21C = NETMSG_POPU32();
    playerInfo->shields = NETMSG_POPU32();
    playerInfo->field_224 = NETMSG_POPU32();

    return 1;
}

void jkSaber_cogMsg_SendSetSaberInfo(sithThing *thing)
{
    NETMSG_START;

    NETMSG_PUSHS32(thing->thing_id);
    NETMSG_PUSHSTR(thing->rdthing.model3->filename, 0x20);
    NETMSG_PUSHSTR(thing->soundclass->snd_fname, 0x20);
    NETMSG_PUSHSTR(thing->playerInfo->polyline.edgeFace.material->mat_fpath, 0x20);
    NETMSG_PUSHSTR(thing->playerInfo->polyline.tipFace.material->mat_fpath, 0x20);

    NETMSG_END(COGMSG_SABERINFO2);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 255, 1);
}

int jkSaber_cogMsg_HandleSetSaberInfo(sithCogMsg *msg)
{
    sithPlayerInfo *v11; // [esp+10h] [ebp-88h]
    char model_3do_fname[32]; // [esp+18h] [ebp-80h] BYREF
    char v14[32]; // [esp+38h] [ebp-60h] BYREF
    
    char material_side_fname[32]; // [esp+58h] [ebp-40h] BYREF
    char material_tip_fname[32]; // [esp+78h] [ebp-20h] BYREF

    NETMSG_IN_START(msg);

    if ( msg->netMsg.cogMsgId == COGMSG_SABERINFO1 && !sithNet_isServer )
        return 1;

    sithThing* v2 = sithThing_GetById(NETMSG_POPS32());
    if ( !v2 )
        return 0;
    v11 = v2->actorParams.playerinfo;
    if ( !v11 || !v2->playerInfo )
        return 0;
    NETMSG_POPSTR(model_3do_fname, 0x20);
    NETMSG_POPSTR(v14, 0x20);
    NETMSG_POPSTR(material_side_fname, 0x20);
    NETMSG_POPSTR(material_tip_fname, 0x20);

    if ( msg->netMsg.cogMsgId == COGMSG_SABERINFO1 )
    {
        if ( (sithNet_MultiModeFlags & 0x20) != 0 )
            return 1;
        if ( (sithNet_MultiModeFlags & 0x100) != 0 )
        {
            _strncpy(model_3do_fname, jkSaber_aKyTeamModels[v11->teamNum], 0x1Fu);
            model_3do_fname[31] = 0;
            _strncpy(v14, "ky.snd", 0x1Fu);
            v14[31] = 0;
        }
    }
    rdModel3* v5 = sithModel_LoadEntry(model_3do_fname, 1);
    if ( !v5 )
        return 1;
    sithThing_SetNewModel(v2, v5);
    sithSoundClass* v6 = sithSoundClass_LoadFile(v14);
    if ( v6 )
        sithSoundClass_SetThingSoundClass(v2, v6);
    sithThing* v10 = sithTemplate_GetEntryByName("+ssparks_saber");
    sithThing* v9 = sithTemplate_GetEntryByName("+ssparks_blood");
    sithThing* v7 = sithTemplate_GetEntryByName("+ssparks_wall");
    jkSaber_InitializeSaberInfo(v2, material_side_fname, material_tip_fname, 0.0031999999, 0.0018, 0.12, v7, v9, v10);

    if ( sithNet_isServer )
    {
        if ( msg->netMsg.cogMsgId == COGMSG_SABERINFO1 )
        {
            jkSaber_cogMsg_SendSetSaberInfo(v2);
        }
    }
    return 1;
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
                NETMSG_PUSHS32(trackIter->keyframe->id);
                NETMSG_PUSHU32(trackIter->field_4);
                NETMSG_PUSHS16(trackIter->lowPri);
                NETMSG_PUSHS16(trackIter->highPri);
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

int jkSaber_cogMsg_Handlex32(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    int v1 = NETMSG_POPS32();
    if ( v1 > jkPlayer_numThings )
        return 0;

    jkPlayerInfo* playerInfo = &playerThings[v1];
    rdModel3* model3 = sithModel_GetByIdx(NETMSG_POPS32());
    if (!model3)
        return 1;


    jkPlayer_SetPovModel(playerInfo, model3);
    
    // Added: puppet nullptr check
    rdPuppet* puppet = playerInfo->povModel.puppet;
    if ( puppet )
    {
        rdPuppetTrack* trackIter = puppet->tracks;

        for (int i = 0; i < 4; i++)
        {
            trackIter->status = NETMSG_POPS32();
            if ( trackIter->status )
            {
                trackIter->keyframe = sithKeyFrame_GetByIdx(NETMSG_POPS32());
                trackIter->field_4 = NETMSG_POPS32();
                trackIter->lowPri = (int)NETMSG_POPS16();
                trackIter->highPri = (int)NETMSG_POPS16();
                trackIter->speed = NETMSG_POPF32();
                trackIter->playSpeed = NETMSG_POPF32();
                trackIter->field_120 = NETMSG_POPF32();
                trackIter->field_124 = NETMSG_POPF32();
            }
            ++trackIter;
        }
    }

    return 1;
}

int jkSaber_cogMsg_Handlex36_setwaggle(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    jkPlayer_waggleVec = NETMSG_POPVEC3();
    jkPlayer_waggleMag = NETMSG_POPF32();
    return 1;
}

int jkSaber_cogMsg_HandleHudTarget(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    jkHud_bHasTarget = NETMSG_POPS16();
    sithThing* v1 = sithThing_GetThingByIdx(NETMSG_POPS16());
    jkHud_pTargetThing = v1;
    if ( !v1 )
        jkHud_bHasTarget = 0;

    jkHud_targetRed = NETMSG_POPS16();
    jkHud_targetBlue = NETMSG_POPS16();
    jkHud_targetGreen = NETMSG_POPS16();
    return 1;
}


void jkSaber_cogMsg_SendSetTeam(int16_t teamNum)
{
    NETMSG_START;

    NETMSG_PUSHS16(playerThingIdx);
    NETMSG_PUSHS16(teamNum);

    NETMSG_END(COGMSG_SETTEAM);
    
    if ( sithNet_isServer )
        jkSaber_cogMsg_HandleSetTeam(&sithCogVm_netMsgTmp);
    else
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sithNet_dword_8C4BA4, 255, 1);
}

int jkSaber_cogMsg_HandleSetTeam(sithCogMsg *pMsg)
{
    unsigned int playerIdx; // edx
    unsigned int teamNum; // ecx
    unsigned int v4; // esi
    rdModel3 *v5; // eax

    NETMSG_IN_START(pMsg);

    playerIdx = NETMSG_POPS16();
    teamNum = NETMSG_POPS16();

    if ( !sithNet_isServer || playerIdx > jkPlayer_maxPlayers - 1 )
        return 0;

    if ( !teamNum || teamNum > 4 )
        return 0;

    if ( (sithNet_MultiModeFlags & 1) == 0 || (sithNet_MultiModeFlags & 0x100) == 0 )
        return 1;

    jkPlayer_playerInfos[playerIdx].teamNum = teamNum;
    if ( jkPlayer_playerInfos[playerIdx].playerThing )
    {
        v5 = sithModel_LoadEntry(&jkSaber_aKyTeamModels[32 * teamNum], 1);
        if ( v5 )
        {
            sithThing_SetNewModel(jkPlayer_playerInfos[playerIdx].playerThing, v5);
            jkSaber_cogMsg_SendSetSaberInfo(jkPlayer_playerInfos[playerIdx].playerThing);
        }
    }

    sithMulti_SyncScores();
    return 1;
}