#include "jkDSS.h"

#include "Cog/sithCog.h"
#include "Dss/sithMulti.h"
#include "Gameplay/jkSaber.h"
#include "World/jkPlayer.h"
#include "Gameplay/sithPlayer.h"
#include "General/stdString.h"
#include "General/stdStrTable.h"
#include "Main/jkDev.h"
#include "Main/jkEpisode.h"
#include "Main/jkRes.h"
#include "Main/jkStrings.h"
#include "World/sithTemplate.h"
#include "World/sithModel.h"
#include "World/sithSoundClass.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithPuppet.h"
#include "Devices/sithComm.h"
#include "Gui/jkGUIMultiplayer.h"
#include "Dss/sithGamesave.h"
#include "Main/jkSmack.h"
#include "jk.h"

const char* jkDSS_aKyTeamModels[5] = {
    "ky.3do",
    "kyX0.3do",
    "kyU0.3do",
    "kyV0.3do",
    "kyT0.3do",
};

int jkDSS_Startup()
{
    sithComm_SetMsgFunc(DSS_JKENABLESABER, jkDSS_ProcessJKEnableSaber);
    sithComm_SetMsgFunc(DSS_SABERINFO3, jkDSS_ProcessSetSaberInfo2);
    sithComm_SetMsgFunc(DSS_JKSETWEAPONMESH, jkDSS_ProcessJKSetWeaponMesh);
    sithComm_SetMsgFunc(DSS_ID_32, jkDSS_Processx32);
    sithComm_SetMsgFunc(DSS_ID_33, jkDSS_Processx33);
    sithComm_SetMsgFunc(DSS_HUDTARGET, jkDSS_ProcessHudTarget);
    sithComm_SetMsgFunc(DSS_ID_36, jkDSS_Processx36_setwaggle);
    sithComm_SetMsgFunc(DSS_JKPRINTUNISTRING, jkDSS_ProcessJKPrintUniString);
    sithComm_SetMsgFunc(DSS_ENDLEVEL, jkDSS_ProcessEndLevel);
    sithComm_SetMsgFunc(DSS_SABERINFO1, jkDSS_ProcessSetSaberInfo);
    sithComm_SetMsgFunc(DSS_SABERINFO2, jkDSS_ProcessSetSaberInfo);
    sithComm_SetMsgFunc(DSS_SETTEAM, jkDSS_ProcessSetTeam);
    sithComm_SetMsgFunc(DSS_JOINING, jkGuiMultiplayer_CogMsgHandleJoining);
    sithGamesave_Setidk(jkDSS_playerconfig_idksync, jkDSS_player_thingsidkfunc, jkDSS_nullsub_2, jkDSS_Write, jkDSS_Load);
    sithMulti_SetHandleridk(jkDSS_idk4);

    // MOTS added:
    //sithWorld_unk_func(jkPlayer_FUN_004069f0);
    //sithEvent_RegisterFunc(5,jkDSS_JKM1,0,2);
    return 1;
}

void jkDSS_Shutdown()
{
    ;
}

// MOTS altered
int jkDSS_idk4()
{
    if ( sithPlayer_pLocalPlayerThing )
    {
        if ( sithNet_isServer )
        {
            if ( sithMulti_leaveJoinType )
            {
                sithComm_netMsgTmp.pktData[0] = jkEpisode_idk1(&jkEpisode_mLoad)->level;
                sithComm_netMsgTmp.netMsg.flag_maybe = 0;
                sithComm_netMsgTmp.netMsg.cogMsgId = DSS_ENDLEVEL;
                sithComm_netMsgTmp.netMsg.msg_size = 4;
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
                sithMulti_EndLevel(sithTime_curMs + MULTI_NEXTLEVEL_DELAY_MS, 1);
            }
        }
        jkDSS_SendSetSaberInfo2(sithPlayer_pLocalPlayerThing);
        jkDSS_SendSetSaberInfo(sithPlayer_pLocalPlayerThing);
        return 1;
    }
    return 0;
}

void jkDSS_playerconfig_idksync()
{
    jkDSS_SendSetSaberInfo2(sithPlayer_pLocalPlayerThing);
    jkDSS_SendSetSaberInfo(sithPlayer_pLocalPlayerThing);
    jkDSS_Sendx32(&playerThings[playerThingIdx]);
    jkDSS_Sendx36(); // MOTS didn't inline

    for (int i = 0; i < jkPlayer_numOtherThings; i++)
    {
        jkDSS_SendSetSaberInfo2(jkPlayer_otherThings[i].actorThing);
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
        
        NETMSG_END(DSS_HUDTARGET);
        
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 4, 1);
    }
}

void jkDSS_player_thingsidkfunc()
{
    int v0; // eax

    v0 = jkSmack_GetCurrentGuiState();
    if ( v0 == 6 || v0 == 5 )
        jkPlayer_Shutdown();
}

void jkDSS_nullsub_2()
{
}

void jkDSS_Write()
{
    stdConffile_Write(jkRes_episodeGobName, 32);
    stdConffile_Write((const char*)&jkEpisode_mLoad.field_8, 4);
}

void jkDSS_Load()
{
    char a1[32]; // [esp+0h] [ebp-20h] BYREF

    stdConffile_Read(a1, 32);
    jkRes_LoadGob(a1);
    stdConffile_Read(&jkEpisode_mLoad.field_8, 4);
}

int jkDSS_wrap_SendSaberInfo_alt()
{
    return jkDSS_SendSaberInfo_alt(
               sithPlayer_pLocalPlayerThing,
               jkGuiMultiplayer_mpcInfo.model,
               jkGuiMultiplayer_mpcInfo.soundClass,
               jkGuiMultiplayer_mpcInfo.sideMat,
               jkGuiMultiplayer_mpcInfo.tipMat);
}

int jkDSS_SendSaberInfo_alt(sithThing *pPlayerThing, char *pModelStr, char *pSoundclassStr, char *pSideMatStr, char *pTipMatStr)
{
    int result; // eax

    NETMSG_START;

    NETMSG_PUSHS32(pPlayerThing->thing_id);
    NETMSG_PUSHSTR(pModelStr, 0x20);
    NETMSG_PUSHSTR(pSoundclassStr, 0x20);
    NETMSG_PUSHSTR(pSideMatStr, 0x20);
    NETMSG_PUSHSTR(pTipMatStr, 0x20);

    NETMSG_END(DSS_SABERINFO1);

    if ( sithNet_isServer )
        result = jkDSS_ProcessSetSaberInfo(&sithComm_netMsgTmp);
    else
        result = sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithNet_serverNetId, 255, 1);
    return result;
}

// MOTS altered
void jkDSS_SendSetSaberInfo(sithThing *thing)
{
    NETMSG_START;

    NETMSG_PUSHS32(thing->thing_id);
    NETMSG_PUSHSTR(thing->rdthing.model3->filename, 0x20);
    NETMSG_PUSHSTR(thing->soundclass->snd_fname, 0x20);
    NETMSG_PUSHSTR(thing->playerInfo->polyline.edgeFace.material->mat_fpath, 0x20);
    NETMSG_PUSHSTR(thing->playerInfo->polyline.tipFace.material->mat_fpath, 0x20);

    NETMSG_END(DSS_SABERINFO2);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
}

// MOTS altered
int jkDSS_ProcessSetSaberInfo(sithCogMsg *msg)
{
    sithPlayerInfo *v11; // [esp+10h] [ebp-88h]
    char model_3do_fname[32]; // [esp+18h] [ebp-80h] BYREF
    char v14[32]; // [esp+38h] [ebp-60h] BYREF
    
    char material_side_fname[32]; // [esp+58h] [ebp-40h] BYREF
    char material_tip_fname[32]; // [esp+78h] [ebp-20h] BYREF

    NETMSG_IN_START(msg);

    if ( msg->netMsg.cogMsgId == DSS_SABERINFO1 && !sithNet_isServer )
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

    if ( msg->netMsg.cogMsgId == DSS_SABERINFO1 )
    {
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_20) != 0 )
            return 1;
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
        {
            _strncpy(model_3do_fname, jkDSS_aKyTeamModels[v11->teamNum], 0x1Fu);
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
        if ( msg->netMsg.cogMsgId == DSS_SABERINFO1 )
        {
            jkDSS_SendSetSaberInfo(v2);
        }
    }
    return 1;
}

void jkDSS_SendJKEnableSaber(sithThing *pPlayerThing)
{
    NETMSG_START;

    jkPlayerInfo* pPlayerInfo = pPlayerThing->playerInfo;

    NETMSG_PUSHS16(pPlayerThing->thingIdx);
    NETMSG_PUSHF32(pPlayerInfo->damage);
    NETMSG_PUSHF32(pPlayerInfo->field_1AC);
    NETMSG_PUSHF32(pPlayerInfo->field_1B0);

    NETMSG_END(DSS_JKENABLESABER);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 0);
}

int jkDSS_ProcessJKEnableSaber(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetThingByIdx(NETMSG_POPS16());
    if ( !pThing )
        return 0;
    if ( !pThing->playerInfo )
        return 0;
    int type = pThing->type;
    if ( type != SITH_THING_PLAYER && type != SITH_THING_ACTOR )
        return 0;

    float arg1 = NETMSG_POPF32();
    float arg2 = NETMSG_POPF32();
    float arg3 = NETMSG_POPF32();

    jkSaber_Enable(pThing, arg1, arg2, arg3);
    return 1;
}

// MOTS altered
void jkDSS_SendSetSaberInfo2(sithThing *thing)
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
        
        NETMSG_END(DSS_SABERINFO3);
        
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
    }
}

int jkDSS_ProcessSetSaberInfo2(sithCogMsg *msg)
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

// MOTS altered
void jkDSS_SendJKSetWeaponMesh(sithThing *pPlayerThing)
{
    NETMSG_START;

    NETMSG_PUSHS32(pPlayerThing->thing_id);

    jkPlayerInfo* pPlayerInfo = pPlayerThing->playerInfo;
    rdModel3* pModel3 = pPlayerInfo->rd_thing.model3;
    if ( pModel3 ) {
        NETMSG_PUSHS32(pModel3->id);
    }
    else {
        NETMSG_PUSHS32(-1);
    }

    NETMSG_PUSHS16(pPlayerInfo->maxTwinkles);
    NETMSG_PUSHS16(pPlayerInfo->twinkleSpawnRate);

    NETMSG_END(DSS_JKSETWEAPONMESH);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
}

int jkDSS_ProcessJKSetWeaponMesh(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);
    int arg0 = NETMSG_POPS32();
    int arg1 = NETMSG_POPS32();
    int16_t arg2 = NETMSG_POPS16();
    int16_t arg3 = NETMSG_POPS16();

    sithThing* pThing = sithThing_GetById(arg0);
    if ( pThing )
    {
        jkPlayerInfo* pPlayerInfo = pThing->playerInfo;
        if ( pPlayerInfo )
        {
            rdModel3* pModel = sithModel_GetByIdx(arg1);
            if ( pModel )
            {
                rdThing_NewEntry(&pPlayerInfo->rd_thing, 0);
                rdThing_SetModel3(&pPlayerInfo->rd_thing, pModel);
            }
            pPlayerInfo->maxTwinkles = arg2;
            pPlayerInfo->twinkleSpawnRate = arg3;
            return 1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

int jkDSS_SendHudTarget()
{
    NETMSG_START;

    NETMSG_PUSHS16(jkHud_bHasTarget);

    if ( jkHud_pTargetThing ) {
        NETMSG_PUSHS16(jkHud_pTargetThing->thingIdx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }

    NETMSG_PUSHS16(jkHud_targetRed);
    NETMSG_PUSHS16(jkHud_targetBlue);
    NETMSG_PUSHS16(jkHud_targetGreen);

    NETMSG_END(DSS_HUDTARGET);

    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 4, 1);
}

int jkDSS_ProcessHudTarget(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    jkHud_bHasTarget = NETMSG_POPS16();
    jkHud_pTargetThing = sithThing_GetThingByIdx(NETMSG_POPS16());
    if ( !jkHud_pTargetThing )
        jkHud_bHasTarget = 0;

    jkHud_targetRed = NETMSG_POPS16();
    jkHud_targetBlue = NETMSG_POPS16();
    jkHud_targetGreen = NETMSG_POPS16();
    return 1;
}

void jkDSS_Sendx32(jkPlayerInfo *playerInfo)
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

    NETMSG_END(DSS_ID_32);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
}

int jkDSS_Processx32(sithCogMsg *msg)
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

// Unused?
int jkDSS_Sendx33(sithThing* pThing, rdKeyframe* pKeyframe, int a3, int16_t a4)
{
    NETMSG_START;

    NETMSG_PUSHS16(pThing->thingIdx);
    NETMSG_PUSHS16(pKeyframe->id);
    NETMSG_PUSHS16(a4);
    NETMSG_PUSHS32(a3);

    NETMSG_END(DSS_ID_33);

    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 2, 1);
}

// Unused?
int jkDSS_Processx33(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);
    int16_t arg0 = NETMSG_POPS16();
    int16_t arg1 = NETMSG_POPS16();
    int16_t arg2 = NETMSG_POPS16();
    int arg3 = NETMSG_POPS32();

    if ( arg0 > sithWorld_pCurrentWorld->numThingsLoaded )
        return 0;
    sithThing* pThing = &sithWorld_pCurrentWorld->things[arg0];


    int type = pThing->type;
    if ( type != SITH_THING_ACTOR && type != SITH_THING_PLAYER )
        return 0;

    jkPlayerInfo* pPlayerInfo = pThing->playerInfo;
    if ( !pPlayerInfo )
        return 0;
    if ( !pPlayerInfo->povModel.puppet )
        return 0;

    rdKeyframe* pKeyframe = sithKeyFrame_GetByIdx(arg1);
    if ( !pKeyframe )
        return 0;
    sithPuppet_StartKey(
        pPlayerInfo->povModel.puppet,
        pKeyframe,
        arg2,
        arg2 + 2,
        arg3,
        0);
    return 1;
}

// MOTS altered
int jkDSS_Sendx36()
{
    NETMSG_START;

    NETMSG_PUSHVEC3(jkPlayer_waggleVec);
    NETMSG_PUSHF32(jkPlayer_waggleMag);

    NETMSG_END(DSS_ID_36);

    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 4, 1);
}

// MOTS altered
int jkDSS_Processx36_setwaggle(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    jkPlayer_waggleVec = NETMSG_POPVEC3();
    jkPlayer_waggleMag = NETMSG_POPF32();
    return 1;
}

void jkDSS_SendJKPrintUniString(int a1, unsigned int a2)
{
    int v2; // eax

    NETMSG_START;

    NETMSG_PUSHS32(a1);

    
    if ( (a2 & 0x80000000) != 0 )
    {
        v2 = -1;
LABEL_6:
        NETMSG_END(DSS_JKPRINTUNISTRING);

        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v2, 255, 1);
        return;
    }
    if ( a2 < jkPlayer_maxPlayers && (jkPlayer_playerInfos[a2].flags & 1) != 0 )
    {
        v2 = jkPlayer_playerInfos[a2].net_id;
        if ( v2 )
            goto LABEL_6;
    }
}

int jkDSS_ProcessJKPrintUniString(sithCogMsg *msg)
{
    char key[64];

    NETMSG_IN_START(msg);

    stdString_snprintf(key, 64, "COG_%05d", NETMSG_POPS32());
    wchar_t* v1 = stdStrTable_GetUniString(&jkCog_strings, key);
    if ( !v1 )
        v1 = jkStrings_GetText(key);
    jkDev_PrintUniString(v1);
    return 1;
}

void jkDSS_SendEndLevel()
{
    NETMSG_START;

    NETMSG_PUSHS32(jkEpisode_idk1(&jkEpisode_mLoad)->level);
    NETMSG_END(DSS_ENDLEVEL);

    // lol
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 1);
    sithMulti_EndLevel(sithTime_curMs + 10000, 1);
}

int jkDSS_ProcessEndLevel(sithCogMsg *msg)
{
    if ( msg->netMsg.thingIdx != sithNet_serverNetId )
        return 0;

    NETMSG_IN_START(msg);
    int arg0 = NETMSG_POPS32();

    jkEpisode_EndLevel(&jkEpisode_mLoad, arg0);
    sithMulti_EndLevel(sithTime_curMs + 10000, 1);
    return 1;
}

// MOTS altered
void jkDSS_SendSetTeam(int16_t teamNum)
{
    NETMSG_START;

    NETMSG_PUSHS16(playerThingIdx);
    NETMSG_PUSHS16(teamNum);

    NETMSG_END(DSS_SETTEAM);
    
    if ( sithNet_isServer )
        jkDSS_ProcessSetTeam(&sithComm_netMsgTmp);
    else
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithNet_serverNetId, 255, 1);
}

// MOTS altered
int jkDSS_ProcessSetTeam(sithCogMsg *pMsg)
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

    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) == 0 || (sithNet_MultiModeFlags & MULTIMODEFLAG_100) == 0 )
        return 1;

    jkPlayer_playerInfos[playerIdx].teamNum = teamNum;
    if ( jkPlayer_playerInfos[playerIdx].playerThing )
    {
        v5 = sithModel_LoadEntry(jkDSS_aKyTeamModels[teamNum], 1);
        if ( v5 )
        {
            sithThing_SetNewModel(jkPlayer_playerInfos[playerIdx].playerThing, v5);
            jkDSS_SendSetSaberInfo(jkPlayer_playerInfos[playerIdx].playerThing);
        }
    }

    sithMulti_SyncScores();
    return 1;
}