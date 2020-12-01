#include "jkPlayer.h"

#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdFileUtil.h"
#include "Engine/sithAnimclass.h"
#include "Engine/sithSave.h"
#include "Engine/rdPuppet.h"
#include "World/sithInventory.h"
#include "World/jkSaber.h"
#include "World/sithThing.h"
#include "World/sithPlayer.h"
#include "World/sithWeapon.h"
#include "World/sithWorld.h"
#include "Primitives/rdMatrix.h"
#include "Win95/sithControl.h"
#include "Gui/jkHudInv.h"
#include "Main/jkGame.h"
#include "jk.h"

int jkPlayer_LoadAutosave()
{
    char tmp[128];

    jkPlayer_dword_525470 = 1;
    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithWorld_pCurWorld->map_jkl_fname);
    stdFnames_ChangeExt(tmp, "jks");
    return sithSave_Load(tmp, 0, 0);
}

int jkPlayer_LoadSave(char *path)
{
    jkPlayer_dword_525470 = 1;
    return sithSave_Load(path, 0, 1);
}

void jkPlayer_Startup()
{
    jkPlayer_InitThings();
    _memcpy(&jkSaber_rotateMat, &rdroid_identMatrix34, sizeof(jkSaber_rotateMat));
}

void jkPlayer_Shutdown()
{
    for (int i = 0; i < jkPlayer_numThings; i++ )
    {
        if (playerThings[i].polylineThing.model3)
        {
            rdThing_FreeEntry(&playerThings[i].polylineThing);
            playerThings[i].polylineThing.model3 = 0;
        }
    }
    _memset(playerThings, 0, sizeof(playerThings));
    
    for (int i = 0; i < jkPlayer_numOtherThings; i++)
    {
        if (jkPlayer_otherThings[i].polylineThing.model3)
        {
            rdThing_FreeEntry(&jkPlayer_otherThings[i].polylineThing);
            jkPlayer_otherThings[i].polylineThing.model3 = 0;
        }
    }
    _memset(jkPlayer_otherThings, 0, sizeof(jkPlayer_otherThings));
    //nullsub_28_free();
}

void jkPlayer_nullsub_29()
{
}

void jkPlayer_nullsub_30()
{
}

void jkPlayer_InitSaber()
{
    jkPlayer_numThings = jkPlayer_maxPlayers;
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        jkSaberInfo* saberInfo = &playerThings[i];
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[i];

        saberInfo->spawnedSparks = playerInfo->playerThing;
        playerInfo->playerThing->saberInfo = saberInfo;
        saberInfo->field_204 = 8;
        saberInfo->field_208 = 16;
        saberInfo->field_21C = 0;
        saberInfo->field_220 = 0;
        playerInfo->playerThing->thingflags |= SITH_TF_RENDERWEAPON;
        saberInfo->field_224 = 0;
        
        sithThing* saberSparks = sithTemplate_GetEntryByName("+ssparks_saber");
        sithThing* bloodSparks = sithTemplate_GetEntryByName("+ssparks_blood");
        sithThing* wallSparks = sithTemplate_GetEntryByName("+ssparks_wall");
        
        jkSaber_InitializeSaberInfo(playerThings[i].spawnedSparks, "sabergreen1.mat", "sabergreen0.mat", 0.0031999999, 0.0018, 0.12, wallSparks, bloodSparks, saberSparks);
    }
}

void jkPlayer_InitThings()
{
    jkPlayer_numThings = jkPlayer_maxPlayers;
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        jkSaberInfo* saberInfo = &playerThings[i];
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[i];

        saberInfo->spawnedSparks = playerInfo->playerThing;
        playerInfo->playerThing->saberInfo = saberInfo;
        playerInfo->playerThing->thingflags |= SITH_TF_RENDERWEAPON;
    }

    int num = 0;
    jkPlayer_numOtherThings = 0;

    jkSaberInfo* saberInfoIter = jkPlayer_otherThings;
    for (int i = 0; i < sithWorld_pCurWorld->numThingsLoaded; i++)
    {
        sithThing* thingIter = &sithWorld_pCurWorld->things[i];

        if (thingIter->thingType == THINGTYPE_ACTOR 
            && thingIter->actorParams.typeflags & THING_TYPEFLAGS_BOSS 
            && saberInfoIter < &jkPlayer_otherThings[16] ) // off by one?
        {
            saberInfoIter->spawnedSparks = thingIter;
            thingIter->saberInfo = saberInfoIter;
            saberInfoIter->rd_thing.model3 = 0;
            thingIter->thingflags |= SITH_TF_RENDERWEAPON;

            saberInfoIter++;
            ++num;
        }
    }

    jkPlayer_numOtherThings = num;
}

void jkPlayer_nullsub_1()
{
}

void jkPlayer_CreateConf(wchar_t *name)
{
    int v1; // ebx
    int v2; // edx
    char *v3; // ebp
    int v4; // eax
    int v5; // ecx
    int v6; // ebp
    char *v7; // edi
    int *v8; // esi
    char *v9; // edi
    int *v10; // esi
    int v11; // [esp+10h] [ebp-144h]
    char a1[32]; // [esp+34h] [ebp-120h]
    char pathName[128]; // [esp+D4h] [ebp-80h]

    stdString_WcharToChar(a1, name, 31);
    v1 = 0;
    a1[31] = 0;
    stdFileUtil_MkDir("player");
    stdFnames_MakePath(pathName, 128, "player", a1);
    stdFileUtil_MkDir(pathName);
    sithControl_InputInit();
    jkHudInv_InputInit();
    sithPlayer_SetBinAmt(SITHBIN_JEDI_RANK, 0.0);
    sithPlayer_SetBinAmt(SITHBIN_CHOICE, 0.0);
    sithWeapon_InitDefaults();
    jkGame_SetDefaultSettings();
    _wcsncpy(jkPlayer_playerShortName, name, 0x1Fu);
    jkPlayer_playerShortName[31] = 0;
    jkPlayer_setNumCutscenes = 0;
    v11 = sithControl_IsOpen();
    if ( v11 )
        sithControl_Close();
    jkPlayer_ReadConf(jkPlayer_playerShortName);
    v2 = 0;
    if ( jkPlayer_setNumCutscenes <= 0 )
    {
LABEL_7:
        if ( jkPlayer_setNumCutscenes < 32 )
        {
            _strncpy(&jkPlayer_cutscenePath[32 * jkPlayer_setNumCutscenes], "01-02a.smk", 0x1Fu);
            v4 = jkPlayer_setNumCutscenes;
            v5 = 32 * jkPlayer_setNumCutscenes;
            jkPlayer_aCutsceneVal[jkPlayer_setNumCutscenes] = 1;
            jkPlayer_cutscenePath[v5 + 31] = 0;
            jkPlayer_setNumCutscenes = v4 + 1;
            jkPlayer_WriteConf(name);
            if ( v11 )
                sithControl_Open();
        }
    }
    else
    {
        v3 = jkPlayer_cutscenePath;
        while ( 1 )
        {
            v1 = 0;
            if ( !_memcmp(v3, "01-02a.smk", 0xBu) )
                break;
            ++v2;
            v3 += 32;
            if ( v2 >= jkPlayer_setNumCutscenes )
                goto LABEL_7;
        }
        v1 = 0;
    }
    jkPlayer_WriteConf(name);
}

void jkPlayer_WriteConf(wchar_t *name)
{
    int v1; // esi
    char *v2; // ebx
    int *v3; // edi
    char nameTmp[32]; // [esp+0h] [ebp-A0h]
    char fpath[128]; // [esp+20h] [ebp-80h]

    stdString_WcharToChar(nameTmp, name, 31);
    nameTmp[31] = 0;
    stdString_snprintf(fpath, 128, "player\\%s\\%s.plr", nameTmp, nameTmp);
    if ( stdConffile_OpenWrite(fpath) )
    {
        stdConffile_Printf("version %d\n", 1);
        stdConffile_Printf("diff %d\n", jkPlayer_setDiff);
        if ( stdConffile_Printf("fullsubtitles %d\n", jkPlayer_setFullSubtitles)
          && stdConffile_Printf("disablecutscenes %d\n", jkPlayer_setDisableCutscenes)
          && stdConffile_Printf("rotateoverlaymap %d\n", jkPlayer_setRotateOverlayMap)
          && stdConffile_Printf("drawstatus %d\n", jkPlayer_setDrawStatus)
          && stdConffile_Printf("crosshair %d\n", jkPlayer_setCrosshair) )
        {
            stdConffile_Printf("sabercam %d\n", jkPlayer_setSaberCam);
        }
        sithWeapon_WriteConf();
        sithControl_WriteConf();
        if ( stdConffile_Printf("numCutscenes %d\n", jkPlayer_setNumCutscenes) )
        {
            v1 = 0;
            if ( jkPlayer_setNumCutscenes > 0 )
            {
                v2 = jkPlayer_cutscenePath;
                v3 = jkPlayer_aCutsceneVal;
                do
                {
                    if ( !stdConffile_Printf("%s %d\n", v2, *v3) )
                        break;
                    ++v1;
                    ++v3;
                    v2 += 32;
                }
                while ( v1 < jkPlayer_setNumCutscenes );
            }
        }
        stdConffile_CloseWrite();
    }
}

int jkPlayer_ReadConf(wchar_t *name)
{
    int result; // eax
    int v2; // esi
    int *v3; // ebx
    char *v4; // edi
    int v5; // [esp+Ch] [ebp-A4h]
    char v6[32]; // [esp+10h] [ebp-A0h]
    char fpath[128]; // [esp+30h] [ebp-80h]

    v5 = 0;
    if ( jkPlayer_SanitizeName(name) )
    {
        stdString_WcharToChar(v6, name, 31);
        v6[31] = 0;
        _wcsncpy(jkPlayer_playerShortName, name, 0x1Fu);
        jkPlayer_playerShortName[31] = 0;
        _sprintf(fpath, "player\\%s\\%s.plr", v6, v6);
        if (stdConffile_OpenRead(fpath))
        {
            if ( stdConffile_ReadLine() && _sscanf(stdConffile_aLine, "version %d", &v5) == 1 && v5 == 1 && stdConffile_ReadLine() )
            {
                _sscanf(stdConffile_aLine, "diff %d", &jkPlayer_setDiff);
                if ( jkPlayer_setDiff < 0 )
                {
                    jkPlayer_setDiff = 0;
                }
                else if ( jkPlayer_setDiff > 2 )
                {
                    jkPlayer_setDiff = 2;
                }
                if ( stdConffile_ReadLine()
                  && _sscanf(stdConffile_aLine, "fullsubtitles %d\n", &jkPlayer_setFullSubtitles) == 1
                  && stdConffile_ReadLine()
                  && _sscanf(stdConffile_aLine, "disablecutscenes %d\n", &jkPlayer_setDisableCutscenes) == 1
                  && stdConffile_ReadLine()
                  && _sscanf(stdConffile_aLine, "rotateoverlaymap %d\n", &jkPlayer_setRotateOverlayMap) == 1
                  && stdConffile_ReadLine()
                  && _sscanf(stdConffile_aLine, "drawstatus %d\n", &jkPlayer_setDrawStatus) == 1
                  && stdConffile_ReadLine()
                  && _sscanf(stdConffile_aLine, "crosshair %d\n", &jkPlayer_setCrosshair) == 1
                  && stdConffile_ReadLine() )
                {
                    _sscanf(stdConffile_aLine, "sabercam %d\n", &jkPlayer_setSaberCam);
                }
                sithWeapon_ReadConf();
                sithControl_ReadConf();
                if ( stdConffile_ReadArgs() )
                {
                    if ( stdConffile_entry.numArgs >= 1u
                      && !_memcmp(stdConffile_entry.args[0].key, "numcutscenes", 0xDu)
                      && _sscanf(stdConffile_entry.args[1].value, "%d", &jkPlayer_setNumCutscenes) == 1 )
                    {
                        v2 = 0;
                        if ( jkPlayer_setNumCutscenes > 0 )
                        {
                            v3 = jkPlayer_aCutsceneVal;
                            v4 = jkPlayer_cutscenePath;
                            do
                            {
                                if ( !stdConffile_ReadArgs() )
                                    break;
                                if ( stdConffile_entry.numArgs < 2u )
                                    break;
                                if ( _sscanf(stdConffile_entry.args[0].key, "%s", v4) != 1 )
                                    break;
                                if ( _sscanf(stdConffile_entry.args[1].value, "%d", v3) != 1 )
                                    break;
                                ++v2;
                                v4 += 32;
                                ++v3;
                            }
                            while ( v2 < jkPlayer_setNumCutscenes );
                        }
                    }
                }
                stdConffile_Close();
                return 1;
            }
            else
            {
                stdConffile_Close();
                jkPlayer_setDiff = 1;
                sithControl_InputInit();
                return 0;
            }
        }
    }
    return 0;
}

void jkPlayer_SetPovModel(jkSaberInfo *info, rdModel3 *model)
{
    rdThing *thing; // esi

    thing = &info->povModel;
    if ( info->povModel.type != 1 || info->povModel.model3 != model )
    {
        rdThing_FreeEntry(&info->povModel);
        rdThing_NewEntry(thing, info->spawnedSparks);
        rdThing_SetModel3(thing, model);
        info->povModel.puppet = rdPuppet_New(thing);
    }
}

void jkPlayer_renderSaberWeaponMesh(sithThing *thing)
{
    jkSaberInfo* saberInfo = thing->saberInfo;
    if (!saberInfo)
        return;

    if (!thing->animclass)
        return;

    rdMatrix34* primaryMat = &thing->rdthing.hierarchyNodeMatrices[thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP]];
        rdMatrix34* secondaryMat = &thing->rdthing.hierarchyNodeMatrices[thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP]];

    if (thing->jkFlags & JKFLAG_PERSUASION)
    {
        if ( g_selfPlayerInfo->iteminfo[SITHBIN_F_SEEING].state & ITEMSTATE_ACTIVATE )
        {
            thing->rdthing.geometryMode = thing->rdthing.geoMode;
            rdVector_Copy3(&thing->lookOrientation.scale, &thing->position);
            rdThing_Draw(&thing->rdthing, &thing->lookOrientation);

            thing->lookOrientation.scale.x = 0.0;
            thing->lookOrientation.scale.y = 0.0;
            thing->lookOrientation.scale.z = 0.0;
            thing->rdthing.geometryMode = thing->rdthing.geometryMode;

            if (saberInfo->rd_thing.model3)
                rdThing_Draw(&saberInfo->rd_thing, primaryMat);

            if (thing->jkFlags & JKFLAG_SABERON)
            {
                jkSaber_PolylineRand(&saberInfo->polylineThing);
                rdThing_Draw(&saberInfo->polylineThing, primaryMat);
                if ( thing->jkFlags & JKFLAG_DUALSABERS)
                    rdThing_Draw(&saberInfo->polylineThing, secondaryMat);
            }
        }
        else
        {
            jkPlayer_renderSaberTwinkle(thing);
        }
    }
    else if ( thing->rdthing.geometryMode > 0 )
    {
        if (saberInfo->rd_thing.model3)
            rdThing_Draw(&saberInfo->rd_thing, primaryMat);
        
        if (thing->jkFlags & JKFLAG_SABERON)
        {
            //jkSaber_PolylineRand(&saberInfo->polylineThing);
            rdThing_Draw(&saberInfo->polylineThing, primaryMat);
            if (thing->jkFlags & JKFLAG_DUALSABERS)
                rdThing_Draw(&saberInfo->polylineThing, secondaryMat);
        }
    }
}
