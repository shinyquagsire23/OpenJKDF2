#include "sithGamesave.h"

#include "AI/sithAI.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Main/jkGame.h"
#include "Engine/sith.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSoundMixer.h"
#include "Engine/sithSurface.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithTime.h"
#include "Engine/sithNet.h"
#include "Engine/sithAnimClass.h"
#include "General/sithStrTable.h"
#include "General/stdPalEffects.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdConffile.h"
#include "General/stdFileUtil.h"
#include "Win95/DebugConsole.h"
#include "Cog/sithCogVm.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "jk.h"

void sithGamesave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5)
{
    sithGamesave_func1 = a1;
    sithGamesave_func2 = a2;
    sithGamesave_func3 = a3;
    sithGamesave_funcWrite = a4;
    sithGamesave_funcRead = a5;
}

int sithGamesave_GetProfilePath(char *out, int outSize, char *a3)
{
    char a1[32]; // [esp+0h] [ebp-20h] BYREF

    stdString_WcharToChar(a1, jkPlayer_playerShortName, 31);
    a1[31] = 0;
    return stdString_snprintf(out, outSize, "player\\%s\\%s", a1, a3);
}

// write

int sithGamesave_Load(char *saveFname, int a2, int a3)
{
    char playerName[32]; // [esp+0h] [ebp-A0h] BYREF
    char fpath[128]; // [esp+20h] [ebp-80h] BYREF

    stdString_WcharToChar(playerName, jkPlayer_playerShortName, 31);
    playerName[31] = 0;
    stdString_snprintf(fpath, 128, "player\\%s\\%s", playerName, saveFname);

    if (stdConffile_OpenMode(fpath, "rb"))
    {
        stdConffile_Close();
        sithGamesave_dword_835914 = a3;
        if (sithWorld_pCurrentWorld)
        {
            sithGamesave_dword_835900 = a2 != 0 ? 3 : 1;
            _strncpy(sithGamesave_fpath, fpath, 0x7Fu);
            sithGamesave_fpath[127] = 0;
            return 1;
        }
        else
        {
            return sithGamesave_LoadEntry(fpath);
        }
    }
    return 0;
}

int sithGamesave_LoadEntry(char *fpath)
{
    int curMs; // [esp+Ch] [ebp-650h] BYREF
    char SrcStr[32]; // [esp+10h] [ebp-64Ch] BYREF
    sithGamesave_Header header; // [esp+30h] [ebp-62Ch] BYREF

    if ( !stdConffile_OpenMode(fpath, "rb") )
        goto load_fail;
    stdConffile_Read(&header, sizeof(sithGamesave_Header));
    if ( header.version != 6 )
        goto load_fail;
    if ( sithGamesave_funcRead )
        sithGamesave_funcRead();
    stdConffile_Read(SrcStr, 32);
    _strtolower(SrcStr);
    if ( sithWorld_pCurrentWorld )
    {
        if ( !_strcmp(SrcStr, sithWorld_pCurrentWorld->map_jkl_fname) )
        {
            sithWorld_ResetSectorRuntimeAlteredVars(sithWorld_pCurrentWorld);
            goto LABEL_11;
        }
        sith_Close();
    }
    if ( !sithOpenNormal(SrcStr) )
    {
        goto load_fail;
    }
LABEL_11:
    sithSoundMixer_Reset();
    sithSurface_Startup3();
    sithEvent_Reset();
    stdPalEffects_FlushAllEffects();
    stdPalEffects_ResetEffectsState(&stdPalEffects_state);
    if ( sithGamesave_func2 )
        sithGamesave_func2();
    if ( !stdConffile_Read(&curMs, 4) )
        goto load_fail;
    sithTime_SetMs(curMs);
    
    // Added: split this apart, g_sithMode is a struct...
    stdConffile_Read((char*)&g_sithMode, sizeof(int32_t));
    stdConffile_Read((char*)&g_submodeFlags, sizeof(int32_t));
    stdConffile_Read((char*)&sithSurface_byte_8EE668, sizeof(int32_t));
    stdConffile_Read((char*)&g_debugmodeFlags, sizeof(int32_t));
    stdConffile_Read((char*)&jkPlayer_setDiff, sizeof(int32_t));
    stdConffile_Read((char*)&g_mapModeFlags, sizeof(int32_t));

    sithThing_freestuff(sithWorld_pCurrentWorld);
    
    // Apparently this works by interpreting a bunch of netMsg packets from the
    // savefile? Funky.
//#ifndef LINUX_TMP
    while (1)
    {
        if ( !stdConffile_Read(&sithCogVm_netMsgTmp.netMsg.cogMsgId, 4) )
        {
            break;
        }
        
        if (!stdConffile_Read(&sithCogVm_netMsgTmp.netMsg.msg_size, 4))
        {
            jk_printf("OpenJKDF2: Save load failed to read msg_size\n");
            goto load_fail;
        }
        
        if (!(!sithCogVm_netMsgTmp.netMsg.msg_size || stdConffile_Read(sithCogVm_netMsgTmp.pktData, sithCogVm_netMsgTmp.netMsg.msg_size)))
        {
            jk_printf("OpenJKDF2: Save load failed to read msg sized %x\n", sithCogVm_netMsgTmp.netMsg.msg_size);
            goto load_fail;
        }
        
        if (!sithCogVm_InvokeMsgByIdx(&sithCogVm_netMsgTmp))
        {
            jk_printf("OpenJKDF2: Save load failed to invoke msg %u\n", sithCogVm_netMsgTmp.netMsg.cogMsgId);
#ifndef SDL2_RENDER
            // Linux fails on SyncSound only
            goto load_fail;
#endif
        }   
    }
//#endif

    sithThing_sub_4CCE60();
    sithPlayer_idk(0);
    if ( sithGamesave_func3 )
        sithGamesave_func3();
    stdConffile_Close();
    _memcpy(&sithGamesave_headerTmp, &header, sizeof(sithGamesave_headerTmp));
    _strncpy(sithGamesave_autosave_fname, stdFnames_FindMedName(fpath), 0x7Fu);
    sithGamesave_autosave_fname[127] = 0;
    if ( sithGamesave_dword_835914 )
    {
        _strncpy(sithGamesave_saveName, stdFnames_FindMedName(fpath), 0x7Fu);
        sithGamesave_saveName[127] = 0;
        _wcsncpy(sithGamesave_wsaveName, sithGamesave_headerTmp.saveName, 0xFFu);
        sithGamesave_wsaveName[255] = 0;
    }
    sithTime_SetMs(curMs);
    sithCamera_SetCurrentCamera(sithCamera_currentCamera);
    return 1;

load_fail:
    stdConffile_Close();
    sithThing_sub_4CCE60();
    sith_Close();
    return 0;
}

int sithGamesave_SerializeAllThings(int mpFlags)
{
    unsigned int v15; // ebx
    int v16; // ebp
    unsigned int v17; // ebx
    int v18; // ebp
    int v19; // ebx
    sithItemDescriptor *v20; // esi

    if ( (sithCogVm_multiplayerFlags & mpFlags) == 0 )
        return 0;
    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numThingsLoaded; i++)
    {
        sithThing* v4 = &sithWorld_pCurrentWorld->things[i];
        if ( sithThing_ShouldSync(v4) )
        {
            sithDSSThing_SendFullDesc(v4, 0, mpFlags);
            if ( v4->rdthing.puppet )
                sithDSS_SendSyncPuppet(v4, 0, mpFlags);
        }
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numThingsLoaded; i++)
    {
        sithThing* v7 = &sithWorld_pCurrentWorld->things[i];
        if (sithThing_ShouldSync(v7))
        {
            if ( v7->attach_flags )
            {
                if ( (v7->attach_flags & 8) != 0 || v7->moveType != SITH_MT_PHYSICS )
                    sithDSSThing_SendSyncThingAttachment(v7, 0, mpFlags, 1);
            }
        }
    }

    for (uint32_t i = 0; i < 256; i++) // TODO define this maximum
    {
        if ( sithAI_actors[i].aiclass )
            sithDSS_SendAIStatus(&sithAI_actors[i], 0, mpFlags);
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numCogsLoaded; i++)
    {
        sithDSSCog_SendSyncCog(&sithWorld_pCurrentWorld->cogs[i], 0, mpFlags);
    }

    if ( sithWorld_pStatic )
    {
        for (uint32_t i = 0; i < sithWorld_pStatic->numCogsLoaded; i++)
        {
            sithDSSCog_SendSyncCog(&sithWorld_pStatic->cogs[i], 0, mpFlags);
        }
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numSurfaces; i++)
    {
        sithDSS_SendSurfaceStatus(&sithWorld_pCurrentWorld->surfaces[i], 0, mpFlags);
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numSectors; i++)
    {
        sithDSS_SendSectorStatus(&sithWorld_pCurrentWorld->sectors[i], 0, mpFlags);
    }

    for (v19 = 0; v19 < SITHBIN_NUMBINS; v19++) // TODO define this maximum
    {
        if ( (sithInventory_aDescriptors[v19].flags & ITEMINFO_VALID) != 0 )
            sithDSS_SendInventory(g_localPlayerThing, v19, 0, mpFlags);
    }

    sithSurface_SyncFull(mpFlags);

    for (sithEvent* timerIter = sithEvent_list; timerIter; timerIter = timerIter->nextTimer )
        sithDSS_SendSyncEvents(timerIter, 0, mpFlags);

    sithDSS_SendSyncPalEffects(0, mpFlags);
    sithDSS_SendSyncCameras(0, mpFlags);
    sithSoundMixer_SyncSounds();
    sithDSS_SendMisc(0, mpFlags);

    return 1;
}

int sithGamesave_Write(char *saveFname, int a2, int a3, wchar_t *saveName)
{
    wchar_t *v5; // esi
    float *v7; // eax
    sithItemInfo *v8; // ecx
    float v9; // edx
    char tmp_playerName[32]; // [esp+Ch] [ebp-2A0h] BYREF
    char PathName[128]; // [esp+2Ch] [ebp-280h] BYREF
    wchar_t v13[256]; // [esp+ACh] [ebp-200h] BYREF

    if ( (g_submodeFlags & 1) != 0 )
        return 0;
    if ( (g_localPlayerThing->thingflags & SITH_TF_DEAD) != 0 )
        return 0;
    v5 = saveName;
    if ( !saveName )
    {
        v5 = v13;
        stdString_CharToWchar(v13, saveFname, 255);
        v13[255] = 0;
    }
    sithGamesave_dword_835914 = a3;
    stdString_WcharToChar(tmp_playerName, jkPlayer_playerShortName, 31);
    tmp_playerName[31] = 0;
    stdString_snprintf(PathName, 128, "player\\%s\\%s", tmp_playerName, &sithGamesave_fpath[128]);
    stdFileUtil_MkDir(PathName);
    stdString_WcharToChar(tmp_playerName, jkPlayer_playerShortName, 31);
    tmp_playerName[31] = 0;
    stdString_snprintf(PathName, 128, "player\\%s\\%s", tmp_playerName, saveFname);
    if ( a2 || !stdConffile_OpenRead(PathName) )
    {
        _memset(&sithGamesave_headerTmp, 0, sizeof(sithGamesave_headerTmp));
        sithGamesave_headerTmp.version = 6;
        _strncpy(sithGamesave_headerTmp.episodeName, sithWorld_pCurrentWorld->episodeName, 0x7Fu);
        sithGamesave_headerTmp.episodeName[127] = 0;
        _strncpy(sithGamesave_headerTmp.jklName, sithWorld_pCurrentWorld->map_jkl_fname, 0x7Fu);
        sithGamesave_headerTmp.jklName[127] = 0;
        _wcsncpy(sithGamesave_headerTmp.saveName, v5, 0xFFu);
        sithGamesave_headerTmp.saveName[255] = 0;
        sithGamesave_headerTmp.playerHealth = g_localPlayerThing->actorParams.health;
        sithGamesave_headerTmp.playerMaxHealth = g_localPlayerThing->actorParams.maxHealth;
        v7 = sithGamesave_headerTmp.binAmts;
        v8 = g_selfPlayerInfo->iteminfo;
        do
        {
            v9 = v8->ammoAmt;
            ++v8;
            *v7++ = v9;
        }
        while ( (intptr_t)v7 < (intptr_t)sithGamesave_headerTmp.saveName );
        sithGamesave_dword_835900 = 2;
        _strncpy(sithGamesave_fpath, PathName, 0x7Fu);
        sithGamesave_fpath[127] = 0;
        return 1;
    }
    else
    {
        stdConffile_Close();
        return 0;
    }
}

int sithGamesave_WriteEntry()
{
    if ( sithGamesave_dword_835900 == 1 )
    {
        if ( sithGamesave_LoadEntry(sithGamesave_fpath) )
        {
            sithGamesave_dword_835900 = 0;
            return 1;
        }
        // TODO inlined?
        sith_set_sithmode_5();
        sithGamesave_dword_835900 = 0;
        return 1;
    }
    if ( sithGamesave_dword_835900 != 2 )
    {
        if ( sithGamesave_dword_835900 != 3 )
            return sithGamesave_dword_835900 - 3;
        if ( sithGamesave_LoadEntry(sithGamesave_fpath) )
        {
            sithPlayer_debug_ToNextCheckpoint(g_localPlayerThing);
            sithGamesave_dword_835900 = 0;
            return 1;
        }
        // TODO inlined?
        sith_set_sithmode_5();
        sithGamesave_dword_835900 = 0;
        return 1;
    }
    if ( (g_localPlayerThing->thingflags & SITH_TF_DEAD) == 0 && stdConffile_OpenWrite(sithGamesave_fpath) )
    {
        int multiplayerFlagsSave = sithCogVm_multiplayerFlags;
        sithCogVm_multiplayerFlags = 4;
        stdConffile_Write((const char*)&sithGamesave_headerTmp, sizeof(sithGamesave_Header));
        if ( sithGamesave_funcWrite )
            sithGamesave_funcWrite();
        stdConffile_Write((const char*)sithWorld_pCurrentWorld->map_jkl_fname, 32);
        stdConffile_Write((const char*)&sithTime_curMs, sizeof(sithTime_curMs));
        
        // Added: split this apart, g_sithMode is a struct...
        stdConffile_Write((const char*)&g_sithMode, sizeof(int32_t));
        stdConffile_Write((const char*)&g_submodeFlags, sizeof(int32_t));
        stdConffile_Write((const char*)&sithSurface_byte_8EE668, sizeof(int32_t));
        stdConffile_Write((const char*)&g_debugmodeFlags, sizeof(int32_t));
        stdConffile_Write((const char*)&jkPlayer_setDiff, sizeof(int32_t));
        stdConffile_Write((const char*)&g_mapModeFlags, sizeof(int32_t));
        
        sithGamesave_SerializeAllThings(4);
        if ( sithGamesave_func1 )
            sithGamesave_func1();
        stdConffile_CloseWrite();
        _strncpy(sithGamesave_autosave_fname, stdFnames_FindMedName(sithGamesave_fpath), 0x7Fu);
        sithGamesave_autosave_fname[127] = 0;
        if ( sithGamesave_dword_835914 )
        {
            _strncpy(sithGamesave_saveName, stdFnames_FindMedName(sithGamesave_fpath), 0x7Fu);
            sithGamesave_saveName[127] = 0;
            _wcsncpy(sithGamesave_wsaveName, sithGamesave_headerTmp.saveName, 0xFFu);
            sithGamesave_wsaveName[255] = 0;
            DebugConsole_PrintUniStr(sithStrTable_GetString("GAME_SAVED"));
        }
        sithCogVm_multiplayerFlags = multiplayerFlagsSave;
    }
    sithGamesave_dword_835900 = 0;
    return 0;
}
