#include "sithSave.h"

#include "AI/sithAI.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithThingPlayer.h"
#include "Main/jkGame.h"
#include "Engine/sith.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithSurface.h"
#include "Engine/sithTimer.h"
#include "Engine/sithTime.h"
#include "Engine/sithNet.h"
#include "General/sithStrTable.h"
#include "General/stdPalEffects.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdConffile.h"
#include "General/stdFileUtil.h"
#include "Win95/DebugConsole.h"
#include "Cog/sithCogVm.h"
#include "jk.h"

void sithSave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5)
{
    sithSave_func1 = a1;
    sithSave_func2 = a2;
    sithSave_func3 = a3;
    sithSave_funcWrite = a4;
    sithSave_funcRead = a5;
}

int sithSave_GetProfilePath(char *out, int outSize, char *a3)
{
    char a1[32]; // [esp+0h] [ebp-20h] BYREF

    stdString_WcharToChar(a1, jkPlayer_playerShortName, 31);
    a1[31] = 0;
    return stdString_snprintf(out, outSize, "player\\%s\\%s", a1, a3);
}

// write

int sithSave_Load(char *saveFname, int a2, int a3)
{
    int result; // eax
    char playerName[32]; // [esp+0h] [ebp-A0h] BYREF
    char fpath[128]; // [esp+20h] [ebp-80h] BYREF

    stdString_WcharToChar(playerName, jkPlayer_playerShortName, 31);
    playerName[31] = 0;
    stdString_snprintf(fpath, 128, "player\\%s\\%s", playerName, saveFname);
    result = stdConffile_OpenMode(fpath, "rb");
    if ( result )
    {
        stdConffile_Close();
        sithSave_dword_835914 = a3;
        if ( sithWorld_pCurWorld )
        {
            sithSave_dword_835900 = a2 != 0 ? 3 : 1;
            _strncpy(sithSave_fpath, fpath, 0x7Fu);
            sithSave_fpath[127] = 0;
            result = 1;
        }
        else
        {
            result = sithSave_LoadEntry(fpath);
        }
    }
    return result;
}

int sithSave_LoadEntry(char *fpath)
{
    char *v1; // eax
    char *v2; // eax
    int curMs; // [esp+Ch] [ebp-650h] BYREF
    char SrcStr[32]; // [esp+10h] [ebp-64Ch] BYREF
    sithSave_Header header; // [esp+30h] [ebp-62Ch] BYREF

    if ( !stdConffile_OpenMode(fpath, "rb") )
        goto load_fail;
    stdConffile_Read(&header, 1580);
    if ( header.version != 6 )
        goto load_fail;
    if ( sithSave_funcRead )
        sithSave_funcRead();
    stdConffile_Read(SrcStr, 32);
    _strtolower(SrcStr);
    if ( sithWorld_pCurWorld )
    {
        if ( !_strcmp(SrcStr, sithWorld_pCurWorld->map_jkl_fname) )
        {
            sithWorld_ResetSectorRuntimeAlteredVars(sithWorld_pCurWorld);
            goto LABEL_11;
        }
        sith_Close();
    }
    if ( !sith_Mode1Init_2(SrcStr) )
    {
        goto load_fail;
    }
LABEL_11:
    sithSoundSys_Reset();
    sithSurface_Startup3();
    sithTimer_Reset();
    stdPalEffects_FlushAllEffects();
    stdPalEffects_ResetEffectsState(&stdPalEffects_state);
    if ( sithSave_func2 )
        sithSave_func2();
    if ( !stdConffile_Read(&curMs, 4) )
        goto load_fail;
    sithTime_SetMs(curMs);
    stdConffile_Read(&g_sithMode, 24);
    sithThing_freestuff(sithWorld_pCurWorld);
    
    // Apparently this works by interpreting a bunch of netMsg packets from the
    // savefile? Funky.
#ifndef LINUX_TMP
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
#ifndef LINUX
            // Linux fails on SyncSound only
            goto load_fail;
#endif
        }   
    }
#endif

    sithThing_sub_4CCE60();
    sithPlayer_idk(0);
    if ( sithSave_func3 )
        sithSave_func3();
    stdConffile_Close();
    _memcpy(&sithSave_headerTmp, &header, sizeof(sithSave_headerTmp));
    v1 = stdFnames_FindMedName(fpath);
    _strncpy(sithSave_autosave_fname, v1, 0x7Fu);
    sithSave_autosave_fname[127] = 0;
    if ( sithSave_dword_835914 )
    {
        v2 = stdFnames_FindMedName(fpath);
        _strncpy(sithSave_saveName, v2, 0x7Fu);
        sithSave_saveName[127] = 0;
        _wcsncpy(sithSave_wsaveName, sithSave_headerTmp.saveName, 0xFFu);
        sithSave_wsaveName[255] = 0;
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

int sithSave_SerializeAllThings(int mpFlags)
{
    unsigned int v3; // ebp
    sithThing *v4; // ebx
    unsigned int v5; // ebp
    int v6; // ebx
    sithThing *v7; // eax
    int v8; // ecx
    unsigned int v10; // ebp
    int v11; // ebx
    sithWorld *v12; // eax
    unsigned int v13; // ebp
    int v14; // ebx
    unsigned int v15; // ebx
    int v16; // ebp
    unsigned int v17; // ebx
    int v18; // ebp
    int v19; // ebx
    sithItemDescriptor *v20; // esi

    if ( (sithCogVm_multiplayerFlags & mpFlags) == 0 )
        return 0;
    v3 = 0;
    v4 = sithWorld_pCurWorld->things;
    if ( sithWorld_pCurWorld->numThingsLoaded )
    {
        do
        {
            if ( sithThing_ShouldSync(v4) )
            {
                sithSector_cogMsg_SendSyncThingFull(v4, 0, mpFlags);
                if ( v4->rdthing.puppet )
                    sithSector_cogMsg_SendSyncPuppet(v4, 0, mpFlags);
            }
            ++v3;
            ++v4;
        }
        while ( v3 < sithWorld_pCurWorld->numThingsLoaded );
    }
    v5 = 0;
    if ( sithWorld_pCurWorld->numThingsLoaded )
    {
        v6 = 0;
        do
        {
            if ( sithThing_ShouldSync(&sithWorld_pCurWorld->things[v6]) )
            {
                v7 = &sithWorld_pCurWorld->things[v6];
                v8 = v7->attach_flags;
                if ( v8 )
                {
                    if ( (v8 & 8) != 0 || v7->move_type != MOVETYPE_PHYSICS )
                        sithSector_cogMsg_SendSyncThingAttachment(v7, 0, mpFlags, 1);
                }
            }
            ++v5;
            ++v6;
        }
        while ( v5 < sithWorld_pCurWorld->numThingsLoaded );
    }
    for (int i = 0; i < 256; i++) // TODO define this maximum
    {
        if ( sithAI_actors[i].aiclass )
            sithSector_cogMsg_SendSyncAI(&sithAI_actors[i], 0, mpFlags);
    }
    v10 = 0;
    if ( sithWorld_pCurWorld->numCogsLoaded )
    {
        v11 = 0;
        do
        {
            sithThingPlayer_cogMsg_SendSyncCog(&sithWorld_pCurWorld->cogs[v11], 0, mpFlags);
            ++v10;
            ++v11;
        }
        while ( v10 < sithWorld_pCurWorld->numCogsLoaded );
    }
    v12 = sithWorld_pStatic;
    if ( sithWorld_pStatic )
    {
        v13 = 0;
        if ( sithWorld_pStatic->numCogsLoaded )
        {
            v14 = 0;
            do
            {
                sithThingPlayer_cogMsg_SendSyncCog(&v12->cogs[v14], 0, mpFlags);
                v12 = sithWorld_pStatic;
                ++v13;
                ++v14;
            }
            while ( v13 < sithWorld_pStatic->numCogsLoaded );
        }
    }
    v15 = 0;
    if ( sithWorld_pCurWorld->numSurfaces )
    {
        v16 = 0;
        do
        {
            sithSector_cogMsg_SendSyncSurface(&sithWorld_pCurWorld->surfaces[v16], 0, mpFlags);
            ++v15;
            ++v16;
        }
        while ( v15 < sithWorld_pCurWorld->numSurfaces );
    }
    v17 = 0;
    if ( sithWorld_pCurWorld->numSectors )
    {
        v18 = 0;
        do
        {
            sithSector_cogMsg_SendSyncSector(&sithWorld_pCurWorld->sectors[v18], 0, mpFlags);
            ++v17;
            ++v18;
        }
        while ( v17 < sithWorld_pCurWorld->numSectors );
    }

    v20 = sithInventory_aDescriptors;
    for (v19 = 0; v19 < 200; v19++) // TODO define this maximum
    {
        if ( (v20->flags & 1) != 0 )
            sithSector_cogMsg_SendSyncItemDesc(g_localPlayerThing, v19, 0, mpFlags);
        ++v20;
    }
    sithSurface_Sync(mpFlags);
    for (sithTimer* timerIter = sithTimer_list; timerIter; timerIter = timerIter->nextTimer )
        sithSector_cogMsg_SendSyncTimers(timerIter, 0, mpFlags);
    sithSector_cogMsg_SendSyncPalEffects(0, mpFlags);
    sithSector_cogMsg_SendSyncCameras(0, mpFlags);
    sithSoundSys_SyncSounds();
    sithSector_cogmsg_send31(0, mpFlags);
    return 1;
}

int sithSave_Write(char *saveFname, int a2, int a3, wchar_t *saveName)
{
    int result; // eax
    wchar_t *v5; // esi
    float v6; // edx
    float *v7; // eax
    sithItemInfo *v8; // ecx
    float v9; // edx
    char tmp_playerName[31]; // [esp+Ch] [ebp-2A0h] BYREF
    char v11; // [esp+2Bh] [ebp-281h]
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
    sithSave_dword_835914 = a3;
    stdString_WcharToChar(tmp_playerName, jkPlayer_playerShortName, 31);
    v11 = 0;
    stdString_snprintf(PathName, 128, "player\\%s\\%s", tmp_playerName, &sithSave_fpath[128]);
    stdFileUtil_MkDir(PathName);
    stdString_WcharToChar(tmp_playerName, jkPlayer_playerShortName, 31);
    v11 = 0;
    stdString_snprintf(PathName, 128, "player\\%s\\%s", tmp_playerName, saveFname);
    if ( a2 || !stdConffile_OpenRead(PathName) )
    {
        _memset(&sithSave_headerTmp, 0, sizeof(sithSave_headerTmp));
        sithSave_headerTmp.version = 6;
        _strncpy(sithSave_headerTmp.episodeName, sithWorld_pCurWorld->episodeName, 0x7Fu);
        sithSave_headerTmp.episodeName[127] = 0;
        _strncpy(sithSave_headerTmp.jklName, sithWorld_pCurWorld->map_jkl_fname, 0x7Fu);
        sithSave_headerTmp.jklName[127] = 0;
        _wcsncpy(sithSave_headerTmp.saveName, v5, 0xFFu);
        sithSave_headerTmp.saveName[255] = 0;
        v6 = g_localPlayerThing->actorParams.maxHealth;
        sithSave_headerTmp.playerHealth = g_localPlayerThing->actorParams.health;
        sithSave_headerTmp.playerMaxHealth = v6;
        v7 = sithSave_headerTmp.binAmts;
        v8 = g_selfPlayerInfo->iteminfo;
        do
        {
            v9 = v8->ammoAmt;
            ++v8;
            *v7++ = v9;
        }
        while ( (intptr_t)v7 < (intptr_t)sithSave_headerTmp.saveName );
        sithSave_dword_835900 = 2;
        _strncpy(sithSave_fpath, PathName, 0x7Fu);
        sithSave_fpath[127] = 0;
        result = 1;
    }
    else
    {
        stdConffile_Close();
        result = 0;
    }
    return result;
}

int sithSave_WriteEntry()
{
    int result; // eax
    int v1; // esi
    char *v2; // eax
    char *v3; // eax
    wchar_t *v4; // eax

    if ( sithSave_dword_835900 == 1 )
    {
        if ( sithSave_LoadEntry(sithSave_fpath) )
        {
LABEL_18:
            sithSave_dword_835900 = 0;
            return 1;
        }
LABEL_17:
        sith_set_sithmode_5();
        goto LABEL_18;
    }
    if ( sithSave_dword_835900 != 2 )
    {
        result = sithSave_dword_835900 - 3;
        if ( sithSave_dword_835900 != 3 )
            return result;
        if ( sithSave_LoadEntry(sithSave_fpath) )
        {
            sithPlayer_debug_ToNextCheckpoint(g_localPlayerThing);
            sithSave_dword_835900 = 0;
            return 1;
        }
        goto LABEL_17;
    }
    if ( (g_localPlayerThing->thingflags & SITH_TF_DEAD) == 0 && stdConffile_OpenWrite(sithSave_fpath) )
    {
        v1 = sithCogVm_multiplayerFlags;
        sithCogVm_multiplayerFlags = 4;
        stdConffile_Write((const char*)&sithSave_headerTmp, sizeof(sithSave_Header));
        if ( sithSave_funcWrite )
            sithSave_funcWrite();
        stdConffile_Write((const char*)sithWorld_pCurWorld->map_jkl_fname, 32);
        stdConffile_Write((const char*)&sithTime_curMs, 4);
        stdConffile_Write((const char*)&g_sithMode, 24);
        sithSave_SerializeAllThings(4);
        if ( sithSave_func1 )
            sithSave_func1();
        stdConffile_CloseWrite();
        v2 = stdFnames_FindMedName(sithSave_fpath);
        _strncpy(sithSave_autosave_fname, v2, 0x7Fu);
        sithSave_autosave_fname[127] = 0;
        if ( sithSave_dword_835914 )
        {
            v3 = stdFnames_FindMedName(sithSave_fpath);
            _strncpy(sithSave_saveName, v3, 0x7Fu);
            sithSave_saveName[127] = 0;
            _wcsncpy(sithSave_wsaveName, sithSave_headerTmp.saveName, 0xFFu);
            sithSave_wsaveName[255] = 0;
            v4 = sithStrTable_GetString("GAME_SAVED");
            DebugConsole_PrintUniStr(v4);
        }
        sithCogVm_multiplayerFlags = v1;
    }
    sithSave_dword_835900 = 0;
    return 0;
}
