#include "sithSave.h"

#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "Main/jkGame.h"
#include "Engine/sith.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithSurface.h"
#include "Engine/sithTimer.h"
#include "Engine/sithTime.h"
#include "General/stdPalEffects.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdConffile.h"
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
        goto LABEL_25;
    stdConffile_Read(&header, 1580);
    if ( header.version != 6 )
        goto LABEL_25;
    if ( sithSave_funcRead )
        sithSave_funcRead();
    stdConffile_Read(SrcStr, 32);
    _strtolower(SrcStr);
    if ( sithWorld_pCurWorld )
    {
        if ( !_strcmp(SrcStr, sithWorld_pCurWorld->map_jkl_fname) )
        {
            sithWorld_sub_4D0AA0(sithWorld_pCurWorld);
            goto LABEL_11;
        }
        sith_Close();
    }
    if ( !sith_Mode1Init_2(SrcStr) )
    {
LABEL_25:
        stdConffile_Close();
        sithThing_sub_4CCE60();
        sith_Close();
        return 0;
    }
LABEL_11:
    sithSoundSys_sub_4DBF90();
    sithSurface_Startup3();
    sithTimer_Reset();
    stdPalEffects_FlushAllEffects();
    stdPalEffects_ResetEffectsState(&stdPalEffects_state);
    if ( sithSave_func2 )
        sithSave_func2();
    if ( !stdConffile_Read(&curMs, 4) )
        goto LABEL_25;
    sithTime_SetMs(curMs);
    stdConffile_Read(&g_sithMode, 24);
    sithThing_freestuff(sithWorld_pCurWorld);
    
    // Apparently this works by interpreting a bunch of netMsg packets from the
    // savefile? Funky.
#ifndef LINUX_TMP
    if ( stdConffile_Read(&g_netMsgTmp.netMsg.cogMsgId, 4) )
    {
        while (1)
        {
            if (!stdConffile_Read(&g_netMsgTmp.netMsg.msg_size, 4))
                goto LABEL_25;
            
            if (!(!g_netMsgTmp.netMsg.msg_size || stdConffile_Read(g_netMsgTmp.pktData, g_netMsgTmp.netMsg.msg_size)))
                goto LABEL_25;
            
            if (!sithCogVm_InvokeMsgByIdx(&g_netMsgTmp.netMsg))
                goto LABEL_25;

            if ( !stdConffile_Read(&g_netMsgTmp.netMsg.cogMsgId, 4) )
                break;
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
}
