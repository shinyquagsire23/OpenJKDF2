#include "jkDev.h"

#include "General/stdHashTable.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdString.h"
#include "Win95/stdDisplay.h"
#include "Devices/sithConsole.h"
#include "Win95/WinIdk.h"
#include "World/sithThing.h"
#include "Gameplay/sithInventory.h"
#include "Gameplay/jkSaber.h"
#include "World/jkPlayer.h"
#include "World/sithActor.h"
#include "Main/sithCommand.h"
#include "Dss/sithMulti.h"
#include "Main/Main.h"
#include "Main/jkMain.h"
#include "Main/jkStrings.h"
#include "stdPlatform.h"
#include "wprintf.h"
#include "Dss/jkDSS.h"
#include "../jk.h"
#include "Main/jkQuakeConsole.h"

void jkDev_DrawEntriesGPU();
void jkDev_BlitLogToScreenGPU();
void jkDev_RenderQuakeConsole();

// MOTS altered
void jkDev_Startup()
{
#ifndef PLATFORM_POSIX
    if ( Main_bDevMode && Main_bWindowGUI)
    {
        jkDev_hDlg = jk_CreateDialogParamA(stdGdi_GetHInstance(), (LPCSTR)0x70, 0, jkDev_DialogFunc, 0);
        if ( jkDev_hDlg )
            Window_AddDialogHwnd(jkDev_hDlg);

    }
#endif

    sithConsole_Startup(JKDEV_NUM_CHEATS*2);
    sithConsole_Open(16);
    sithConsole_SetPrintFuncs(jkDev_DebugLog, jkDev_PrintUniString);

    jkDev_cheatHashtable = stdHashTable_New(JKDEV_NUM_CHEATS*2);
    _memset(jkDev_aCheatCmds, 0, sizeof(stdDebugConsoleCmd) * JKDEV_NUM_CHEATS);

    sithConsole_RegisterDevCmd(jkDev_CmdVersion, "version", 0);
    sithConsole_RegisterDevCmd(jkDev_CmdTeam, "team", 0);
    sithConsole_RegisterDevCmd(jkDev_CmdFramerate, "framerate", 0);
    sithConsole_RegisterDevCmd(jkDev_CmdDispStats, "dispstats", 0);
    sithConsole_RegisterDevCmd(jkDev_CmdKill, "kill", 0);
    sithConsole_RegisterDevCmd(jkDev_CmdEndLevel, "endlevel", 0);

    jkDev_RegisterCmd(jkDev_CmdDebugFlags, "whiteflag", "Disable AI", 0);
    jkDev_RegisterCmd(jkDev_CmdFly, "eriamjh", "", 0);
    jkDev_RegisterCmd(jkDev_CmdDebugFlags2, "jediwannabe", "Invul", 5);
    jkDev_RegisterCmd(jkDev_CmdWarp, "warp", "", 0);
    jkDev_RegisterCmd(jkDev_CmdActivate, "activate", "", 0);
    jkDev_RegisterCmd(jkDev_CmdDebugFlags3, "slowmo", "Slowmo", 7);
    jkDev_RegisterCmd(jkDev_CmdJump, "hyper", "", 0);
    jkDev_RegisterCmd(jkDev_CmdEndLevel2, "thereisnotry", "", 0);
    jkDev_RegisterCmd(jkDev_CmdAllWeapons, "red5", "", 0);
    jkDev_RegisterCmd(jkDev_CmdAllItems, "wamprat", "", 0);
    jkDev_RegisterCmd(jkDev_CmdLightMaster, "imayoda", "", 0); // MOTS removed
    jkDev_RegisterCmd(jkDev_CmdDarkMaster, "sithlord", "", 0); // MOTS removed
    jkDev_RegisterCmd(jkDev_CmdUberJedi, "raccoonking", "", 0);
    jkDev_RegisterCmd(jkDev_CmdLevelUp, "deeznuts", "", 0);
    jkDev_RegisterCmd(jkDev_CmdHeal, "bactame", "", 0);
    jkDev_RegisterCmd(jkDev_CmdAllMap, "5858lvr", "", 0);
    jkDev_RegisterCmd(jkDev_CmdMana, "yodajammies", "", 0);
    jkDev_RegisterCmd(jkDev_CmdSkipToLevel, "pinotnoir", "", 0);

    // Added: MoTS cheats
    jkDev_RegisterCmd(jkDev_CmdDebugFlags, "statuesque", "Disable AI", 0);
    jkDev_RegisterCmd(jkDev_CmdFly, "freebird", "", 0);
    jkDev_RegisterCmd(jkDev_CmdDebugFlags2, "boinga", "Invul", 5);
    jkDev_RegisterCmd(jkDev_CmdWarp, "youarehere", "", 0); // Undoc'd?
    jkDev_RegisterCmd(jkDev_CmdActivate, "makeitwork", "", 0); // Undoc'd?
    jkDev_RegisterCmd(jkDev_CmdDebugFlags3, "gospeedgo", "Slowmo", 7);
    jkDev_RegisterCmd(jkDev_CmdJump, "quickzap", "", 0);
    jkDev_RegisterCmd(jkDev_CmdEndLevel2, "gameover", "", 0);
    jkDev_RegisterCmd(jkDev_CmdAllWeapons, "diediedie", "", 0);
    jkDev_RegisterCmd(jkDev_CmdAllItems, "gimmestuff", "", 0);
    jkDev_RegisterCmd(jkDev_CmdUberJedi, "iamagod", "", 0);
    jkDev_RegisterCmd(jkDev_CmdLevelUp, "trainme", "", 0);
    jkDev_RegisterCmd(jkDev_CmdHeal, "morelife", "", 0); // Undoc'd?
    jkDev_RegisterCmd(jkDev_CmdAllMap, "cartograph", "", 0);
    jkDev_RegisterCmd(jkDev_CmdMana, "trixie", "", 0);
    jkDev_RegisterCmd(jkDev_CmdSkipToLevel, "takemeto", "", 0); // Undoc'd?

#ifdef QOL_IMPROVEMENTS
    jkDev_RegisterCmd(jkDev_CmdNoclip, "noclip", "Noclip", 0);
	jkDev_RegisterCmd(jkDev_Custom_CmdJumpNextCheckpoint, "checkmate", "", 0);  // cycles to next auto-restart checkpoint
#endif

    jkDev_bInitted = 1;
}

void jkDev_Shutdown()
{
    if ( jkDev_cheatHashtable )
    {
        stdHashTable_Free(jkDev_cheatHashtable);
        jkDev_cheatHashtable = 0;
    }
    sithConsole_Close();
    sithConsole_Shutdown();
    jkDev_bInitted = 0;
}

int jkDev_Open()
{
    stdVBuffer **v1; // edx
    stdBitmap *v3; // edx
    stdVBufferTexFmt a1; // [esp+0h] [ebp-4Ch] BYREF

    if ( jkDev_bOpened )
        return 0;

    v1 = jkHud_pMsgFontSft->bitmap->mipSurfaces;
    jkDev_log_55A4A4 = 0;
    jkDev_BMFontHeight = (*v1)->format.height;

    _memcpy(&a1, &stdDisplay_pCurVideoMode->format, sizeof(a1));
    a1.height = 5 * jkDev_BMFontHeight;
#ifdef SDL2_RENDER
    a1.width -= (48*2); // Make sure the hud scaling doesn't cause overlap
#endif

    jkDev_vbuf = stdDisplay_VBufferNew(&a1, 1, 0, 0);
    v3 = jkHud_pMsgFontSft->bitmap;
    jkDev_ColorKey = v3->colorkey;

    if ( jkDev_vbuf )
    {
        stdDisplay_VBufferFill(jkDev_vbuf, jkDev_ColorKey, 0);
        stdDisplay_VBufferSetColorKey(jkDev_vbuf, jkDev_ColorKey);
    }

    jkDev_bOpened = 1;
    return 1;
}

void jkDev_Close()
{
    if (!jkDev_bOpened)
        return;

    if ( jkDev_vbuf )
    {
        stdDisplay_VBufferFree(jkDev_vbuf);
        jkDev_vbuf = NULL;
    }

    jkDev_bOpened = 0;
}

void jkDev_DrawLog()
{
    stdVBuffer *v0; // ecx
    int v1; // ebp
    signed int v2; // edi
    jkDevLogEnt* v4; // esi
    int v5; // edx
    int v6; // eax
    rdCanvas *v7; // ebp
    int v8; // edx
    signed int v9; // ebx
    int v10; // edi
    jkDevLogEnt* v11; // esi
    int v12; // eax
    int v13; // edx
    int v14; // eax
    rdRect a4; // [esp+10h] [ebp-10h] BYREF

    jkDev_UpdateEntries();
    v0 = jkDev_vbuf;
    v1 = 0;
    jkDev_DrawEntries();

    if ( v0 )
    {
        v7 = Video_pCanvas;
        v8 = jkDev_dword_55A9D0;
        a4.height = jkDev_BMFontHeight;
        v9 = 4;
        v10 = 0;
        v11 = &jkDev_aEntries[0];
        for (int i = 0; i < 5; i++)
        {
            if ( v11->field_10C && (v9 < v7->yStart || jkDev_aEntryPositions[v8 + v10].x < v7->xStart) )
            {
                v12 = v8 + v10;
                a4.y = v9;
                v13 = jkDev_aEntryPositions[v12].x;
                v14 = jkDev_aEntryPositions[v12].y;
                a4.x = v13;
                a4.width = v14;
                stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, &a4);
                v7 = Video_pCanvas;
                v8 = jkDev_dword_55A9D0;
            }
            v11->bDrawEntry = v11->field_10C;
            if ( v11->field_10C > 0 )
                --v11->field_10C;
            ++v11;
            v9 += jkDev_BMFontHeight;
            v10 += 2;
        }
    }
}

// MOTS altered
void jkDev_BlitLogToScreen()
{
    int v0; // ecx
    int v1; // ebx
    int v2; // ebp
    jkDevLogEnt* v3; // edi
    int v4; // esi
    int v5; // ecx
    int v6; // eax
    rdRect v7; // [esp+0h] [ebp-10h] BYREF

#ifdef SDL2_RENDER
    jkDev_BlitLogToScreenGPU();
    return;
#endif

    if ( jkDev_vbuf )
    {
        v0 = jkDev_BMFontHeight;
        v7.x = 0;
        v7.y = 0;
        v7.height = jkDev_BMFontHeight;
        v1 = 4;
        v2 = 0;
        v3 = &jkDev_aEntries[0];
        for (int i = 0; i < 5; i++)
        {
            if ( v2 < jkDev_log_55A4A4 && (v1 + v7.height > Video_pCanvas->yStart || v3->bDrawEntry) )
            {
                v7.width = v3->drawWidth;
                v4 = (signed int)(stdDisplay_pCurVideoMode->format.width - v7.width) / 2;
                if ( v4 < 0 )
                    v4 = 0;
                stdDisplay_VBufferCopy(Video_pMenuBuffer, jkDev_vbuf, v4, v1, &v7, 1);
                v5 = v7.width;
                v6 = jkDev_dword_55A9D0 + 2 * v2;
                jkDev_aEntryPositions[v6].x = v4;
                jkDev_aEntryPositions[v6].y = v5;
                v0 = jkDev_BMFontHeight;
            }
            if ( v3->bDrawEntry > 0 )
                --v3->bDrawEntry;
            v1 += v0;
            ++v3;
            ++v2;
            v7.y += v0;
        }
        jkDev_dword_55A9D0 = (jkDev_dword_55A9D0 + 1) % 2;
    }
}

// MOTS altered
void jkDev_BlitLogToScreenGPU()
{
    int v1; // ebx
    int v2; // ebp
    jkDevLogEnt* v3; // edi
    int v4; // esi
    int v5; // ecx
    int v6; // eax
    rdRect v7; // [esp+0h] [ebp-10h] BYREF

    if (!jkDev_vbuf) return;

    v7.x = 0;
    v7.y = 0;
    v7.height = (int)((float)jkDev_BMFontHeight * jkPlayer_hudScale);
    v1 = 4;
    v2 = 0;
    v3 = &jkDev_aEntries[0];
    for (int i = 0; i < 5; i++)
    {
        if ( v2 < jkDev_log_55A4A4 && (v1 + v7.height > Video_pCanvas->yStart || v3->bDrawEntry) )
        {
            v7.width = v3->drawWidth;
            v4 = (signed int)(stdDisplay_pCurVideoMode->format.width - v7.width) / 2;
            if ( v4 < 0 )
                v4 = 0;
            //stdDisplay_VBufferCopy(Video_pMenuBuffer, jkDev_vbuf, v4, v1, &v7, 1);
            stdFont_DrawMultilineCenteredGPU(jkHud_pMsgFontSft, 0, v1, stdDisplay_pCurVideoMode->format.width, v3->text, 1, jkPlayer_hudScale);
            v5 = v7.width;
            v6 = jkDev_dword_55A9D0 + 2 * v2;
            jkDev_aEntryPositions[v6].x = v4;
            jkDev_aEntryPositions[v6].y = v5;
            //printf("Draw?\n %u %u\n", v4, v1);
        }
        if ( v3->bDrawEntry > 0 )
            --v3->bDrawEntry;
        //v1 += (int)((float)jkDev_BMFontHeight * jkPlayer_hudScale);
        v1 += stdFont_DrawMultilineCenteredHeight(jkHud_pMsgFontSft, 0, v1, stdDisplay_pCurVideoMode->format.width, v3->text, 1, jkPlayer_hudScale);
        ++v3;
        ++v2;
        v7.y += (int)((float)jkDev_BMFontHeight * jkPlayer_hudScale);
    }
    jkDev_dword_55A9D0 = (jkDev_dword_55A9D0 + 1) % 2;
}

// MOTS altered? inlined?
int jkDev_PrintUniString(const wchar_t *str)
{
    int v1; // ecx
    int v2; // edx
    int v3; // ecx
    int v5; // edi
    int v6; // esi

    v1 = jkDev_log_55A4A4;
    if ( jkDev_log_55A4A4 >= 5 )
    {
        v2 = 0;
        v3 = 0;
        while ( jkDev_aEntries[v3].timeMsExpiration == -1 )
        {
            ++v3;
            if ( v3 >= 5 )
                goto LABEL_7;
        }
        v2 = v3;
LABEL_7:
        jkDev_aEntries[v2].timeMsExpiration = 0;
        jkDev_UpdateEntries();
        v1 = jkDev_log_55A4A4;
    }
    v5 = v1;
    v6 = v1;
    _wcsncpy(jkDev_aEntries[v1].text, str, 0x80u);
    jkDev_aEntries[v6].field_104 = 0;
    jkDev_aEntries[v6].timeMsExpiration = stdPlatform_GetTimeMsec() + 5000;
    jkDev_bScreenNeedsUpdate = 1;
    ++jkDev_log_55A4A4;
    jkDev_aEntries[v6].bDrawEntry = 2;
    jkDev_aEntries[v6].field_10C = 2;
#ifdef QOL_IMPROVEMENTS
    char tmp[256];
    char tmp2[256+2];
    stdString_WcharToChar(tmp, str, 255);
    tmp[255] = 0;
    printf("\r                                            \r");
    stdString_snprintf(tmp2, sizeof(tmp2), "%s%c", tmp, _strlen(tmp) && tmp[_strlen(tmp)-1] == '\n' ? ' ' : '\n');
    printf("%s", tmp2);
    jkQuakeConsole_PrintLine(tmp2);
#endif
    return v5;
}

// MOTS altered? inlined?
int jkDev_DebugLog(const char *lParam)
{
    HWND v1; // eax
    wchar_t a1[128]; // [esp+8h] [ebp-100h] BYREF

    stdString_CharToWchar(a1, lParam, 127);
    a1[127] = 0;
    int ret = jkDev_PrintUniString(a1);
#ifdef WIN32
    if ( jkDev_hDlg )
    {
        v1 = GetDlgItem(jkDev_hDlg, 1037);
        WinIdk_PrintConsole(v1, (LPARAM)lParam, 50);
    }
#else
    //printf("%s", lParam);
#endif
    return ret;
}

int jkDev_sub_41FB80(int a1, const wchar_t *a2)
{
    int result; // eax
    int v3; // edi
    jkDevLogEnt *v4; // esi

    result = 0;
    v3 = 0;
    if ( jkDev_log_55A4A4 <= 0 )
    {
LABEL_9:
        if ( !result )
        {
            int tmp = jkDev_PrintUniString(a2);
            jkDev_aEntries[tmp].field_104 = a1;
            jkDev_aEntries[tmp].timeMsExpiration = -1;
        }
    }
    else
    {
        v4 = jkDev_aEntries;
        while ( !result )
        {
            if ( v4->field_104 == a1 )
            {
                if ( __wcscmp(v4->text, a2) )
                {
                    _wcsncpy(v4->text, a2, 0x80u);
                    v4->bDrawEntry = 2;
                    v4->field_10C = 2;
                    jkDev_bScreenNeedsUpdate = 1;
                }
                result = 1;
            }
            ++v3;
            ++v4;
            if ( v3 >= jkDev_log_55A4A4 )
                goto LABEL_9;
        }
    }
    return result;
}

int jkDev_sub_41FC40(int a1, const char *a2)
{
    wchar_t a1a[128]; // [esp+0h] [ebp-100h] BYREF

    stdString_CharToWchar(a1a, a2, 127);
    a1a[127] = 0;
    return jkDev_sub_41FB80(a1, a1a);
}

void jkDev_sub_41FC90(int a1)
{
    int v1; // eax
    jkDevLogEnt* v2; // ecx

    v1 = 0;
    if ( jkDev_log_55A4A4 > 0 )
    {
        v2 = &jkDev_aEntries[0];
        do
        {
            if ( v2->field_104 == a1 )
                break;
            ++v1;
            ++v2;
        }
        while ( v1 < jkDev_log_55A4A4 );
    }
    if ( v1 < jkDev_log_55A4A4 )
        jkDev_aEntries[v1].timeMsExpiration = 0;
}

int jkDev_RegisterCmd(void *pfCheatFunc, const char *pCryptCheatStr, const char *pCheatFlavortext, int extra)
{
    if ( jkDev_numCheats == JKDEV_NUM_CHEATS )
        return 0;

    _strncpy(jkDev_aCheatCmds[jkDev_numCheats].cmdStr, pCheatFlavortext, 0x1Fu);
    jkDev_aCheatCmds[jkDev_numCheats].cmdStr[31] = 0;
    jkDev_aCheatCmds[jkDev_numCheats].cmdFunc = pfCheatFunc;
    jkDev_aCheatCmds[jkDev_numCheats].extra = extra;
    stdHashTable_SetKeyVal(jkDev_cheatHashtable, pCryptCheatStr, &jkDev_aCheatCmds[jkDev_numCheats]);

    ++jkDev_numCheats;
    return 1;
}

int jkDev_TryCommand(const char *cmd)
{
    char *v1; // eax
    stdDebugConsoleCmd *pFoundCmd; // esi
    char *v5; // eax
    char key[128]; // Added: increased len 32->128
    char SrcStr[128]; // [esp+24h] [ebp-80h] BYREF

    _strncpy(SrcStr, cmd, 0x80);
    SrcStr[127] = 0;
    _strtolower(SrcStr);
    v1 = _strtok(SrcStr, ", \t\n\r");
    if ( !v1 )
        return 0;
    _strncpy(key, v1, 128);
    key[127] = 0;
    jkDev_Decrypt(key);
    pFoundCmd = (stdDebugConsoleCmd *)stdHashTable_GetKeyVal(jkDev_cheatHashtable, key);
    if ( !pFoundCmd )
        return 0;
    v5 = _strtok(0, "\n\r");
    pFoundCmd->cmdFunc(pFoundCmd, v5);
    return 1;
}

char* jkDev_Decrypt(char *cheatStr)
{
    char* result = cheatStr;

    // Added: Don't bother with the weird cheat encryption
#if 0
    for (char i = *cheatStr; i; ++result )
    {
        *result = i ^ 0xC5;
        i = result[1];
    }
#endif
    return result;
}

int jkDev_CmdVersion(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    _sprintf(std_genBuffer, "Jedi Knight v%d.%d%c %s %s\n", jkGuiTitle_verMajor, jkGuiTitle_verMinor, jkGuiTitle_verRevision, "Sep  8 1997", "16:17:30");
    sithConsole_Print(std_genBuffer);
    return 1;
}

int jkDev_CmdFramerate(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    Main_bFrameRate = !Main_bFrameRate;
    return 1;
}

int jkDev_CmdDispStats(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    Main_bDispStats = !Main_bDispStats;
    return 1;
}

int jkDev_CmdKill(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    sithActor_Hit(sithPlayer_pLocalPlayerThing, sithPlayer_pLocalPlayerThing, 200.0, 1);
    return 1;
}

int jkDev_CmdEndLevel(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( sithNet_isMulti && sithNet_isServer )
        jkDSS_SendEndLevel();
    return 1;
}

int jkDev_CmdSkipToLevel(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int argInt = 0;

    if ( sithNet_isMulti )
        return 1;
    if ( !pArgStr || !_sscanf(pArgStr, "%d", &argInt) )
        return 0;
    if ( !jkEpisode_mLoad.paEntries )
        return 0;

    jkMain_SetMap(argInt);
    return 1;
}

int jkDev_Custom_CmdJumpNextCheckpoint(stdDebugConsoleCmd* pCmd, const char* pArgStr)
{
    char tmp[128];

    if (sithNet_isMulti)
        return 1;

    jkPlayer_dword_525470 = 1;
    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithWorld_pCurrentWorld->map_jkl_fname);
    stdFnames_ChangeExt(tmp, "jks");
    return sithGamesave_Load(tmp, 1, 0);
}

int jkDev_CmdDebugFlags(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        sithCommand_CheatSetDebugFlags(pCmd, pArgStr);
    return 1;
}

int jkDev_CmdFly(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        sithCommand_CmdFly(pCmd, pArgStr);
    return 1;
}

int jkDev_CmdDebugFlags2(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        sithCommand_CheatSetDebugFlags(pCmd, pArgStr);
    return 1;
}

int jkDev_CmdWarp(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    float v4; // [esp+4h] [ebp-8h] BYREF
    float v5; // [esp+8h] [ebp-4h] BYREF
    float v6;

    if ( !sithNet_isMulti )
    {
        if ( pArgStr )
        {
            if ( _sscanf(pArgStr, "%f %f %f", &v5, &v4, &v6) == 3 )
                sithCommand_CmdWarp(pCmd, pArgStr);
        }
    }
    return 1;
}

int jkDev_CmdActivate(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        sithCommand_CmdActivate(pCmd, pArgStr);
    return 1;
}

int jkDev_CmdDebugFlags3(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        sithCommand_CheatSetDebugFlags(pCmd, pArgStr);
    return 1;
}

int jkDev_CmdJump(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        sithCommand_CmdJump(pCmd, pArgStr);
    return 1;
}

int jkDev_CmdEndLevel2(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
        jkMain_EndLevel(1);
    return 1;
}

// MOTS altered
int jkDev_CmdAllWeapons(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        if (!Main_bMotsCompat) {
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_STORMTROOPER_RIFLE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_THERMAL_DETONATOR, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_TUSKEN_PROD, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_REPEATER, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_RAIL_DETONATOR, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_SEQUENCER_CHARGE, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_CONCUSSION_RIFLE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_LIGHTSABER, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_ENERGY, 500.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_POWER, 500.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_BATTERY, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_RAILCHARGES, 100.0);
        }

        if (Main_bMotsCompat) {
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_BRYARPISTOL, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_STORMTROOPER_RIFLE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_THERMAL_DETONATOR, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_CARBO_GUN, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_REPEATER, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_RAIL_DETONATOR, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_SEQUENCER_CHARGE, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_CONCUSSION_RIFLE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_EWEB, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_LIGHTSABER, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_BLASTECH, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_STORMTROOPER_SCOPE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_FLASH_BOMB, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_TUSKEN_PROD, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_RAIL_SEEKER, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_MOTS_MANUAL_SEQUENCER, 1.0);

            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_ENERGY, 500.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_POWER, 500.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_BATTERY, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_RAILCHARGES, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_CARBPELLETS, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_SEEKRAILS, 100.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_EWEB_ROUNDS, 500.0);
        }

        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_ALLWEAPONS"));
    }
    return 1;
}

// MOTS altered
int jkDev_CmdAllItems(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        if (!Main_bMotsCompat)
        {
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_BACTATANK, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_IRGOGGLES, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_FIELDLIGHT, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYIMPERIAL, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_WRENCH, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_DATADISK, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYRED, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYBLUE, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYYELLOW, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHBLUE, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHYELLOW, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYGREEN, 1);

            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_BACTATANK, 9.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_IRGOGGLES, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FIELDLIGHT, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYIMPERIAL, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_WRENCH, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_DATADISK, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYRED, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYBLUE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYYELLOW, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHBLUE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHYELLOW, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYGREEN, 1.0);
        }
        else {
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_BACTATANK, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_IRGOGGLES, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_FIELDLIGHT, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYIMPERIAL, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_WRENCH, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_DATADISK, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYRED, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYBLUE, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYYELLOW, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHBLUE, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHYELLOW, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_KEYGREEN, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_TSKNCLOTHES, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_HVYEXPLOSIVE, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_HLCRN, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_DRARM, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_PRYBAR, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_RADIO, 1);

            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_BACTATANK, 9.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_IRGOGGLES, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FIELDLIGHT, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYIMPERIAL, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_WRENCH, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_DATADISK, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYRED, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYBLUE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYYELLOW, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHBLUE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_WRCHYELLOW, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_KEYGREEN, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_TSKNCLOTHES, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_HVYEXPLOSIVE, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_HLCRN, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_DRARM, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_PRYBAR, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_RADIO, 1.0);
        }
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_ALLITEMS"));
    }
    return 1;
}

int jkDev_CmdLightMaster(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if (Main_bMotsCompat) return 1; // Added

    if ( !sithNet_isMulti )
    {
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_JEDI_RANK, 2.0);
        jkPlayer_SetRank(2);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, (float)(50 * jkPlayer_GetJediRank()));
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_THROW, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_LIGHTNING, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 1.0);
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_LIGHTMASTER"));
    }
    return 1;
}

int jkDev_CmdDarkMaster(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if (Main_bMotsCompat) return 1; // Added

    if ( !sithNet_isMulti )
    {
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_JEDI_RANK, 2.0);
        jkPlayer_SetRank(2);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, (float)(50 * jkPlayer_GetJediRank()));
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 0);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_THROW, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_LIGHTNING, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 1);
        sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 1);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_THROW, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_LIGHTNING, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 1.0);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 1.0);
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_DARKMASTER"));
    }
    return 1;
}

// MOTS altered
int jkDev_CmdUberJedi(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        if (!Main_bMotsCompat)
        {
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_JEDI_RANK, 2.0);
            jkPlayer_SetRank(2);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, 100.0);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_THROW, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_LIGHTNING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 1);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_THROW, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_LIGHTNING, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 1.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 1.0);
        }
        else {
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_JEDI_RANK, 8.0);
            jkPlayer_SetRank(8);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, 400.0);

            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_FARSIGHT, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROJECT, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_SABERTHROW, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_PUSH, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_CHAINLIGHT, 1);
            sithInventory_SetAvailable(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEFENSE, 1);

            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_FARSIGHT, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROJECT, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SABERTHROW, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PUSH, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_CHAINLIGHT, 4.0);
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEFENSE, 4.0);
        }
        
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_UBERJEDI"));
    }
    return 1;
}

// MOTS altered
int jkDev_CmdLevelUp(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        jkDev_amt = jkDev_amt - -1.0;
        if ( jkDev_amt > 4.0 )
            jkDev_amt = 1.0;
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_JEDI_RANK, jkDev_amt + jkDev_amt);
        jkPlayer_SetRank((__int64)(jkDev_amt + jkDev_amt));
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, (float)(50 * jkPlayer_GetJediRank()));
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_JUMP, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SPEED, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_SEEING, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PULL, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_HEALING, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PERSUASION, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_ABSORB, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_BLINDING, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_PROTECTION, jkDev_amt);
        if (!Main_bMotsCompat)
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_THROW, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_GRIP, jkDev_amt);
        if (!Main_bMotsCompat)
            sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_LIGHTNING, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DESTRUCTION, jkDev_amt);
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_F_DEADLYSIGHT, jkDev_amt);

        if (!Main_bMotsCompat) {
            float v9 = 0.0;
            for (int i = SITHBIN_F_HEALING; i <= SITHBIN_F_ABSORB; ++i )
            {
                if ( sithInventory_GetCarries(sithPlayer_pLocalPlayerThing, i) )
                    v9 = sithInventory_GetBinAmount(sithPlayer_pLocalPlayerThing, i) * 5.0 + v9;
            }
            for (int j = SITHBIN_F_THROW; j <= SITHBIN_F_DESTRUCTION; ++j )
            {
                if ( sithInventory_GetCarries(sithPlayer_pLocalPlayerThing, j) )
                    v9 = v9 - sithInventory_GetBinAmount(sithPlayer_pLocalPlayerThing, j) * 5.0;
            }
        }

        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_LEVELUP"));
    }
    return 1;
}

int jkDev_CmdHeal(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        sithPlayer_pLocalPlayerThing->actorParams.health = sithPlayer_pLocalPlayerThing->actorParams.maxHealth;
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_SHIELDS, 200.0);
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_HEAL"));
    }
    return 1;
}

int jkDev_CmdAllMap(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        g_mapModeFlags ^= 0x42u;
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_ALLMAP"));
    }
    return 1;
}

int jkDev_CmdMana(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !sithNet_isMulti )
    {
        sithInventory_SetBinAmount(sithPlayer_pLocalPlayerThing, SITHBIN_FORCEMANA, 400.0);
        sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GAME_MANA"));
    }
    return 1;
}

// MOTS altered
int jkDev_CmdTeam(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if ( !pArgStr || !sithNet_isMulti || (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) == 0 || (sithNet_MultiModeFlags & MULTIMODEFLAG_100) == 0 )
        return 1;

    uint32_t v2 = _atol(pArgStr);
    if ( !v2 || v2 >= 5 )
        return 0;

    jkDSS_SendSetTeam(v2);
    return 1;
}

// Dialog stuff

int jkDev_UpdateEntries()
{
    int v0; // ebp
    signed int result; // eax
    jkDevLogEnt* v2; // edi
    jkDevLogEnt* v3; // esi
    int v4; // [esp+4h] [ebp-8h]
    unsigned int v5; // [esp+8h] [ebp-4h]

    v0 = 0;
    v4 = 0;
    v5 = stdPlatform_GetTimeMsec();
    result = 0;
    if ( jkDev_log_55A4A4 > 0 )
    {
        v2 = &jkDev_aEntries[0];
        v3 = &jkDev_aEntries[0];
        do
        {
            if ( v3->timeMsExpiration <= v5 )
            {
                v3->bDrawEntry = 2;
                v3->field_10C = 2;
            }
            else
            {
                if ( v4 != v0 )
                {
                    _wcsncpy(v2->text, v3->text, 0x80u);
                    result = 1;
                    v2->timeMsExpiration = v3->timeMsExpiration;
                    v2->field_104 = v3->field_104;
                    v2->bDrawEntry = 2;
                    v2->field_10C = 2;
                    v3->bDrawEntry = 2;
                    v3->field_10C = 2;
                    jkDev_bScreenNeedsUpdate = 1;
                }
                ++v2;
                ++v4;
            }
            ++v0;
            ++v3;
        }
        while ( v0 < jkDev_log_55A4A4 );
    }
    jkDev_log_55A4A4 = v4;
    return result;
}

void jkDev_DrawEntries()
{
    int v0; // ebp
    signed int v1; // edi
    jkDevLogEnt* v3; // esi
    rdRect a4; // [esp+8h] [ebp-10h] BYREF

    // Added: GPU rendered text
#ifdef SDL2_RENDER
    jkDev_DrawEntriesGPU();
    return;
#endif

    v0 = 0;
    if ( jkDev_vbuf )
    {
        if ( jkDev_bScreenNeedsUpdate )
        {
            v1 = 0;
            jkDev_bScreenNeedsUpdate = 0;
            if ( jkDev_log_55A4A4 > 0 )
            {
                v3 = &jkDev_aEntries[0];
                do
                {
                    if ( v3->bDrawEntry )
                    {
                        a4.height = jkDev_BMFontHeight;
                        a4.width = v3->drawWidth;
                        a4.x = 0;
                        a4.y = v1;
                        stdDisplay_VBufferFill(jkDev_vbuf, jkDev_ColorKey, &a4);
                        v3->drawWidth = stdFont_Draw1(jkDev_vbuf, jkHud_pMsgFontSft, 0, v1, jkDev_vbuf->format.width, v3->text, 0);
                    }
                    v1 += jkDev_BMFontHeight;
                    ++v0;
                    ++v3;
                }
                while ( v0 < jkDev_log_55A4A4 );
            }
        }
    }
}

void jkDev_DrawEntriesGPU()
{
    int v0; // ebp
    signed int v1; // edi
    jkDevLogEnt* v3; // esi
    rdRect a4; // [esp+8h] [ebp-10h] BYREF

    v0 = 0;
    if ( jkDev_vbuf )
    {
        //if ( jkDev_bScreenNeedsUpdate )
        {
            v1 = 0;
            jkDev_bScreenNeedsUpdate = 0;
            if ( jkDev_log_55A4A4 > 0 )
            {
                v3 = &jkDev_aEntries[v0];
                do
                {
                    //if ( v3->bDrawEntry )
                    {
                        a4.height = (int)((float)jkDev_BMFontHeight * jkPlayer_hudScale);
                        a4.width = v3->drawWidth;
                        a4.x = 0;
                        a4.y = v1;
                        stdDisplay_VBufferFill(jkDev_vbuf, jkDev_ColorKey, &a4); // jkDev_vbuf->format.width
                        v3->drawWidth = stdFont_Draw1Width(jkHud_pMsgFontSft, 0, v1, Video_menuBuffer.format.width, v3->text, 0, jkPlayer_hudScale);
                    }
                    v1 += (int)((float)jkDev_BMFontHeight * jkPlayer_hudScale);
                    ++v0;
                    ++v3;
                }
                while ( v0 < jkDev_log_55A4A4 );
            }
        }
    }
}

#ifdef QOL_IMPROVEMENTS
int jkDev_CmdNoclip(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if (sithNet_isMulti ) return 1;

    sithThing *v0; // ecx
    wchar_t *v3; // eax

    if (!sithWorld_pCurrentWorld || !sithWorld_pCurrentWorld->playerThing) {
        sithConsole_Print("No world.");
        return 0;
    }

    v0 = sithWorld_pCurrentWorld->playerThing;

    if ( v0->moveType == SITH_MT_PHYSICS )
    {
        if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP))
        {
            v0->physicsParams.physflags &= ~SITH_PF_FLY;
            v0->physicsParams.physflags |= SITH_PF_USEGRAVITY;
            g_debugmodeFlags &= ~DEBUGFLAG_NOCLIP;
            sithPlayer_bNoClippingRend = 0;
            sithConsole_Print("Noclip OFF");
        }
        else
        {
            v0->physicsParams.physflags &= ~SITH_PF_USEGRAVITY;
            v0->physicsParams.physflags |= SITH_PF_FLY;
            g_debugmodeFlags |= DEBUGFLAG_NOCLIP;
            sithConsole_Print("Noclip ON");
        }
        
        return 1;
    }
    else
    {
        sithConsole_Print("Not physics thing.");
        return 0;
    }

    return 0;
}
#endif
