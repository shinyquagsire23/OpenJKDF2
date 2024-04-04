#include "jkGUIMultiplayer.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Dss/sithMulti.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIBuildMulti.h"
#include "Gui/jkGUINetHost.h"
#include "Gui/jkGUIDialog.h"
#include "Main/jkStrings.h"
#include "Main/jkMain.h"
#include "Win95/stdComm.h"
#include "Platform/wuRegistry.h"
#include "General/stdString.h"
#include "Devices/sithComm.h"

static int jkGuiMultiplayer_bInitted = 0;
static int jkGuiMultiplayer_aElements2_aIdk[2] = {0xd, 0xe};
static int jkGuiMultiplayer_aElements3_aIdk[2] = {0xd, 0xe};

static jkGuiElement jkGuiMultiplayer_aElements[6] = {
    {ELEMENT_TEXT,  0,  6, "GUI_MULTIPLAYER",  3, {0x4, 20, 0x258, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, 0x64,  2, "GUI_JOINGAME",  3, {0x50, 0x50, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, 0x65,  2, "GUI_STARTGAME",  3, {0x168, 0x50, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, 0x66,  2, "GUI_MULTIPLAYER_CHARACTERS",  3, {170, 0x78, 300, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, -1,  2, "GUI_CANCEL",  3, {20, 0x1AE, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0},
};

static jkGuiElement jkGuiMultiplayer_aElements2[7] = {
    {ELEMENT_TEXT,  0,  0,  0,  3, {0, 0x19A, 0x280, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  6, "GUI_MULTIPLAYER",  3, {20, 20, 0x258, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  2, "GUI_CHOOSEAPROVIDER",  2, {170, 0x82, 0x1D6, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_LISTBOX,  1,  0,  0,  0, {100, 0xB4, 0x1B8, 0x6E},  1,  0, "GUI_PROVIDER_HINT",  0,  0, jkGuiMultiplayer_aElements2_aIdk, {0},  0},
    {ELEMENT_TEXTBUTTON,  1,  2, "GUI_OK",  3, {0x1A4, 0x1AE, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, -1,  2, "GUI_CANCEL",  3, {20, 0x1AE, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0},
};

static jkGuiElement jkGuiMultiplayer_aElements3[13] = {
    {ELEMENT_TEXT,  0,  0,  0,  3, { 0, 0x19A, 0x280, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  6, "GUI_MULTIPLAYER",  3, {20, 20, 0x258, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  0, "GUI_CHOOSEAGAME",  2, {170, 0x82, 0x1C2, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_LISTBOX,  1,  0,  0,  0, {170, 0xA0, 320, 0x6E},  1,  0, "GUI_GAMESTOJOIN_HINT",  0, jkGuiMultiplayer_sub_413E00, jkGuiMultiplayer_aElements3_aIdk, {0},  0},
#ifdef QOL_IMPROVEMENTS
    {ELEMENT_TEXT,  0,  0, "GUINET_PASSWORD",  2, {170, 300+5, 100, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBOX,  0,  0, jkGuiMultiplayer_stru_556168.field_300, 0x20, {280, 295+10, 210, 20},  1,  0,  0,  0,  0,  0, {0},  0},
#else
    {ELEMENT_TEXT,  0,  0, "GUINET_PASSWORD",  2, {170, 300, 100, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBOX,  0,  0, jkGuiMultiplayer_stru_556168.field_300, 0x20, {280, 295, 210, 20},  1,  0,  0,  0,  0,  0, {0},  0},
#endif
    {ELEMENT_TEXT,  0,  1, jkGuiMultiplayer_stru_556168.field_0,  3, {0x32, 0x14A, 0x21C, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  0, jkGuiMultiplayer_stru_556168.field_100,  3, {0x32, 0x163, 0x21C, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  0, jkGuiMultiplayer_stru_556168.field_200,  3, {0x32, 0x17C, 0x21C, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON,  1,  2, "GUI_OK",  3, {0x1A4, 0x1AE, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, -1,  2, "GUI_CANCEL",  3, {20, 0x1AE, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
#ifdef QOL_IMPROVEMENTS
    { ELEMENT_TEXTBOX, 0, 0, NULL, 255, { 170, 280, 320, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
#endif
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0},
};

static jkGuiElement jkGuiMultiplayer_aElements4[4] = {
    {ELEMENT_TEXT,  0,  6, "GUI_MULTIPLAYER",  3, {20, 20, 0x258, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  2, "GUI_SYNCHRONIZING",  3, { 0, 0xD2, 0x280, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXTBUTTON, -1,  2, "GUI_CANCEL",  3, {20, 0x1AE, 0xC8, 0x28},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0},
};

static jkGuiMenu jkGuiMultiplayer_menu = {jkGuiMultiplayer_aElements, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};
static jkGuiMenu jkGuiMultiplayer_menu2 = {jkGuiMultiplayer_aElements2, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};
static jkGuiMenu jkGuiMultiplayer_menu3 = {jkGuiMultiplayer_aElements3, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiMultiplayer_sub_4140B0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};
static jkGuiMenu jkGuiMultiplayer_menu4 = {jkGuiMultiplayer_aElements4, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiMultiplayer_idk, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

wchar_t jkGuiMultiplayer_ipText[256];

void jkGuiMultiplayer_Startup()
{
    jkGui_InitMenu(&jkGuiMultiplayer_menu, jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]);
    jkGui_InitMenu(&jkGuiMultiplayer_menu2, jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]);
    jkGui_InitMenu(&jkGuiMultiplayer_menu3, jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]);
    jkGui_InitMenu(&jkGuiMultiplayer_menu4, jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]);
    jkGuiMultiplayer_bInitted = 1;

#ifdef QOL_IMPROVEMENTS
    wuRegistry_GetWString("lastConnectedHost", jkGuiMultiplayer_ipText, 0x100, L"127.0.0.1");
    jkGuiMultiplayer_aElements3[11].wstr = jkGuiMultiplayer_ipText;
    jkGuiMultiplayer_aElements3[11].selectedTextEntry = 255;
#endif
}

void jkGuiMultiplayer_Shutdown()
{
    jkGuiMultiplayer_bInitted = 0;
}

// MOTS altered?
int jkGuiMultiplayer_Show()
{
    int result; // eax
    unsigned int v1; // esi
    sith_dplay_connection *v2; // edi
    int v3; // esi
    HRESULT v4; // eax
    wchar_t *v5; // eax
    wchar_t *v6; // eax
    int v7; // esi
    BOOL v8; // ecx
    HRESULT v10; // eax
    wchar_t *v11; // eax
    int v12; // esi
    int v13; // eax
    unsigned int v14; // esi
    sith_dplay_connection *v15; // edi
    int v16; // esi
    HRESULT v17; // eax
    wchar_t *v18; // eax
    wchar_t *v19; // eax
    wchar_t *v20; // eax
    int v21; // eax
    wchar_t *v22; // eax
    wchar_t *v23; // eax
    wchar_t *v24; // [esp-4h] [ebp-268h]
    wchar_t *v25; // [esp-4h] [ebp-268h]
    wchar_t *v27; // [esp-4h] [ebp-268h]
    wchar_t *v28; // [esp-4h] [ebp-268h]
    wchar_t *v29; // [esp-4h] [ebp-268h]
    wchar_t *v30; // [esp-4h] [ebp-268h]
    wchar_t *v31; // [esp-4h] [ebp-268h]
    Darray array; // [esp+10h] [ebp-254h] BYREF
    Darray a1; // [esp+28h] [ebp-23Ch] BYREF
    jkMultiEntry3 v34; // [esp+40h] [ebp-224h] BYREF
    jkMultiEntry4 v35; // [esp+180h] [ebp-E4h] BYREF

LABEL_1:
    while ( 2 )
    {
        while ( 2 )
        {
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu, &jkGuiMultiplayer_aElements[4]);
            result = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu);
            switch ( result )
            {
                case -1:
                    return result;
                case 100:
                    jkGuiRend_DarrayNewStr(&a1, 4, 1);
                    jkGuiRend_DarrayFreeEntry(&a1);
                    v1 = 0;
                    if ( jkGuiMultiplayer_numConnections )
                    {
                        v2 = jkGuiMultiplayer_aConnections;
                        do
                        {
                            jkGuiRend_DarrayReallocStr(&a1, v2->name, 0);
                            ++v1;
                            ++v2;
                        }
                        while ( v1 < jkGuiMultiplayer_numConnections );
                    }
                    jkGuiRend_AddStringEntry(&a1, 0, 0);
                    jkGuiRend_SetClickableString(&jkGuiMultiplayer_aElements2[3], &a1);
                    jkGuiMultiplayer_aElements2[3].selectedTextEntry = 0;
                    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMultiplayer_menu2, &jkGuiMultiplayer_aElements2[4]);
                    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu2, &jkGuiMultiplayer_aElements2[5]);
                    v3 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu2);
                    if ( v3 > 0 )
                    {
                        // TODO if this is a ptr, fix it
                        v4 = stdComm_OpenConnection((void*)jkGuiMultiplayer_aElements2[3].selectedTextEntry);
                        if ( v4 == 0x887700FA )
                        {
                            v24 = jkStrings_GetUniStringWithFallback("GUINET_NOTAVAIL");
                            v5 = jkStrings_GetUniStringWithFallback("GUINET_NETERROR");
                            jkGuiDialog_ErrorDialog(v5, v24);
                            v3 = -1;
                        }
                        else if ( v4 )
                        {
                            v25 = jkStrings_GetUniStringWithFallback("GUINET_NOCONNECT");
                            v6 = jkStrings_GetUniStringWithFallback("GUINET_NETERROR");
                            jkGuiDialog_ErrorDialog(v6, v25);
                            v3 = -1;
                        }
                        else
                        {
                            v3 = 1;
                        }
                    }
                    jkGuiRend_DarrayFree(&a1);
                    if ( v3 != 1 )
                        continue;
                    _memset(&v35, 0, sizeof(v35));
                    _memset(&jkGuiMultiplayer_stru_556168, 0, sizeof(jkGuiMultiplayer_stru_556168));
                    memset(&jkGui_guid_556040, 0, sizeof(GUID));
                    jkGuiRend_DarrayNewStr(&jkGuiMultiplayer_stru_5564A8, 8, 1);
                    jkGuiRend_DarrayReallocStr(&jkGuiMultiplayer_stru_5564A8, 0, 0);
                    jkGuiRend_SetClickableString(&jkGuiMultiplayer_aElements3[3], &jkGuiMultiplayer_stru_5564A8);
                    jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[9], &jkGuiMultiplayer_menu3, 0);
                    jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[5], &jkGuiMultiplayer_menu3, 0);
                    jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[4], &jkGuiMultiplayer_menu3, 0);
                    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMultiplayer_menu3, &jkGuiMultiplayer_aElements3[9]);
                    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu3, &jkGuiMultiplayer_aElements3[10]);
                    if ( jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu3) != 1 )
                        goto LABEL_29;
                    break;
                case 101:
                    _memset(&v34, 0, sizeof(v34));
                    jkGuiRend_DarrayNewStr(&array, 4, 1);
                    jkGuiRend_DarrayFreeEntry(&array);
                    v14 = 0;
                    if ( jkGuiMultiplayer_numConnections )
                    {
                        v15 = jkGuiMultiplayer_aConnections;
                        do
                        {
                            jkGuiRend_DarrayReallocStr(&array, v15->name, 0);
                            ++v14;
                            ++v15;
                        }
                        while ( v14 < jkGuiMultiplayer_numConnections );
                    }
                    jkGuiRend_AddStringEntry(&array, 0, 0);
                    jkGuiRend_SetClickableString(&jkGuiMultiplayer_aElements2[3], &array);
                    jkGuiMultiplayer_aElements2[3].selectedTextEntry = 0;
                    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMultiplayer_menu2, &jkGuiMultiplayer_aElements2[4]);
                    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu2, &jkGuiMultiplayer_aElements2[5]);
                    v16 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu2);
                    if ( v16 > 0 )
                    {
                        // TODO if this is a ptr, fix it
                        v17 = stdComm_OpenConnection((void*)jkGuiMultiplayer_aElements2[3].selectedTextEntry);
                        if ( v17 == 0x887700FA )
                        {
                            v28 = jkStrings_GetUniStringWithFallback("GUINET_NOTAVAIL");
                            v18 = jkStrings_GetUniStringWithFallback("GUINET_NETERROR");
                            jkGuiDialog_ErrorDialog(v18, v28);
                            v16 = -1;
                        }
                        else if ( v17 )
                        {
                            v29 = jkStrings_GetUniStringWithFallback("GUINET_NOCONNECT");
                            v19 = jkStrings_GetUniStringWithFallback("GUINET_NETERROR");
                            jkGuiDialog_ErrorDialog(v19, v29);
                            v16 = -1;
                        }
                        else
                        {
                            v16 = 1;
                        }
                    }
                    jkGuiRend_DarrayFree(&array);
                    if ( v16 != 1 )
                        continue;
                    v20 = jkStrings_GetUniStringWithFallback("GUI_DEFAULT_GAME_NAME");
                    jk_snwprintf(v34.serverName, 0x20u, v20, jkPlayer_playerShortName);
                    if ( jkGuiNetHost_Show(&v34) != 1 )
                        goto LABEL_51;
                    do
                    {
                        sithNet_scorelimit = v34.scoreLimit;
                        sithNet_multiplayer_timelimit = v34.timeLimit;
                        if ( jkGuiBuildMulti_ShowLoad(&jkGuiMultiplayer_mpcInfo, v34.episodeGobName, v34.mapJklFname, 0, v34.maxRank, v34.multiModeFlags & MULTIMODEFLAG_1000) == 1 ) // MOTS altered: last arg
                        {
                            v21 = sithMulti_CreatePlayer(
                                      v34.serverName,
                                      v34.wPassword,
                                      v34.episodeGobName,
                                      v34.mapJklFname,
                                      v34.maxPlayers,
                                      v34.sessionFlags,
                                      v34.multiModeFlags,
                                      v34.tickRateMs,
                                      v34.maxRank);
                            if ( v21 == 0x88770118 )
                            {
                                v31 = jkStrings_GetUniStringWithFallback("GUINET_USERCANCEL");
                                v23 = jkStrings_GetUniStringWithFallback("GUINET_HOSTERROR");
                                jkGuiDialog_ErrorDialog(v23, v31);
                            }
                            else if ( v21 )
                            {
                                v30 = jkStrings_GetUniStringWithFallback("GUINET_NOCONNECT");
                                v22 = jkStrings_GetUniStringWithFallback("GUINET_HOSTERROR");
                                jkGuiDialog_ErrorDialog(v22, v30);
                            }
                            else if ( jkMain_loadFile2(v34.episodeGobName, v34.mapJklFname) )
                            {
                                return 1;
                            }
                        }
                    }
                    while ( jkGuiNetHost_Show(&v34) == 1 );
LABEL_51:
                    stdComm_CloseConnection();
                    continue;
                case 102:
                    jkGuiBuildMulti_Show();
                    continue;
                default:
                    continue;
            }
            break;
        }
        while ( 1 )
        {
            stdString_SafeWStrCopy(v35.sessionName, jkGuiMultiplayer_aElements3[5].wstr, 0x20);
            v7 = jkGuiMultiplayer_aElements3[3].selectedTextEntry;
            if ( jkGuiMultiplayer_aElements3[3].selectedTextEntry < 0 )
                v8 = 0;
            else
                v8 = jkGuiMultiplayer_aElements3[3].selectedTextEntry <= dplay_dword_55D618 - 1;
            if ( !v8 )
                goto LABEL_51;
            if ( jkGuiMultiplayer_aEntries[jkGuiMultiplayer_aElements3[3].selectedTextEntry].field_E0 == 10 )
                break;
            jkGuiDialog_ErrorDialog(jkStrings_GetUniStringWithFallback("GUINET_JOINERROR"), jkStrings_GetUniStringWithFallback("GUINET_WRONGVERSION"));
LABEL_28:
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMultiplayer_menu3, &jkGuiMultiplayer_aElements3[9]);
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu3, &jkGuiMultiplayer_aElements3[10]);
            if ( jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu3) != 1 )
            {
LABEL_29:
                stdComm_EnumSessions2();
                stdComm_CloseConnection();
                goto LABEL_1;
            }
        }
        if ( jkGuiBuildMulti_ShowLoad(
                 &jkGuiMultiplayer_mpcInfo,
                 jkGuiMultiplayer_aEntries[jkGuiMultiplayer_aElements3[3].selectedTextEntry].episodeGobName,
                 jkGuiMultiplayer_aEntries[jkGuiMultiplayer_aElements3[3].selectedTextEntry].mapJklFname,
                 0,
                 jkGuiMultiplayer_aEntries[jkGuiMultiplayer_aElements3[3].selectedTextEntry].maxRank,
                 jkGuiMultiplayer_aEntries[jkGuiMultiplayer_aElements3[3].selectedTextEntry].multiModeFlags & MULTIMODEFLAG_1000) != 1 )
            goto LABEL_28;
#ifdef QOL_IMPROVEMENTS
        // HACK: Actually do passwords correctly
        int check = __wcscmp(jkGuiMultiplayer_aEntries[jkGuiMultiplayer_aElements3[3].selectedTextEntry].wPassword, jkGuiMultiplayer_stru_556168.field_300);
        if (check) {
            v27 = jkStrings_GetUniStringWithFallback("GUINET_WRONGPASSWORD");
            v11 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
            jkGuiDialog_ErrorDialog(v11, v27);
            goto LABEL_28;
        }

        wuRegistry_SetWString("lastConnectedHost", jkGuiMultiplayer_ipText);
#endif
        v10 = stdComm_Open(v7, v35.sessionName);
        if ( v10 )
        {
            if ( v10 == 0x8877014A )
            {
                v27 = jkStrings_GetUniStringWithFallback("GUINET_GAMEFULL");
                v11 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
            }
            else if ( v10 == 0x88770154 )
            {
                v27 = jkStrings_GetUniStringWithFallback("GUINET_WRONGPASSWORD");
                v11 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
            }
            else
            {
                v27 = jkStrings_GetUniStringWithFallback("GUINET_NOGAMECONNECT");
                v11 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
            }
            jkGuiDialog_ErrorDialog(v11, v27);
            goto LABEL_28;
        }
        v12 = v7;
#ifdef QOL_IMPROVEMENTS
        sithMulti_multiModeFlags = jkGuiMultiplayer_aEntries[v12].multiModeFlags; // TODO: why?
#endif
        stdString_SafeStrCopy(v35.mapJklFname, (const char *)jkGuiMultiplayer_aEntries[v12].mapJklFname, 0x20);
        stdString_SafeStrCopy(v35.episodeGobName, (const char *)jkGuiMultiplayer_aEntries[v12].episodeGobName, 0x20);
        v13 = jkGuiMultiplayer_aEntries[v12].tickRateMs;
        v35.tickRateMs = v13;
        jkGuiRend_DarrayFree(&jkGuiMultiplayer_stru_5564A8);
        sithMulti_InitTick(v35.tickRateMs);
        if ( !jkMain_loadFile2(v35.episodeGobName, v35.mapJklFname) )
            continue;
        return 1;
    }
}

int jkGuiMultiplayer_ShowSynchronizing()
{
    int v0; // esi
    void *v2; // [esp-4h] [ebp-8h]

    v2 = jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]->palette;
    g_submodeFlags |= 8u;
    jkGui_SetModeMenu(v2);
    jkGuiMultiplayer_aElements4[1].wstr = jkStrings_GetUniStringWithFallback("GUI_SYNCHRONIZING");
    jkGuiMultiplayer_menu4.idkFunc = jkGuiMultiplayer_idk;
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu4, &jkGuiMultiplayer_aElements4[2]);
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu4);
    jkGui_SetModeGame();
    return v0;
}


int jkGuiMultiplayer_CogMsgHandleJoining(sithCogMsg *msg)
{
    wchar_t *v2; // eax
    wchar_t *v3; // [esp-4h] [ebp-4h]

    if ( (g_submodeFlags & 8) != 0 )
    {
        switch ( msg->pktData[0] )
        {
            case 0:
                jkGuiMultiplayer_aElements4[1].wstr = jkStrings_GetUniStringWithFallback("GUINET_JOININGOK");
                jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiplayer_aElements4[1], &jkGuiMultiplayer_menu4, 1);
                return 1;
            case 1:
                jkGuiMultiplayer_aElements4[1].wstr = jkStrings_GetUniStringWithFallback("GUINET_JOININGBUSY");
                jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiplayer_aElements4[1], &jkGuiMultiplayer_menu4, 1);
                return 1;
            case 3:
                v3 = jkStrings_GetUniStringWithFallback("GUINET_JOINCANCEL");
                v2 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
                goto LABEL_9;
            case 4:
                v3 = jkStrings_GetUniStringWithFallback("GUINET_WRONGCHECKSUM");
                v2 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
                goto LABEL_9;
            case 5:
                v3 = jkStrings_GetUniStringWithFallback("GUINET_GAMEFULL");
                v2 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
                goto LABEL_9;
            case 6:
                v3 = jkStrings_GetUniStringWithFallback("GUINET_WRONGLEVEL");
                v2 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
LABEL_9:
                jkGuiDialog_ErrorDialog(v2, v3);
                jkGuiMultiplayer_menu4.lastClicked = -2;
                sithComm_SetNeedsSync();
                break;
            default:
                return 1;
        }
    }
    return 1;
}

void jkGuiMultiplayer_sub_4140B0(jkGuiMenu *pMenu)
{
    uint32_t v1; // eax
    int v2; // esi
    HRESULT v3; // eax
    wchar_t *v4; // eax
    int v5; // ebp
    jkMultiEntry *v6; // ebx
    wchar_t *v7; // eax
    int v8; // [esp-14h] [ebp-18h]
    wchar_t *v9; // [esp-14h] [ebp-18h]
    int v10; // [esp+0h] [ebp-4h]

    if ( g_app_suspended )
    {
        v1 = stdPlatform_GetTimeMsec();
        if ( v1 > jkGuiMultiplayer_dword_5564E8 + 5000 )
        {
            v2 = -1;
            jkGuiMultiplayer_dword_5564E8 = v1;
            v10 = -1;
            v3 = stdComm_EnumSessions(1, (wchar_t *)jkGuiMultiplayer_aElements3[5].wstr);
            if ( !v3 )
            {
                jkGuiRend_DarrayFreeEntry(&jkGuiMultiplayer_stru_5564A8);
                if ( dplay_dword_55D618 )
                {
                    v5 = 0;
                    if ( dplay_dword_55D618 > 0 )
                    {
                        v6 = jkGuiMultiplayer_aEntries;
                        do
                        {
                            jkGuiRend_DarrayReallocStr(&jkGuiMultiplayer_stru_5564A8, v6->serverName, 0);
                            if ( !memcmp(&jkGui_guid_556040, &v6->guidInstance, sizeof(GUID)) )
                                v10 = v5;
                            ++v5;
                            ++v6;
                        }
                        while ( v5 < dplay_dword_55D618 );
                        v2 = v10;
                    }
                    jkGuiRend_DarrayReallocStr(&jkGuiMultiplayer_stru_5564A8, 0, 0);
                    jkGuiRend_SetClickableString(&jkGuiMultiplayer_aElements3[3], &jkGuiMultiplayer_stru_5564A8);
                    jkGuiMultiplayer_aElements3[3].enableHover = 0;
                }
                else
                {
                    v8 = dplay_dword_55D618;
                    v4 = jkStrings_GetUniStringWithFallback("GUI_NOGAMESTOJOIN");
                    jkGuiRend_DarrayReallocStr(&jkGuiMultiplayer_stru_5564A8, v4, v8);
                    jkGuiMultiplayer_aElements3[3].enableHover = 1;
                }
                jkGuiMultiplayer_aElements3[3].selectedTextEntry = v2;
                jkGuiMultiplayer_sub_413E50(v2);
                v3 = 0;
            }
            if ( v3 == 0x88770118 )
            {
                pMenu->lastClicked = -1;
            }
            else if ( v3 )
            {
                v9 = jkStrings_GetUniStringWithFallback("GUINET_NOCONNECT");
                v7 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
                jkGuiDialog_ErrorDialog(v7, v9);
                pMenu->lastClicked = -1;
            }
            jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiplayer_aElements3[3], &jkGuiMultiplayer_menu3, 1);
        }
    }
}

void jkGuiMultiplayer_sub_413E50(int idx)
{
    wchar_t *v1; // eax
    wchar_t *v2; // eax
    wchar_t *v3; // eax
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    int v6; // [esp-10h] [ebp-38h]
    int v7; // [esp-Ch] [ebp-34h]
    wchar_t *v8; // [esp-8h] [ebp-30h]
    int v9; // [esp-4h] [ebp-2Ch]
    char v10[32]; // [esp+8h] [ebp-20h] BYREF

    if ( idx >= 0 )
    {
        v1 = jkStrings_GetUniStringWithFallback("GUI_LEVEL");
        jk_snwprintf(
            jkGuiMultiplayer_stru_556168.field_0,
            0x80u,
            v1,
            jkGuiMultiplayer_aEntries[idx].serverName,
            jkGuiMultiplayer_aEntries[idx].episodeGobName,
            jkGuiMultiplayer_aEntries[idx].mapJklFname);
        stdString_snprintf(v10, 32, "RANK_%d_L", jkGuiMultiplayer_aEntries[idx].maxRank);
        v9 = jkGuiMultiplayer_aEntries[idx].maxRank;
        v8 = jkStrings_GetUniStringWithFallback(v10);
        v7 = jkGuiMultiplayer_aEntries[idx].maxPlayers;
        // Added: dedicated
        if (jkGuiMultiplayer_aEntries[idx].sessionFlags & SESSIONFLAG_ISDEDICATED) {
            v7 -= 1;
        }
        v6 = jkGuiMultiplayer_aEntries[idx].numPlayers;
        v2 = jkStrings_GetUniStringWithFallback("GUI_NUM_PLAYERS");
        jk_snwprintf(jkGuiMultiplayer_stru_556168.field_100, 0x80u, v2, v6, v7, v8, v9);
        jkGui_guid_556040 = jkGuiMultiplayer_aEntries[idx].guidInstance;
        if ( (jkGuiMultiplayer_aEntries[idx].sessionFlags & SESSIONFLAG_PASSWORD) != 0 )
        {
            v3 = jkStrings_GetUniStringWithFallback("GUINET_GAMEPASSWORD");
            __wcscat(jkGuiMultiplayer_stru_556168.field_100, v3);
            jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[5], &jkGuiMultiplayer_menu3, 1);
            jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[4], &jkGuiMultiplayer_menu3, 1);
        }
        else
        {
            jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[5], &jkGuiMultiplayer_menu3, 0);
            jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[4], &jkGuiMultiplayer_menu3, 0);
        }
        if ( (jkGuiMultiplayer_aEntries[idx].multiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
        {
            v4 = jkStrings_GetUniStringWithFallback("GUINET_GAMETEAM");
            __wcscat(jkGuiMultiplayer_stru_556168.field_100, v4);
        }
        if ( (jkGuiMultiplayer_aEntries[idx].sessionFlags & SESSIONFLAG_20) != 0 )
        {
            v5 = jkStrings_GetUniStringWithFallback("GUINET_GAMECLOSED");
            jk_snwprintf(jkGuiMultiplayer_stru_556168.field_100, 0x80u, v5);
            jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[9], &jkGuiMultiplayer_menu3, 0);
        }
        else
        {
            jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[9], &jkGuiMultiplayer_menu3, 1);
        }
    }
    else
    {
        memset(&jkGuiMultiplayer_stru_556168.field_0, 0, 0x100u);
        memset(jkGuiMultiplayer_stru_556168.field_100, 0, 0x100u);
        memset(&jkGuiMultiplayer_stru_556168.field_200, 0, 0x100u);
        jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[9], &jkGuiMultiplayer_menu3, 0);
        jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[5], &jkGuiMultiplayer_menu3, 0);
        jkGuiRend_SetVisibleAndDraw(&jkGuiMultiplayer_aElements3[4], &jkGuiMultiplayer_menu3, 0);
        memset(&jkGui_guid_556040, 0, sizeof(GUID));
    }
    jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiplayer_aElements3[6], &jkGuiMultiplayer_menu3, 1);
    jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiplayer_aElements3[7], &jkGuiMultiplayer_menu3, 1);
    jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiplayer_aElements3[8], &jkGuiMultiplayer_menu3, 1);
}

int jkGuiMultiplayer_sub_413E00(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int bRedraw)
{
    int v5; // eax

    jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, bRedraw);
    if ( jkGuiMultiplayer_aElements3[3].selectedTextEntry < 0 )
        v5 = 0;
    else
        v5 = jkGuiMultiplayer_aElements3[3].selectedTextEntry <= dplay_dword_55D618 - 1;
    if ( v5 )
        jkGuiMultiplayer_sub_413E50(jkGuiMultiplayer_aElements3[3].selectedTextEntry);
    return 0;
}

// MOTS added: Weird random waits?
void jkGuiMultiplayer_idk(jkGuiMenu *pMenu)
{
    uint32_t v1; // eax
    wchar_t *v2; // eax
    wchar_t *v3; // [esp-4h] [ebp-4h]

    if ( stdComm_dword_8321E0 && (g_submodeFlags & 8) != 0 )
    {
        v1 = stdPlatform_GetTimeMsec();
        if ( v1 <= jkGuiMultiplayer_dword_5564EC + 2000 || (jkGuiMultiplayer_dword_5564EC = v1, sithMulti_SendJoinRequest(sithNet_serverNetId)) )
        {
            sithComm_Sync();
            if ( (g_submodeFlags & 8) == 0 )
                pMenu->lastClicked = 1;
        }
        else
        {
            v3 = jkStrings_GetUniStringWithFallback("GUINET_NOGAMECONNECT");
            v2 = jkStrings_GetUniStringWithFallback("GUINET_JOINERROR");
            jkGuiDialog_ErrorDialog(v2, v3);
            pMenu->lastClicked = -2;
        }
    }
}

int jkGuiMultiplayer_Show2()
{
    int result; // eax
    int v1; // eax
    int v2; // esi
    HRESULT v3; // eax
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    wchar_t *v6; // [esp-4h] [ebp-14Ch]
    wchar_t *v7; // [esp-4h] [ebp-14Ch]
    jkMultiEntry3 v8; // [esp+8h] [ebp-140h] BYREF

    memset(&v8, 0, sizeof(v8));
    if ( stdComm_dword_8321F8 )
    {
        if ( stdComm_dword_8321F8 != 1 )
        {
            result = stdComm_dword_8321F8 - 2;
            if ( stdComm_dword_8321F8 != 2 )
                return result;
            g_submodeFlags |= 8;
            jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]->palette);
            jkGuiMultiplayer_aElements4[1].wstr = jkStrings_GetUniStringWithFallback("GUINET_WAITHOSTSETTINGS");
            jkGuiMultiplayer_menu4.idkFunc = jkGuiMultiplayer_sub_4142C0;
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu4, &jkGuiMultiplayer_aElements4[2]);
            v2 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu4);
            jkGui_SetModeGame();
            if ( v2 == 1
              && jkGuiBuildMulti_ShowLoad(&jkGuiMultiplayer_mpcInfo, jkGuiMultiplayer_multiEntry.episodeGobName, jkGuiMultiplayer_multiEntry.mapJklFname, 0, jkGuiMultiplayer_multiEntry.maxRank, jkGuiMultiplayer_multiEntry.multiModeFlags & MULTIMODEFLAG_1000) == 1 )
            {
                sithMulti_InitTick(jkGuiMultiplayer_multiEntry.tickRateMs);
                jkMain_loadFile2(jkGuiMultiplayer_multiEntry.episodeGobName, jkGuiMultiplayer_multiEntry.mapJklFname);
                return 1;
            }
            goto LABEL_10;
        }
        if ( jkGuiNetHost_Show(&v8) != 1
          || (sithNet_scorelimit = v8.scoreLimit,
              sithNet_multiplayer_timelimit = v8.timeLimit,
              jkGuiBuildMulti_ShowLoad(&jkGuiMultiplayer_mpcInfo, v8.episodeGobName, v8.mapJklFname, 0, v8.maxRank, v8.multiModeFlags & MULTIMODEFLAG_1000) != 1) )
        {
LABEL_10:
            stdComm_CloseConnection();
            return -1;
        }
        v3 = sithMulti_CreatePlayer(
                 v8.serverName,
                 v8.wPassword,
                 v8.episodeGobName,
                 v8.mapJklFname,
                 v8.maxPlayers,
                 v8.sessionFlags,
                 v8.multiModeFlags,
                 v8.tickRateMs,
                 v8.maxRank);
        if ( v3 == 0x88770118 )
        {
            v7 = jkStrings_GetUniStringWithFallback("GUINET_USERCANCEL");
            v5 = jkStrings_GetUniStringWithFallback("GUINET_HOSTERROR");
            jkGuiDialog_ErrorDialog(v5, v7);
        }
        else
        {
            if ( !v3 )
            {
                jkMain_loadFile2(v8.episodeGobName, v8.mapJklFname);
                return 1;
            }
            v6 = jkStrings_GetUniStringWithFallback("GUINET_NOCONNECT");
            v4 = jkStrings_GetUniStringWithFallback("GUINET_HOSTERROR");
            jkGuiDialog_ErrorDialog(v4, v6);
        }
    }
    return -1;
}

void jkGuiMultiplayer_sub_4142C0(jkGuiMenu *pMenu)
{
    uint32_t v1; // eax

    if ( stdComm_dword_8321E0 )
    {
        v1 = stdPlatform_GetTimeMsec();
        if ( v1 > jkGuiMultiplayer_dword_5564F0 + 2000 )
        {
            jkGuiMultiplayer_dword_5564F0 = v1;
            DirectPlay_IdkSessionDesc(&jkGuiMultiplayer_multiEntry);
            if ( jkGuiMultiplayer_multiEntry.field_E0 )
            {
                jkGuiMultiplayer_checksumSeed = jkGuiMultiplayer_multiEntry.checksumSeed;
                pMenu->lastClicked = 1;
            }
        }
    }
}

int jkGuiMultiplayer_sub_413C80(Darray *pDarray, jkGuiElement *pElement, int a3)
{
    unsigned int v3; // esi
    sith_dplay_connection *v4; // edi
    int result; // eax

    jkGuiRend_DarrayFreeEntry(pDarray);
    v3 = 0;
    if ( jkGuiMultiplayer_numConnections )
    {
        v4 = jkGuiMultiplayer_aConnections;
        do
        {
            jkGuiRend_DarrayReallocStr(pDarray, v4->name, 0);
            ++v3;
            ++v4;
        }
        while ( v3 < jkGuiMultiplayer_numConnections );
    }
    jkGuiRend_AddStringEntry(pDarray, 0, 0);
    jkGuiRend_SetClickableString(pElement, pDarray);
    result = a3;
    pElement->selectedTextEntry = a3;
    return result;
}

int jkGuiMultiplayer_ShowWaitHostSettings()
{
    int v0; // esi
    void *v2; // [esp-4h] [ebp-8h]

    v2 = jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]->palette;
    g_submodeFlags |= 8u;
    jkGui_SetModeMenu(v2);
    jkGuiMultiplayer_aElements4[1].wstr = jkStrings_GetUniStringWithFallback("GUINET_WAITHOSTSETTINGS");
    jkGuiMultiplayer_menu4.idkFunc = jkGuiMultiplayer_sub_4142C0;
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiplayer_menu4, &jkGuiMultiplayer_aElements4[2]);
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiplayer_menu4);
    jkGui_SetModeGame();
    return v0;
}
