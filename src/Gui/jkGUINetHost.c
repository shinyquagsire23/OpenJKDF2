#include "jkGUINetHost.h"

#include <errno.h>

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Dss/sithMulti.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUIMultiplayer.h"
#include "Main/jkStrings.h"
#include "Main/jkMain.h"
#include "Win95/stdComm.h"
#include "Platform/wuRegistry.h"
#include "General/stdString.h"
#include "Main/jkRes.h"
#include "Main/jkEpisode.h"
#include "Gui/jkGUISingleplayer.h"

enum jkGuiNetHostButton_t
{
    GUI_OK = 1,
    GUI_CANCEL = -1,

    GUI_ADVANCED = 200,
};

enum jkGuiNetHostElement_t
{
    NETHOST_GAMENAME_TEXTBOX = 3,
    NETHOST_MAXPLAYERS_TEXTBOX = 5,
    NETHOST_SCORELIMIT_CHECKBOX = 6,
    NETHOST_SCORELIMIT_TEXTBOX = 7,
    NETHOST_TIMELIMIT_CHECKBOX = 8,
    NETHOST_TIMELIMIT_TEXTBOX = 9,
    NETHOST_TEAMMODE_CHECKBOX = 10,
    NETHOST_SINGLELEVEL_CHECKBOX = 11,
    NETHOST_STARS_TEXT = 13,
    NETHOST_PASSWORD_TEXTBOX = 17,
    NETHOST_EPISODE_LISTBOX = 19,
    NETHOST_LEVEL_LISTBOX = 21,

    NETHOST_PORT_TEXTBOX = 26,
};

enum jkGuiNetHostAdvancedElement_t
{
    NETHOST_TICKRATE_TEXTBOX = 3,
};

static int jkGuiNetHost_aIdk[2] = {0xd, 0xe};

// MOTS altered
static jkGuiElement jkGuiNetHost_aElements[28] =
{
    { ELEMENT_TEXT,         0, 0, NULL, 3, { 0, 410, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 6, "GUI_MULTIPLAYER", 3, { 20, 20, 600, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, "GUI_GAMENAME", 2, { 20, 80, 270, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX,      0, 0, NULL, 16, { 20, 125, 270, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, "GUI_MAXPLAYERS", 2, { 20, 155, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX,      0, 0, NULL, 2, { 225, 160, 65, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_CHECKBOX,     0, 0, "GUI_SCORELIMIT", 0, { 20, 190, 200, 40 }, 1, 0, "GUI_SCORELIMIT_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX,      0, 0, NULL, 3, { 225, 195, 65, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_CHECKBOX,     0, 0, "GUI_TIMELIMIT", 0, { 20, 225, 200, 40 }, 1, 0, "GUI_TIMELIMIT_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX,      0, 0, NULL, 3, { 225, 230, 65, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_CHECKBOX,     0, 0, "GUI_TEAMMODE", 0, { 20, 260, 200, 40 }, 1, 0, "GUI_TEAMMODE_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_CHECKBOX,     0, 0, "GUI_SINGLELEVEL", 0, { 20, 295, 200, 40 }, 1, 0, "GUI_SINGLELEVEL_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, "GUI_MAXSTARS", 2, { 310, 80, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, NULL, 2, { 375, 120, 120, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_PICBUTTON,    1, 0, NULL, 33, { 310, 120, 30, 30 }, 1, 0, NULL, NULL, &jkGuiNetHost_sub_411AE0, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_PICBUTTON,    2, 0, NULL, 34, { 340, 120, 30, 30 }, 1, 0, NULL, NULL, &jkGuiNetHost_sub_411AE0, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, "GUINET_PASSWORD", 2, { 20, 340, 270, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX,      0, 0, NULL, 16, { 20, 380, 270, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, "GUI_CHOOSEEPISODE", 2, { 310, 150, 240, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_LISTBOX,      0, 0, NULL, 0, { 310, 175, 320, 80 }, 1, 0, NULL, NULL, NULL, jkGuiNetHost_aIdk, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT,         0, 0, "GUI_CHOOSELEVEL", 2, { 310, 265, 260, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_LISTBOX,      1, 0, NULL, 0, { 310, 290, 320, 110 }, 1, 0, NULL, NULL, NULL, jkGuiNetHost_aIdk, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON,   GUI_ADVANCED, 2, "GUI_ADVANCED", 3, { 220, 430, 200, 40 }, 1, 0, "GUI_ADVANCED_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON,   GUI_OK,  2, "GUI_OK", 3, { 420, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON,   GUI_CANCEL, 2, "GUI_CANCEL", 3, { 20, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
#ifdef QOL_IMPROVEMENTS
    { ELEMENT_TEXT, 0, 0, "GUIEXT_SERVER_PORT", 2, { 540, 80, 90, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX, 0, 0, NULL, 16, { 540, 125, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    
#endif
    { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiNetHost_menu =
{
    &jkGuiNetHost_aElements, 0, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiElement jkGuiNetHost_aSettingsElements[9] =
{
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 410, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 6, "GUI_MULTIPLAYER", 3, { 20, 20, 600, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, "GUI_TICKRATE", 2, { 70, 230, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX, 0, 0, NULL, 0, { 280, 240, 50, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
#ifdef QOL_IMPROVEMENTS
    { ELEMENT_CHECKBOX, 0, 0, "GUIEXT_DEDICATED_SERVER", 0, { 70, 270, 200, 40 }, 1, 0, "GUIEXT_DEDICATED_SERVER_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_CHECKBOX, 0, 0, "GUIEXT_COOP", 0, { 70, 300, 200, 40 }, 1, 0, "GUIEXT_COOP_HINT", NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
#endif
    { ELEMENT_TEXTBUTTON, GUI_OK, 2, "GUI_OK", 3, { 420, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, GUI_CANCEL, 2, "GUI_CANCEL", 3, { 20, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiNetHost_menuSettings =
{
    &jkGuiNetHost_aSettingsElements, 0, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static int jkGuiNetHost_bInitted;
static wchar_t jkGuiNetHost_wstrStarsText[32];
static Darray jkGuiNetHost_dArray1;
static Darray jkGuiNetHost_dArray2;

// Added
wchar_t jkGuiNetHost_portText[32];
int jkGuiNetHost_portNum = 27020;
int jkGuiNetHost_bIsDedicated = 0;
int jkGuiNetHost_bIsCoop = 0;
int jkGuiNetHost_bIsEpisodeCoop = 0;

int wstr_to_int_clamped(wchar_t *pWstr, int minVal, int maxVal)
{
    wchar_t *dummy;
    int val = jk_wcstol(pWstr, &dummy, 10);
     if (val < minVal)
    {
        return minVal;
    }
    else if (val > maxVal)
    {
        return maxVal;
    }

    return val;
}

// Added: Make sure stuff actually gets into the registry
void jkGuiNetHost_SaveSettings()
{
#ifdef QOL_IMPROVEMENTS
    if (jkGuiNetHost_bIsDedicated) {
        jkGuiNetHost_maxPlayers -= 1;
    }
    if (jkGuiNetHost_bIsDedicated) {
        jkGuiNetHost_sessionFlags |= SESSIONFLAG_ISDEDICATED;
    }
    else {
        jkGuiNetHost_sessionFlags &= ~SESSIONFLAG_ISDEDICATED;
    }

    if (jkGuiNetHost_bIsEpisodeCoop) {
        jkGuiNetHost_gameFlags |= MULTIMODEFLAG_COOP;
    }
    else {
        jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_COOP;
    }

#endif
    wuRegistry_SaveInt("maxRank", jkGuiNetHost_maxRank);
    wuRegistry_SaveInt("sessionFlags", jkGuiNetHost_sessionFlags);
    wuRegistry_SaveInt("gameFlags", jkGuiNetHost_gameFlags);
    wuRegistry_SaveInt("timeLimit", jkGuiNetHost_timeLimit);
    wuRegistry_SaveInt("scoreLimit", jkGuiNetHost_scoreLimit);
    wuRegistry_SaveInt("maxPlayers", jkGuiNetHost_maxPlayers);
    wuRegistry_SaveInt("tickRate", jkGuiNetHost_tickRate);
#ifndef ARCH_WASM
    wuRegistry_SetWString("gameName", jkGuiNetHost_gameName);
#endif
#ifdef QOL_IMPROVEMENTS
    wuRegistry_SaveInt("portNum", jkGuiNetHost_portNum);
    wuRegistry_SaveBool("bIsDedicated", jkGuiNetHost_bIsDedicated);
    wuRegistry_SaveBool("bIsCoop", jkGuiNetHost_bIsCoop);
    wuRegistry_SaveBool("bIsEpisodeCoop", jkGuiNetHost_bIsEpisodeCoop);

    wuRegistry_SaveBool("bUseScoreLimit", jkGuiNetHost_gameFlags & MULTIMODEFLAG_SCORELIMIT);
    wuRegistry_SaveBool("bUseTimeLimit", jkGuiNetHost_gameFlags & MULTIMODEFLAG_TIMELIMIT);
    wuRegistry_SaveBool("bIsSingleLevel", jkGuiNetHost_gameFlags & MULTIMODEFLAG_SINGLE_LEVEL);
    wuRegistry_SaveBool("bIsTeams", jkGuiNetHost_gameFlags & MULTIMODEFLAG_TEAMS);
#endif
}

void jkGuiNetHost_LoadSettings()
{
    jkGuiNetHost_maxRank = wuRegistry_GetInt("maxRank", jkGuiNetHost_maxRank);
    jkGuiNetHost_sessionFlags = wuRegistry_GetInt("sessionFlags", jkGuiNetHost_sessionFlags);
    jkGuiNetHost_gameFlags = wuRegistry_GetInt("gameFlags", jkGuiNetHost_gameFlags);
    jkGuiNetHost_timeLimit = wuRegistry_GetInt("timeLimit", jkGuiNetHost_timeLimit);
    jkGuiNetHost_scoreLimit = wuRegistry_GetInt("scoreLimit", jkGuiNetHost_scoreLimit);
    jkGuiNetHost_maxPlayers = wuRegistry_GetInt("maxPlayers", jkGuiNetHost_maxPlayers);
    jkGuiNetHost_tickRate = wuRegistry_GetInt("tickRate", jkGuiNetHost_tickRate);

    // MOTS added:
    //if (jkGuiNetHost_maxRank > 8) {
    //    jkGuiNetHost_maxRank = 8;
    //}

    memset(jkGuiNetHost_gameName, 0, sizeof(jkGuiNetHost_gameName));
#ifndef ARCH_WASM
    wuRegistry_GetWString("gameName", jkGuiNetHost_gameName, 0x40u, jkGuiNetHost_gameName);
#endif

#ifdef QOL_IMPROVEMENTS
    jkGuiNetHost_portNum = wuRegistry_GetInt("portNum", jkGuiNetHost_portNum);
    jkGuiNetHost_bIsDedicated = wuRegistry_GetBool("bIsDedicated", jkGuiNetHost_bIsDedicated);

    if (jkGuiNetHost_bIsDedicated) {
        jkGuiNetHost_maxPlayers += 1;
    }

    if (jkGuiNetHost_bIsDedicated) {
        jkGuiNetHost_sessionFlags |= SESSIONFLAG_ISDEDICATED;
    }
    else {
        jkGuiNetHost_sessionFlags &= ~SESSIONFLAG_ISDEDICATED;
    }

    jkGuiNetHost_bIsCoop = wuRegistry_GetBool("bIsCoop", jkGuiNetHost_bIsCoop);
    jkGuiNetHost_bIsEpisodeCoop = wuRegistry_GetBool("bIsEpisodeCoop", jkGuiNetHost_bIsCoop);
    if (jkGuiNetHost_bIsEpisodeCoop) {
        jkGuiNetHost_gameFlags |= MULTIMODEFLAG_COOP;
    }
    else {
        jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_COOP;
    }

    if(wuRegistry_GetBool("bUseScoreLimit", jkGuiNetHost_gameFlags & MULTIMODEFLAG_SCORELIMIT)) {
        jkGuiNetHost_gameFlags |= MULTIMODEFLAG_SCORELIMIT;
    }
    else {
        jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_SCORELIMIT;
    }

    if(wuRegistry_GetBool("bUseTimeLimit", jkGuiNetHost_gameFlags & MULTIMODEFLAG_TIMELIMIT)) {
        jkGuiNetHost_gameFlags |= MULTIMODEFLAG_TIMELIMIT;
    }
    else {
        jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_TIMELIMIT;
    }

    if(wuRegistry_GetBool("bIsSingleLevel", jkGuiNetHost_gameFlags & MULTIMODEFLAG_SINGLE_LEVEL)) {
        jkGuiNetHost_gameFlags |= MULTIMODEFLAG_SINGLE_LEVEL;
    }
    else {
        jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_SINGLE_LEVEL;
    }

    if(wuRegistry_GetBool("bIsTeams", jkGuiNetHost_gameFlags & MULTIMODEFLAG_TEAMS)) {
        jkGuiNetHost_gameFlags |= MULTIMODEFLAG_TEAMS;
    }
    else {
        jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_TEAMS;
    }

#endif
}

void jkGuiNetHost_Startup()
{
    jkGui_InitMenu(&jkGuiNetHost_menu, jkGui_stdBitmaps[JKGUI_BM_BK_MULTI]);
    jkGui_InitMenu(&jkGuiNetHost_menuSettings, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
    
    jkGuiNetHost_LoadSettings();
    jkGuiNetHost_bInitted = 1;
}

void jkGuiNetHost_Shutdown()
{
    jkGuiNetHost_SaveSettings();
    jkGuiNetHost_bInitted = 0;

    // Added: clean reset
    memset(jkGuiNetHost_wstrStarsText, 0, sizeof(jkGuiNetHost_wstrStarsText));
    memset(&jkGuiNetHost_dArray1, 0, sizeof(jkGuiNetHost_dArray1));
    memset(&jkGuiNetHost_dArray2, 0, sizeof(jkGuiNetHost_dArray2));

    memset(jkGuiNetHost_portText, 0, sizeof(jkGuiNetHost_portText));

    jkGuiNetHost_portNum = 27020;
    jkGuiNetHost_bIsDedicated = 0;
    jkGuiNetHost_bIsCoop = 0;
}

// MOTS altered
int jkGuiNetHost_Show(jkMultiEntry3 *pMultiEntry)
{
    wchar_t *v3; // eax
    int v4; // ebp
    wchar_t *i; // eax
    int v10; // eax
    __int64 v11; // rax
    int v12; // eax
    int v13; // eax
    int v14; // eax
    int v15; // eax
    int v23; // [esp+14h] [ebp-16Ch]
    wchar_t *a2; // [esp+18h] [ebp-168h] BYREF
    wchar_t v25[32]; // [esp+20h] [ebp-160h] BYREF
    wchar_t v26[32]; // [esp+60h] [ebp-120h] BYREF
    wchar_t v27[32]; // [esp+A0h] [ebp-E0h] BYREF
    wchar_t a1[32]; // [esp+E0h] [ebp-A0h] BYREF
    char v29[32]; // [esp+120h] [ebp-60h] BYREF
    wchar_t v30[32]; // [esp+140h] [ebp-40h] BYREF

    jkGuiNetHost_LoadSettings(); // Added

    stdString_SafeWStrCopy(v25, L"8", 0x20);
    stdString_SafeWStrCopy(v26, L"", 0x20);
    stdString_SafeWStrCopy(v27, L"", 0x20);
    jkGuiNetHost_aElements[NETHOST_SCORELIMIT_CHECKBOX].selectedTextEntry = jkGuiNetHost_gameFlags & MULTIMODEFLAG_SCORELIMIT;
    jkGuiNetHost_aElements[NETHOST_TIMELIMIT_CHECKBOX].selectedTextEntry = jkGuiNetHost_gameFlags & MULTIMODEFLAG_TIMELIMIT;
    jkGuiNetHost_aElements[NETHOST_SINGLELEVEL_CHECKBOX].selectedTextEntry = jkGuiNetHost_gameFlags & MULTIMODEFLAG_SINGLE_LEVEL;
    jkGuiNetHost_aElements[NETHOST_TEAMMODE_CHECKBOX].selectedTextEntry = jkGuiNetHost_gameFlags & MULTIMODEFLAG_TEAMS;
    if ( !jkGuiNetHost_gameName[0] )
    {
        jk_snwprintf(jkGuiNetHost_gameName, 0x20u, jkStrings_GetUniStringWithFallback("GUI_DEFAULT_GAME_NAME"), jkPlayer_playerShortName);
    }
    jkGuiNetHost_aElements[NETHOST_GAMENAME_TEXTBOX].wstr = jkGuiNetHost_gameName;
    jkGuiNetHost_aElements[NETHOST_GAMENAME_TEXTBOX].selectedTextEntry = 16;
#ifdef QOL_IMPROVEMENTS
    jk_snwprintf(v25, 0x20u, L"%d", jkGuiNetHost_bIsDedicated ? jkGuiNetHost_maxPlayers-1 : jkGuiNetHost_maxPlayers);
#else
    jk_snwprintf(v25, 0x20u, L"%d", jkGuiNetHost_maxPlayers);
#endif
    jkGuiNetHost_aElements[NETHOST_MAXPLAYERS_TEXTBOX].wstr = v25;
    jkGuiNetHost_aElements[NETHOST_MAXPLAYERS_TEXTBOX].selectedTextEntry = 3;
    jk_snwprintf(v27, 0x20u, L"%d", jkGuiNetHost_scoreLimit);
    //a2[0] = (unsigned int)jkGuiNetHost_timeLimit; wat??
    jkGuiNetHost_aElements[NETHOST_SCORELIMIT_TEXTBOX].wstr = v27;
    jkGuiNetHost_aElements[NETHOST_SCORELIMIT_TEXTBOX].selectedTextEntry = 4;
#ifdef QOL_IMPROVEMENTS
    jk_snwprintf(jkGuiNetHost_portText, 0x20u, L"%d", jkGuiNetHost_portNum);
    jkGuiNetHost_aElements[NETHOST_PORT_TEXTBOX].wstr = jkGuiNetHost_portText;
    jkGuiNetHost_aElements[NETHOST_PORT_TEXTBOX].selectedTextEntry = 31;
#endif
    jk_snwprintf(v26, 0x20u, L"%d", (unsigned int)(__int64)((double)(unsigned int)jkGuiNetHost_timeLimit * 0.000016666667));
    jkGuiNetHost_aElements[NETHOST_TIMELIMIT_TEXTBOX].wstr = v26;
    jkGuiNetHost_aElements[NETHOST_TIMELIMIT_TEXTBOX].selectedTextEntry = 4;
    __snprintf(v29, 32, "RANK_%d_L", jkGuiNetHost_maxRank); // sprintf -> snprintf
    jk_snwprintf(jkGuiNetHost_wstrStarsText, 0x80u, jkStrings_GetUniStringWithFallback("GUI_RANK"), jkGuiNetHost_maxRank, jkStrings_GetUniStringWithFallback(v29));
    memset(v30, 0, sizeof(v30));
    jkGuiNetHost_aElements[NETHOST_STARS_TEXT].wstr = jkGuiNetHost_wstrStarsText;
    jkGuiNetHost_aElements[NETHOST_PASSWORD_TEXTBOX].wstr = v30;
    jkGuiNetHost_aElements[NETHOST_PASSWORD_TEXTBOX].selectedTextEntry = 16;
    jkGuiRend_DarrayNewStr(&jkGuiNetHost_dArray1, jkEpisode_var2 + 1, 1);

    jkEpisodeTypeFlags_t loadMask = (JK_EPISODE_DEATHMATCH | JK_EPISODE_4_UNK | JK_EPISODE_SPECIAL_CTF);
#ifdef QOL_IMPROVEMENTS
    if (jkGuiNetHost_bIsCoop)
        loadMask |= JK_EPISODE_SINGLEPLAYER;
#endif
    jkGuiSingleplayer_EnumEpisodes(&jkGuiNetHost_dArray1, &jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX], 0, loadMask);
    jkGuiRend_DarrayNewStr(&jkGuiNetHost_dArray2, 10, 1);
    jkGuiRend_DarrayReallocStr(&jkGuiNetHost_dArray2, 0, 0);
    jkGuiRend_SetClickableString(&jkGuiNetHost_aElements[NETHOST_LEVEL_LISTBOX], &jkGuiNetHost_dArray2);
    jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX].clickHandlerFunc = jkGuiNetHost_sub_4119D0;
    jkGui_sub_412E20(&jkGuiNetHost_menu, 100, 101, 101);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiNetHost_menu, &jkGuiNetHost_aElements[23]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiNetHost_menu, &jkGuiNetHost_aElements[24]);
    
    jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX].selectedTextEntry = 0;
    jkGuiNetHost_sub_4119D0(&jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX], &jkGuiNetHost_menu, -1, -1, 0);

    do
    {
        v4 = jkGuiRend_DisplayAndReturnClicked(&jkGuiNetHost_menu);
        if ( v4 == GUI_OK )
        {
            pMultiEntry->multiModeFlags = 0;
            stdString_SafeWStrCopy(pMultiEntry->serverName, jkGuiNetHost_gameName, 0x20);
            for ( i = __wcschr(pMultiEntry->serverName, ':'); i; i = __wcschr(pMultiEntry->serverName, ':') )
                *i = '-';
            
            stdString_SafeStrCopy(pMultiEntry->episodeGobName, jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX].unistr[jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX].selectedTextEntry].c_str, 0x20);
            stdString_SafeStrCopy(pMultiEntry->mapJklFname, jkGuiNetHost_aElements[NETHOST_LEVEL_LISTBOX].unistr[jkGuiNetHost_aElements[NETHOST_LEVEL_LISTBOX].selectedTextEntry].c_str, 0x80);
            
            v10 = wstr_to_int_clamped(v25, 1, 32);

            // Added: Clamping is slightly different for dedicated
            if (jkGuiNetHost_bIsDedicated) {
                v10 += 1;
                if (v10 < 2)
                    v10 = 2;
                if (v10 > 31)
                    v10 = 31;
            }

            pMultiEntry->maxPlayers = v10;
            jkGuiNetHost_maxPlayers = v10;
            pMultiEntry->maxRank = jkGuiNetHost_maxRank;
            v23 = wstr_to_int_clamped(v26, 1, 100);
            v11 = (__int64)((double)v23 * 60000.0);
            pMultiEntry->timeLimit = v11;
            jkGuiNetHost_timeLimit = v11;
            if ( jkGuiNetHost_aElements[NETHOST_TIMELIMIT_CHECKBOX].selectedTextEntry )
            {
                pMultiEntry->multiModeFlags |= MULTIMODEFLAG_TIMELIMIT;
            }
            v13 = wstr_to_int_clamped(v27, 0, 999);
            pMultiEntry->scoreLimit = v13;
            jkGuiNetHost_scoreLimit = v13;
            if ( jkGuiNetHost_aElements[NETHOST_SCORELIMIT_CHECKBOX].selectedTextEntry )
            {
                pMultiEntry->multiModeFlags |= MULTIMODEFLAG_SCORELIMIT;
            }
            if ( jkGuiNetHost_aElements[NETHOST_SINGLELEVEL_CHECKBOX].selectedTextEntry )
            {
                pMultiEntry->multiModeFlags |= MULTIMODEFLAG_SINGLE_LEVEL;
            }
            if ( jkGuiNetHost_aElements[NETHOST_TEAMMODE_CHECKBOX].selectedTextEntry )
                pMultiEntry->multiModeFlags |= (MULTIMODEFLAG_100 | MULTIMODEFLAG_2 | MULTIMODEFLAG_TEAMS);
            stdString_SafeWStrCopy(pMultiEntry->wPassword, v30, 0x20);
            if (_wcslen(pMultiEntry->wPassword)) {
                jkGuiNetHost_sessionFlags |= SESSIONFLAG_PASSWORD; // Added: wtf?
            }
            pMultiEntry->tickRateMs = jkGuiNetHost_tickRate;
            pMultiEntry->sessionFlags = jkGuiNetHost_sessionFlags;
            jkGuiNetHost_gameFlags = pMultiEntry->multiModeFlags;
#ifdef QOL_IMPROVEMENTS
            jkGuiNetHost_portNum = wstr_to_int_clamped(jkGuiNetHost_portText, 1, 65535);
            wuRegistry_SetWString("serverPassword", pMultiEntry->wPassword);
            wuRegistry_SetString("serverEpisodeGob", pMultiEntry->episodeGobName);
            wuRegistry_SetString("serverMapJkl", pMultiEntry->mapJklFname);

            // Added: Only add Co-op flags on singleplayer levels
            if (jkGuiSingleplayer_FUN_0041d590(pMultiEntry->episodeGobName) & JK_EPISODE_SINGLEPLAYER) {
                jkGuiNetHost_bIsEpisodeCoop = 1;
            }
            else {
                jkGuiNetHost_bIsEpisodeCoop = 0;
            }

            if (jkGuiNetHost_bIsDedicated) {
                jkGuiNetHost_sessionFlags |= SESSIONFLAG_ISDEDICATED;
            }

            if (jkGuiNetHost_bIsEpisodeCoop) {
                jkGuiNetHost_gameFlags |= MULTIMODEFLAG_COOP;
            }
            else {
                jkGuiNetHost_gameFlags &= ~MULTIMODEFLAG_COOP;
            }
            pMultiEntry->multiModeFlags = jkGuiNetHost_gameFlags;
            pMultiEntry->sessionFlags = jkGuiNetHost_sessionFlags;
#endif
        }
        else if ( v4 == GUI_ADVANCED )
        {
            stdString_SafeWStrCopy(a1, L"", 0x20);
            jk_snwprintf(a1, 0x20u, L"%d", jkGuiNetHost_tickRate);
            jkGuiNetHost_aSettingsElements[NETHOST_TICKRATE_TEXTBOX].wstr = a1;
            jkGuiNetHost_aSettingsElements[NETHOST_TICKRATE_TEXTBOX].selectedTextEntry = 32;
#ifdef QOL_IMPROVEMENTS
            jkGuiNetHost_aSettingsElements[4].selectedTextEntry = jkGuiNetHost_bIsDedicated;
            jkGuiNetHost_aSettingsElements[5].selectedTextEntry = jkGuiNetHost_bIsCoop;
#endif
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiNetHost_menuSettings, &jkGuiNetHost_aSettingsElements[4]);
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiNetHost_menuSettings, &jkGuiNetHost_aSettingsElements[5]);
            if ( jkGuiRend_DisplayAndReturnClicked(&jkGuiNetHost_menuSettings) == GUI_OK )
            {
                pMultiEntry->sessionFlags = 0;
                pMultiEntry->tickRateMs = wstr_to_int_clamped(a1, TICKRATE_MIN, TICKRATE_MAX);
                jkGuiNetHost_tickRate = pMultiEntry->tickRateMs;
                jkGuiNetHost_sessionFlags = pMultiEntry->sessionFlags;
            }
#ifdef QOL_IMPROVEMENTS
            jkGuiNetHost_bIsDedicated = !!jkGuiNetHost_aSettingsElements[4].selectedTextEntry;
            jkGuiNetHost_bIsCoop = !!jkGuiNetHost_aSettingsElements[5].selectedTextEntry;

            jkEpisodeTypeFlags_t loadMask = (JK_EPISODE_DEATHMATCH | JK_EPISODE_4_UNK | JK_EPISODE_SPECIAL_CTF);
            if (jkGuiNetHost_bIsCoop)
                loadMask |= JK_EPISODE_SINGLEPLAYER;
            jkGuiSingleplayer_EnumEpisodes(&jkGuiNetHost_dArray1, &jkGuiNetHost_aElements[NETHOST_EPISODE_LISTBOX], 0, loadMask);
#endif
        }
    }
    while ( v4 == GUI_ADVANCED );

    jkGuiNetHost_SaveSettings(); // Added: Make sure stuff actually gets into the registry
    jkGuiRend_DarrayFree(&jkGuiNetHost_dArray1);
    jkGuiRend_DarrayFree(&jkGuiNetHost_dArray2);
    return v4;
}

int jkGuiNetHost_sub_4118C0(jkMultiEntry3 *pEntry)
{
    int v1; // edi
    int tickRate; // eax
    wchar_t a1a[32]; // [esp+8h] [ebp-40h] BYREF

    a1a[0] = 0;
    memset(&a1a[1], 0, 0x3Cu);
    a1a[31] = 0;
    jk_snwprintf(a1a, 0x20u, L"%d", jkGuiNetHost_tickRate);
    jkGuiNetHost_aSettingsElements[NETHOST_TICKRATE_TEXTBOX].wstr = a1a;
    jkGuiNetHost_aSettingsElements[NETHOST_TICKRATE_TEXTBOX].selectedTextEntry = 32;
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiNetHost_menuSettings, &jkGuiNetHost_aSettingsElements[4]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiNetHost_menuSettings, &jkGuiNetHost_aSettingsElements[5]);
    v1 = jkGuiRend_DisplayAndReturnClicked(&jkGuiNetHost_menuSettings);
    if ( v1 == GUI_OK )
    {
        pEntry->sessionFlags = 0;
        tickRate = wstr_to_int_clamped(a1a, TICKRATE_MIN, TICKRATE_MAX);
        pEntry->tickRateMs = tickRate;
        jkGuiNetHost_tickRate = tickRate;
        jkGuiNetHost_sessionFlags = pEntry->sessionFlags;
    }
    return v1;
}

// MOTS altered
int jkGuiNetHost_sub_4119D0(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int redraw)
{
    if ( mouseX != -1 || mouseY != -1 )
        jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, redraw);

    jkRes_LoadGob(pElement->unistr[pElement->selectedTextEntry].c_str);

    if ( jkEpisode_Load(&jkGui_episodeLoad) )
    {
        jkGuiSingleplayer_sub_41AA30(
            &jkGuiNetHost_dArray2,
            &jkGuiNetHost_aElements[NETHOST_LEVEL_LISTBOX],
            0,
            jkRes_episodeGobName,
            jkGui_episodeLoad.type,
            jkGui_episodeLoad.numSeq,
            jkGui_episodeLoad.field_8,
            jkGui_episodeLoad.paEntries);
    }
    else
    {
        jkGuiRend_DarrayFreeEntry(&jkGuiNetHost_dArray2);
        jkGuiRend_DarrayReallocStr(&jkGuiNetHost_dArray2, jkStrings_GetUniStringWithFallback("GUI_NO_LEVELS_IN_EPISODE"), 0);
        jkGuiRend_DarrayReallocStr(&jkGuiNetHost_dArray2, 0, 0);
        jkGuiRend_SetClickableString(&jkGuiNetHost_aElements[NETHOST_LEVEL_LISTBOX], &jkGuiNetHost_dArray2);
    }

#ifdef QOL_IMPROVEMENTS
    // Added: Only add Co-op flags on singleplayer levels
    if (jkGuiSingleplayer_FUN_0041d590(pElement->unistr[pElement->selectedTextEntry].c_str) & JK_EPISODE_SINGLEPLAYER) {
        jkGuiNetHost_bIsEpisodeCoop = 1;
    }
    else {
        jkGuiNetHost_bIsEpisodeCoop = 0;
    }
#endif

    // MOTS added
    /*
    if (jkGuiSingleplayer_FUN_0041d590(a1) & 0x10) {
        jkGuiNetHost_aElements[16].unlabelled16 = 1;
        jkGuiNetHost_aElements[15].unlabelled16 = 0;
        jkGuiNetHost_aElements[12].bIsVisible = 1;
        jkGuiNetHost_aElements[13].bIsVisible = 1;
        jkGuiNetHost_aElements[14].bIsVisible = 1;
    }
    */

    if ( mouseX != -1 || mouseY != -1 )
        jkGuiRend_UpdateAndDrawClickable(&jkGuiNetHost_aElements[NETHOST_LEVEL_LISTBOX], &jkGuiNetHost_menu, 1);
    return 0;
}

int jkGuiNetHost_sub_411AE0(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int redraw)
{
    wchar_t *v7; // eax
    int v9; // [esp-8h] [ebp-28h]
    wchar_t *v11; // [esp-4h] [ebp-24h]
    char v12[32]; // [esp+0h] [ebp-20h] BYREF

    if ( pElement->hoverId == 1 )
    {
        if ( jkGuiNetHost_maxRank )
        {
            stdString_snprintf(v12, 32, "RANK_%d_L", --jkGuiNetHost_maxRank);
            v11 = jkStrings_GetUniStringWithFallback(v12);
            v9 = jkGuiNetHost_maxRank;
            v7 = jkStrings_GetUniStringWithFallback("GUI_RANK");
            jk_snwprintf(jkGuiNetHost_wstrStarsText, 0x80u, v7, v9, v11);
            jkGuiNetHost_aElements[NETHOST_STARS_TEXT].wstr = jkGuiNetHost_wstrStarsText;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiNetHost_aElements[NETHOST_STARS_TEXT], pMenu, 1);
        }
    }
    else if ( pElement->hoverId == 2 && (unsigned int)jkGuiNetHost_maxRank < 8 )
    {
        stdString_snprintf(v12, 32, "RANK_%d_L", ++jkGuiNetHost_maxRank);
        jk_snwprintf(jkGuiNetHost_wstrStarsText, 0x80u, jkStrings_GetUniStringWithFallback("GUI_RANK"), jkGuiNetHost_maxRank, jkStrings_GetUniStringWithFallback(v12));
        jkGuiNetHost_aElements[NETHOST_STARS_TEXT].wstr = jkGuiNetHost_wstrStarsText;
        jkGuiRend_UpdateAndDrawClickable(&jkGuiNetHost_aElements[NETHOST_STARS_TEXT], pMenu, 1);
        return 0;
    }
    return 0;
}
