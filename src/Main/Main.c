#include "Main.h"

#include "../jk.h"
#include "stdPlatform.h"
#include "Cog/jkCog.h"
#include "Gui/jkGUINetHost.h"
#include "Gui/jkGUISound.h"
#include "Gui/jkGUIMultiplayer.h"
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIDisplay.h"
#include "Gui/jkGUIForce.h"
#include "Gui/jkGUIMain.h"
#include "Gui/jkGUIPlayer.h"
#include "Gui/jkGUIEsc.h"
#include "Gui/jkGUIMap.h"
#include "Gui/jkGUIKeyboard.h"
#include "Gui/jkGUIJoystick.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUIMouse.h"
#include "Gui/jkGUIControlOptions.h"
#include "Gui/jkGUIObjectives.h"
#include "Gui/jkGUISingleTally.h"
#include "Gui/jkGUIMultiTally.h"
#include "Gui/jkGUIBuildMulti.h"
#include "Gui/jkGUITitle.h"
#include "Gui/jkGUIGeneral.h"
#include "Gui/jkGUIGameplay.h"
#include "Gui/jkGUIDecision.h"
#include "Gui/jkGUISingleplayer.h"
#include "Gui/jkGUIControlSaveLoad.h"
#include "Gui/jkGUISaveLoad.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIMods.h"
#include "World/jkPlayer.h"
#include "Gameplay/jkSaber.h"
#include "Win95/std.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdConsole.h"
#include "Platform/wuRegistry.h"
#include "Platform/std3D.h"
#include "Win95/Video.h"
#include "Win95/Window.h"
#include "Win95/Windows.h"
#include "Main/jkGob.h"
#include "Main/jkRes.h"
#include "Main/jkStrings.h"
#include "Main/jkAI.h"
#include "Main/jkEpisode.h"
#include "Main/jkDev.h"
#include "Main/jkGame.h"
#include "Main/jkHudInv.h"
#include "Main/jkCutscene.h"
#include "Main/jkCredits.h"
#include "Main/jkControl.h"
#include "Main/jkSmack.h"
#include "Main/smack.h"
#include "Main/jkMain.h"
#include "Main/jkQuakeConsole.h"
#include "Engine/rdroid.h"
#include "Main/sithMain.h"
#include "Dss/sithMulti.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/util.h"
#include "General/stdFileUtil.h"
#include "General/stdJSON.h"
#include "Dss/jkDSS.h"
#include "Main/InstallHelper.h"
#include "sithCvar.h"

#include "Platform/Common/stdHttp.h"
#include "Platform/Common/stdUpdater.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

#if defined(SDL2_RENDER)
#include "SDL2_helper.h"
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <stdbool.h>
#if defined(LINUX) || defined(MACOS) || defined(TARGET_SWITCH)
#include <pwd.h>
#endif
#include "nfd.h"
#endif

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

static HostServices hs;

#ifdef QOL_IMPROVEMENTS
int32_t Main_bDedicatedServer = 0;
int32_t Main_bAutostart = 0;
int32_t Main_bAutostartSp = 0;
int32_t Main_bHeadless = 0;
int32_t Main_bVerboseNetworking = 0;
int32_t Main_bMotsCompat = 0;
int32_t Main_bDwCompat = 0;
int32_t Main_bEnhancedCogVerbs = 0;
char Main_strEpisode[129];
char Main_strMap[128+4];
#endif

#if defined(QOL_IMPROVEMENTS) && !defined(TARGET_NO_MULTIPLAYER_MENUS)
int Main_StartupDedicated(int bFullyDedicated)
{
    char* pRemoveExt;
    int bExplicitMap = 1;
    char aTmpPlayerShortName[32];
    const char* defaultEpisode = Main_bMotsCompat ? "" : "JK1MP";
    const char* defaultMap = Main_bMotsCompat ? "" : "m2.jkl";

    jkSmack_stopTick = 1;
    jkSmack_nextGuiState = JK_GAMEMODE_TITLE;
    Window_SetDrawHandlers(stdDisplay_DrawAndFlipGdi, stdDisplay_SetCooperativeLevel);

    if (!strlen(Main_strEpisode)) {
        strcpy(Main_strEpisode, defaultEpisode);
        bExplicitMap = 0;
    }
    if (!strlen(Main_strMap)) {
        strcpy(Main_strEpisode, defaultEpisode); // TODO
        strcpy(Main_strMap, defaultMap);
        bExplicitMap = 0;
    }
    if (pRemoveExt = strchr(Main_strEpisode, '.')) {
        *pRemoveExt = 0;
    }
    if (pRemoveExt = strchr(Main_strMap, '.')) {
        *pRemoveExt = 0;
    }
    strcat(Main_strMap, ".jkl");

    if (bFullyDedicated) {
        strcpy(aTmpPlayerShortName, "ServerDed");
        stdString_CharToWchar(jkPlayer_playerShortName, aTmpPlayerShortName, 31);
        jkPlayer_playerShortName[31] = 0;
        jkPlayer_CreateConf(L"ServerDed");
    }
    else {
        wuRegistry_GetString("playerShortName", aTmpPlayerShortName, 32, "ServerDed");
        stdString_CharToWchar(jkPlayer_playerShortName, aTmpPlayerShortName, 31);
        jkPlayer_playerShortName[31] = 0;
        jkPlayer_CreateConf(jkPlayer_playerShortName);
    }
    

    // Dedicated player has no control at all
    if (bFullyDedicated) {
        jkGuiNetHost_bIsDedicated = 1;
    }

    jkGuiNetHost_SaveSettings();
    jkGuiNetHost_LoadSettings();

    // Fake player
    stdString_SafeWStrCopy(jkGuiMultiplayer_mpcInfo.name, L"", 32);
    stdString_SafeStrCopy(jkGuiMultiplayer_mpcInfo.model, "ky.3do", 32);
    stdString_SafeStrCopy(jkGuiMultiplayer_mpcInfo.soundClass, "ky.snd", 32);
    //stdString_SafeStrCopy(jkGuiMultiplayer_mpcInfo.gap80, "", 32);
    stdString_SafeStrCopy(jkGuiMultiplayer_mpcInfo.sideMat, "sabergreen1.mat", 32);
    stdString_SafeStrCopy(jkGuiMultiplayer_mpcInfo.tipMat, "sabergreen0.mat", 32);
    jkGuiMultiplayer_mpcInfo.jediRank = 0;

    // Set up minimal render settings
    //jkPlayer_fov = 90;
    //jkPlayer_fovIsVertical = 1;
    //jkPlayer_enableTextureFilter = 0;
    //jkPlayer_enableOrigAspect = 0;
    //jkPlayer_enableBloom = 0;
    //jkPlayer_fpslimit = 150;
    //jkPlayer_enableVsync = 0;
    //jkPlayer_ssaaMultiple = 1.0;
    //jkPlayer_enableSSAO = 0;
    //jkPlayer_gamma = 1.0;
    
    jkMultiEntry3 v34;
    memset(&v34, 0, sizeof(v34));

    if (bExplicitMap) {
        wuRegistry_SetString("serverEpisodeGob", Main_strEpisode);
        wuRegistry_SetString("serverMapJkl", Main_strMap);
    }

    wuRegistry_GetWString("gameName", v34.serverName, 32, L"OpenJKDF2 Dedicated Server");
    wuRegistry_GetWString("serverPassword", v34.wPassword, 32, L"");
    wuRegistry_GetString("serverEpisodeGob", v34.episodeGobName, 32, Main_strEpisode);
    wuRegistry_GetString("serverMapJkl", v34.mapJklFname, 32, Main_strMap);

    if (_wcslen(v34.wPassword)) {
        jkGuiNetHost_sessionFlags |= SESSIONFLAG_PASSWORD;
    }

    jkGuiNetHost_sessionFlags |= SESSIONFLAG_ISDEDICATED;

    v34.tickRateMs = jkGuiNetHost_tickRate;
    v34.maxPlayers = jkGuiNetHost_maxPlayers;
    v34.sessionFlags = jkGuiNetHost_sessionFlags;
    v34.multiModeFlags = jkGuiNetHost_gameFlags;
    v34.maxRank = jkGuiNetHost_maxRank;
    v34.scoreLimit = jkGuiNetHost_scoreLimit;
    v34.timeLimit = jkGuiNetHost_timeLimit;

    sithNet_scorelimit = v34.scoreLimit;
    sithNet_multiplayer_timelimit = v34.timeLimit;

    if (!Main_bAutostartSp) {
        int v21 = sithMulti_CreatePlayer(
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
            jkGuiDialog_ErrorDialog(jkStrings_GetUniStringWithFallback("GUINET_HOSTERROR"), jkStrings_GetUniStringWithFallback("GUINET_USERCANCEL"));
        }
        else if ( v21 )
        {
            jkGuiDialog_ErrorDialog(jkStrings_GetUniStringWithFallback("GUINET_HOSTERROR"), jkStrings_GetUniStringWithFallback("GUINET_NOCONNECT"));
        }
    }
    
    
    std3D_StartScene();
    std3D_EndScene();
    sithMain_Load("static.jkl");
    jkHudInv_InitItems();

    if (!Main_bAutostartSp) {
        if (jkMain_loadFile2(v34.episodeGobName, v34.mapJklFname))
        {
            return 1;
        }
    }
    else {
        if (jkMain_LoadLevelSingleplayer(v34.episodeGobName, v34.mapJklFname))
        {
            return 1;
        }
    }
    

    return 0;
}
#endif // QOL_IMPROVEMENTS

int Main_Startup(const char *cmdline)
{
    int result; // eax

#if defined(PLATFORM_POSIX)
    // Make sure floating point stuff is using . and not ,
    setlocale(LC_ALL, "C");
#endif

    stdInitServices(&hs);
    jkGuiNetHost_maxRank = 4;
    jkGuiNetHost_maxPlayers = 4;
    Video_modeStruct.geoMode = 4;
    pHS = &hs;
    jkPlayer_setFullSubtitles = 1; // Added: Set subtitles as default for opening cutscene
    jkPlayer_setDisableCutscenes = 0;
    jkPlayer_setRotateOverlayMap = 1;
    jkPlayer_setDrawStatus = 1;
    jkPlayer_setCrosshair = 0;
    jkPlayer_setSaberCam = 0;
    jkGuiNetHost_gameFlags = 144;
    jkGuiNetHost_scoreLimit = 100;
    jkGuiNetHost_timeLimit = 30;
    jkGuiNetHost_sessionFlags = 0;
    jkGuiNetHost_tickRate = 180;
    Video_modeStruct.modeIdx = 0;
    Video_modeStruct.descIdx = 0;
    Video_modeStruct.Video_8605C8 = 0;
    Video_modeStruct.b3DAccel = 0;
    Video_modeStruct.viewSizeIdx = 5;
    Video_modeStruct.Video_8606A4 = 0;
    Video_modeStruct.Video_8606A8 = 1;
    Video_modeStruct.lightMode = 3;
    Video_modeStruct.texMode = 1;
    Video_modeStruct.Video_8606B8 = 0;
    Video_modeStruct.Video_8606BC = 0;
    Video_modeStruct.Video_8606C0 = 0;
    //Main_path[0] = 0; // Added: We reset this elsewhere
    Main_bWindowGUI = 1;
    Main_bDisplayConfig = 0;
    Main_dword_86078C = 0;
    Main_bFrameRate = 0;
    Main_bDispStats = 0;
    Main_bNoHUD = 0;
    Main_logLevel = 0;
    Main_verboseLevel = 0;
    Main_bDevMode = 0;
    jkGuiSound_musicVolume = 1.0;
    stdPlatform_Printf("%s\n", Main_path);
    Main_ParseCmdLine((char *)cmdline);
#ifdef TARGET_TWL
    Main_bNoHUD = 1;
#endif

    if ( Main_logLevel == 1 )
    {
        if ( Main_verboseLevel )
        {
            if ( Main_verboseLevel == 1 )
            {
                hs.messagePrint = stdConsolePrintf;
                hs.errorPrint = stdConsolePrintf;
            }
            else if ( Main_verboseLevel == 2 )
            {
                hs.debugPrint = stdConsolePrintf;
                hs.messagePrint = stdConsolePrintf;
                hs.errorPrint = stdConsolePrintf;
            }
        }
        else
        {
            hs.errorPrint = stdConsolePrintf;
        }
        stdConsole_Startup("Debug", 7u, Main_verboseLevel == 0);
    }
    else if ( Main_logLevel == 2 )
    {
        debug_log_fp = (stdFile_t)fopen("debug.log", "w+");
        if ( Main_verboseLevel )
        {
            if ( Main_verboseLevel == 1 )
            {
                hs.messagePrint = Main_FPrintf;
                hs.errorPrint = Main_FPrintf;
            }
            else if ( Main_verboseLevel == 2 )
            {
                hs.debugPrint = Main_FPrintf;
                hs.messagePrint = Main_FPrintf;
                hs.errorPrint = Main_FPrintf;
            }
        }
        else
        {
            hs.errorPrint = Main_FPrintf;
        }
    }
    stdStartup(&hs); // Added
    InstallHelper_SetCwd(); // Added

    wuRegistry_Startup(HKEY_LOCAL_MACHINE, "Software\\LucasArts Entertainment Company\\JediKnight\\v1.0", (BYTE*)"0.1");
    //stdStartup(&hs); // Moved

    stdHttp_Startup();

    jkGob_Startup();
    jkRes_Startup(pHS);
    Windows_Startup();
    jkStrings_Startup();
    sithCvar_Startup(); // Added

    if (Windows_InitWindow())
    {
        rdStartup(&hs);
        jkGuiRend_Startup(); // B15E8
        jkGui_Startup(); // 15C6D1
#if !defined(TARGET_NO_MULTIPLAYER_MENUS)
        jkGuiMultiplayer_Startup();
        jkGuiNetHost_Startup();
#endif
        jkGuiSetup_Startup();
        jkGuiDisplay_Startup();
        jkGuiForce_Startup();
        jkGuiMain_Startup();
        jkGuiPlayer_Startup();
        jkGuiSound_Startup();
        jkGuiEsc_Startup();
        jkGuiMap_Startup();
        jkGuiKeyboard_Startup();
        jkGuiJoystick_Startup();
        jkGuiDialog_Startup();
        jkGuiMouse_Startup();
        jkGuiControlOptions_Startup();
        jkGuiObjectives_Startup();
        jkGuiSingleTally_Startup();
#if !defined(TARGET_NO_MULTIPLAYER_MENUS)
        jkGuiMultiTally_Startup();
        jkGuiBuildMulti_StartupEditCharacter();
#endif
        jkGuiTitle_Startup();
        jkGuiGeneral_Startup();
        jkGuiGameplay_Startup();
        jkGuiDecision_Startup();
        jkGuiSingleplayer_Startup();
#if !defined(TARGET_NO_MULTIPLAYER_MENUS)
        jkGuiBuildMulti_Startup();
#endif
        jkGuiSaveLoad_Startup();
        jkGuiControlSaveLoad_Startup();
#ifdef QOL_IMPROVEMENTS
        jkGuiMods_Startup();
#endif
#ifndef LINUX_TMP
        smack_Startup(); // TODO
#endif
        sithMain_Startup(&hs); // ~TODO
        jkAI_Startup();
        jkCog_Startup();
        sithCog_StartupEnhanced();
        jkEpisode_Startup();
        jkDev_Startup();
        jkGame_Startup();
        Video_Startup();
        jkControl_Startup(); // ~TODO
        jkHudInv_Startup();
        jkDSS_Startup();
        jkCutscene_Startup("ui\\cutStrings.uni");
        jkCredits_Startup("ui\\credits.uni");
        jkSmack_Startup();

        std3D_Startup(); // Added
#ifdef QUAKE_CONSOLE
        jkQuakeConsole_Startup(); // Added
#endif

        if (jkRes_LoadCD(0))
        {
#if defined(QOL_IMPROVEMENTS) && !defined(TARGET_NO_MULTIPLAYER_MENUS)
            if (Main_bDedicatedServer || Main_bAutostart) {
                if (Main_StartupDedicated(Main_bDedicatedServer))
                {
                    return 1;
                }
            }
#endif
            if (!Main_bMotsCompat) {
                jkSmack_SmackPlay("01-02a.smk");
            }
            else {
                jkSmack_SmackPlay("jkmintro.san");
            }
            
            Window_SetDrawHandlers(stdDisplay_DrawAndFlipGdi, stdDisplay_SetCooperativeLevel);
            return 1;
        }
        return 0;
    }

    return 0;
}

void Main_Shutdown()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

    std3D_Shutdown(); // Added
#ifdef QUAKE_CONSOLE
    jkQuakeConsole_Shutdown();
#endif

    jkSmack_Shutdown();
    jkGuiControlSaveLoad_Shutdown();
    jkGuiSaveLoad_Shutdown();
#if !defined(TARGET_NO_MULTIPLAYER_MENUS)
    jkGuiBuildMulti_Shutdown();
#endif
    jkGuiSingleplayer_Shutdown();
    jkGuiDecision_Shutdown();
    jkGuiGameplay_Shutdown();
    jkGuiGeneral_Shutdown();
    jkGuiTitle_Shutdown();
    jkGuiControlOptions_Shutdown();
    jkGuiMouse_Shutdown();
    jkGuiDialog_Shutdown();
    jkGuiJoystick_Shutdown();
    jkGuiKeyboard_Shutdown();
    jkGuiMap_Shutdown();
    jkGuiEsc_Shutdown();
    jkGuiForce_Shutdown();
    jkGuiDisplay_Shutdown();
    jkGuiSetup_Shutdown();
#if !defined(TARGET_NO_MULTIPLAYER_MENUS)
    jkGuiNetHost_Shutdown();
    jkGuiMultiplayer_Shutdown();
#endif
    jkGuiMain_Shutdown();
    jkGuiPlayer_Shutdown();
    jkGuiSound_Shutdown();
    jkGuiObjectives_Shutdown();
    jkGuiSingleTally_Shutdown();
#ifdef QOL_IMPROVEMENTS
    jkGuiMods_Shutdown();
#endif
    jkGuiRend_Shutdown();
    jkCog_Shutdown();
    sithMain_Free();
    jkCredits_Shutdown();
    jkCutscene_Shutdown();
    jkDSS_Shutdown();
    jkControl_Shutdown(); // Added
    jkHudInv_Shutdown();
    if ( jkCutscene_isRendering )
        jkCutscene_stop();
    Video_Shutdown();
    jkGame_Shutdown();
    jkDev_Shutdown();
    sithMain_Shutdown();
#ifndef LINUX_TMP
    smack_Shutdown();
#endif
    jkGui_Shutdown();
    rdShutdown();
    sithCvar_Shutdown(); // Added
    jkStrings_Shutdown();
    Windows_Shutdown();
    jkRes_Shutdown();
    jkGob_Shutdown();
    stdShutdown();
    if ( Main_logLevel == 1 )
    {
        stdConsole_Shutdown();
    }
    else if ( Main_logLevel == 2 )
    {
        fclose((FILE*)debug_log_fp);
    }
    
    jkPlayer_ResetVars(); // Added

    stdHttp_Shutdown(); // Added

    // Added
    Main_bDedicatedServer = 0;
    Main_bAutostart = 0;
    Main_bHeadless = 0;
    Main_bVerboseNetworking = 0;
    Main_bDwCompat = 0;
    Main_bEnhancedCogVerbs = 0;
    memset(Main_strEpisode, 0, sizeof(Main_strEpisode));
    memset(Main_strMap, 0, sizeof(Main_strMap));

    stdPlatform_Printf("OpenJKDF2: %s done\n", __func__);

#ifndef QOL_IMPROVEMENTS
    exit(0);
#endif
}

// Inlined?
void Main_ShowHelp()
{
    pHS->messagePrint("\n", 0, 0, 0, 0);
    pHS->messagePrint(
        "Dark Forces II: Jedi Knight v%d.%02d%c\n",
        jkGuiTitle_verMajor,
        jkGuiTitle_verMinor,
        jkGuiTitle_verRevision,
        0);
    pHS->messagePrint("(c) 1997 Lucasfilm Ltd. and LucasArts Entertainment Company. All Rights Reserved.");
    pHS->messagePrint("Built %s %s\n", "Sep 10 1997", "09:39:21");
    pHS->messagePrint("\n");
    pHS->messagePrint("\n");
    jk_exit(3);
}

void Main_ParseCmdLine(char *cmdline)
{
    for (char* pArgTok = _strtok(cmdline, " \t"); pArgTok; pArgTok = _strtok(0, " \t"))
    {
        if ( !__strcmpi(pArgTok, "-path") || !__strcmpi(pArgTok, "/path") )
        {
            char* pArgNext = _strtok(0, " \t");
            stdString_SafeStrCopy(Main_path, pArgNext, 0x80);
        }
        else if ( !__strcmpi(pArgTok, "-fail") || !__strcmpi(pArgTok, "/fail") ) // MOTS added
        {
            //Main_failLogFp = fopen("fail.log", "w");
        }
        else if ( !__strcmpi(pArgTok, "-devMode") || !__strcmpi(pArgTok, "devMode") )
        {
            Main_bDevMode = 1;
            Main_bDisplayConfig = 1;
        }
        else if (!__strcmpi(pArgTok, "-dispStats") || !__strcmpi(pArgTok, "/dispStats") )
        {
            Main_bDispStats = 1;
        }
        else if (!__strcmpi(pArgTok, "-frameRate") || !__strcmpi(pArgTok, "/frameRate") )
        {
            Main_bFrameRate = 1;
        }
        else if (!__strcmpi(pArgTok, "-windowGUI") || !__strcmpi(pArgTok, "/windowGUI") )
        {
            Main_bWindowGUI = 1;
        }
        else if ( !__strcmpi(pArgTok, "-displayConfig") || !__strcmpi(pArgTok, "/displayConfig") )
        {
            Main_bDisplayConfig = 1;
        }
        else if ( !__strcmpi(pArgTok, "-?") || !__strcmpi(pArgTok, "/?") )
        {
            Main_ShowHelp();
        }
        else if (!__strcmpi(pArgTok, "-debug") || !__strcmpi(pArgTok, "/debug") )
        {
            char* pArgNext = _strtok(0, " \t");
            if (!__strcmpi(pArgNext, "con") )
            {
                Main_logLevel = 1;
            }
            else if (!__strcmpi(pArgNext, "log") )
            {
                Main_logLevel = 2;
            }
            else if (!__strcmpi(pArgNext, "none") )
            {
                Main_logLevel = 0;
            }
            else
            {
                Main_ShowHelp();
            }
        }
        else if (!__strcmpi(pArgTok, "-verbose") || !__strcmpi(pArgTok, "/verbose") )
        {
            char* pArgNext = _strtok(0, " \t");
            if ( _atoi(pArgNext) < 0 )
            {
                Main_verboseLevel = 0;
            }
            else if ( _atoi(pArgNext) > 2 )
            {
                Main_verboseLevel = 2;
            }
            else
            {
                Main_verboseLevel = _atoi(pArgNext);
            }
        }
        else if (!__strcmpi(pArgTok, "-noHUD") || !__strcmpi(pArgTok, "/noHUD") )
        {
            Main_bNoHUD = 1;
        }
        else if ( !__strcmpi(pArgTok, "-record") || !__strcmpi(pArgTok, "/record") ) // MOTS added
        {
            //sithTime_idk_record(0x53,0x53);
            //Main_bRecord = 1;
        }
        else if ( !__strcmpi(pArgTok, "-fixed") || !__strcmpi(pArgTok, "/fixed") ) // MOTS added
        {
            //sithTime_idk_record(0x53,0x53);
        }
        else if ( !__strcmpi(pArgTok, "-coglog") || !__strcmpi(pArgTok, "/coglog") ) // MOTS added
        {
            //Main_cogLogFp = fopen("cog.log", "wc");
        }
#ifdef QOL_IMPROVEMENTS
        else if (!__strcmpi(pArgTok, "-dedicatedServer") || !__strcmpi(pArgTok, "/dedicatedServer") )
        {
            Main_bDedicatedServer = 1;
        }
        else if (!__strcmpi(pArgTok, "-autostart") || !__strcmpi(pArgTok, "/autostart") )
        {
            Main_bAutostart = 1;
        }
        else if (!__strcmpi(pArgTok, "-sp") || !__strcmpi(pArgTok, "/sp") || !__strcmpi(pArgTok, "-singleplayer") || !__strcmpi(pArgTok, "/singleplayer"))
        {
            Main_bAutostartSp = 1;
        }
        else if (!__strcmpi(pArgTok, "-mp") || !__strcmpi(pArgTok, "/mp") || !__strcmpi(pArgTok, "-multiplayer") || !__strcmpi(pArgTok, "/multiplayer"))
        {
            Main_bAutostartSp = 0;
        }
        else if (!__strcmpi(pArgTok, "-episode") || !__strcmpi(pArgTok, "/episode") )
        {
            char* pArgNext = _strtok(0, " \t");
            stdString_SafeStrCopy(Main_strEpisode, pArgNext, 0x80);
        }
        else if (!__strcmpi(pArgTok, "-map") || !__strcmpi(pArgTok, "/map") )
        {
            char* pArgNext = _strtok(0, " \t");
            stdString_SafeStrCopy(Main_strMap, pArgNext, 0x80);
        }
        else if (!__strcmpi(pArgTok, "-headless") || !__strcmpi(pArgTok, "/headless") )
        {
            Main_bHeadless = 1;
        }
        else if (!__strcmpi(pArgTok, "-verboseNetworking") || !__strcmpi(pArgTok, "/verboseNetworking") )
        {
            Main_bVerboseNetworking = 1;
        }
        else if (!__strcmpi(pArgTok, "-motsCompat") || !__strcmpi(pArgTok, "/motsCompat"))
        {
            Main_bMotsCompat = 1;
        }
        else if (!__strcmpi(pArgTok, "-enhancedCogVerbs") || !__strcmpi(pArgTok, "/enhancedCogVerbs"))
        {
            Main_bEnhancedCogVerbs = 1;
        }
        else if (!__strcmpi(pArgTok, "-dwCompat") 
                 || !__strcmpi(pArgTok, "/dwCompat") 
                 || !__strcmpi(pArgTok, "-droidworksCompat") 
                 || !__strcmpi(pArgTok, "/droidworksCompat"))
        {
            Main_bDwCompat = 1;
        }
#endif
        else
        {
            pHS->errorPrint("Error in arguments.\n", 0, 0, 0, 0);
            Main_ShowHelp();
        }
    }
}

int Main_FPrintf(const char* fmt, ...) {
    va_list args;
    va_start (args, fmt);
    int ret = __vsnprintf(std_genBuffer, 0x400, fmt, args);
    va_end (args);

    fputs(std_genBuffer, (FILE*)debug_log_fp);
    fflush((FILE*)debug_log_fp);

    return ret;
}
