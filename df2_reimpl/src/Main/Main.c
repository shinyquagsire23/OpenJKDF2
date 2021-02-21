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
#include "World/jkPlayer.h"
#include "World/jkSaber.h"
#include "Win95/std.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdConsole.h"
#include "Win95/wuRegistry.h"
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
#include "Engine/rdroid.h"
#include "Engine/sith.h"

static common_functions hs;

int Main_Startup(const char *cmdline)
{
    int result; // eax

    stdInitServices(&hs);
    jkGuiNetHost_maxRank = 4;
    jkGuiNetHost_maxPlayers = 4;
    Video_8606AC = 4;
    pHS = &hs;
    jkPlayer_setFullSubtitles = 0;
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
    Video_modeIdx = 0;
    Video_descIdx = 0;
    Video_8605C8 = 0;
    Video_8605EC = 0;
    Video_8605F0 = 5;
    Video_8606A4 = 0;
    Video_8606A8 = 1;
    Video_8606B0 = 3;
    Video_8606B4 = 1;
    Video_8606B8 = 0;
    Video_8606BC = 0;
    Video_8606C0 = 0;
    Main_path[0] = 0;
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
    Main_ParseCmdLine((char *)cmdline);

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
        debug_log_fp = fopen("debug.log", "w+");
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
    wuRegistry_Startup(HKEY_LOCAL_MACHINE, "Software\\LucasArts Entertainment Company\\JediKnight\\v1.0", "0.1");
    stdStartup(&hs);
    jkGob_Startup();
    jkRes_Startup(pHS);
    Windows_Startup();
    jkStrings_Initialize();

    if (Windows_InitWindow())
    {
        rdStartup(&hs);
        jkGuiRend_Initialize();
        jkGui_Initialize();
        jkGuiMultiplayer_Initialize();
        jkGuiNetHost_Initialize();
        jkGuiSetup_Initialize();
        jkGuiDisplay_Initialize();
        jkGuiForce_Initialize();
        jkGuiMain_Initialize();
        jkGuiPlayer_Initialize();
        jkGuiSound_Initialize();
        jkGuiEsc_Startup();
        jkGuiMap_Initialize();
        jkGuiKeyboard_Initialize();
        jkGuiJoystick_Initialize();
        jkGuiDialog_Initialize();
        jkGuiMouse_Initialize();
        jkGuiControlOptions_Initialize();
        jkGuiObjectives_Initialize();
        jkGuiSingleTally_Initialize();
        jkGuiMultiTally_Initialize();
        jkGuiBuildMulti_InitializeEditCharacter();
        jkGuiTitle_Initialize();
        jkGuiGeneral_Initialize();
        jkGuiGameplay_Initialize();
        jkGuiDecision_Initialize();
        jkGuiSingleplayer_Initialize();
        jkGuiBuildMulti_Initialize();
        jkGuiSaveLoad_Initialize();
        jkGuiControlSaveLoad_Initialize();
        smack_Initialize();
        sith_Startup(&hs);
        jkAI_Startup();
        jkCog_Initialize();
        jkEpisode_Startup();
        jkDev_Startup();
        jkGame_Initialize();
        Video_Startup();
        jkControl_Initialize();
        jkHudInv_Initialize();
        jkSaber_Startup();
        jkCutscene_Initialize("ui\\cutStrings.uni");
        jkCredits_Initialize((int)"ui\\credits.uni");
        jkSmack_Initialize();

        if (jkRes_LoadCD(0))
        {
            jkSmack_SmackPlay("01-02a.smk");
            Window_SetDrawHandlers(stdDisplay_DrawAndFlipGdi, stdDisplay_SetCooperativeLevel);
            return 1;
        }
        return 0;
    }
    return 0;
}
