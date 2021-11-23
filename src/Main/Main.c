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

#if defined(MACOS) && defined(SDL2_RENDER)
#include <SDL2/SDL.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

static common_functions hs;

int Main_Startup(const char *cmdline)
{
    int result; // eax

    // TODO bring this to Windows (%appdata%) and Linux
#if defined(MACOS) && defined(SDL2_RENDER)
    const char *homedir;
    char fname[256];

    // Default working directory to the folder the .app bundle is in
    chdir(SDL_GetBasePath());

    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }

    if (homedir) {
        strcpy(fname, homedir);
        strcat(fname, "/.local/share/openjkdf2/resource/jk_.cd");

        // If ~/.local/share/openjkdf2/resource/jk_cd exists, use that directory as resource root
        if( access( fname, F_OK ) == 0 ) {
            strcpy(fname, homedir);
            strcat(fname, "/.local/share/openjkdf2");
            chdir(fname);
        }
    }    
#endif

    stdInitServices(&hs);    
    jkGuiNetHost_maxRank = 4;
    jkGuiNetHost_maxPlayers = 4;
    Video_modeStruct.geoMode = 4;
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

#ifndef __APPLE__
    stdFile_t tf = std_pHS->fileOpen("is_alive.txt", "w");
    const char* msg = "OpenJKDF2 is hooked and alive! \nCmdline: \n";
    std_pHS->fileWrite(tf, msg, _strlen(msg));
    std_pHS->fileWrite(tf, cmdline, _strlen(cmdline));
    std_pHS->fileClose(tf);
#endif

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
#ifndef LINUX_TMP
        jkGuiNetHost_Initialize(); //TODO
#endif
        jkGuiSetup_Initialize();
#ifndef SDL2_RENDER
        jkGuiDisplay_Initialize(); //TODO
#endif
        jkGuiForce_Initialize();
        jkGuiMain_Initialize();
        jkGuiPlayer_Initialize();
        jkGuiSound_Initialize();
        jkGuiEsc_Startup();
#ifndef LINUX_TMP
        jkGuiMap_Initialize(); // TODO
        jkGuiKeyboard_Initialize(); // TODO
        jkGuiJoystick_Initialize(); // TODO
#endif
        jkGuiDialog_Initialize();
#ifndef LINUX_TMP
        jkGuiMouse_Initialize(); // TODO
        jkGuiControlOptions_Initialize(); // TODO
#endif
        jkGuiObjectives_Initialize();
        jkGuiSingleTally_Initialize();
#ifndef LINUX_TMP
        jkGuiMultiTally_Initialize(); // TODO
        jkGuiBuildMulti_InitializeEditCharacter(); // TODO
#endif
        jkGuiTitle_Initialize();
        jkGuiGeneral_Initialize();
        jkGuiGameplay_Initialize();
        jkGuiDecision_Initialize();
        jkGuiSingleplayer_Initialize();
#ifndef LINUX_TMP
        jkGuiBuildMulti_Initialize(); // TODO
#endif
        jkGuiSaveLoad_Initialize(); // TODO
#ifndef LINUX_TMP
        jkGuiControlSaveLoad_Initialize(); // TODO
        smack_Initialize(); // TODO
#endif
        sith_Startup(&hs); // ~TODO
        jkAI_Startup();
        jkCog_Initialize();
        jkEpisode_Startup();
        jkDev_Startup();
        jkGame_Initialize();
        Video_Startup();
        jkControl_Initialize(); // ~TODO
        jkHudInv_Initialize();
        jkSaber_Startup();
        jkCutscene_Initialize("ui\\cutStrings.uni"); // TODO
        jkCredits_Initialize("ui\\credits.uni"); // TODO
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

void Main_Shutdown()
{
    jkSmack_Shutdown();
    jkGuiControlSaveLoad_Shutdown();
    jkGuiSaveLoad_Shutdown();
    jkGuiBuildMulti_Shutdown();
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
    jkGuiNetHost_Shutdown();
    jkGuiMultiplayer_Shutdown();
    jkGuiMain_Shutdown();
    jkGuiPlayer_Shutdown();
    jkGuiSound_Shutdown();
    jkGuiObjectives_Shutdown();
    jkGuiSingleTally_Shutdown();
    jkGuiRend_Shutdown();
    jkCog_Shutdown();
    sith_Free();
    jkCredits_Shutdown();
    jkCutscene_Shutdown();
    jkSaber_Shutdown();
    jkHudInv_Shutdown();
    if ( jkCutscene_smack_loaded )
        jkCutscene_sub_421410();
    Video_Shutdown();
    jkGame_Shutdown();
    jkDev_Shutdown();
    sith_Shutdown();
    smack_Shutdown();
    jkGui_Shutdown();
    rdShutdown();
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
        fclose(debug_log_fp);
    }
    
    exit(0);
}

void Main_ParseCmdLine(char *cmdline)
{
    char *v1; // esi
    char *v2; // esi
    char *v3; // esi
    char *v4; // eax

    v1 = _strtok(cmdline, " \t");
    if ( v1 )
    {
        while ( 1 )
        {
            if ( !__strcmpi(v1, "-path") || !__strcmpi(v1, "/path") )
            {
                v4 = _strtok(0, " \t");
                _strncpy(Main_path, v4, 0x7Fu);
                Main_path[127] = 0;
                goto LABEL_40;
            }
            if ( !__strcmpi(v1, "-devMode") || !__strcmpi(v1, "devMode") )
                break;
            if ( __strcmpi(v1, "-dispStats") && __strcmpi(v1, "/dispStats") )
            {
                if ( __strcmpi(v1, "-frameRate") && __strcmpi(v1, "/frameRate") )
                {
                    if ( __strcmpi(v1, "-windowGUI") && __strcmpi(v1, "/windowGUI") )
                    {
                        if ( !__strcmpi(v1, "-displayConfig") || !__strcmpi(v1, "/displayConfig") )
                            goto LABEL_38;
                        if ( !__strcmpi(v1, "-?") || !__strcmpi(v1, "/?") )
                            goto LABEL_43;
                        if ( __strcmpi(v1, "-debug") && __strcmpi(v1, "/debug") )
                        {
                            if ( __strcmpi(v1, "-verbose") && __strcmpi(v1, "/verbose") )
                            {
                                if ( __strcmpi(v1, "-noHUD") && __strcmpi(v1, "/noHUD") )
                                {
                                    pHS->errorPrint("Error in arguments.\n", 0, 0, 0, 0);
LABEL_43:
                                    pHS->messagePrint("\n", 0, 0, 0, 0);
                                    pHS->messagePrint(
                                        "Dark Forces II: Jedi Knight v%d.%02d%c\n",
                                        jkGuiTitle_verMajor,
                                        jkGuiTitle_verMinor,
                                        jkGuiTitle_verRevision,
                                        0);
                                    pHS->messagePrint("(c) 1997 Lucasfilm Ltd. and LucasArts Entertainment Company. All Rights Reserved.", 0, 0, 0, 0);
                                    pHS->messagePrint("Built %s %s\n", "Sep 10 1997", "09:39:21", 0, 0);
                                    pHS->messagePrint("\n", 0, 0, 0, 0);
                                    pHS->messagePrint("\n", 0, 0, 0, 0);
                                    jk_exit(3);
                                }
                                Main_bNoHUD = 1;
                            }
                            else
                            {
                                v2 = _strtok(0, " \t");
                                if ( _atoi(v2) < 0 )
                                {
                                    Main_verboseLevel = 0;
                                }
                                else if ( _atoi(v2) > 2 )
                                {
                                    Main_verboseLevel = 2;
                                }
                                else
                                {
                                    Main_verboseLevel = _atoi(v2);
                                }
                            }
                        }
                        else
                        {
                            v3 = _strtok(0, " \t");
                            if ( __strcmpi(v3, "con") )
                            {
                                if ( __strcmpi(v3, "log") )
                                {
                                    if ( __strcmpi(v3, "none") )
                                        goto LABEL_43;
                                    Main_logLevel = 0;
                                }
                                else
                                {
                                    Main_logLevel = 2;
                                }
                            }
                            else
                            {
                                Main_logLevel = 1;
                            }
                        }
                    }
                    else
                    {
                        Main_bWindowGUI = 1;
                    }
                }
                else
                {
                    Main_bFrameRate = 1;
                }
            }
            else
            {
                Main_bDispStats = 1;
            }
LABEL_40:
            v1 = _strtok(0, " \t");
            if ( !v1 )
                return;
        }
        Main_bDevMode = 1;
LABEL_38:
        Main_bDisplayConfig = 1;
        goto LABEL_40;
    }
}
