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
#include "Platform/wuRegistry.h"
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

#include "General/util.h"
#include "General/stdFileUtil.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

#if defined(SDL2_RENDER)
#include <SDL.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <stdbool.h>
#if defined(LINUX) || defined(MACOS)
#include <pwd.h>
#endif
#include "nfd.h"
#endif

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

static common_functions hs;

#if defined(SDL2_RENDER) && !defined(ARCH_WASM)
const char* aRequiredAssets[] = {
    "episode/JK1.gob",
    "episode/JK1CTF.gob",
    "episode/JK1MP.gob",
    "resource/Res1hi.gob",
    "resource/Res2.gob",
    "resource/jk_.cd",
};

const size_t aRequiredAssets_len = sizeof(aRequiredAssets) / sizeof(const char*);

#define BUF_SIZE 65536 //2^16

int Main_copy(const char* in_path, const char* out_path){
  size_t n;
  FILE* in=NULL, * out=NULL;
  char* buf = calloc(BUF_SIZE, 1);
  if((in = fopen(in_path, "rb")) && (out = fopen(out_path, "wb")))
    while((n = fread(buf, 1, BUF_SIZE, in)) && fwrite(buf, 1, n, out));
  free(buf);
  if(in) fclose(in);
  if(out) fclose(out);
  return EXIT_SUCCESS;
}

int Main_CopyFile(const char* pFolder, const char* pName)
{
    char tmp[4096];
    char tmpTo[4096];
    
    strncpy(tmp, pFolder, sizeof(tmp)-1);
    strncat(tmp, "/", sizeof(tmp)-1);
    strncat(tmp, pName, sizeof(tmp)-1);
    strncpy(tmpTo, pName, sizeof(tmpTo)-1);

#ifdef LINUX
    char *r = malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free(r);

    r = malloc(strlen(tmpTo) + 16);
    if (casepath(tmpTo, r))
    {
        strcpy(tmpTo, r);
    }
    free(r);
#endif

#ifdef WIN32
    for (int i = 0; i < strlen(tmp); i++)
    {
        if (tmp[i] == '/') {
            tmp[i] = '\\';
        }
    }

    for (int i = 0; i < strlen(tmpTo); i++)
    {
        if (tmpTo[i] == '/') {
            tmpTo[i] = '\\';
        }
    }
#endif

    printf("asset copy: %s -> %s\n", tmp, tmpTo);

    // Files are the same
    if (!strcmp(tmp, tmpTo)) {
        return 0;
    }

    if (!util_FileExists(tmp)) {
        return 0;
    }

    Main_copy(tmp, tmpTo);

    if (!util_FileExists(tmpTo)) {
        return 0;
    }

    return 1;
}

int Main_CopyFileDisk(const char* pFolder, const char* pName)
{
    char tmp[4096];
    char tmpTo[4096];
    
    strncpy(tmp, pFolder, sizeof(tmp)-1);
    strncat(tmp, "/GAMEDATA/", sizeof(tmp)-1);
    if (!strcmp(pName, "resource/Res1hi.gob")) {
        strncat(tmp, "MININSTALL/RES1HI.GOB", sizeof(tmp)-1);
    }
    else if (!strcmp(pName, "resource/Res1low.gob")) {
        strncat(tmp, "MININSTALL/RES1LOW.GOB", sizeof(tmp)-1);
    }
    else if (!strcmp(pName, "JK.EXE")) {
        strncat(tmp, "EXE/JK.EXE", sizeof(tmp)-1);
    }
    else
    {
        strncat(tmp, pName, sizeof(tmp)-1);
    }
    strncpy(tmpTo, pName, sizeof(tmpTo)-1);

#ifdef LINUX
    char *r = malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free(r);

    r = malloc(strlen(tmpTo) + 16);
    if (casepath(tmpTo, r))
    {
        strcpy(tmpTo, r);
    }
    free(r);
#endif

#ifdef WIN32
    for (int i = 0; i < strlen(tmp); i++)
    {
        if (tmp[i] == '/') {
            tmp[i] = '\\';
        }
    }

    for (int i = 0; i < strlen(tmpTo); i++)
    {
        if (tmpTo[i] == '/') {
            tmpTo[i] = '\\';
        }
    }
#endif

    printf("disk copy: %s -> %s\n", tmp, tmpTo);

    // Files are the same
    if (!strcmp(tmp, tmpTo)) {
        return 0;
    }

    if (!util_FileExists(tmp)) {
        return 0;
    }

    Main_copy(tmp, tmpTo);

    if (!util_FileExists(tmpTo)) {
        return 0;
    }

    return 1;
}

void Main_UseLocalData()
{
    const char *homedir;
    char fname[256];

#if defined(MACOS) || defined(LINUX)
    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }

    if (homedir) {
        strcpy(fname, homedir);
        strcat(fname, "/.local");
        stdFileUtil_MkDir(fname);
        strcat(fname, "/share");
        stdFileUtil_MkDir(fname);
        strcat(fname, "/openjkdf2");
        stdFileUtil_MkDir(fname);
        chdir(fname);   
        printf("Using root directory: %s\n", fname);     
    }

#elif defined(WIN32)
    homedir = getenv("AppData");

    if (homedir) {
        strcpy(fname, homedir);
        stdFileUtil_MkDir(fname);
        strcat(fname, "\\Local");
        stdFileUtil_MkDir(fname);
        strcat(fname, "\\openjkdf2");
        stdFileUtil_MkDir(fname);
        chdir(fname);
        printf("Using root directory: %s\n", fname);
    }
#endif
}

int Main_AttemptInstallFromExisting(nfdu8char_t* path)
{
    const char* aOptionalAssets[] = {
        "JK.EXE",

        // idk if these are possible, but whatever, try it.
        "MUSIC/Track0.ogg",
        "MUSIC/Track1.ogg",
        "MUSIC/Track2.ogg",
        "MUSIC/Track3.ogg",
        "MUSIC/Track4.ogg",
        "MUSIC/Track5.ogg",
        "MUSIC/Track6.ogg",
        "MUSIC/Track7.ogg",
        "MUSIC/Track8.ogg",
        "MUSIC/Track9.ogg",
        "MUSIC/Track10.ogg",
        "MUSIC/Track11.ogg",

        // OpenJKDF2 song rips
        "MUSIC/1/Track0.ogg",
        "MUSIC/1/Track1.ogg",
        "MUSIC/1/Track2.ogg",
        "MUSIC/1/Track3.ogg",
        "MUSIC/1/Track4.ogg",
        "MUSIC/1/Track5.ogg",
        "MUSIC/1/Track6.ogg",
        "MUSIC/1/Track7.ogg",
        "MUSIC/1/Track8.ogg",
        "MUSIC/1/Track9.ogg",
        "MUSIC/1/Track10.ogg",
        "MUSIC/1/Track11.ogg",

        "MUSIC/2/Track0.ogg",
        "MUSIC/2/Track1.ogg",
        "MUSIC/2/Track2.ogg",
        "MUSIC/2/Track3.ogg",
        "MUSIC/2/Track4.ogg",
        "MUSIC/2/Track5.ogg",
        "MUSIC/2/Track6.ogg",
        "MUSIC/2/Track7.ogg",
        "MUSIC/2/Track8.ogg",
        "MUSIC/2/Track9.ogg",
        "MUSIC/2/Track10.ogg",
        "MUSIC/2/Track11.ogg",

        // GOG tracks
        "MUSIC/Track12.ogg",
        "MUSIC/Track13.ogg",
        "MUSIC/Track14.ogg",
        "MUSIC/Track15.ogg",
        "MUSIC/Track16.ogg",
        "MUSIC/Track17.ogg",
        "MUSIC/Track18.ogg",
        "MUSIC/Track22.ogg",
        "MUSIC/Track23.ogg",
        "MUSIC/Track24.ogg",
        "MUSIC/Track25.ogg",
        "MUSIC/Track26.ogg",
        "MUSIC/Track27.ogg",
        "MUSIC/Track28.ogg",
        "MUSIC/Track29.ogg",
        "MUSIC/Track30.ogg",
        "MUSIC/Track31.ogg",
        "MUSIC/Track32.ogg",

        // Technically optional
        "resource/video/01-02A.SMK",
        "resource/video/03-04A.SMK",
        "resource/video/06A.SMK",
        "resource/video/08-10A.SMK",
        "resource/video/12A.SMK",
        "resource/video/16A.SMK",
        "resource/video/18-19A.SMK",
        "resource/video/21A.SMK",
        "resource/video/23A.SMK",
        "resource/video/25A.SMK",
        "resource/video/27A.SMK",
        "resource/video/33-34A.SMK",
        "resource/video/36A.SMK",
        "resource/video/38A.SMK",
        "resource/video/39A.SMK",
        "resource/video/41-42A.SMK",
        "resource/video/41DA.SMK",
        "resource/video/41DSA.SMK",
        "resource/video/44A.SMK",
        "resource/video/46A.SMK",
        "resource/video/48A.SMK",
        "resource/video/50A.SMK",
        "resource/video/52-53A.SMK",
        "resource/video/54A.SMK",
        "resource/video/57A.SMK",

        // Controls
        "controls/assassin.ctl",
        "controls/chkeybrd.ctl",
        "controls/fcskybrd.ctl",
        "controls/ms_3dpro.ctl",
        "controls/wwarrior.ctl",
        "controls/ch_f-16.ctl",
        "controls/cybrman2.ctl",
        "controls/gamepad.ctl",
        "controls/prcision.ctl",
        "controls/ch_pro.ctl",
        "controls/fcs.ctl",
        "controls/gravis.ctl",
        "controls/spaceorb.ctl",
        "controls/CH F-16 COMBAT STICK.CTL",
        "controls/CH FLIGHTSTICK PRO OPTIMIZED WITH KEYBOARD.CTL",
        "controls/CH FLIGHTSTICK PRO.CTL",
        "controls/FP GAMING ASSASSIN 3D WITH JOYSTICK.CTL",
        "controls/GRAVIS GAMEPAD PRO.CTL",
        "controls/LOGITECH CYBERMAN 2.CTL",
        "controls/LOGITECH WINGMAN WARRIOR.CTL",
        "controls/MS SIDEWINDER 3D PRO.CTL",
        "controls/MS SIDEWINDER GAME PAD.CTL",
        "controls/MS SIDEWINDER PRECISION PRO OR FF.CTL",
        "controls/SPACETEC SPACEORB 360.CTL",
        "controls/THRUSTMASTER FCS OPTIMIZED WITH KEYBOARD.CTL",
        "controls/THRUSTMASTER FCS.CTL",

        // Demo assets
        "jkdemo.exe",
        "episode/jk1demo.gob",
        "episode/jk1mpdem.gob",
        "episode/jk1mpdemo.gob",
        "resource/res1demo.gob",
        "resource/video/splash.smk",

        // OpenJKDF2, not really optional but if they copied it, then copy it.
        "resource/shaders/default_f.glsl",
        "resource/shaders/default_v.glsl",
        "resource/shaders/menu_f.glsl",
        "resource/shaders/menu_v.glsl",
    };

    if (path[strlen(path)-1] == '/' || path[strlen(path)-1] == '\\')
    {
        path[strlen(path)-1] = 0;
    }

    const size_t aOptionalAssets_len = sizeof(aOptionalAssets) / sizeof(const char*);

    Main_UseLocalData();
    stdFileUtil_MkDir("episode");
    stdFileUtil_MkDir("MUSIC");
    stdFileUtil_MkDir("MUSIC/1");
    stdFileUtil_MkDir("MUSIC/2");
    stdFileUtil_MkDir("player");
    stdFileUtil_MkDir("resource");
    stdFileUtil_MkDir("resource/shaders");
    stdFileUtil_MkDir("resource/video");
    for (size_t i = 0; i < aRequiredAssets_len; i++)
    {
        if (!Main_CopyFile(path, aRequiredAssets[i]))
        {
            char tmp[4096+256];
            snprintf(tmp, sizeof(tmp), "Missing required asset `%s`!", aRequiredAssets[i]);
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "OpenJKDF2 Install Helper", tmp, NULL);
        }
    }

    for (size_t i = 0; i < aOptionalAssets_len; i++)
    {
        Main_CopyFile(path, aOptionalAssets[i]);
    }

    uint32_t magic = 0x699232C4;
    FILE* f = fopen("resource/jk_.cd", "wb");
    if (f) {
        fwrite(&magic, 1, sizeof(magic), f);
        fclose(f);
    }

    NFD_Quit();

    return 1;
}

int Main_AttemptInstallFromDisk(nfdu8char_t* path)
{
    bool isTwoPartCD = false;

    const char* aOptionalAssets[] = {
        "JK.EXE",

        // Technically optional
        "resource/video/01-02A.SMK",
        "resource/video/03-04A.SMK",
        "resource/video/06A.SMK",
        "resource/video/08-10A.SMK",
        "resource/video/12A.SMK",
        "resource/video/16A.SMK",
        "resource/video/18-19A.SMK",
        "resource/video/21A.SMK",
        "resource/video/23A.SMK",
        "resource/video/25A.SMK",
        "resource/video/27A.SMK",
        "resource/video/33-34A.SMK",
        "resource/video/36A.SMK",
        "resource/video/38A.SMK",
        "resource/video/39A.SMK",
        "resource/video/41-42A.SMK",
        "resource/video/41DA.SMK",
        "resource/video/41DSA.SMK",
        "resource/video/44A.SMK",
        "resource/video/46A.SMK",
        "resource/video/48A.SMK",
        "resource/video/50A.SMK",
        "resource/video/52-53A.SMK",
        "resource/video/54A.SMK",
        "resource/video/57A.SMK",

        // Controls
        "controls/assassin.ctl",
        "controls/chkeybrd.ctl",
        "controls/fcskybrd.ctl",
        "controls/ms_3dpro.ctl",
        "controls/wwarrior.ctl",
        "controls/ch_f-16.ctl",
        "controls/cybrman2.ctl",
        "controls/gamepad.ctl",
        "controls/prcision.ctl",
        "controls/ch_pro.ctl",
        "controls/fcs.ctl",
        "controls/gravis.ctl",
        "controls/spaceorb.ctl",
        "controls/CH F-16 COMBAT STICK.CTL",
        "controls/CH FLIGHTSTICK PRO OPTIMIZED WITH KEYBOARD.CTL",
        "controls/CH FLIGHTSTICK PRO.CTL",
        "controls/FP GAMING ASSASSIN 3D WITH JOYSTICK.CTL",
        "controls/GRAVIS GAMEPAD PRO.CTL",
        "controls/LOGITECH CYBERMAN 2.CTL",
        "controls/LOGITECH WINGMAN WARRIOR.CTL",
        "controls/MS SIDEWINDER 3D PRO.CTL",
        "controls/MS SIDEWINDER GAME PAD.CTL",
        "controls/MS SIDEWINDER PRECISION PRO OR FF.CTL",
        "controls/SPACETEC SPACEORB 360.CTL",
        "controls/THRUSTMASTER FCS OPTIMIZED WITH KEYBOARD.CTL",
        "controls/THRUSTMASTER FCS.CTL",

        // Demo assets
        "jkdemo.exe",
        "episode/jk1demo.gob",
        "episode/jk1mpdem.gob",
        "episode/jk1mpdemo.gob",
        "resource/res1demo.gob",
        "resource/video/splash.smk",

        // OpenJKDF2, not really optional but if they copied it, then copy it.
        "resource/shaders/default_f.glsl",
        "resource/shaders/default_v.glsl",
        "resource/shaders/menu_f.glsl",
        "resource/shaders/menu_v.glsl",
    };

    if (path[strlen(path)-1] == '/' || path[strlen(path)-1] == '\\')
    {
        path[strlen(path)-1] = 0;
    }

    const size_t aOptionalAssets_len = sizeof(aOptionalAssets) / sizeof(const char*);

    // Check if this is a two-disk set, or one of the new-printed single disks
    char checkDisk1[4096];
    char checkDisk2[4096];

    strncpy(checkDisk1, path, sizeof(checkDisk1)-1);
    strncat(checkDisk1, "/GAMEDATA/RESOURCE/VIDEO/01-02A.SMK", sizeof(checkDisk1)-1);

    strncpy(checkDisk2, path, sizeof(checkDisk2)-1);
    strncat(checkDisk2, "/GAMEDATA/RESOURCE/VIDEO/23A.SMK", sizeof(checkDisk2)-1);
    if (!util_FileExists(checkDisk1) || !util_FileExists(checkDisk2)) {
        isTwoPartCD = true;
    }

    Main_UseLocalData();
    stdFileUtil_MkDir("episode");
    stdFileUtil_MkDir("MUSIC");
    stdFileUtil_MkDir("MUSIC/1");
    stdFileUtil_MkDir("MUSIC/2");
    stdFileUtil_MkDir("player");
    stdFileUtil_MkDir("resource");
    stdFileUtil_MkDir("resource/shaders");
    stdFileUtil_MkDir("resource/video");
    for (size_t i = 0; i < aRequiredAssets_len; i++)
    {
        Main_CopyFileDisk(path, aRequiredAssets[i]);
    }

    for (size_t i = 0; i < aOptionalAssets_len; i++)
    {
        Main_CopyFileDisk(path, aOptionalAssets[i]);
    }

    if (isTwoPartCD) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "OpenJKDF2 Install Helper", "Finished copying from Disk 1.\nPlease mount and then select Disk 2.", NULL);

        nfdresult_t selRet = NFD_PickFolderU8(&path, NULL);
        if (selRet != NFD_OKAY || !path) {
            //SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", "Failed during file chooser", NULL);
            //return 0;
            goto final_check;
        }

        if (path[strlen(path)-1] == '/' || path[strlen(path)-1] == '\\')
        {
            path[strlen(path)-1] = 0;
        }

        for (size_t i = 0; i < aRequiredAssets_len; i++)
        {
            Main_CopyFileDisk(path, aRequiredAssets[i]);
        }

        for (size_t i = 0; i < aOptionalAssets_len; i++)
        {
            Main_CopyFileDisk(path, aOptionalAssets[i]);
        }
    }

final_check:

#if 0
    // Final check
    for (size_t i = 0; i < aRequiredAssets_len; i++)
    {
        if (!util_FileExists(aRequiredAssets[i]))
        {
            char tmp[4096+256];
            snprintf(tmp, sizeof(tmp), "Missing required asset `%s`!", aRequiredAssets[i]);
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "OpenJKDF2 Install Helper", tmp, NULL);
        }
    }
#endif
    Main_CheckRequiredAssets(0);

    uint32_t magic = 0x699232C4;
    FILE* f = fopen("resource/jk_.cd", "wb");
    if (f) {
        fwrite(&magic, 1, sizeof(magic), f);
        fclose(f);
    }

    NFD_Quit();

    return 1;
}

int Main_AttemptInstall()
{
    // TODO: Polyglot
    const SDL_MessageBoxButtonData buttons[] = {
        { SDL_MESSAGEBOX_BUTTON_RETURNKEY_DEFAULT, 0, "Install" },
        { SDL_MESSAGEBOX_BUTTON_ESCAPEKEY_DEFAULT, 1, "Cancel" },
    };
    const SDL_MessageBoxColorScheme colorScheme = {
        { /* .colors (.r, .g, .b) */
            /* [SDL_MESSAGEBOX_COLOR_BACKGROUND] */
            { 56,  54,  53 },
            /* [SDL_MESSAGEBOX_COLOR_TEXT] */
            {   209, 207, 205 },
            /* [SDL_MESSAGEBOX_COLOR_BUTTON_BORDER] */
            { 209, 207, 205 },
            /* [SDL_MESSAGEBOX_COLOR_BUTTON_BACKGROUND] */
            { 105, 102, 99 },
            /* [SDL_MESSAGEBOX_COLOR_BUTTON_SELECTED] */
            { 205, 202, 53 }
        }
    };
    const SDL_MessageBoxData messageboxdata = {
        SDL_MESSAGEBOX_INFORMATION, /* .flags */
        NULL, /* .window */
        "OpenJKDF2 Install Helper", /* .title */
        "OpenJKDF2 could not find required game assets.\nWould you like to install assets now?", /* .message */
        SDL_arraysize(buttons), /* .numbuttons */
        buttons, /* .buttons */
        &colorScheme /* .colorScheme */
    };

    int buttonid;
    if (SDL_ShowMessageBox(&messageboxdata, &buttonid) < 0) {
        SDL_Log("error displaying message box");
        return 0;
    }

    if (buttonid == -1 || buttonid == 1) return 0;

    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "OpenJKDF2 Install Helper", "Please select your existing JKDF2 installation, or an install disk mount.", NULL);
    
    if (NFD_Init() != NFD_OKAY) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", "Failed to initialize file chooser", NULL);
        return 0;
    }

    nfdu8char_t* path;
    nfdresult_t selRet = NFD_PickFolderU8(&path, NULL);
    if (selRet != NFD_OKAY || !path) {
        //SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", "Failed during file chooser", NULL);
        return 0;
    }
    //SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "OpenJKDF2 Install Helper", path, NULL);

    // Check if this is a disk
    char checkDisk[4096];

    strncpy(checkDisk, path, sizeof(checkDisk)-1);
    strncat(checkDisk, "/AUTORUN.INF", sizeof(checkDisk)-1);
    if (util_FileExists(checkDisk)) {
        return Main_AttemptInstallFromDisk(path);
    }

    // Disk 2 has no autorun
    strncpy(checkDisk, path, sizeof(checkDisk)-1);
    strncat(checkDisk, "/GAMEDATA/RESOURCE/JK_.CD", sizeof(checkDisk)-1);
    if (util_FileExists(checkDisk)) {
        return Main_AttemptInstallFromDisk(path);
    }

    return Main_AttemptInstallFromExisting(path);
}

void Main_CheckRequiredAssets(int doInstall)
{
    const char* msg = "OpenJKDF2 is missing the following required assets:\n";

    char* bigList = NULL;
    size_t bigList_len = strlen(msg);
    bool missingRequireds = false;
    for (size_t i = 0; i < aRequiredAssets_len; i++)
    {
        if (!util_FileExists(aRequiredAssets[i]))
        {
            missingRequireds = true;
            bigList_len += strlen(aRequiredAssets[i]) + 2;
        }
    }

    if (!missingRequireds) return;

    bigList = malloc(bigList_len);
    if (!bigList) return;
    memset(bigList, 0, bigList_len);

    strcpy(bigList, msg);

    for (size_t i = 0; i < aRequiredAssets_len; i++)
    {
        if (!util_FileExists(aRequiredAssets[i]))
        {
            strcat(bigList, aRequiredAssets[i]);
            strcat(bigList, "\n");
        }
    }

    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", bigList, NULL);

    if (doInstall) {
        Main_AttemptInstall();
    }
}
#endif // defined(SDL2_RENDER) && !defined(ARCH_WASM)

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
    wuRegistry_Startup(HKEY_LOCAL_MACHINE, "Software\\LucasArts Entertainment Company\\JediKnight\\v1.0", "0.1");
    stdStartup(&hs);

    // TODO bring this to Windows (%appdata%) and Linux
#if (defined(MACOS) || defined(LINUX)) && defined(SDL2_RENDER) && !defined(ARCH_WASM)
    const char *homedir;
    char fname[256];

#if defined(MACOS)
    // Default working directory to the folder the .app bundle is in
    char* base_path = SDL_GetBasePath();
    chdir(base_path);
    chdir("..");
    SDL_free(base_path);
#endif

    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }

    if (homedir) {
        strcpy(fname, homedir);
        strcat(fname, "/.local/share/openjkdf2/resource/jk_.cd");

        // If ~/.local/share/openjkdf2/resource/jk_cd exists, use that directory as resource root
        if(util_FileExists(fname) && !util_FileExists("resource/jk_.cd")) {
            Main_UseLocalData();
        }
    }
#elif defined(WIN32)&& defined(SDL2_RENDER)
    const char *homedir;
    char fname[256];
    homedir = getenv("AppData");
    if (homedir) {
        strcpy(fname, homedir);
        strcat(fname, "\\Local\\openjkdf2\\resource\\jk_.cd");

        if (util_FileExists(fname) && !util_FileExists("resource\\jk_.cd")) {
            Main_UseLocalData();
        }
    }
#endif // (defined(MACOS) || defined(LINUX)) && defined(SDL2_RENDER)

#if defined(SDL2_RENDER) && !defined(ARCH_WASM)
    /*if (!util_FileExists("resource/jk_.cd")) {
        // TODO: polyglot
        //SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", "OpenJKDF2 could not find any game assets (`resource/jk_.cd` is missing). Would you like to install assets now?", NULL);
        Main_AttemptInstall();
    }*/
    if (!util_FileExists("resource/jk_.cd")) {
        Main_CheckRequiredAssets(1);
    }
#endif

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
        jkGuiNetHost_Initialize(); //TODO
        jkGuiSetup_Initialize();
        jkGuiDisplay_Initialize();
        jkGuiForce_Initialize();
        jkGuiMain_Initialize();
        jkGuiPlayer_Initialize();
        jkGuiSound_Initialize();
        jkGuiEsc_Startup();
        jkGuiMap_Initialize();
        jkGuiKeyboard_Initialize(); // TODO
#ifndef LINUX_TMP
        jkGuiJoystick_Initialize(); // TODO
#endif
        jkGuiDialog_Initialize();
        jkGuiMouse_Initialize();
        jkGuiControlOptions_Initialize();
        jkGuiObjectives_Initialize();
        jkGuiSingleTally_Initialize();
        jkGuiMultiTally_Initialize();
        jkGuiBuildMulti_InitializeEditCharacter(); // TODO
        jkGuiTitle_Initialize();
        jkGuiGeneral_Initialize();
        jkGuiGameplay_Initialize();
        jkGuiDecision_Initialize();
        jkGuiSingleplayer_Initialize();
        jkGuiBuildMulti_Initialize();
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
        fclose((FILE*)debug_log_fp);
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
