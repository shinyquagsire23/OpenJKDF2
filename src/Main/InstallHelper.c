#include "InstallHelper.h"

#include "../jk.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/util.h"
#include "General/stdFileUtil.h"
#include "Main/jkRes.h"
#include "stdPlatform.h"

#if defined(SDL2_RENDER) && !defined(ARCH_WASM) && !defined(TARGET_ANDROID)

const char* aRequiredAssets[] = {
    "episode/JK1.gob",
    "episode/JK1CTF.gob",
    "episode/JK1MP.gob",
    "resource/Res1hi.gob",
    "resource/Res2.gob",
    "resource/jk_.cd",
};

const size_t aRequiredAssets_len = sizeof(aRequiredAssets) / sizeof(const char*);

const char* aRequiredAssetsMots[] = {
    "episode/JKM_KFY.goo",
    "episode/JKM_MP.goo",
    "episode/JKM_SABER.goo",
    "episode/JKM.goo",
    "resource/Jkmres.goo",
    "resource/JKMsndLO.goo",
    "resource/jk_.cd",
};

const size_t aRequiredAssetsMots_len = sizeof(aRequiredAssetsMots) / sizeof(const char*);

#define BUF_SIZE 65536 //2^16

#define INSTALL_APPDATA_FOLDER_NAME (Main_bMotsCompat ? "openjkmots" : "openjkdf2")
#define INSTALL_OVERRIDE_ENVVAR_NAME (Main_bMotsCompat ? "OPENJKMOTS_ROOT" : "OPENJKDF2_ROOT")

int InstallHelper_copy(const char* in_path, const char* out_path)
{
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

int InstallHelper_CopyFile(const char* pFolder, const char* pName)
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

    stdPlatform_Printf("asset copy: %s -> %s\n", tmp, tmpTo);

    // Files are the same
    if (!strcmp(tmp, tmpTo)) {
        return 0;
    }

    if (!util_FileExists(tmp)) {
        return 0;
    }

    InstallHelper_copy(tmp, tmpTo);

    if (!util_FileExists(tmpTo)) {
        return 0;
    }

    return 1;
}

int InstallHelper_CopyFileDisk(const char* pFolder, const char* pName)
{
    char tmp[4096];
    char tmpTo[4096];
    
    strncpy(tmp, pFolder, sizeof(tmp)-1);
    strncat(tmp, "/GAMEDATA/", sizeof(tmp)-1);

    const char* aAssetMap[] = {
        // JK CD
        "resource/Res1hi.gob",      "MININSTALL/RES1HI.GOB",
        "resource/Res1low.gob",     "MININSTALL/RES1LOW.GOB",
        "JK.EXE",                   "EXE/JK.EXE",

        // MOTS CD
        "JKM.EXE",                  "EXE/JKM.EXE",
        "resource/JKMsndLO.goo",    "MININSTALL/JKMSNDLO.GOO",

        "END", "END"

    };
    const size_t aAssetMap_len = sizeof(aAssetMap) / sizeof(const char*);

    int bFound = 0;
    for (size_t i = 0; i < aAssetMap_len; i += 2)
    {
        stdPlatform_Printf("%s %s %s\n", pName, aAssetMap[i], aAssetMap[i+1]);
        if (!strcmp(pName, aAssetMap[i])) {
            strncat(tmp, aAssetMap[i+1], sizeof(tmp)-1);
            bFound = 1;
            break;
        }
    }

    if (!bFound) {
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

    stdPlatform_Printf("disk copy: %s -> %s\n", tmp, tmpTo);

    // Files are the same
    if (!strcmp(tmp, tmpTo)) {
        return 0;
    }

    if (!util_FileExists(tmp)) {
        return 0;
    }

    InstallHelper_copy(tmp, tmpTo);

    if (!util_FileExists(tmpTo)) {
        return 0;
    }

    return 1;
}

/*
Summary of local data override priorities:

Linux:
 - OPENJKDF2_ROOT (OPENJKMOTS_ROOT for motsCompat) trumps everything, even if files don't exist.
 - If $CWD/resource/jk_.cd exists, the cwd will be used.

 - if XDG_DATA_HOME is set:
    - $XDG_DATA_HOME/openjkdf2/resource/jk_.cd (legacy)
    - $XDG_DATA_HOME/OpenJKDF2/openjkdf2/resource/jk_.cd

 - ~/.local/share/openjkdf2/resource/jk_.cd (legacy)
 - ~/.local/share/OpenJKDF2/openjkdf2/resource/jk_.cd (install default)

macOS:
 - OPENJKDF2_ROOT (OPENJKMOTS_ROOT for motsCompat) trumps everything, even if files don't exist.
 - If OpenJKDF2.app/../resource/jk_.cd exists, assets will be loaded relative to the app bundle.

 - if XDG_DATA_HOME is set:
    - $XDG_DATA_HOME/openjkdf2/resource/jk_.cd (legacy)
    - $XDG_DATA_HOME/OpenJKDF2/openjkdf2/resource/jk_.cd

 - ~/.local/share/openjkdf2/resource/jk_.cd (legacy)
 - ~/Library/Application Support/OpenJKDF2/openjkdf2/resource/jk_.cd (install default)

Windows:
 - OPENJKDF2_ROOT (OPENJKMOTS_ROOT for motsCompat) trumps everything, even if files don't exist.
 - If $CWD/resource/jk_.cd exists, assets will be loaded relative to the EXE.

 - %APPDATA\local\openjkdf2\resource\jk_.cd (legacy)
 - %APPDATA\OpenJKDF2\openjkdf2\resource\jk_.cd (install default)
*/
int InstallHelper_GetLocalDataDir(char* pOut, size_t pOut_sz, int bChdir)
{
    const char *homedir;
    char fname[256];
    char fname_tmp[256];
    int bIsOverride = 0;

    if (pOut_sz > sizeof(fname)) {
        pOut_sz = sizeof(fname);
    }

#if defined(MACOS) || defined(LINUX)
    char* data_home;
    if ((data_home = getenv(INSTALL_OVERRIDE_ENVVAR_NAME)) != NULL) {

        strncpy(fname, data_home, 256);

        // Expand home directory
        if (data_home[0] == '~') {
            if ((homedir = getenv("HOME")) == NULL) {
                homedir = getpwuid(getuid())->pw_dir;
            }
            if (homedir) {
                char* data_home_shift = data_home+1;
                 if (*data_home_shift == '/')
                    data_home_shift++;
                stdFnames_MakePath(fname, 256, homedir, data_home_shift);
            }
        }

        stdFileUtil_MkDir(fname);
        if (bChdir) {
            chdir(fname);
            stdPlatform_Printf("Using OPENJKDF2_ROOT, root directory: %s\n", fname);
        }
        bIsOverride = 1;
    }
    else if ((data_home = getenv("XDG_DATA_HOME")) != NULL) {
        char data_home_tmp[256];

        // Expand home directory
        if (data_home[0] == '~') {
            if ((homedir = getenv("HOME")) == NULL) {
                homedir = getpwuid(getuid())->pw_dir;
            }
            if (homedir) {
                char* data_home_shift = data_home+1;
                 if (*data_home_shift == '/')
                    data_home_shift++;


                stdFnames_MakePath(data_home_tmp, 256, homedir, data_home_shift);
                data_home = data_home_tmp;
            }
        }

        stdFnames_MakePath(fname, 256, data_home, INSTALL_APPDATA_FOLDER_NAME);
        
        // Check if data exists here. If it does not, we want to use the newer organization structure.
        strncpy(fname_tmp, fname, sizeof(fname_tmp)-1);
        strncat(fname_tmp, "/resource/jk_.cd", sizeof(fname_tmp)-1);

        if(util_FileExists(fname_tmp)) {
            stdFileUtil_MkDir(fname);
            if (bChdir) {
                chdir(fname);
                stdPlatform_Printf("Using XDG root directory: %s\n", fname);
            }
        }
        else {
            stdFnames_MakePath(fname, 256, data_home, "OpenJKDF2");
            strncat(fname, "/", sizeof(fname)-1);
            strncat(fname, INSTALL_APPDATA_FOLDER_NAME, sizeof(fname)-1);
            stdFileUtil_MkDir(fname);

            if (bChdir) {
                chdir(fname);
                stdPlatform_Printf("Using new XDG root directory: %s\n", fname);
            }
        }
    }
    else 
    {
        // Legacy folders: Check ~/.local/share/openjkdf2
        int bFound = 0;
        if ((homedir = getenv("HOME")) == NULL) {
            homedir = getpwuid(getuid())->pw_dir;
        }

        if (homedir) {
            snprintf(fname, sizeof(fname), "%s/.local/share/%s", homedir, INSTALL_APPDATA_FOLDER_NAME);

            // If ~/.local/share/openjkdf2/resource/jk_.cd exists, use that directory as resource root
            strncpy(fname_tmp, fname, sizeof(fname_tmp)-1);
            strncat(fname_tmp, "/resource/jk_.cd", sizeof(fname_tmp)-1);
            if(util_FileExists(fname_tmp)) {
                stdFileUtil_MkDir(fname);
                if (bChdir) {
                    chdir(fname);
                    stdPlatform_Printf("Using root directory: %s\n", fname);
                }
                bFound = 1;
            }
        }

        if (!bFound) {
            data_home = SDL_GetPrefPath("OpenJKDF2", INSTALL_APPDATA_FOLDER_NAME);
            if (data_home) {
                strncpy(fname, data_home, sizeof(fname));
                stdFileUtil_MkDir(fname);
                if (bChdir) {
                    chdir(fname);
                    stdPlatform_Printf("Using SDL_GetPrefPath: %s\n", fname);
                }
                SDL_free(data_home);
                data_home = NULL;
            }
        }
    }
#elif defined(WIN32)
    char* data_home = NULL;

    if ((homedir = getenv(INSTALL_OVERRIDE_ENVVAR_NAME)) != NULL) {
        strcpy(fname, homedir);
        stdFileUtil_MkDir(fname);
        if (bChdir) {
            chdir(fname);
            stdPlatform_Printf("Using OPENJKDF2_ROOT, root directory: %s\n", fname);
        }
    }
    else if ((homedir = getenv("AppData")) != NULL) {
        int bFound = 0;

        strcpy(fname, homedir);
        stdFileUtil_MkDir(fname);
        strncat(fname, "\\Local", sizeof(fname)-1);
        stdFileUtil_MkDir(fname);
        strncat(fname, "\\", sizeof(fname)-1);
        strncat(fname, INSTALL_APPDATA_FOLDER_NAME, sizeof(fname)-1);

        strncpy(fname_tmp, fname, sizeof(fname_tmp)-1);
        strncat(fname_tmp, "\\resource\\jk_.cd", sizeof(fname_tmp)-1);

        // If %appdata%/local/openjkdf2/resource/jk_.cd exists, use that directory as resource root
        if(util_FileExists(fname_tmp)) {
            stdFileUtil_MkDir(fname);
            if (bChdir) {
                chdir(fname);
                stdPlatform_Printf("Using root directory: %s\n", fname);
            }
            bFound = 1;
        }

        if (!bFound) {
            data_home = SDL_GetPrefPath("OpenJKDF2", INSTALL_APPDATA_FOLDER_NAME);
            if (data_home) {
                strncpy(fname, data_home, sizeof(fname));
                stdFileUtil_MkDir(fname);
                if (bChdir) {
                    chdir(fname);
                    stdPlatform_Printf("Using SDL_GetPrefPath: %s\n", fname);
                }
                SDL_free(data_home);
                data_home = NULL;
            }
        }
    }
#endif

    if (pOut && pOut_sz) {
        strncpy(pOut, fname, pOut_sz);
    }
    return bIsOverride;
}

int InstallHelper_UseLocalData()
{
    return InstallHelper_GetLocalDataDir(NULL, 0, 1);
}

int InstallHelper_AttemptInstallFromExisting(nfdu8char_t* path)
{
    const char* aOptionalAssets[] = {
        "JK.EXE",
        "JKM.EXE",

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

        // Gog tracks
        "MUSIC/Track00.ogg",
        "MUSIC/Track01.ogg",
        "MUSIC/Track02.ogg",
        "MUSIC/Track03.ogg",
        "MUSIC/Track04.ogg",
        "MUSIC/Track05.ogg",
        "MUSIC/Track06.ogg",
        "MUSIC/Track07.ogg",
        "MUSIC/Track08.ogg",
        "MUSIC/Track09.ogg",

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

        // %02d
        "MUSIC/1/Track00.ogg",
        "MUSIC/1/Track01.ogg",
        "MUSIC/1/Track02.ogg",
        "MUSIC/1/Track03.ogg",
        "MUSIC/1/Track04.ogg",
        "MUSIC/1/Track05.ogg",
        "MUSIC/1/Track06.ogg",
        "MUSIC/1/Track07.ogg",
        "MUSIC/1/Track08.ogg",
        "MUSIC/1/Track09.ogg",

        // %02d
        "MUSIC/2/Track00.ogg",
        "MUSIC/2/Track01.ogg",
        "MUSIC/2/Track02.ogg",
        "MUSIC/2/Track03.ogg",
        "MUSIC/2/Track04.ogg",
        "MUSIC/2/Track05.ogg",
        "MUSIC/2/Track06.ogg",
        "MUSIC/2/Track07.ogg",
        "MUSIC/2/Track08.ogg",
        "MUSIC/2/Track09.ogg",

        // GOG tracks
        "MUSIC/Track12.ogg",
        "MUSIC/Track13.ogg",
        "MUSIC/Track14.ogg",
        "MUSIC/Track15.ogg",
        "MUSIC/Track16.ogg",
        "MUSIC/Track17.ogg",
        "MUSIC/Track18.ogg",
        "MUSIC/Track19.ogg",
        "MUSIC/Track20.ogg",
        "MUSIC/Track21.ogg",
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

        // Technically optional (MOTS)
        "Resource/VIDEO/FINALE.SAN",
        "Resource/VIDEO/JKMINTRO.SAN",
        "Resource/VIDEO/S1L1ECS.SAN",
        "Resource/VIDEO/S1L1OCS.SAN",
        "Resource/VIDEO/S1L2ECS.SAN",
        "Resource/VIDEO/S1L2OCS.SAN",
        "Resource/VIDEO/S1L3ECS.SAN",
        "Resource/VIDEO/S1L3OCS.SAN",
        "Resource/VIDEO/S1L4ECS.SAN",
        "Resource/VIDEO/S2L1ECS.SAN",
        "Resource/VIDEO/S2L1OCS.SAN",
        "Resource/VIDEO/S2L2AECS.SAN",
        "Resource/VIDEO/S2L2ECS.SAN",
        "Resource/VIDEO/S2L2OCS.SAN",
        "Resource/VIDEO/S2L4ECS.SAN",
        "Resource/VIDEO/S4L1ECS.SAN",
        "Resource/VIDEO/S4L1OCS.SAN",
        "Resource/VIDEO/S4L2ECS.SAN",
        "Resource/VIDEO/S4L2OCS.SAN",
        "Resource/VIDEO/S4L3ECS.SAN",
        "Resource/VIDEO/S4L3OCS.SAN",
        "Resource/VIDEO/S5L2OCS.SAN",
        "Resource/VIDEO/S5L3ECS.SAN",
        "Resource/VIDEO/CUTSCENES.ZIP",
        "Resource/VIDEO/UNSUPPORTED.ZIP",
        "Resource/VIDEO/cutscenes.goo",

        // Controls (MOTS)
        "Controls/assassin.ctm",
        "Controls/chkeybrd.ctm",
        "Controls/fcskybrd.ctm",
        "Controls/ms_3dpro.ctm",
        "Controls/wwarrior.ctm",
        "Controls/ch_f-16.ctm",
        "Controls/cybrman2.ctm",
        "Controls/gamepad.ctm",
        "Controls/prcision.ctm",
        "Controls/ch_pro.ctm",
        "Controls/fcs.ctm",
        "Controls/gravis.ctm",
        "Controls/spaceorb.ctm",
        "Controls/CH F-16 COMBAT STICK.CTM",
        "Controls/CH FLIGHTSTICK PRO OPTIMIZED WITH KEYBOARD.CTM",
        "Controls/CH FLIGHTSTICK PRO.CTM",
        "Controls/CHIP'S PRECISION PRO CONFIGURATION.CTM",
        "Controls/FP GAMING ASSASSIN 3D WITH JOYSTICK.CTM",
        "Controls/GRAVIS GAMEPAD PRO.CTM",
        "Controls/LOGITECH CYBERMAN 2.CTM",
        "Controls/LOGITECH THUNDERPAD DIGITAL.CTM",
        "Controls/LOGITECH WINGMAN EXTREME DIGITAL.CTM",
        "Controls/LOGITECH WINGMAN WARRIOR.CTM",
        "Controls/MS SIDEWINDER 3D PRO.CTM",
        "Controls/MS SIDEWINDER GAME PAD.CTM",
        "Controls/MS SIDEWINDER PRECISION PRO OR FF.CTM",
        "Controls/SPACETEC SPACEORB 360.CTM",
        "Controls/THRUSTMASTER FCS OPTIMIZED WITH KEYBOARD.CTM",
        "Controls/THRUSTMASTER FCS.CTM",
        "Controls/XBOX 360 Controller for Windows.ctm",

        // MoTS demo assets TODO
    };

    const char** paOptionalAssets = aOptionalAssets;
    const char** paRequiredAssets = Main_bMotsCompat ? aRequiredAssetsMots : aRequiredAssets;
    size_t paRequiredAssets_len = Main_bMotsCompat ? aRequiredAssetsMots_len : aRequiredAssets_len;

    if (path[strlen(path)-1] == '/' || path[strlen(path)-1] == '\\')
    {
        path[strlen(path)-1] = 0;
    }

    const size_t aOptionalAssets_len = sizeof(aOptionalAssets) / sizeof(const char*);

    InstallHelper_UseLocalData();
    stdFileUtil_MkDir("episode");
    stdFileUtil_MkDir("MUSIC");
    stdFileUtil_MkDir("MUSIC/1");
    stdFileUtil_MkDir("MUSIC/2");
    stdFileUtil_MkDir("player");
    stdFileUtil_MkDir("resource");
    stdFileUtil_MkDir("resource/shaders");
    stdFileUtil_MkDir("resource/video");
    for (size_t i = 0; i < paRequiredAssets_len; i++)
    {
        if (!InstallHelper_CopyFile(path, paRequiredAssets[i]))
        {
            char tmp[4096+256];

            snprintf(tmp, sizeof(tmp), "Missing required asset `%s`!", paRequiredAssets[i]);
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "OpenJKDF2 Install Helper", tmp, NULL);
        }
    }

    for (size_t i = 0; i < aOptionalAssets_len; i++)
    {
        InstallHelper_CopyFile(path, paOptionalAssets[i]);
    }

    uint32_t magic = JKRES_MAGIC_1;
    FILE* f = fopen("resource/jk_.cd", "wb");
    if (f) {
        fwrite(&magic, 1, sizeof(magic), f);
        fclose(f);
    }

    NFD_Quit();

    return 1;
}

int InstallHelper_AttemptInstallFromDisk(nfdu8char_t* path)
{
    bool isTwoPartCD = false;

    const char* aOptionalAssets[] = {
        "JK.EXE",
        "JKM.EXE",

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

        // Technically optional (MOTS)
        "Resource/VIDEO/FINALE.SAN",
        "Resource/VIDEO/JKMINTRO.SAN",
        "Resource/VIDEO/S1L1ECS.SAN",
        "Resource/VIDEO/S1L1OCS.SAN",
        "Resource/VIDEO/S1L2ECS.SAN",
        "Resource/VIDEO/S1L2OCS.SAN",
        "Resource/VIDEO/S1L3ECS.SAN",
        "Resource/VIDEO/S1L3OCS.SAN",
        "Resource/VIDEO/S1L4ECS.SAN",
        "Resource/VIDEO/S2L1ECS.SAN",
        "Resource/VIDEO/S2L1OCS.SAN",
        "Resource/VIDEO/S2L2AECS.SAN",
        "Resource/VIDEO/S2L2ECS.SAN",
        "Resource/VIDEO/S2L2OCS.SAN",
        "Resource/VIDEO/S2L4ECS.SAN",
        "Resource/VIDEO/S4L1ECS.SAN",
        "Resource/VIDEO/S4L1OCS.SAN",
        "Resource/VIDEO/S4L2ECS.SAN",
        "Resource/VIDEO/S4L2OCS.SAN",
        "Resource/VIDEO/S4L3ECS.SAN",
        "Resource/VIDEO/S4L3OCS.SAN",
        "Resource/VIDEO/S5L2OCS.SAN",
        "Resource/VIDEO/S5L3ECS.SAN",
        "Resource/VIDEO/CUTSCENES.ZIP",
        "Resource/VIDEO/UNSUPPORTED.ZIP",
        "Resource/VIDEO/cutscenes.goo",

        // Controls (MOTS)
        "Controls/assassin.ctm",
        "Controls/chkeybrd.ctm",
        "Controls/fcskybrd.ctm",
        "Controls/ms_3dpro.ctm",
        "Controls/wwarrior.ctm",
        "Controls/ch_f-16.ctm",
        "Controls/cybrman2.ctm",
        "Controls/gamepad.ctm",
        "Controls/prcision.ctm",
        "Controls/ch_pro.ctm",
        "Controls/fcs.ctm",
        "Controls/gravis.ctm",
        "Controls/spaceorb.ctm",
        "Controls/CH F-16 COMBAT STICK.CTM",
        "Controls/CH FLIGHTSTICK PRO OPTIMIZED WITH KEYBOARD.CTM",
        "Controls/CH FLIGHTSTICK PRO.CTM",
        "Controls/CHIP'S PRECISION PRO CONFIGURATION.CTM",
        "Controls/FP GAMING ASSASSIN 3D WITH JOYSTICK.CTM",
        "Controls/GRAVIS GAMEPAD PRO.CTM",
        "Controls/LOGITECH CYBERMAN 2.CTM",
        "Controls/LOGITECH THUNDERPAD DIGITAL.CTM",
        "Controls/LOGITECH WINGMAN EXTREME DIGITAL.CTM",
        "Controls/LOGITECH WINGMAN WARRIOR.CTM",
        "Controls/MS SIDEWINDER 3D PRO.CTM",
        "Controls/MS SIDEWINDER GAME PAD.CTM",
        "Controls/MS SIDEWINDER PRECISION PRO OR FF.CTM",
        "Controls/SPACETEC SPACEORB 360.CTM",
        "Controls/THRUSTMASTER FCS OPTIMIZED WITH KEYBOARD.CTM",
        "Controls/THRUSTMASTER FCS.CTM",
        "Controls/XBOX 360 Controller for Windows.ctm",

        // MoTS demo assets TODO
    };

    const char** paOptionalAssets = aOptionalAssets;
    const char** paRequiredAssets = Main_bMotsCompat ? aRequiredAssetsMots : aRequiredAssets;
    size_t paRequiredAssets_len = Main_bMotsCompat ? aRequiredAssetsMots_len : aRequiredAssets_len;

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
    if (!Main_bMotsCompat && (!util_FileExists(checkDisk1) || !util_FileExists(checkDisk2))) {
        isTwoPartCD = true;
    }

    InstallHelper_UseLocalData();
    stdFileUtil_MkDir("episode");
    stdFileUtil_MkDir("MUSIC");
    stdFileUtil_MkDir("MUSIC/1");
    stdFileUtil_MkDir("MUSIC/2");
    stdFileUtil_MkDir("player");
    stdFileUtil_MkDir("resource");
    stdFileUtil_MkDir("resource/shaders");
    stdFileUtil_MkDir("resource/video");
    for (size_t i = 0; i < paRequiredAssets_len; i++)
    {
        InstallHelper_CopyFileDisk(path, paRequiredAssets[i]);
    }

    for (size_t i = 0; i < aOptionalAssets_len; i++)
    {
        InstallHelper_CopyFileDisk(path, paOptionalAssets[i]);
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

        for (size_t i = 0; i < paRequiredAssets_len; i++)
        {
            InstallHelper_CopyFileDisk(path, paRequiredAssets[i]);
        }

        for (size_t i = 0; i < aOptionalAssets_len; i++)
        {
            InstallHelper_CopyFileDisk(path, paOptionalAssets[i]);
        }
    }

final_check:
    InstallHelper_CheckRequiredAssets(0);

    uint32_t magic = JKRES_MAGIC_1;
    FILE* f = fopen("resource/jk_.cd", "wb");
    if (f) {
        fwrite(&magic, 1, sizeof(magic), f);
        fclose(f);
    }

    NFD_Quit();

    return 1;
}

int InstallHelper_AttemptInstall()
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

    char tmpMsg[2048];
    char tmpCwd[256];
    InstallHelper_GetLocalDataDir(tmpCwd, sizeof(tmpCwd), 0);
    snprintf(tmpMsg, sizeof(tmpMsg), "OpenJKDF2 could not find required game assets.\nWould you like to install assets now?\n\nAssets will be installed to:\n%s", tmpCwd);

    const SDL_MessageBoxData messageboxdata = {
        SDL_MESSAGEBOX_INFORMATION, /* .flags */
        NULL, /* .window */
        "OpenJKDF2 Install Helper", /* .title */
        tmpMsg, /* .message */
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

    if (Main_bMotsCompat)
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "OpenJKDF2 Install Helper", "Please select your existing JKMOTS installation, or an install disk mount.", NULL);
    else
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
        return InstallHelper_AttemptInstallFromDisk(path);
    }

    // Disk 2 has no autorun
    strncpy(checkDisk, path, sizeof(checkDisk)-1);
    strncat(checkDisk, "/GAMEDATA/RESOURCE/JK_.CD", sizeof(checkDisk)-1);
    if (util_FileExists(checkDisk)) {
        return InstallHelper_AttemptInstallFromDisk(path);
    }

    return InstallHelper_AttemptInstallFromExisting(path);
}

void InstallHelper_CheckRequiredAssets(int doInstall)
{
    const char* msg = "OpenJKDF2 is missing the following required assets:\n";

    const char** paRequiredAssets = Main_bMotsCompat ? aRequiredAssetsMots : aRequiredAssets;
    size_t paRequiredAssets_len = Main_bMotsCompat ? aRequiredAssetsMots_len : aRequiredAssets_len;

    char* bigList = NULL;
    size_t bigList_len = strlen(msg);
    bool missingRequireds = false;
    for (size_t i = 0; i < paRequiredAssets_len; i++)
    {
        if (!util_FileExists(paRequiredAssets[i]))
        {
            missingRequireds = true;
            bigList_len += strlen(paRequiredAssets[i]) + 2;
        }
    }

    bigList_len += 512; // root dir msg

    if (!missingRequireds) return;

    bigList = malloc(bigList_len);
    if (!bigList) return;
    memset(bigList, 0, bigList_len);

    strcpy(bigList, msg);

    for (size_t i = 0; i < paRequiredAssets_len; i++)
    {
        if (!util_FileExists(paRequiredAssets[i]))
        {
            strcat(bigList, paRequiredAssets[i]);
            strcat(bigList, "\n");
        }
    }

    char tmpCwd[256];
    getcwd(tmpCwd, sizeof(tmpCwd));
    strcat(bigList, "\nRoot dir: ");
    strcat(bigList, tmpCwd);

    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", bigList, NULL);

    if (doInstall) {
        InstallHelper_AttemptInstall();
    }
}

void InstallHelper_SetCwd()
{
#if (defined(MACOS) || defined(LINUX) || defined(WIN32)) && defined(SDL2_RENDER) && !defined(ARCH_WASM) && !defined(TARGET_ANDROID)
    const char *homedir;
    char fname[256];

#if defined(MACOS)
    // Default working directory to the folder the .app bundle is in
    char* base_path = SDL_GetBasePath();
    chdir(base_path);
    chdir("..");
    SDL_free(base_path);
#endif

    int found_override = 0;
    
    char data_home[256];
    found_override = InstallHelper_GetLocalDataDir(data_home, sizeof(data_home), 0);

    stdFnames_MakePath(fname, 256, data_home, "resource/jk_.cd");

    // If ~/.local/share/openjkdf2/resource/jk_cd exists, use that directory as resource root
    if(openjkdf2_bSkipWorkingDirData || (util_FileExists(fname) && !util_FileExists("resource/jk_.cd"))) {
        InstallHelper_UseLocalData();
        found_override = 1;
    }

    if (!found_override) {
        stdPlatform_Printf("Running from current working directory.\n");
        openjkdf2_bIsRunningFromExistingInstall = 1;
        if (openjkdf2_bIsFirstLaunch) {
            openjkdf2_bOrigWasRunningFromExistingInstall = 1;
        }
    }
    else {
        openjkdf2_bIsRunningFromExistingInstall = 0;
        if (openjkdf2_bIsFirstLaunch) {
            openjkdf2_bOrigWasRunningFromExistingInstall = 0;
        }
    }

    // If we can tell that we're loading MoTS assets, enable Main_bMotsCompat
    int keyval = jkRes_ReadKeyRawEarly();
    if (JKRES_IS_MOTS_MAGIC(keyval)) {
        Main_bMotsCompat = 1;
        if (openjkdf2_bIsFirstLaunch) {
            openjkdf2_bOrigWasDF2 = 0;
        }
    }

#endif // (defined(MACOS) || defined(LINUX) || defined(WIN32)) && defined(SDL2_RENDER) && !defined(ARCH_WASM)

#if defined(SDL2_RENDER) && !defined(ARCH_WASM) && !defined(TARGET_ANDROID)
    /*if (!util_FileExists("resource/jk_.cd")) {
        // TODO: polyglot
        //SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", "OpenJKDF2 could not find any game assets (`resource/jk_.cd` is missing). Would you like to install assets now?", NULL);
        InstallHelper_AttemptInstall();
    }*/
    if (!util_FileExists("resource/jk_.cd")) {
        InstallHelper_CheckRequiredAssets(1);
    }

    stdFileUtil_MkDir("mods");
    stdFileUtil_MkDir("expansions");
#endif
}

#else
void InstallHelper_SetCwd()
{
#if defined(TARGET_ANDROID)
    chdir(SDL_AndroidGetExternalStoragePath());
    if (!Main_bMotsCompat) {
        chdir("jk1/");
    }
    else {
        chdir("mots/");
    }
#else
    if (!Main_bMotsCompat) {
        chdir("/jk1/");
    }
    else {
        chdir("/mots/");
    }
#endif
    char tmpCwd[256];
    getcwd(tmpCwd, sizeof(tmpCwd));

    stdPlatform_Printf("Running from: %s\n", tmpCwd);
}
#endif // defined(SDL2_RENDER) && !defined(ARCH_WASM) && !defined(TARGET_ANDROID)