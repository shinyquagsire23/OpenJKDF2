#include "stdUpdater.h"

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <nlohmann/json.hpp>

#include "Platform/Common/stdHttp.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdFileUtil.h"
#include "Main/sithCvar.h"
#include "Main/jkStrings.h"
#include "stdPlatform.h"

#ifdef PLATFORM_PHYSFS
#include <physfs.h>
#endif

#include "SDL2_helper.h"

#if defined(LINUX)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#endif

extern "C" {

std::string stdUpdater_strBrowserDownloadUrl;
std::string stdUpdater_strUpdateVersion;
std::string stdUpdater_strDlFname;
bool stdUpdater_bDownloading;
bool stdUpdater_bFoundUpdate;
bool stdUpdater_bCompletedUpdate;
int stdUpdater_bDisableUpdates = 0;
int stdUpdater_bTestUpdate = 0;

char stdUpdater_pUpdaterUrl[SITHCVAR_MAX_STRLEN];
char stdUpdater_pWin64UpdateFilename[SITHCVAR_MAX_STRLEN];
char stdUpdater_pMacosUpdateFilename[SITHCVAR_MAX_STRLEN];
char* stdUpdater_pUpdateFilename = "";

void stdUpdater_StartupCvars()
{
    sithCvar_RegisterBool("net_disableUpdates", 0, &stdUpdater_bDisableUpdates, CVARFLAG_GLOBAL);
    sithCvar_RegisterBool("net_testUpdate", 0, &stdUpdater_bTestUpdate, CVARFLAG_GLOBAL | CVARFLAG_UPDATABLE_DEFAULT);
    sithCvar_RegisterStr("net_updaterUrl", STDUPDATER_DEFAULT_URL, &stdUpdater_pUpdaterUrl, CVARFLAG_GLOBAL | CVARFLAG_UPDATABLE_DEFAULT);
    sithCvar_RegisterStr("net_win64UpdateFilename", STDUPDATER_DEFAULT_WIN64_FILENAME, &stdUpdater_pWin64UpdateFilename, CVARFLAG_GLOBAL | CVARFLAG_UPDATABLE_DEFAULT);
    sithCvar_RegisterStr("net_macosUpdateFilename", STDUPDATER_DEFAULT_MACOS_FILENAME, &stdUpdater_pMacosUpdateFilename, CVARFLAG_GLOBAL | CVARFLAG_UPDATABLE_DEFAULT);

#if defined(WIN64_STANDALONE)
    stdUpdater_pUpdateFilename = stdUpdater_pWin64UpdateFilename;
#elif defined(MACOS)
    stdUpdater_pUpdateFilename = stdUpdater_pMacosUpdateFilename;
#endif
}

void stdUpdater_Reset()
{
    stdUpdater_strBrowserDownloadUrl = "";
    stdUpdater_strUpdateVersion = "";
    stdUpdater_strDlFname = "";
    stdUpdater_bFoundUpdate = false;
    stdUpdater_bCompletedUpdate = false;
    stdUpdater_bDownloading = false;
}

int stdUpdater_CheckForUpdates()
{
    stdUpdater_Reset();

#if defined(PLATFORM_LINUX) || defined(ARCH_WASM)
    return 0;
#else
    if (stdUpdater_bDisableUpdates) {
        return 0;
    }

    char* pData = NULL;
    for (int i = 0; i < 2; i++)
    {
        pData = (char*)stdHttp_Fetch(stdUpdater_pUpdaterUrl);
        if (pData) break;
    }
    
    if (!pData) {
        return 0;
    }

    std::string dataStr(pData);
    free(pData);

    try {
        nlohmann::json json_file = nlohmann::json::parse(dataStr);

        if (json_file.size() <= 0) {
            return 0;
        }

        auto entry = json_file[0];
        if (!entry.contains("tag_name")) {
            return 0;
        }
        if (!entry.contains("assets")) {
            return 0;
        }
        auto assets = entry["assets"];
        if (assets <= 0) {
            return 0;
        }

        stdUpdater_strUpdateVersion = entry["tag_name"].get<std::string>();

        if (!strcmp(openjkdf2_aReleaseVersion, stdUpdater_strUpdateVersion.c_str())) {
            if (!stdUpdater_bTestUpdate) {
                return 0;
            }
        }

        stdPlatform_Printf("stdUpdater: An update is available! Current: %s -> Latest: %s\n", openjkdf2_aReleaseVersion, stdUpdater_strUpdateVersion.c_str());

        for (int i = 0; i < assets.size(); i++) {
            auto asset = assets[i];
            if (!asset.contains("name")) {
                continue;
            }
            if (!asset.contains("browser_download_url")) {
                continue;
            }

            stdUpdater_strDlFname = asset["name"].get<std::string>();
            if (strcmp(stdUpdater_strDlFname.c_str(), stdUpdater_pUpdateFilename)) {
                continue;
            }

            stdUpdater_strBrowserDownloadUrl = asset["browser_download_url"].get<std::string>();

            stdPlatform_Printf("stdUpdater: %s\n", stdUpdater_strBrowserDownloadUrl.c_str());

            stdUpdater_bFoundUpdate = true;
            break;
        }

        if (!stdUpdater_bFoundUpdate) {
            stdPlatform_Printf("stdUpdater: An update is available, but no payload? updateFilename: %s, updaterURL: %s\n", stdUpdater_pUpdateFilename, stdUpdater_pUpdaterUrl);
        }

        return 1;
    }
    catch (...)
    {
        stdPlatform_Printf("stdUpdater: Failed to parse JSON?\n");
        return 0;
    }
#endif // defined(PLATFORM_LINUX) || defined(ARCH_WASM)
}

void stdUpdater_GetUpdateText(wchar_t* pOut, size_t outSz)
{
    // TODO: i8n
    if (stdUpdater_bCompletedUpdate) {
#if defined(WIN64_STANDALONE)
        jk_snwprintf(pOut, outSz/sizeof(wchar_t), jkStrings_GetUniStringWithFallback("GUIEXT_UPDATE_COMPLETE_RESTART"));
#else
        jk_snwprintf(pOut, outSz/sizeof(wchar_t), jkStrings_GetUniStringWithFallback("GUIEXT_UPDATE_COMPLETE_SEMIAUTO"));
#endif
        return;
    }
    else if (stdUpdater_bDownloading) {
        jk_snwprintf(pOut, outSz/sizeof(wchar_t), jkStrings_GetUniStringWithFallback("GUIEXT_UPDATE_DOWNLOADING"));
        return;
    }
    
    jk_snwprintf(pOut, outSz/sizeof(wchar_t), jkStrings_GetUniStringWithFallback("GUIEXT_UPDATE_IS_AVAIL"), openjkdf2_aReleaseVersion, stdUpdater_strUpdateVersion.c_str());
}

void stdUpdater_Win64UpdateThread()
{
    char buffer[1024];
    char **rc;
    int file_count;
    char **i;

    char tmp_exepath[512];
    char tmp_zippath[512];
    char* exe_fname = stdFnames_FindMedName(openjkdf2_pExecutablePath);
    stdFnames_CopyDir(tmp_exepath, sizeof(tmp_exepath), openjkdf2_pExecutablePath);
    stdFnames_MakePath(tmp_zippath, sizeof(tmp_zippath), tmp_exepath, stdUpdater_strDlFname.c_str());

    stdPlatform_Printf("stdUpdater: %s %s\n", tmp_zippath, stdUpdater_strBrowserDownloadUrl.c_str());
    stdUpdater_bDownloading = true;
    stdHttp_DownloadToPath(stdUpdater_strBrowserDownloadUrl.c_str(), tmp_zippath);

#if defined(PLATFORM_PHYSFS)
    PHYSFS_mount(tmp_zippath, "update", 1);

    rc = PHYSFS_enumerateFiles("update");
    if (rc == NULL) {
        stdPlatform_Printf("stdUpdater: Failure. reason: %s.\n", PHYSFS_getLastError());
    }
    else
    {
        for (i = rc, file_count = 0; *i != NULL; i++, file_count++)
        {
            char tmp[512];
            char tmp2[512];

            // TODO: Check openjkdf2-64.exe instead? idk if I'll ever ship two EXEs.
            // Basically what we're solving for here is if someone renames their EXE to
            // JediKnight.EXE or JK.EXE for Steam/GOG launchers.
            if(!__strcmpi(stdFnames_FindExt(*i), "exe"))
            {
                stdFnames_MakePath(tmp, sizeof(tmp), tmp_exepath, exe_fname);
                stdString_snprintf(tmp2, sizeof(tmp2), "%s.bak", tmp);
            }
            else
            {
                stdFnames_MakePath(tmp, sizeof(tmp), tmp_exepath, *i);
                stdString_snprintf(tmp2, sizeof(tmp2), "%s.bak", tmp);
            }
            
            stdPlatform_Printf("stdUpdater: Renaming: %s -> %s\n", tmp, tmp2);

            stdFileUtil_DelFile(tmp2);
            rename(tmp, tmp2);

            stdString_snprintf(tmp2, sizeof(tmp2), "update/%s", *i);

            PHYSFS_File* f_in = PHYSFS_openRead(tmp2);
            FILE* f_out = fopen(tmp, "wb");

            stdPlatform_Printf("stdUpdater: Writing:  %s\n", tmp);

            PHYSFS_sint64 rc, i2;
            while (1)
            {
                rc = PHYSFS_readBytes(f_in, buffer, sizeof (buffer));
                if (rc > 0) {
                    fwrite(buffer, 1, rc, f_out);
                }
                else {
                    break;
                }
            }

            fclose(f_out);
            PHYSFS_close(f_in);
        }

        stdPlatform_Printf("\nstdUpdater: total (%d) files.\n", file_count);
        PHYSFS_freeList(rc);
    }

    PHYSFS_unmount("update");
#endif

    stdUpdater_bCompletedUpdate = true;
    stdUpdater_bDownloading = false;
}

#if defined(MACOS)
void stdUpdater_MacOSUpdateThread()
{
    stdPlatform_Printf("stdUpdater: Starting update...\n");
    stdUpdater_bDownloading = true;
    stdHttp_DownloadToPath(stdUpdater_strBrowserDownloadUrl.c_str(), stdUpdater_strDlFname.c_str());

    // TODO: idk if the rename weirdness will work on macOS
    char tmpCwd[256];
    char tmpUrl[512];
    getcwd(tmpCwd, sizeof(tmpCwd));
    snprintf(tmpUrl, sizeof(tmpUrl), "file://%s/%s", tmpCwd, stdUpdater_strDlFname.c_str());

    SDL_ClearError();

    SDL_OpenURL(tmpUrl);
    stdPlatform_Printf("stdUpdater: Done update. File: %s\n", stdUpdater_strDlFname.c_str());

    stdUpdater_bCompletedUpdate = true;
    stdUpdater_bDownloading = false;
}
#endif

int stdUpdater_UpdateThread(void* unused)
{
#if defined(WIN64_STANDALONE)
    stdUpdater_Win64UpdateThread();
#elif defined(MACOS)
    stdUpdater_MacOSUpdateThread();
#endif

    return 1;
}

void stdUpdater_DoUpdate()
{
#if defined(PLATFORM_LINUX)
    stdUpdater_bFoundUpdate = false;
    stdUpdater_bDownloading = false;
    stdUpdater_bCompletedUpdate = false;
    return;
#endif

    if (!stdUpdater_bFoundUpdate) {
        return;
    }

#ifdef SDL2_RENDER
    SDL_Thread* stdUpdater_thread = SDL_CreateThread(stdUpdater_UpdateThread, "stdComm_EnumThread", (void *)NULL);
#else
    stdUpdater_UpdateThread(NULL);
#endif

    stdUpdater_bFoundUpdate = false;
}

}