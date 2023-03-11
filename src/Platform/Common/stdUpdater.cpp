#include "stdUpdater.h"

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <nlohmann/json.hpp>

#include "Platform/Common/stdHttp.h"
#include "General/stdString.h"
#include "Main/sithCvar.h"
#include "stdPlatform.h"

extern "C" {

std::string stdUpdater_strBrowserDownloadUrl;
std::string stdUpdater_strUpdateVersion;
std::string stdUpdater_strDlFname;
bool stdUpdater_bFoundUpdate;

char stdUpdater_pUpdateUrl[SITHCVAR_MAX_STRLEN];

void stdUpdater_StartupCvars()
{
    sithCvar_RegisterStr("net_updaterUrl", STDUPDATER_DEFAULT_URL, &stdUpdater_pUpdateUrl, CVARFLAG_GLOBAL);
}

void stdUpdater_Reset()
{
    stdUpdater_strBrowserDownloadUrl = "";
    stdUpdater_strUpdateVersion = "";
    stdUpdater_strDlFname = "";
    stdUpdater_bFoundUpdate = false;
}

int stdUpdater_CheckForUpdates()
{
    stdUpdater_Reset();

    char* pData = (char*)stdHttp_Fetch(stdUpdater_pUpdateUrl);
    if (!pData) {
        return 0;
    }

    std::string dataStr(pData);
    free(pData);

    //stdPlatform_Printf("Test: %s\n", dataStr.c_str());

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
            return 0;
        }

        for (int i = 0; i < assets.size(); i++) {
            auto asset = assets[i];
            if (!asset.contains("name")) {
                continue;
            }
            if (!asset.contains("browser_download_url")) {
                continue;
            }

            stdUpdater_strDlFname = asset["name"].get<std::string>();
            if (stdUpdater_strDlFname != "win64-debug.zip") {
                continue;
            }

            stdUpdater_strBrowserDownloadUrl = asset["browser_download_url"].get<std::string>();

            stdPlatform_Printf("stdUpdater: An update is available! Current: %s -> Latest: %s\n", openjkdf2_aReleaseVersion, stdUpdater_strUpdateVersion.c_str());
            stdPlatform_Printf("stdUpdater: %s %s\n", stdUpdater_strDlFname.c_str(), stdUpdater_strBrowserDownloadUrl.c_str());
            stdUpdater_bFoundUpdate = true;

            return 1;
        }

        return 0;
    }
    catch (...)
    {
        stdPlatform_Printf("stdUpdater: Failed to parse JSON?");
        return 0;
    }
}

void stdUpdater_GetUpdateText(char* pOut, size_t outSz)
{
    // TODO: i8n
    stdString_snprintf(pOut, outSz, "An update is available: %s => %s", openjkdf2_aReleaseVersion, stdUpdater_strUpdateVersion.c_str());
}

}