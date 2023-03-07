#include "stdUpdater.h"

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <nlohmann/json.hpp>

#include "Platform/Common/stdHttp.h"
#include "stdPlatform.h"

extern "C" {

int stdUpdater_CheckForUpdates()
{
    char* pData = (char*)stdHttp_Fetch("https://api.github.com/repos/shinyquagsire23/OpenJKDF2/releases?per_page=1");
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

        for (int i = 0; i < assets.size(); i++) {
            auto asset = assets[i];
            if (!asset.contains("name")) {
                continue;
            }
            if (!asset.contains("browser_download_url")) {
                continue;
            }

            std::string name = asset["name"].get<std::string>();
            std::string browser_download_url = asset["browser_download_url"].get<std::string>();

            if (name != "win64-debug.zip") {
                continue;
            }

            stdPlatform_Printf("stdUpdater: %s %s\n", name.c_str(), browser_download_url.c_str());
            break;
        }

        std::string tag_name = entry["tag_name"].get<std::string>();
        stdPlatform_Printf("%s\n", tag_name.c_str());

        if (strcmp(openjkdf2_aReleaseVersion, tag_name.c_str())) {
            stdPlatform_Printf("stdUpdater: An update is available! Current: %s -> Latest: %s\n", openjkdf2_aReleaseVersion, tag_name.c_str());
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

}