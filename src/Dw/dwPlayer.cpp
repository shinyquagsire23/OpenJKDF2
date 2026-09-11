// dwPlayer — player PROFILE persistence (.plr files).
//
// DroidWorks.exe 0x429180-0x4299ff: dwPlayer_CreateProfile@429180 /
// DeleteProfile@4291e0 / LoadPlr@429200 / SavePlr@4296d0 /
// EnumProfiles@429950. (The dwGuiQuickView/dwGuiDroidPreview widgets that
// share the unit range are P6 — dwGuiQuickView.c.)
//
// Compiled as C++ (the binary functions carry MSVC EH frames around their
// dwString/dwConfFile locals); the whole surface keeps C linkage via
// dwPlayer.h. Directory work goes through the dwInits VFS helpers with the
// pseudo-extension "PLR" — not in the 27-entry ext table, so inits_MakeDir/
// RemoveDirTree/EnumSubdirs resolve it to dwPlayer_basePath, and the hooked
// fileOpen resolves bare "<name>.plr" into dwPlayer_profileDir.

#include "Dw/dwPlayer.h"

#include "Dw/dwMission.h"
#include "Dw/dwInits.h"
#include "Dw/dwConfFile.h"
#include "Dw/dwColormap.h"
#include "Dw/dwSound.h"
#include "Dw/dwGuiWidgets.h" // dwGuiWidgets_Write/ReadDroidFile (WORKSPACE section)
#include "stdPlatform.h"
#include "General/stdFileUtil.h" // stdFileUtil_MkDir (dwPlayer_SetupBasePath; has own guards)

extern "C" {
#include "Devices/sithSoundMixer.h" // sithSoundMixer_UpdateMusicVolume (no guards of its own)
}

#include <stdio.h>
#include <stdlib.h>

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// ------------------------------------------------------------------
// Cross-unit externs
// ------------------------------------------------------------------

// Owner: dw core P7 (dwMain.c placeholder) — global blueprint list sentinel
// (dwList of dwPart*) and workspace droid node list sentinel.
extern "C" dwListNode* dwCore_pBlueprintList;  // @0x53d964
extern "C" dwListNode* dwCore_pWorkspaceNodes; // @0x53d984

// TODO(dw-decomp): provided by dw core (P7) — the workspace droid's display
// name (@0x53d978) and the current reference-room topic file (@0x53d968,
// binary static ctor dwCore_RefFileInit; the .plr TOPIC key).
extern "C" dwString dwCore_workspaceName;
extern "C" dwString dwCore_currentRefFile;

// dwPart blueprint class (landed this wave) — .plr PARTS reads/writes
// bAvailable + name on the real type.
#include "Dw/dwPart.h"

// ------------------------------------------------------------------
// Unit-owned globals
// ------------------------------------------------------------------

extern "C" {
dwString dwPlayer_name;       // @0x53d900 (CRT static ctor dwCore_PlayerNameInit@4113b0)
dwString dwPlayer_basePath;   // @0x53d8f0 (dwCore_PlayerBasePathInit@411430; dw_Startup fills it)
dwString dwPlayer_profileDir; // @0x53d930 (dwCore_PlayerProfileDirInit@411470)

// Added (P7 boot): construct dwPlayer_basePath the way dw_Startup @419bd0 does —
// (installPath || workingDir) + the player-dir name + '\'. The binary sources
// the dir name from global.txt's PLAYER_DIR; until the boot flow loads global.txt
// callers pass the DW default "Player".
// TODO(dw-decomp) P7: fold into the real dw_Startup and read PLAYER_DIR from
// dwCore_pGlobalStrings.
extern "C" void dwPlayer_SetupBasePath(const char* pPlayerDirName)
{
    dwPlayer_basePath.AssignString(&dwCore_installPath);
    if (dwPlayer_basePath.length == 0)
        dwPlayer_basePath.AssignString(&dwCore_workingDir);
    dwPlayer_basePath.Append(pPlayerDirName, 0); // len 0 = strlen
    stdFileUtil_MkDir(dwPlayer_basePath.pBuffer);
    dwPlayer_basePath.Append("\\", 1);
}

// Shared settings — defaults from the binary's .data initializers @0x527d50.
uint8_t dw_settingShowText = 1;      // @0x527d50
uint32_t dw_settingBrightness = 4;   // @0x527d54
uint32_t dw_viewSizePct = 100;       // @0x527d58
uint32_t dw_settingMusicVol = 50;    // @0x527d5c
uint32_t dw_settingSoundVol = 60;    // @0x527d60

uint32_t dwPlayer_statsFlags = 0;    // @0x53d9f8 (BSS)
}

// Module statics reset (no binary counterpart; soft-reset loop rule — the
// binary's values came from CRT static ctors / .data / BSS).
extern "C" void dwPlayer_Startup(void)
{
    dwPlayer_name.Free();
    dwPlayer_basePath.Free();
    dwPlayer_profileDir.Free();
    dw_settingShowText = 1;
    dw_settingBrightness = 4;
    dw_viewSizePct = 100;
    dw_settingMusicVol = 50;
    dw_settingSoundVol = 60;
    dwPlayer_statsFlags = 0;
}

// ------------------------------------------------------------------
// API
// ------------------------------------------------------------------

// @429180 (dwPlayer_CreateProfile)
extern "C" void dwPlayer_CreateProfile(const char* pName)
{
    if (inits_MakeDir("PLR", pName))
    {
        dwPlayer_name.AssignCStr(pName);
        dwPlayer_profileDir.AssignString(&dwPlayer_basePath);
        dwPlayer_profileDir.Append(dwPlayer_name.pBuffer, dwPlayer_name.length);
        dwPlayer_profileDir.Append("\\", 1);
        dwPlayer_SavePlr();
    }
}

// @4291e0 (dwPlayer_DeleteProfile) — recursive rmdir of the profile dir.
extern "C" void dwPlayer_DeleteProfile(const char* pName)
{
    inits_RemoveDirTree("PLR", pName);
}

// @429200 (dwPlayer_LoadPlr)
extern "C" void dwPlayer_LoadPlr(const char* pName)
{
    dwConfFile conf;
    dwListNode* pNode;
    char* pToken;
    dwPart* pBp;
    dwMission* pMission;
    uint32_t tmp;

    dwPlayer_name.AssignCStr(pName);
    dwPlayer_profileDir.AssignString(&dwPlayer_basePath);
    dwPlayer_profileDir.Append(dwPlayer_name.pBuffer, dwPlayer_name.length);
    dwPlayer_profileDir.Append("\\", 1);

    // Bare "<name>.plr" — the hooked VFS open resolves it into profileDir
    // (PLR is not in the ext table).
    dwString fname(pName, 0);
    fname.Append(".plr", 0);
    dwConfFile_Open(&conf, fname.pBuffer);

    while (!conf.bEof)
    {
        dwConfFile_ReadLine(&conf);
        pToken = dwConfFile_NextToken(&conf);
        if (dwString_Equals(pToken, "NAME"))
        {
            dwPlayer_name.AssignCStr(conf.pCursor);
        }
        else if (dwString_Equals(pToken, "BRIGHTNESS"))
        {
            dwConfFile_ParseULong(&conf, &dw_settingBrightness);
            dwColormap_SetDisplayPalette((void*)(intptr_t)dw_settingBrightness);
        }
        else if (dwString_Equals(pToken, "SCREEN_SIZE"))
        {
            dwConfFile_ParseULong(&conf, &dw_viewSizePct);
        }
        else if (dwString_Equals(pToken, "MUSIC_VOLUME"))
        {
            dwConfFile_ParseULong(&conf, &dw_settingMusicVol);
            // binary: sithSoundMixer music-volume setter @45ea00
            sithSoundMixer_UpdateMusicVolume((flex_t)dw_settingMusicVol * 0.01);
        }
        else if (dwString_Equals(pToken, "SOUND_VOLUME"))
        {
            dwConfFile_ParseULong(&conf, &dw_settingSoundVol);
            dwSound_SetMenuVolume((float)dw_settingSoundVol * 0.01f);
        }
        else if (dwString_Equals(pToken, "SHOW_TEXT"))
        {
            dw_settingShowText = 1;
        }
        else if (dwString_Equals(pToken, "STATS"))
        {
            dwConfFile_ParseULong(&conf, &dwPlayer_statsFlags);
        }
        else if (dwString_Equals(pToken, "TOPIC"))
        {
            dwConfFile_ParseQuotedString(&conf, &dwCore_currentRefFile);
        }
        else if (dwString_Equals(pToken, "PARTS"))
        {
            // Reset ownership, then re-mark every listed blueprint.
            for (pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList; pNode = pNode->pNext)
            {
                ((dwPart*)pNode->pData)->bAvailable = 0;
            }
            dwConfFile_ReadLine(&conf);
            if (conf.bEof)
                break;
            do
            {
                pToken = dwConfFile_NextToken(&conf);
                if (!pToken || !*pToken || dwString_Equals(pToken, "END"))
                    break;
                pBp = dwPart_FindBlueprint(pToken);
                if (!pBp)
                {
                    stdPlatform_Printf("Blueprint %s not found\n", pToken); // binary: jk_logtofile (no \n there)
                }
                else
                {
                    pBp->bAvailable = 1;
                }
                dwConfFile_ReadLine(&conf);
            } while (!conf.bEof);
        }
        else if (dwString_Equals(pToken, "MISSIONS"))
        {
            // Reset progress, then apply every "<name> <rank> <done>" line.
            for (pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
            {
                pMission = (dwMission*)pNode->pData;
                pMission->bDone = 0;
                pMission->rank = 0;
                pMission->bUnlocked = (pMission->missionType == DW_MISSION_NORMAL);
            }
            dwConfFile_ReadLine(&conf);
            if (conf.bEof)
                break;
            do
            {
                pToken = dwConfFile_NextToken(&conf);
                if (!pToken || !*pToken || dwString_Equals(pToken, "END"))
                    break;
                for (pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
                {
                    if (dwString_Equals(pToken, ((dwMission*)pNode->pData)->name.pBuffer))
                        break;
                }
                if (pNode != dwCore_pMissionList)
                {
                    pMission = (dwMission*)pNode->pData;
                    pMission->bUnlocked = 1;
                    tmp = 0;
                    dwConfFile_ParseULong(&conf, &tmp);
                    pMission->rank = (uint8_t)tmp;
                    tmp = 0;
                    dwConfFile_ParseULong(&conf, &tmp);
                    if (tmp != 0)
                        pMission->bDone = 1;
                }
                dwConfFile_ReadLine(&conf);
            } while (!conf.bEof);
        }
        else if (dwString_Equals(pToken, "WORKSPACE"))
        {
            dwGuiWidgets_ReadDroidFile(&conf, &dwCore_workspaceName, (dwList*)&dwCore_pWorkspaceNodes);
        }
    }
    dwConfFile_Close(&conf);
    // fname freed by the dwString dtor (binary: explicit dwString_Free)
}

// @4296d0 (dwPlayer_SavePlr)
extern "C" void dwPlayer_SavePlr(void)
{
    char aFname[128];
    stdFile_t file;
    dwListNode* pNode;
    dwPart* pBp;
    dwMission* pMission;

    if (dwPlayer_name.length == 0)
        return;
    snprintf(aFname, sizeof(aFname), "%s.plr", dwPlayer_name.pBuffer); // binary: sprintf into a 0x80 stack buffer
    file = dwMain_pHS->fileOpen(aFname, "wb");
    if (!file)
        return;

    dwMain_pHS->filePrintf(file, "NAME\t\t%s\n", dwPlayer_name.pBuffer);
    dwMain_pHS->filePrintf(file, "\n");
    dwMain_pHS->filePrintf(file, "BRIGHTNESS\t\t%lu\n", (unsigned long)dw_settingBrightness);
    dwMain_pHS->filePrintf(file, "SCREEN_SIZE\t\t%lu\n", (unsigned long)dw_viewSizePct);
    dwMain_pHS->filePrintf(file, "MUSIC_VOLUME\t\t%lu\n", (unsigned long)dw_settingMusicVol);
    dwMain_pHS->filePrintf(file, "SOUND_VOLUME\t\t%lu\n", (unsigned long)dw_settingSoundVol);
    dwMain_pHS->filePrintf(file, "\n");
    if (dw_settingShowText)
    {
        dwMain_pHS->filePrintf(file, "SHOW_TEXT\n");
    }
    dwMain_pHS->filePrintf(file, "\nSTATS\t%lu\n", (unsigned long)dwPlayer_statsFlags);
    dwMain_pHS->filePrintf(file, "\nTOPIC\t\"%s\"\n", dwCore_currentRefFile.pBuffer);

    dwMain_pHS->filePrintf(file, "\nPARTS\n");
    for (pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList; pNode = pNode->pNext)
    {
        pBp = (dwPart*)pNode->pData;
        if (pBp->bAvailable)
            dwMain_pHS->filePrintf(file, "%s\n", pBp->name.pBuffer);
    }
    dwMain_pHS->filePrintf(file, "END\n");

    dwMain_pHS->filePrintf(file, "\nMISSIONS\n");
    for (pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
    {
        pMission = (dwMission*)pNode->pData;
        if (pMission->bUnlocked)
        {
            dwMain_pHS->filePrintf(file, "%s\t%lu\t%lu\n", pMission->name.pBuffer,
                                   (unsigned long)pMission->rank,
                                   (unsigned long)(pMission->bDone != 0));
        }
    }
    dwMain_pHS->filePrintf(file, "END\n");

    dwMain_pHS->filePrintf(file, "\nWORKSPACE\n");
    dwGuiWidgets_WriteDroidFile(file, &dwCore_workspaceName, (dwList*)&dwCore_pWorkspaceNodes);
    dwMain_pHS->filePrintf(file, "END\n");

    dwMain_pHS->fileClose(file);
}

// @429950 (dwPlayer_EnumProfiles) — list profile subdirs, then drop entries
// lacking <name>\<name>.plr.
extern "C" void dwPlayer_EnumProfiles(dwList* pOutList)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwString* pName;

    inits_EnumSubdirs("PLR", pOutList);
    for (pNode = pOutList->pSentinel->pNext; pNode != pOutList->pSentinel; pNode = pNext)
    {
        pNext = pNode->pNext;
        pName = (dwString*)pNode->pData;

        dwString path(dwPlayer_basePath);
        path.Append(pName->pBuffer, pName->length);
        path.Append("\\", 1);
        path.Append(pName->pBuffer, pName->length);
        path.Append(".plr", 4);
        if (!inits_FileExists(path.pBuffer))
        {
            delete pName; // binary: dwString_Free + FreeHandle
            dwList::UnlinkNode(&pNode);
            free(pNode);
        }
        // path freed by the dwString dtor (binary: explicit dwString_Free)
    }
}
