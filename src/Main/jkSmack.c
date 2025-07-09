#include "jkSmack.h"

#include "../jk.h"
#include "stdPlatform.h"
#include "General/util.h"
#include "Main/jkGame.h"
#include "Main/jkMain.h"
#include "Main/jkRes.h"
#include "Gui/jkGUIRend.h"
#include "Win95/stdComm.h"
#include "World/jkPlayer.h"
#include "Main/jkEpisode.h"
#include "General/stdFnames.h"

#ifdef FS_POSIX
#include "external/fcaseopen/fcaseopen.h"
#endif

void jkSmack_Startup()
{
    jkSmack_bInit = 1;
    jkSmack_currentGuiState = 0;
    jkSmack_stopTick = 0;
}

void jkSmack_Shutdown()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__); // Added
    jkSmack_bInit = 0;
    if ( jkEpisode_mLoad.paEntries )
    {
        pHS->free(jkEpisode_mLoad.paEntries);
        jkEpisode_mLoad.paEntries = 0;

        // Added: prevent UAF
        jkMain_pEpisodeEnt = NULL;
        jkMain_pEpisodeEnt2 = NULL;
    }
}

int jkSmack_GetCurrentGuiState()
{
    return jkSmack_currentGuiState;
}

int jkSmack_SmackPlay(const char *fname)
{
#ifndef ARCH_WASM
    if ( stdComm_EarlyInit() || jkPlayer_setDisableCutscenes )
#endif
    {
        if ( jkGuiRend_thing_five )
            jkGuiRend_thing_four = 1;

        jkSmack_stopTick = 1;
        jkSmack_nextGuiState = JK_GAMEMODE_TITLE;
        return 1;
    }
    _sprintf(std_genBuffer, "video%c%s", LEC_PATH_SEPARATOR_CHR, fname);

#ifdef FS_POSIX
    char *r = (char*)malloc(strlen(std_genBuffer) + 16);
    if (casepath(std_genBuffer, r))
    {
        strcpy(std_genBuffer, r);
    }
    free(r);
#endif

    if ( !util_FileExists(std_genBuffer) )
    {
        if ( jkGuiRend_thing_five )
            jkGuiRend_thing_four = 1;

        jkSmack_stopTick = 1;
        jkSmack_nextGuiState = JK_GAMEMODE_TITLE;
        return 1;
    }
    jkRes_FileExists(std_genBuffer, jkMain_aLevelJklFname, 128);

    if ( jkGuiRend_thing_five )
        jkGuiRend_thing_four = 1;

    jkSmack_stopTick = 1;
    jkSmack_nextGuiState = JK_GAMEMODE_VIDEO;
    return 1;
}
