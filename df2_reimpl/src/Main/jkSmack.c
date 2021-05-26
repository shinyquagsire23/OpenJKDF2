#include "jkSmack.h"

#include "../jk.h"
#include "stdPlatform.h"
#include "General/util.h"
#include "Main/jkGame.h"
#include "Main/jkMain.h"
#include "Main/jkRes.h"
#include "Gui/jkGUIRend.h"
#include "Win95/sithDplay.h"
#include "World/jkPlayer.h"
#include "Main/jkEpisode.h"

void jkSmack_Initialize()
{
    jkSmack_bInit = 1;
    jkSmack_currentGuiState = 0;
    jkSmack_stopTick = 0;
}

void jkSmack_Shutdown()
{
    jkSmack_bInit = 0;
    if ( jkEpisode_mLoad.paEntries )
    {
        pHS->free(jkEpisode_mLoad.paEntries);
        jkEpisode_mLoad.paEntries = 0;
    }
}

int jkSmack_GetCurrentGuiState()
{
    return jkSmack_currentGuiState;
}

int jkSmack_SmackPlay(const char *fname)
{
    if ( sithDplay_EarlyInit() || jkPlayer_setDisableCutscenes )
    {
        if ( jkGuiRend_thing_five )
            jkGuiRend_thing_four = 1;

        jkSmack_stopTick = 1;
        jkSmack_nextGuiState = 2;
        return 1;
    }
    _sprintf(std_genBuffer, "video%c%s", '\\', fname);
    if ( !util_FileExists(std_genBuffer) )
    {
        if ( jkGuiRend_thing_five )
            jkGuiRend_thing_four = 1;

        jkSmack_stopTick = 1;
        jkSmack_nextGuiState = 2;
        return 1;
    }
    jkRes_FileExists(std_genBuffer, gamemode_0_2_str, 128);

    if ( jkGuiRend_thing_five )
        jkGuiRend_thing_four = 1;

    jkSmack_stopTick = 1;
    jkSmack_nextGuiState = 1;
    return 1;
}
