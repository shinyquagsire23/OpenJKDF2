#include "jkControl.h"

#include "Engine/sithControl.h"
#include "Gameplay/sithOverlayMap.h"
#include "Engine/sithCamera.h"
#include "Dss/sithGamesave.h"
#include "Cog/jkCog.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithInventory.h"
#include "Platform/stdControl.h"
#include "Win95/Window.h"
#include "Win95/DebugConsole.h"
#include "Main/jkGame.h"
#include "Main/jkHud.h"
#include "Main/jkDev.h"
#include "Main/jkStrings.h"
#include "Gui/jkGUITitle.h"
#include "../jk.h"

static int jkControl_bInit;

int jkControl_Initialize()
{
    sithControl_Initialize();
    sithControl_AddInputHandler(sithControl_HandlePlayer);
    sithControl_AddInputHandler(sithWeapon_HandleWeaponKeys);
    sithControl_AddInputHandler(sithInventory_HandleInvSkillKeys);
    sithControl_AddInputHandler(jkControl_HandleHudKeys);
    Window_AddMsgHandler(stdControl_MessageHandler);

    jkControl_bInit = 1;
    return 1;
}

int jkControl_Shutdown()
{
    jkControl_bInit = 0;
    return 1;
}

void jkControl_nullsub_37()
{
}

int jkControl_HandleHudKeys(sithThing *player, float b)
{
    wchar_t *v2; // eax
    wchar_t *v5; // eax
    int v15; // [esp+4h] [ebp-304h] BYREF
    wchar_t v16[128]; // [esp+8h] [ebp-300h] BYREF
    wchar_t a4[256]; // [esp+108h] [ebp-200h] BYREF

    if ( (player->actorParams.typeflags & SITH_TF_RENDERWEAPON) == 0 )
    {
        if ( !jkHud_bChatOpen )
        {
            sithControl_ReadFunctionMap(INPUT_FUNC_TALK, &v15);
            if ( v15 )
                jkHud_Chat();
        }

        if ( (g_submodeFlags & 1) == 0 )
        {
            sithControl_ReadFunctionMap(INPUT_FUNC_GAMESAVE, &v15);
            if ( v15 )
            {
                v2 = jkGuiTitle_quicksave_related_func1(&jkCog_strings, sithWorld_pCurrentWorld->map_jkl_fname);
                jk_snwprintf(a4, 0x100u, L"%s~%s", v2, jkStrings_GetText("GUI_SLQUICKSAVE"));
                
                sithGamesave_Write("quicksave.jks", 1, 0, a4);
                DebugConsole_PrintUniStr(jkStrings_GetText("GUI_SLGAMEQUICKSAVED"));
            }
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_CAMERAMODE, &v15);
        for (int i = v15-- == 0; !i; --v15 )
        {
            if ( (player->thingflags & 0x202) == 0 )
            {
                sithCamera_CycleCamera();
                if ( (sithCamera_currentCamera->cameraPerspective & 0xFC) != 0 )
                    v5 = jkStrings_GetText("GAME_EXTERNALCAM");
                else
                    v5 = jkStrings_GetText("GAME_INTERNALCAM");
                jkDev_PrintUniString(v5);
            }
            i = v15 == 0;
        }

        if ( !sithOverlayMap_bShowMap )
        {
            sithControl_ReadFunctionMap(INPUT_FUNC_INCREASE, &v15);
            for (int i = v15-- == 0; !i; --v15 )
            {
                jkGame_ScreensizeIncrease();
                jk_snwprintf(v16, 0x80u, jkStrings_GetText("GAME_SCREENSIZE"), jkGame_screenSize);
                jkDev_PrintUniString(v16);
                i = v15 == 0;
            }
            sithControl_ReadFunctionMap(INPUT_FUNC_DECREASE, &v15);
            for (int i = v15-- == 0; !i; --v15 )
            {
                jkGame_ScreensizeDecrease();
                jk_snwprintf(v16, 0x80u, jkStrings_GetText("GAME_SCREENSIZE"), jkGame_screenSize);
                jkDev_PrintUniString(v16);
                i = v15 == 0;
            }
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_GAMMA, &v15);
        for (int i = v15-- == 0; !i; --v15 )
        {
            jkGame_Gamma();
            jk_snwprintf(v16, 0x80u, jkStrings_GetText("GAME_GAMMA"), jkGame_gamma);
            jkDev_PrintUniString(v16);
            i = v15 == 0;
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_SCREENSHOT, &v15);
        if ( v15 )
        {
            jkGame_Screenshot();
            jkDev_PrintUniString(jkStrings_GetText("GAME_SCREENSHOT"));
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_TALLY, &v15);
        if ( v15 )
            jkHud_Tally();
    }
    return 0;
}
