#include "jkControl.h"

#include "Devices/sithControl.h"
#include "Gameplay/sithOverlayMap.h"
#include "Engine/sithCamera.h"
#include "Dss/sithGamesave.h"
#include "Cog/jkCog.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "Gameplay/sithInventory.h"
#include "Platform/stdControl.h"
#include "Win95/Window.h"
#include "Devices/sithConsole.h"
#include "Main/jkGame.h"
#include "Main/jkHud.h"
#include "Main/jkDev.h"
#include "Main/jkStrings.h"
#include "Gui/jkGUITitle.h"
#include "Dss/sithMulti.h"
#include "../jk.h"

static int jkControl_bInit;

int jkControl_Startup()
{
    sithControl_Startup();
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
    sithControl_Shutdown(); // Added
    jkControl_bInit = 0;
    return 1;
}

void jkControl_nullsub_37()
{
}

// MOTS altered done
int jkControl_HandleHudKeys(sithThing *player, float b)
{
    wchar_t *v2; // eax
    wchar_t *v5; // eax
    int v15; // [esp+4h] [ebp-304h] BYREF
    wchar_t v16[128]; // [esp+8h] [ebp-300h] BYREF
    wchar_t a4[256]; // [esp+108h] [ebp-200h] BYREF

    // Added: dedicated
    if ((sithNet_isServer && jkGuiNetHost_bIsDedicated) || (player->actorParams.typeflags & SITH_TF_RENDERWEAPON) == 0 )
    {
        if ( !jkHud_bChatOpen )
        {
            sithControl_ReadFunctionMap(INPUT_FUNC_TALK, &v15);
            if (v15 && sithThing_MotsTick(0xe,0,1.0))
                jkHud_Chat();
        }

        if ( (g_submodeFlags & 1) == 0 )
        {
            sithControl_ReadFunctionMap(INPUT_FUNC_GAMESAVE, &v15);
            if (v15 && sithThing_MotsTick(0xe,0,2.0))
            {
                v2 = jkGuiTitle_quicksave_related_func1(&jkCog_strings, sithWorld_pCurrentWorld->map_jkl_fname);
                jk_snwprintf(a4, 0x100u, L"%s~%s", v2, jkStrings_GetUniStringWithFallback("GUI_SLQUICKSAVE"));
                
                sithGamesave_Write("quicksave.jks", 1, 0, a4);
                sithConsole_PrintUniStr(jkStrings_GetUniStringWithFallback("GUI_SLGAMEQUICKSAVED"));
            }
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_CAMERAMODE, &v15);
        for (int i = v15-- == 0; !i; --v15 )
        {
            if ( (player->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 && sithThing_MotsTick(0xe,0,0.0)) // MOTS altered
            {
                sithCamera_CycleCamera();
                //DAT_005b9254 = 2; // MOTS TODO
                if ( (sithCamera_currentCamera->cameraPerspective & 0xFC) != 0 )
                    v5 = jkStrings_GetUniStringWithFallback("GAME_EXTERNALCAM");
                else
                    v5 = jkStrings_GetUniStringWithFallback("GAME_INTERNALCAM");
                jkDev_PrintUniString(v5);
            }
            i = v15 == 0;
        }

        if ( !sithOverlayMap_bShowMap )
        {
            sithControl_ReadFunctionMap(INPUT_FUNC_INCREASE, &v15);
            for (int i = v15-- == 0; !i; --v15 )
            {
                if (sithThing_MotsTick(0xe,1,3.0)) { // MOTS altered
                    jkGame_ScreensizeIncrease();
                    jk_snwprintf(v16, 0x80u, jkStrings_GetUniStringWithFallback("GAME_SCREENSIZE"), jkGame_screenSize);
                    jkDev_PrintUniString(v16);
                }
                i = v15 == 0;
            }
            sithControl_ReadFunctionMap(INPUT_FUNC_DECREASE, &v15);
            for (int i = v15-- == 0; !i; --v15 )
            {
                if (sithThing_MotsTick(0xe,-1,3.0)) { // MOTS altered
                    jkGame_ScreensizeDecrease();
                    jk_snwprintf(v16, 0x80u, jkStrings_GetUniStringWithFallback("GAME_SCREENSIZE"), jkGame_screenSize);
                    jkDev_PrintUniString(v16);
                }
                i = v15 == 0;
            }
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_GAMMA, &v15);
        for (int i = v15-- == 0; !i; --v15 )
        {
            if (sithThing_MotsTick(0xe,0,4.0)) { // MOTS altered
                jkGame_Gamma();
                jk_snwprintf(v16, 0x80u, jkStrings_GetUniStringWithFallback("GAME_GAMMA"), jkGame_gamma);
                jkDev_PrintUniString(v16);
            }
            i = v15 == 0;
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_SCREENSHOT, &v15);
        if (v15 && sithThing_MotsTick(0xe,0,6.0))
        {
            jkGame_Screenshot();
            jkDev_PrintUniString(jkStrings_GetUniStringWithFallback("GAME_SCREENSHOT"));
        }

        sithControl_ReadFunctionMap(INPUT_FUNC_TALLY, &v15);
        if (v15 && sithThing_MotsTick(0xe,0,5.0))
            jkHud_Tally();
    }
    return 0;
}
