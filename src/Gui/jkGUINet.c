#include "jkGUINet.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Engine/sithMulti.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIBuildMulti.h"
#include "Gui/jkGUINetHost.h"
#include "Gui/jkGUIDialog.h"
#include "Main/jkStrings.h"
#include "Main/jkMain.h"
#include "Win95/sithDplay.h"
#include "World/sithPlayer.h"
#include "World/sithThing.h"

void jkGuiNet_idk(jkGuiMenu *pMenu)
{
    uint32_t v1; // eax
    wchar_t *v2; // eax
    wchar_t *v3; // [esp-4h] [ebp-4h]

    if ( sithDplay_dword_8321E0 && (g_submodeFlags & 8) != 0 )
    {
        v1 = stdPlatform_GetTimeMsec();
        if ( v1 <= jkGuiNet_dword_5564EC + 2000 || (jkGuiNet_dword_5564EC = v1, sithMulti_SendRequestConnect(sithNet_dword_8C4BA4)) )
        {
            sithCogVm_Sync();
            if ( (g_submodeFlags & 8) == 0 )
                pMenu->lastButtonUp = 1;
#ifdef SDL2_RENDER
            pMenu->lastButtonUp = 1;

            for (int i = 0; i < jkPlayer_maxPlayers; i++ )
            {
                jkPlayer_playerInfos[i].field_13B0 = sithTime_curMs;
            }

            g_submodeFlags &= ~8u;
            sithThing_sub_4CCE60();
            sithPlayer_sub_4C87C0(0, sithDplay_dword_8321EC);
            sithPlayer_idk(0);
            sithPlayer_ResetPalEffects();
            //sithEvent_RegisterFunc(2, (int)sithMulti_ServerLeft, sithNet_tickrate, 1);
            sithCogVm_SetNeedsSync();

            sithNet_isServer = 1;
#endif
        }
        else
        {
            v3 = jkStrings_GetText("GUINET_NOGAMECONNECT");
            v2 = jkStrings_GetText("GUINET_JOINERROR");
            jkGuiDialog_ErrorDialog(v2, v3);
            pMenu->lastButtonUp = -2;
        }
    }
}