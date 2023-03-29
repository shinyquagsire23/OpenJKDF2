#include "jkGUISingleTally.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdStrTable.h"
#include "General/stdFileUtil.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "Gameplay/sithPlayer.h"
#include "World/jkPlayer.h"
#include "Main/jkStrings.h"
#include "Win95/stdDisplay.h"
#include "General/stdString.h"

static jkGuiElement jkGuiSingleTally_buttons[8] = {
{ELEMENT_TEXT, 0, 2, 0, 3, {0, 20, 640, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
{ELEMENT_TEXT, 0, 2, 0, 3, {0, 60, 640, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
{ELEMENT_TEXT, 0, 2, 0, 3, {0, 120, 640, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
{ELEMENT_TEXT, 0, 2, 0, 3, {0, 180, 640, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
{ELEMENT_CUSTOM, 0, 0, 0, 0, {0, 220, 640, 40}, 1, 0, 0, jkGuiSingleTally_ForceStarsRender, 0, 0, {0}, 0},
{ELEMENT_TEXTBUTTON, 0xFFFFFFFF, 2, "GUI_QUIT", 3, {0, 420, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
{ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {490, 420, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
{ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0}
};

static jkGuiMenu jkGuiSingleTally_menu = {jkGuiSingleTally_buttons, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};


int jkGuiSingleTally_Show()
{
    int v7; // esi
    int ret; // eax
    wchar_t v14[32]; // [esp+8h] [ebp-40h] BYREF

    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]->palette);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleTally_menu, &jkGuiSingleTally_buttons[6]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleTally_menu, &jkGuiSingleTally_buttons[5]);
    jkGuiSingleTally_buttons[0].wstr = jkPlayer_playerShortName;
    stdString_snprintf(std_genBuffer, 1024, "RANK_%d_%c", jkPlayer_GetJediRank(), (jkPlayer_CalcAlignment(0) >= 0.0) ? 'L' : 'D');
    jkGuiSingleTally_buttons[1].wstr = jkStrings_GetUniStringWithFallback(std_genBuffer);
    if ( (int)sithPlayer_GetBinAmt(SITHBIN_MAXSECRETS) <= 0 )
    {
        jk_snwprintf(v14, 0x20u, L"%ls %ls", jkStrings_GetUniStringWithFallback("GUI_SECRETS_FOUND"), jkStrings_GetUniStringWithFallback("GUI_NO_SECRETS"));
    }
    else
    {
        jk_snwprintf(v14, 0x20u, L"%ls %d/%d", jkStrings_GetUniStringWithFallback("GUI_SECRETS_FOUND"), (int)sithPlayer_GetBinAmt(SITHBIN_SECRETS), (int)sithPlayer_GetBinAmt(SITHBIN_MAXSECRETS));
    }
    jkGuiSingleTally_buttons[2].wstr = v14;
    jkGuiSingleTally_buttons[3].wstr = jkStrings_GetUniStringWithFallback("GUI_STARS_EARNED");
    do
    {
        v7 = 1;
        ret = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleTally_menu);
        if ( ret == -1 )
        {
            if ( !jkGuiDialog_YesNoDialog(jkStrings_GetUniStringWithFallback("GUI_ABORT_GAME"), jkStrings_GetUniStringWithFallback("GUI_CONFIRM_ABORTCD")) )
                continue;
        }
        else if ( ret != 1 )
        {
            continue;
        }
        v7 = 0;
    }
    while ( v7 );
    jkGui_SetModeGame();
    return ret;
}

void jkGuiSingleTally_Startup()
{
    if (Main_bMotsCompat) {
        jkGuiSingleTally_foStars = stdBitmap_Load("ui\\bm\\oneStar.bm", 1, 0);
    }
    else {
        jkGuiSingleTally_foStars = stdBitmap_Load("ui\\bm\\foStars.bm", 1, 0);
    }
    
    jkGui_InitMenu(&jkGuiSingleTally_menu, jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]);
}

void jkGuiSingleTally_Shutdown()
{
    // Added: clean reset
    if (jkGuiSingleTally_foStars) {
        stdBitmap_Free(jkGuiSingleTally_foStars);
        jkGuiSingleTally_foStars = NULL;
    }
}

void jkGuiSingleTally_ForceStarsRender(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int d)
{
    int v3; // ebx
    int v4; // esi
    stdVBuffer *v5; // ebp

    v3 = (__int64)sithPlayer_GetBinAmt(SITHBIN_NEW_STARS);
    if ( v3 > 0 )
    {
        v4 = 0;
        v5 = *jkGuiSingleTally_foStars->mipSurfaces;
        do {
            stdDisplay_VBufferCopy(
                vbuf,
                v5,
                element->rect.x + v5->format.width * v4++ + ((element->rect.width - v5->format.width * v3) >> 1),
                element->rect.y,
                0,
                1);
        }
        while ( v4 < v3 );
    }
}
