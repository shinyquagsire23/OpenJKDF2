#include "jkGUIDecision.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"

enum jkGuiDecisionButton_t
{
    JKGUIDECISION_A = 45,
    JKGUIDECISION_B = 46
};

static jkGuiElement jkGuiDecision_buttons[4] = {
    { ELEMENT_TEXT,        0,               2, "GUI_LIGHT_OR_DARK",  3, {130, 140, 390, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, JKGUIDECISION_A,  2, "GUI_DECIDE_A",       3, {320, 290, 320, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, JKGUIDECISION_B,  2, "GUI_DECIDE_B",       3, {0,   290, 320, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_END,         0,               0,  NULL,                0, {0},                 0, 0, 0, 0, 0, 0, {0}, 0}
};
static jkGuiMenu jkGuiDecision_menu = {jkGuiDecision_buttons, -1, 0x0E1, 0x0FF, 0x0F, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiDecision_Startup()
{
    jkGui_InitMenu(&jkGuiDecision_menu, jkGui_stdBitmaps[JKGUI_BM_BK_DECISION]);
}

void jkGuiDecision_Shutdown()
{
}

int jkGuiDecision_Show()
{
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_DECISION]->palette);

    int clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiDecision_menu);

    jkGui_SetModeGame();
    return (clicked == JKGUIDECISION_A);
}
