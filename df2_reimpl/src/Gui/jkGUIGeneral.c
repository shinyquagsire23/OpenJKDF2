#include "jkGUIGeneral.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUISetup.h"
#include "World/jkPlayer.h"

enum jkGuiDecisionButton_t
{
    GUI_GENERAL = 100,
    GUI_GAMEPLAY = 101,
    GUI_DISPLAY = 102,
    GUI_SOUND = 103,
    GUI_CONTROLS = 104
};

static jkGuiElement jkGuiGeneral_aElements[13] = { 
    { ELEMENT_TEXT,        0,            0, NULL,                   3, {0, 410, 640, 20},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXT,        0,            6, "GUI_SETUP",            3, {20, 20, 600, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_GENERAL,  2, "GUI_GENERAL",          3, {20, 80, 120, 40},   1, 0, "GUI_GENERAL_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_GAMEPLAY, 2, "GUI_GAMEPLAY",         3, {140, 80, 120, 40},  1, 0, "GUI_GAMEPLAY_HINT",         0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_DISPLAY,  2, "GUI_DISPLAY",          3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_SOUND,    2, "GUI_SOUND",            3, {380, 80, 120, 40},  1, 0, "GUI_SOUND_HINT",            0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_CONTROLS, 2, "GUI_CONTROLS",         3, {500, 80, 120, 40},  1, 0, "GUI_CONTROLS_HINT",         0, 0, 0, {0}, 0},
    { ELEMENT_CHECKBOX,    0,            0, "GUI_FULLSUB",          0, {20, 150, 300, 40},  1, 0, "GUI_FULLSUB_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_CHECKBOX,    0,            0, "GUI_ROTATEOVERLAY",    0, {330, 150, 300, 40}, 1, 0, "GUI_ROTATEOVERLAY_HINT",    0, 0, 0, {0}, 0},
    { ELEMENT_CHECKBOX,    0,            0, "GUI_DISABLECUTSCENES", 0, {20, 180, 300, 40},  1, 0, "GUI_DISABLECUTSCENES_HINT", 0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  1,            2, "GUI_OK",               3, {440, 430, 200, 40}, 1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, -1,            2, "GUI_CANCEL",           3, {0, 430, 200, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_END,         0,            0, NULL,                   0, {0},                 0, 0, NULL,                        0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiGeneral_menu = { jkGuiGeneral_aElements, 0, 0xFF, 0xE1, 0x0F, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0 };

void jkGuiGeneral_Initialize()
{
    jkGui_InitMenu(&jkGuiGeneral_menu, jkGui_stdBitmaps[3]);
}

void jkGuiGeneral_Shutdown()
{
    ;
}

int jkGuiGeneral_Show()
{
    int v0; // esi

    jkGui_sub_412E20(&jkGuiGeneral_menu, 100, 104, 100);
    jkGuiGeneral_aElements[7].selectedTextEntry = jkPlayer_setFullSubtitles;
    jkGuiGeneral_aElements[8].selectedTextEntry = jkPlayer_setRotateOverlayMap;
    jkGuiGeneral_aElements[9].selectedTextEntry = jkPlayer_setDisableCutscenes;
    jkGuiRend_MenuSetLastElement(&jkGuiGeneral_menu, &jkGuiGeneral_aElements[10]);
    jkGuiRend_SetDisplayingStruct(&jkGuiGeneral_menu, &jkGuiGeneral_aElements[11]);
    jkGuiSetup_sub_412EF0(&jkGuiGeneral_menu, 0);
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiGeneral_menu);
    if ( v0 != -1 )
    {
        jkPlayer_setFullSubtitles = jkGuiGeneral_aElements[7].selectedTextEntry;
        jkPlayer_setRotateOverlayMap = jkGuiGeneral_aElements[8].selectedTextEntry;
        jkPlayer_setDisableCutscenes = jkGuiGeneral_aElements[9].selectedTextEntry;
        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }
    return v0;
}
