#include "jkGUIControlOptions.h"

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
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIControlSaveLoad.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"

static jkGuiElement jkGuiControlOptions_buttons[19] = {
    {ELEMENT_TEXT, 0, 0, 0, 3, {0, 410, 640, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 6, "GUI_SETUP", 3, {20, 20, 600, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 100, 2, "GUI_GENERAL", 3, {20, 80, 120, 40},  1, 0, "GUI_GENERAL_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 101, 2, "GUI_GAMEPLAY", 3, {140, 80, 120, 40}, 1, 0, "GUI_GAMEPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 102, 2, "GUI_DISPLAY", 3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 103, 2, "GUI_SOUND", 3, {380, 80, 120, 40}, 1, 0, "GUI_SOUND_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 104, 2, "GUI_CONTROLS", 3, {500, 80, 120, 40}, 1, 0, "GUI_CONTROLS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 105, 2, "GUI_KEYBOARD", 3, {40, 120, 140, 40}, 1, 0, "GUI_KEYBOARD_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 106, 2, "GUI_MOUSE", 3, {180, 120, 140, 40},  1, 0, "GUI_MOUSE_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 107, 2, "GUI_JOYSTICK", 3, {320, 120, 140, 40}, 1, 0, "GUI_JOYSTICK_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 108, 2, "GUI_CONTROLOPTIONS", 3, {460, 120, 140,  40}, 1, 0, "GUI_CONTROLOPTIONS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_FREELOOK", 0, {40, 230, 360, 20}, 1,  0, "GUI_FREELOOK_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_VIEWCENTER", 0, {40, 260, 360, 20},  1, 0, "GUI_VIEWCENTER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_ALWAYSRUN", 0, {40, 290, 360, 20}, 1, 0, "GUI_ALWAYSRUN_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 4445, 2, "GUI_LOADCONFIG", 3, {0, 170, 320, 50}, 1, 0, "GUI_LOADCONFIG_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 4444, 2, "GUI_SAVECONFIG", 3, {320, 170, 320,  50}, 1, 0, "GUI_SAVECONFIG_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {440, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, {0, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiControlOptions_menu = {jkGuiControlOptions_buttons, 0, 0xFF, 0xE1, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiControlOptions_Startup()
{
    jkGui_InitMenu(&jkGuiControlOptions_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiControlOptions_Shutdown()
{
    ;
}

// MOTS altered
int jkGuiControlOptions_Show()
{
    int v0; // eax
    int v1; // esi
    int v2; // eax
    char v3; // al
    char v4; // al

    jkGui_sub_412E20(&jkGuiControlOptions_menu, 100, 104, 108);
    jkGuiControlOptions_buttons[11].boxChecked = sithWeapon_controlOptions & 4;
    jkGuiControlOptions_buttons[12].boxChecked = sithWeapon_controlOptions & 0x10;
    jkGuiControlOptions_buttons[13].boxChecked = sithWeapon_controlOptions & 2;
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiControlOptions_menu, &jkGuiControlOptions_buttons[16]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiControlOptions_menu, &jkGuiControlOptions_buttons[17]);
    jkGuiSetup_sub_412EF0(&jkGuiControlOptions_menu, 1);
    while ( 1 )
    {
        while ( 1 )
        {
            v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiControlOptions_menu);
            v1 = v0;
            if ( v0 != 4444 )
                break;
            jkGuiControlSaveLoad_Write(1);
        }
        if ( v0 != 4445 )
            break;
        jkGuiControlSaveLoad_Write(0);
    }
    if ( v0 != -1 )
    {
        if ( jkGuiControlOptions_buttons[11].boxChecked )
            sithWeapon_controlOptions |= 4;
        else
            sithWeapon_controlOptions &= ~4;

        if ( jkGuiControlOptions_buttons[12].boxChecked )
            sithWeapon_controlOptions |= 0x10;
        else
            sithWeapon_controlOptions &= ~0x10;

        if ( jkGuiControlOptions_buttons[13].boxChecked )
            sithWeapon_controlOptions |= 2;
        else
            sithWeapon_controlOptions &= ~2;

        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }
    return v1;
}
