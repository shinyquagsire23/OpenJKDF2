#include "jkGUISetup.h"

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
#include "Gui/jkGUIGameplay.h"
#include "Gui/jkGUIDisplay.h"
#include "Gui/jkGUISound.h"
#include "Gui/jkGUIKeyboard.h"
#include "Gui/jkGUIMouse.h"
#include "Gui/jkGUIJoystick.h"
#include "Gui/jkGUIGeneral.h"
#include "Gui/jkGUIControlOptions.h"

static jkGuiElement jkGuiSetup_buttons[9] = {
    {ELEMENT_TEXT, 0, 0, 0, 3, {0, 410, 640, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 6, "GUI_SETUP", 3, {20, 20, 600, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 100, 2, "GUI_GENERAL", 3, {20, 80, 120, 40},  1, 0, "GUI_GENERAL_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 101, 2, "GUI_GAMEPLAY", 3, {140, 80, 120, 40}, 1, 0, "GUI_GAMEPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 102, 2, "GUI_DISPLAY", 3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 103, 2, "GUI_SOUND", 3, {380, 80, 120, 40}, 1, 0, "GUI_SOUND_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 104, 2, "GUI_CONTROLS", 3, {500, 80, 120, 40}, 1, 0, "GUI_CONTROLS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {440, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiSetup_menu = {jkGuiSetup_buttons, 0, 0xFF, 0xE1, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

static jkGuiElement jkGuiSetupControls_buttons[13] = {
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
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {440, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiSetupControls_menu = {jkGuiSetupControls_buttons, 0, 0xFF, 0xE1, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiSetup_sub_412EF0(jkGuiMenu *menu, int a2)
{
    jkGuiElement *paElements; // eax

    paElements = menu->paElements;
    paElements[2].enableHover = 1;
    paElements[3].enableHover = 1;
    paElements[4].enableHover = 1;
    paElements[5].enableHover = 1;
    paElements[6].enableHover = 1;
    if ( a2 )
    {
        paElements[7].enableHover = 1;
        paElements[8].enableHover = 1;
        paElements[9].enableHover = 1;
        paElements[10].enableHover = 1;
    }
}

void jkGuiSetup_Show()
{
    int i; // esi
    int v1; // edi
    int v2; // eax
;
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSetup_menu, &jkGuiSetup_buttons[7]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSetup_menu, &jkGuiSetup_buttons[7]);
    for ( i = jkGuiRend_DisplayAndReturnClicked(&jkGuiSetup_menu); i != -1; i = jkGuiRend_DisplayAndReturnClicked(&jkGuiSetup_menu) )
    {
        if ( i == 1 )
            break;
        if ( i >= 100 )
        {
            while ( 2 )
            {
                if ( i <= 104 )
                {
                    switch ( i )
                    {
                        case 100:
                            i = jkGuiGeneral_Show();
                            goto LABEL_23;
                        case 101:
                            i = jkGuiGameplay_Show();
                            goto LABEL_23;
                        case 102:
                            i = jkGuiDisplay_Show();
                            goto LABEL_23;
                        case 103:
                            i = jkGuiSound_Show();
                            goto LABEL_23;
                        case 104:
                            do
                            {
                                jkGui_sub_412E20(&jkGuiSetupControls_menu, 105, 108, 0);
                                jkGui_sub_412E20(&jkGuiSetupControls_menu, 102, 107, 104);
                                jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSetupControls_menu, &jkGuiSetupControls_buttons[11]);
                                jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSetupControls_menu, &jkGuiSetupControls_buttons[11]);
                                i = jkGuiRend_DisplayAndReturnClicked(&jkGuiSetupControls_menu);
                                v1 = 0;
                                while ( i >= 105 )
                                {
                                    if ( i > 108 )
                                        break;
                                    switch ( i )
                                    {
                                        case 105:
                                            v2 = jkGuiKeyboard_Show();
                                            goto LABEL_17;
                                        case 106:
                                            v2 = jkGuiMouse_Show();
                                            goto LABEL_17;
                                        case 107:
                                            v2 = jkGuiJoystick_Show();
                                            goto LABEL_17;
                                        case 108:
                                            v2 = jkGuiControlOptions_Show();
LABEL_17:
                                            i = v2;
                                            v1 = 1;
                                            break;
                                        default:
                                            break;
                                    }
                                    if ( !v1 )
                                    {
                                        jkGui_sub_412E20(&jkGuiSetup_menu, 105, 108, i);
                                        jkGuiSetup_menu.paElements[jkGuiSetup_menu.clickableIdxIdk].wstr = 0; // MOTS added
                                        jkGuiRend_Paint(&jkGuiSetup_menu);
                                    }
                                }
                            }
                            while ( v1 );
                            if ( i != -1 )
                                goto LABEL_23;
                            return;
                        default:
LABEL_23:
                            jkGui_sub_412E20(&jkGuiSetup_menu, 100, 104, i);
                            jkGuiSetup_menu.paElements[jkGuiSetup_menu.clickableIdxIdk].wstr = 0; // MOTS added
                            jkGuiRend_Paint(&jkGuiSetup_menu);
                            if ( i < 100 )
                                break;
                            continue;
                    }
                }
                break;
            }
        }
        jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSetup_menu, &jkGuiSetup_buttons[7]);
        jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSetup_menu, &jkGuiSetup_buttons[7]);
    }
}

void jkGuiSetup_Startup()
{
    jkGui_InitMenu(&jkGuiSetup_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
    jkGui_InitMenu(&jkGuiSetupControls_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiSetup_Shutdown()
{
    ;
}
