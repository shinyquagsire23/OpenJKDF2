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
#include "Win95/Window.h"

enum jkGuiDecisionButton_t
{
    GUI_GENERAL = 100,
    GUI_GAMEPLAY = 101,
    GUI_DISPLAY = 102,
    GUI_SOUND = 103,
    GUI_CONTROLS = 104
};

static wchar_t slider_val_text[5] = {0};
static int slider_1[2] = {18, 17};
void jkGuiGeneral_FovDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

static jkGuiElement jkGuiGeneral_aElements[20] = { 
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

#ifdef QOL_IMPROVEMENTS
    {ELEMENT_TEXT,         0,            0, L"FOV",                 3, {20, 240, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER,       0,            0, (FOV_MAX - FOV_MIN),                    0, {10, 270, 320, 30}, 1, 0, L"Set FOV", jkGuiGeneral_FovDraw, 0, slider_1, {0}, 0},
    {ELEMENT_TEXT,         0,            0, slider_val_text,        3, {20, 300, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"FOV is vertical (Hor+)",    0, {20, 320, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
#ifdef SDL2_RENDER
    {ELEMENT_CHECKBOX,     0,            0, L"Enable HiDPI",    0, {20, 340, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
#endif
#endif

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

#ifdef QOL_IMPROVEMENTS
void jkGuiGeneral_FovDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    jkPlayer_fov = FOV_MIN + jkGuiGeneral_aElements[13].selectedTextEntry;
    
    jk_snwprintf(slider_val_text, 5, L"%u", jkPlayer_fov);
    jkGuiGeneral_aElements[14].wstr = slider_val_text;
    
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    jkGuiRend_UpdateAndDrawClickable(&jkGuiGeneral_aElements[14], menu, 1);
}
#endif

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

#ifdef QOL_IMPROVEMENTS
    jkGuiGeneral_aElements[13].selectedTextEntry = jkPlayer_fov - FOV_MIN;
    jkGuiGeneral_aElements[15].selectedTextEntry = jkPlayer_fovIsVertical;
#ifdef SDL2_RENDER
    jkGuiGeneral_aElements[16].selectedTextEntry = Window_isHiDpi;
#endif
#endif

    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiGeneral_menu);
    if ( v0 != -1 )
    {
        jkPlayer_setFullSubtitles = jkGuiGeneral_aElements[7].selectedTextEntry;
        jkPlayer_setRotateOverlayMap = jkGuiGeneral_aElements[8].selectedTextEntry;
        jkPlayer_setDisableCutscenes = jkGuiGeneral_aElements[9].selectedTextEntry;

#ifdef QOL_IMPROVEMENTS
        jkPlayer_fovIsVertical = jkGuiGeneral_aElements[15].selectedTextEntry;
#ifdef SDL2_RENDER
        Window_SetHiDpi(jkGuiGeneral_aElements[16].selectedTextEntry);
#endif
#endif

        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }
    return v0;
}
