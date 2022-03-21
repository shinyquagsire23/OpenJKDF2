#include "Gui/jkGUIDisplay.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdString.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUISetup.h"
#include "World/jkPlayer.h"
#include "Win95/Window.h"

#include "jk.h"

enum jkGuiDecisionButton_t
{
    GUI_GENERAL = 100,
    GUI_GAMEPLAY = 101,
    GUI_DISPLAY = 102,
    GUI_SOUND = 103,
    GUI_CONTROLS = 104
};

static wchar_t render_level[256] = {0};
static wchar_t gamma_level[256] = {0};

static wchar_t slider_val_text[5] = {0};
static wchar_t slider_val_text_2[5] = {0};
static int slider_1[2] = {18, 17};
static int slider_2[2] = {18, 17};
void jkGuiDisplay_FovDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
void jkGuiDisplay_FramelimitDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

static jkGuiElement jkGuiDisplay_aElements[28] = { 
    { ELEMENT_TEXT,        0,            0, NULL,                   3, {0, 410, 640, 20},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXT,        0,            6, "GUI_SETUP",            3, {20, 20, 600, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_GENERAL,  2, "GUI_GENERAL",          3, {20, 80, 120, 40},   1, 0, "GUI_GENERAL_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_GAMEPLAY, 2, "GUI_GAMEPLAY",         3, {140, 80, 120, 40},  1, 0, "GUI_GAMEPLAY_HINT",         0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_DISPLAY,  2, "GUI_DISPLAY",          3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_SOUND,    2, "GUI_SOUND",            3, {380, 80, 120, 40},  1, 0, "GUI_SOUND_HINT",            0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_CONTROLS, 2, "GUI_CONTROLS",         3, {500, 80, 120, 40},  1, 0, "GUI_CONTROLS_HINT",         0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  1,            2, "GUI_OK",               3, {440, 430, 200, 40}, 1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, -1,            2, "GUI_CANCEL",           3, {0, 430, 200, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},

    // 9
    {ELEMENT_TEXT,         0,            0, L"FOV",                 3, {20, 130, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER,       0,            0, (FOV_MAX - FOV_MIN),                    0, {10, 160, 320, 30}, 1, 0, L"Set FOV", jkGuiDisplay_FovDraw, 0, slider_1, {0}, 0},
    {ELEMENT_TEXT,         0,            0, slider_val_text,        3, {20, 190, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"FOV is vertical (Hor+)",    0, {20, 210, 200, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"Enable Fullscreen",    0, {400, 150, 200, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"Enable HiDPI",    0, {400, 180, 200, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"Enable Texture Filtering",    0, {400, 210, 200, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"Use 1:1 aspect",    0, {20, 240, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},

    // 17
    {ELEMENT_TEXT,         0,            0, L"FPS Limit",                 3, {20, 280, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER,       0,            0, (FPS_LIMIT_MAX - FPS_LIMIT_MIN),                    0, {10, 310, 320, 30}, 1, 0, L"Set FPS limit", jkGuiDisplay_FramelimitDraw, 0, slider_2, {0}, 0},
    {ELEMENT_TEXT,         0,            0, slider_val_text_2,        3, {20, 340, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, L"Enable VSync",    0, {20, 360, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    
    // 21
    {ELEMENT_CHECKBOX,     0,            0, L"Enable Bloom",    0, {400, 240, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},

    // 22
    {ELEMENT_CHECKBOX,     0,            0, L"Enable SSAO",    0, {400, 270, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    
    // 23
    { ELEMENT_TEXT,        0,            0, L"SSAA Multiplier:",            2, {400, 310, 120, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBOX,      0,            0, NULL,    100, {530, 310+10, 80, 20}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    
    // 25
    { ELEMENT_TEXT,        0,            0, L"Gamma Value:",            2, {400, 310+40, 120, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBOX,      0,            0, NULL,    100, {530, 310+10+40, 80, 20}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    

    { ELEMENT_END,         0,            0, NULL,                   0, {0},                 0, 0, NULL,                        0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiDisplay_menu = { jkGuiDisplay_aElements, 0, 0xFF, 0xE1, 0x0F, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0 };

void jkGuiDisplay_Initialize()
{
    jkGui_InitMenu(&jkGuiDisplay_menu, jkGui_stdBitmaps[3]);
    jkGuiDisplay_aElements[24].wstr = render_level;

    jkGuiDisplay_aElements[26].wstr = gamma_level;

    jk_snwprintf(render_level, 255, L"%.2f", jkPlayer_ssaaMultiple);
    jk_snwprintf(gamma_level, 255, L"%.2f", jkPlayer_gamma);
}

void jkGuiDisplay_Shutdown()
{
    ;
}

void jkGuiDisplay_FovDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    jkPlayer_fov = FOV_MIN + jkGuiDisplay_aElements[10].selectedTextEntry;
    
    jk_snwprintf(slider_val_text, 5, L"%u", jkPlayer_fov);
    jkGuiDisplay_aElements[11].wstr = slider_val_text;
    
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    jkGuiRend_UpdateAndDrawClickable(&jkGuiDisplay_aElements[11], menu, 1);
}

void jkGuiDisplay_FramelimitDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    jkPlayer_fpslimit = FPS_LIMIT_MIN + jkGuiDisplay_aElements[18].selectedTextEntry;
    
    if (jkPlayer_fpslimit)
        jk_snwprintf(slider_val_text_2, 5, L"%u", jkPlayer_fpslimit);
    else
        jk_snwprintf(slider_val_text_2, 5, L"None");

    jkGuiDisplay_aElements[19].wstr = slider_val_text_2;
    
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    jkGuiRend_UpdateAndDrawClickable(&jkGuiDisplay_aElements[19], menu, 1);
}

int jkGuiDisplay_Show()
{
    int v0; // esi

    jkGui_sub_412E20(&jkGuiDisplay_menu, 102, 104, 102);
    jkGuiRend_MenuSetLastElement(&jkGuiDisplay_menu, &jkGuiDisplay_aElements[7]);
    jkGuiRend_SetDisplayingStruct(&jkGuiDisplay_menu, &jkGuiDisplay_aElements[8]);
    jkGuiSetup_sub_412EF0(&jkGuiDisplay_menu, 0);

    jkGuiDisplay_aElements[10].selectedTextEntry = jkPlayer_fov - FOV_MIN;
    jkGuiDisplay_aElements[12].selectedTextEntry = jkPlayer_fovIsVertical;
    jkGuiDisplay_aElements[13].selectedTextEntry = Window_isFullscreen;
    jkGuiDisplay_aElements[14].selectedTextEntry = Window_isHiDpi;
    jkGuiDisplay_aElements[15].selectedTextEntry = jkPlayer_enableTextureFilter;
    jkGuiDisplay_aElements[16].selectedTextEntry = jkPlayer_enableOrigAspect;

    jkGuiDisplay_aElements[18].selectedTextEntry = jkPlayer_fpslimit - FPS_LIMIT_MIN;
    jkGuiDisplay_aElements[20].selectedTextEntry = jkPlayer_enableVsync;
    jkGuiDisplay_aElements[21].selectedTextEntry = jkPlayer_enableBloom;
    jkGuiDisplay_aElements[22].selectedTextEntry = jkPlayer_enableSSAO;

    jk_snwprintf(render_level, 255, L"%.2f", jkPlayer_ssaaMultiple);
    jk_snwprintf(gamma_level, 255, L"%.2f", jkPlayer_gamma);

    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiDisplay_menu);
    if ( v0 != -1 )
    {
        jkPlayer_fovIsVertical = jkGuiDisplay_aElements[12].selectedTextEntry;
        Window_SetFullscreen(jkGuiDisplay_aElements[13].selectedTextEntry);
        Window_SetHiDpi(jkGuiDisplay_aElements[14].selectedTextEntry);
        jkPlayer_enableTextureFilter = jkGuiDisplay_aElements[15].selectedTextEntry;
        jkPlayer_enableOrigAspect = jkGuiDisplay_aElements[16].selectedTextEntry;
        jkPlayer_enableVsync = jkGuiDisplay_aElements[20].selectedTextEntry;
        jkPlayer_enableBloom = jkGuiDisplay_aElements[21].selectedTextEntry;
        jkPlayer_enableSSAO = jkGuiDisplay_aElements[22].selectedTextEntry;

        char tmp[256];
        stdString_WcharToChar(tmp, render_level, 255);

        if(_sscanf(tmp, "%f", &jkPlayer_ssaaMultiple) != 1) {
            jkPlayer_ssaaMultiple = 1.0;
        }

        stdString_WcharToChar(tmp, gamma_level, 255);
        if(_sscanf(tmp, "%f", &jkPlayer_gamma) != 1) {
            jkPlayer_gamma = 1.0;
        }

        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }
    return v0;
}
