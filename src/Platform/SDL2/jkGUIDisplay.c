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
#include "Platform/std3D.h"

#include "jk.h"

enum jkGuiDecisionButton_t
{
    GUI_GENERAL = 100,
    GUI_GAMEPLAY = 101,
    GUI_DISPLAY = 102,
    GUI_SOUND = 103,
    GUI_CONTROLS = 104,

    GUI_ADVANCED = 105,
};

static wchar_t render_level[256] = {0};
static wchar_t gamma_level[256] = {0};
static wchar_t hud_level[256] = {0};

static wchar_t slider_val_text[5] = {0};
static wchar_t slider_val_text_2[5] = {0};

static int slider_images[2] = {JKGUI_BM_SLIDER_BACK, JKGUI_BM_SLIDER_THUMB};

static wchar_t colordepth_text[8];

void jkGuiDisplay_FovDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
void jkGuiDisplay_FramelimitDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiDisplay_ColorDepthArrowButtonClickHandler(jkGuiElement* pElement, jkGuiMenu* pMenu, int mouseX, int mouseY, BOOL a5);

static jkGuiElement jkGuiDisplay_aElements[] = { 
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
    {ELEMENT_TEXT,         0,            0, "GUIEXT_FOV",                 3, {20, 130, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER,       0,            0, (const char*)(FOV_MAX - FOV_MIN),                    0, {10, 160, 320, 30}, 1, 0, "GUIEXT_FOV_HINT", jkGuiDisplay_FovDraw, 0, slider_images, {0}, 0},
    {ELEMENT_TEXT,         0,            0, slider_val_text,        3, {20, 190, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, "GUIEXT_FOV_VERTICAL",    0, {20, 210, 200, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_FULLSCREEN",    0, {400, 190, 200, 30}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_HIDPI",    0, {400, 250, 200, 30}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_TEXTURE_FILTERING",    0, {400, 280, 200, 30}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_SQUARE_ASPECT",    0, {20, 240, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},

    // 17
    {ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_VSYNC",    0, {400, 220, 300, 30}, 1,  0, NULL, 0, 0, 0, {0}, 0},

    // 18
    { ELEMENT_TEXT,        0,            0, "GUIEXT_SSAA_MULT",            2, {20, 320, 120, 20},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBOX,      0,            0, NULL,    100, {150, 320, 80, 20}, 1,  0, NULL, 0, 0, 0, {0}, 0},
    
    // 20
    { ELEMENT_TEXT,        0,            0, "GUIEXT_GAMMA_VAL",            2, {20, 350, 120, 20},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBOX,      0,            0, NULL,    100, {150, 350, 80, 20}, 1,  0, NULL, 0, 0, 0, {0}, 0},

    // 22
    { ELEMENT_TEXT,        0,            0, "GUIEXT_HUD_SCALE",            2, {20, 380, 100, 20},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBOX,      0,            0, NULL,    100, {150, 380, 80, 20}, 1,  0, NULL, 0, 0, 0, {0}, 0},

	// 24
	{ ELEMENT_TEXT,        0,            0, "GUIEXT_EN_COLORDEPTH",  3,  { 400, 160, 100, 25}, 1,  0, 0, 0, 0, 0, {0}, 0},
	{ ELEMENT_TEXT,        0,            0, NULL,                    3,  { 536, 165, 50, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
	{ ELEMENT_PICBUTTON, 103,            0, NULL,                    33, { 510, 160, 24, 24 }, 1, 0, NULL, NULL, jkGuiDisplay_ColorDepthArrowButtonClickHandler, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
	{ ELEMENT_PICBUTTON, 104,            0, NULL,                    34, { 584, 160, 24, 24 }, 1, 0, NULL, NULL, jkGuiDisplay_ColorDepthArrowButtonClickHandler, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },


    { ELEMENT_TEXTBUTTON,  GUI_ADVANCED, 2, "GUI_ADVANCED",               3, {220, 430, 200, 40}, 1, 0, NULL,                        0, 0, 0, {0}, 0},

    { ELEMENT_END,         0,            0, NULL,                   0, {0},                 0, 0, NULL,                        0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiDisplay_menu = { jkGuiDisplay_aElements, 0, 0xFF, 0xE1, 0x0F, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0 };

static jkGuiElement jkGuiDisplay_aElementsAdvanced[] = { 
    { ELEMENT_TEXT,        0,            0, NULL,                   3, {0, 410, 640, 20},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXT,        0,            6, "GUI_SETUP",            3, {20, 20, 600, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_GENERAL,  2, "GUI_GENERAL",          3, {20, 80, 120, 40},   1, 0, "GUI_GENERAL_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_GAMEPLAY, 2, "GUI_GAMEPLAY",         3, {140, 80, 120, 40},  1, 0, "GUI_GAMEPLAY_HINT",         0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_DISPLAY,  2, "GUI_DISPLAY",          3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_SOUND,    2, "GUI_SOUND",            3, {380, 80, 120, 40},  1, 0, "GUI_SOUND_HINT",            0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON,  GUI_CONTROLS, 2, "GUI_CONTROLS",         3, {500, 80, 120, 40},  1, 0, "GUI_CONTROLS_HINT",         0, 0, 0, {0}, 0},
    
    { ELEMENT_TEXTBUTTON,  1,            2, "GUI_OK",               3, {440, 430, 200, 40}, 1, 0, NULL,                        0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, -1,            2, "GUI_CANCEL",           3, {0, 430, 200, 40},   1, 0, NULL,                        0, 0, 0, {0}, 0},
  
    { ELEMENT_CHECKBOX,    0,            0, "GUIEXT_EN_JKGFXMOD",            0, {20, 150, 250, 40},  1, 0, "GUIEXT_EN_JKGFXMOD_HINT",          0, 0, 0, {0}, 0},
    { ELEMENT_CHECKBOX,    0,            0, "GUIEXT_EN_TEXTURE_PRECACHE",   0, {20, 190, 250, 40},  1, 0, "GUIEXT_EN_TEXTURE_PRECACHE_HINT",          0, 0, 0, {0}, 0},

	 // 11
	{ELEMENT_TEXT,         0,            0, "GUIEXT_FPS_LIMIT",                 3, {300, 150, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},
	{ELEMENT_SLIDER,       0,            0, (const char*)(FPS_LIMIT_MAX - FPS_LIMIT_MIN),                    0, {290, 180, 320, 30}, 1, 0, "GUIEXT_FPS_LIMIT_HINT", jkGuiDisplay_FramelimitDraw, 0, slider_images, {0}, 0},
	{ELEMENT_TEXT,         0,            0, slider_val_text_2,        3, {300, 210, 300, 30}, 1,  0, 0, 0, 0, 0, {0}, 0},

	// 14
	{ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_BLOOM",    0, {20, 230, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},

	// 15
	{ELEMENT_CHECKBOX,     0,            0, "GUIEXT_EN_SSAO",    0, {20, 270, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},

#ifdef SPHERE_AO
	// 16
	{ ELEMENT_CHECKBOX,     0,           0, "GUIEXT_EN_SHADOWS",    0, {20, 310, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
#endif

#ifdef DECAL_RENDERING
	// 17
	{ ELEMENT_CHECKBOX,     0,           0, "GUIEXT_EN_DECALS",    0, {20, 350, 300, 40}, 1,  0, NULL, 0, 0, 0, {0}, 0},
#endif

    { ELEMENT_END,         0,            0, NULL,                   0, {0},                 0, 0, NULL,                        0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiDisplay_menuAdvanced = { jkGuiDisplay_aElementsAdvanced, 0, 0xFF, 0xE1, 0x0F, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0 };


void jkGuiDisplay_Startup()
{
    jkGui_InitMenu(&jkGuiDisplay_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
    jkGui_InitMenu(&jkGuiDisplay_menuAdvanced, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
    jkGuiDisplay_aElements[19].wstr = render_level;

    jkGuiDisplay_aElements[21].wstr = gamma_level;

    jkGuiDisplay_aElements[23].wstr = hud_level;

	jk_snwprintf(colordepth_text, 8u, jkPlayer_enable32Bit ? L"32-bit" : L"16-bit");
	jkGuiDisplay_aElements[25].wstr = colordepth_text;

    jk_snwprintf(render_level, 255, L"%.2f", jkPlayer_ssaaMultiple);
    jk_snwprintf(gamma_level, 255, L"%.2f", jkPlayer_gamma);
    jk_snwprintf(hud_level, 255, L"%.2f", jkPlayer_hudScale);
}

void jkGuiDisplay_Shutdown()
{
    ;
}

void jkGuiDisplay_FovDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    uint32_t tmp = FOV_MIN + jkGuiDisplay_aElements[10].selectedTextEntry;
    
    jk_snwprintf(slider_val_text, 5, L"%u", tmp);
    jkGuiDisplay_aElements[11].wstr = slider_val_text;
    
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    jkGuiRend_UpdateAndDrawClickable(&jkGuiDisplay_aElements[11], menu, 1);
}

void jkGuiDisplay_FramelimitDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    uint32_t tmp = FPS_LIMIT_MIN + jkGuiDisplay_aElementsAdvanced[12].selectedTextEntry;
    
    if (tmp)
        jk_snwprintf(slider_val_text_2, 5, L"%u", tmp);
    else
        jk_snwprintf(slider_val_text_2, 5, L"None");

	jkGuiDisplay_aElementsAdvanced[13].wstr = slider_val_text_2;
    
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    jkGuiRend_UpdateAndDrawClickable(&jkGuiDisplay_aElementsAdvanced[13], menu, 1);
}

int jkGuiDisplay_ShowAdvanced()
{
    int v0; // esi

    jkGui_sub_412E20(&jkGuiDisplay_menuAdvanced, 100, 104, 100);
    jkGuiDisplay_aElementsAdvanced[9].selectedTextEntry = jkPlayer_bEnableJkgm;
    jkGuiDisplay_aElementsAdvanced[10].selectedTextEntry = jkPlayer_bEnableTexturePrecache;
    
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiDisplay_menuAdvanced, &jkGuiDisplay_aElementsAdvanced[7]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiDisplay_menuAdvanced, &jkGuiDisplay_aElementsAdvanced[8]);
    jkGuiSetup_sub_412EF0(&jkGuiDisplay_menuAdvanced, 0);

	jkGuiDisplay_aElementsAdvanced[12].selectedTextEntry = jkPlayer_fpslimit - FPS_LIMIT_MIN;

	jkGuiDisplay_aElementsAdvanced[14].selectedTextEntry = jkPlayer_enableBloom;
	jkGuiDisplay_aElementsAdvanced[15].selectedTextEntry = jkPlayer_enableSSAO;

	int id = 16;
#ifdef SPHERE_AO
	jkGuiDisplay_aElementsAdvanced[id++].selectedTextEntry = jkPlayer_enableShadows;
#endif

#ifdef DECAL_RENDERING
	jkGuiDisplay_aElementsAdvanced[id++].selectedTextEntry = jkPlayer_enableDecals;
#endif

    while (1)
    {
        v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiDisplay_menuAdvanced);

        if ( v0 != -1 )
        {
			jkPlayer_fpslimit = FPS_LIMIT_MIN + jkGuiDisplay_aElementsAdvanced[12].selectedTextEntry;

            jkPlayer_bEnableJkgm = jkGuiDisplay_aElementsAdvanced[9].selectedTextEntry;
            jkPlayer_bEnableTexturePrecache = jkGuiDisplay_aElementsAdvanced[10].selectedTextEntry;

			jkPlayer_enableBloom = jkGuiDisplay_aElementsAdvanced[14].selectedTextEntry;
			jkPlayer_enableSSAO = jkGuiDisplay_aElementsAdvanced[15].selectedTextEntry;

			id = 16;
#ifdef SPHERE_AO
			jkPlayer_enableShadows = jkGuiDisplay_aElementsAdvanced[id++].selectedTextEntry;
#endif

#ifdef DECAL_RENDERING
			jkPlayer_enableDecals = jkGuiDisplay_aElementsAdvanced[id++].selectedTextEntry;
#endif

            std3D_PurgeTextureCache();

            jkPlayer_WriteConf(jkPlayer_playerShortName);
        }
        break;
    }
    return v0;
}

int jkGuiDisplay_Show()
{
    int v0; // esi

    jkGui_sub_412E20(&jkGuiDisplay_menu, 102, 104, 102);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiDisplay_menu, &jkGuiDisplay_aElements[7]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiDisplay_menu, &jkGuiDisplay_aElements[8]);
    jkGuiSetup_sub_412EF0(&jkGuiDisplay_menu, 0);

    jkGuiDisplay_aElements[10].selectedTextEntry = jkPlayer_fov - FOV_MIN;
    jkGuiDisplay_aElements[12].selectedTextEntry = jkPlayer_fovIsVertical;
    jkGuiDisplay_aElements[13].selectedTextEntry = Window_isFullscreen;
    jkGuiDisplay_aElements[14].selectedTextEntry = Window_isHiDpi;
    jkGuiDisplay_aElements[15].selectedTextEntry = jkPlayer_enableTextureFilter;
    jkGuiDisplay_aElements[16].selectedTextEntry = jkPlayer_enableOrigAspect;

    jkGuiDisplay_aElements[17].selectedTextEntry = jkPlayer_enableVsync;
	jkGuiDisplay_aElements[25].selectedTextEntry = jkPlayer_enable32Bit;

    jk_snwprintf(render_level, 255, L"%.2f", jkPlayer_ssaaMultiple);
    jk_snwprintf(gamma_level, 255, L"%.2f", jkPlayer_gamma);
    jk_snwprintf(hud_level, 255, L"%.2f", jkPlayer_hudScale);

continue_menu:
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiDisplay_menu);
    if (v0 == GUI_ADVANCED)
    {
        jkGuiDisplay_ShowAdvanced();
        goto continue_menu;
    }
    else if ( v0 != -1 )
    {
        jkPlayer_fov = FOV_MIN + jkGuiDisplay_aElements[10].selectedTextEntry;
        jkPlayer_fovIsVertical = jkGuiDisplay_aElements[12].selectedTextEntry;
        Window_SetFullscreen(jkGuiDisplay_aElements[13].selectedTextEntry);
        Window_SetHiDpi(jkGuiDisplay_aElements[14].selectedTextEntry);
        jkPlayer_enableTextureFilter = jkGuiDisplay_aElements[15].selectedTextEntry;
        jkPlayer_enableOrigAspect = jkGuiDisplay_aElements[16].selectedTextEntry;
        jkPlayer_enableVsync = jkGuiDisplay_aElements[17].selectedTextEntry;

        char tmp[256];
        stdString_WcharToChar(tmp, render_level, 255);

        if(_sscanf(tmp, "%f", &jkPlayer_ssaaMultiple) != 1) {
            jkPlayer_ssaaMultiple = 1.0;
        }

        stdString_WcharToChar(tmp, gamma_level, 255);
        if(_sscanf(tmp, "%f", &jkPlayer_gamma) != 1) {
            jkPlayer_gamma = 1.0;
        }

        stdString_WcharToChar(tmp, hud_level, 255);
        if(_sscanf(tmp, "%f", &jkPlayer_hudScale) != 1) {
            jkPlayer_hudScale = 1.0;
        }

        if (jkPlayer_hudScale > 100.0) {
            jkPlayer_hudScale = 100.0;
        }

        jkPlayer_WriteConf(jkPlayer_playerShortName);

        // Make sure filter settings get applied
        std3D_UpdateSettings();
    }
    return v0;
}

void jkGuiDisplay_sub_4149C0(){}


int jkGuiDisplay_ColorDepthArrowButtonClickHandler(jkGuiElement* pElement, jkGuiMenu* pMenu, int mouseX, int mouseY, BOOL a5)
{
	if (pElement->hoverId == 103)
	{
		int v4 = jkPlayer_enable32Bit - 1;
		if (v4 < 0)
			v4 = 1;
		jkPlayer_enable32Bit = v4;
	}
	else if (pElement->hoverId == 104)
	{
		int v2 = jkPlayer_enable32Bit + 1;
		if (v2 > 1)
			v2 = 0;
		jkPlayer_enable32Bit = v2;
	}

	jk_snwprintf(colordepth_text, 8u, jkPlayer_enable32Bit ? L"32-bit" : L"16-bit");
	jkGuiDisplay_aElements[25].wstr = colordepth_text;
	jkGuiRend_UpdateAndDrawClickable(&jkGuiDisplay_aElements[25], pMenu, 1);

	return 0;
}