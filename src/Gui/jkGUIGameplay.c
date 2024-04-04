#include "jkGUIGameplay.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdStrTable.h"
#include "General/stdFileUtil.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "globals.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUISetup.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"
#include "types_enums.h"

static wchar_t slider_val_text[5] = {0};
static int slider_images[2] = {JKGUI_BM_SLIDER_BACK_200, JKGUI_BM_SLIDER_THUMB};

void jkGuiGameplay_ScaleDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

static jkGuiElement jkGuiGameplay_buttons[44] = {
    {ELEMENT_TEXT, 0, 0, 0, 3, {0, 410, 640, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 6, "GUI_SETUP", 3, {20, 20, 600, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 100, 2, "GUI_GENERAL", 3, {20, 80, 120, 40},  1, 0, "GUI_GENERAL_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 101, 2, "GUI_GAMEPLAY", 3, {140, 80, 120, 40}, 1, 0, "GUI_GAMEPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 102, 2, "GUI_DISPLAY", 3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 103, 2, "GUI_SOUND", 3, {380, 80, 120, 40}, 1, 0, "GUI_SOUND_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 104, 2, "GUI_CONTROLS", 3, {500, 80, 120, 40}, 1, 0, "GUI_CONTROLS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_AUTOAIM", 0, {30, 170, 270, 20}, 1, 0, "GUI_AUTOAIM_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_CROSSHAIR", 0, {30, 200, 270, 20}, 1, 0, "GUI_CROSSHAIR_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_SABERCAM", 0, {30, 230, 270, 20}, 1, 0, "GUI_SABERCAM_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_SINGLE", 2, {310, 130, 50, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_MP", 2, {360, 130, 50, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_AUTOPICKUP", 2, {400, 170, 240, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_NODANGER", 2, {420, 190, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_NOWEAKER", 2, {420, 210, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_KEEPSABER", 2, {420, 230, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_AUTOSWITCH", 2, {400, 270, 240, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_NODANGER", 2, {420, 290, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_AUTORELOAD", 2, {400, 330, 240, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_KEEPSABER", 2, {420, 350, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 170, 40, 20}, 1, 0, "GUI_AUTOPICKUP_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 190, 40, 20}, 1, 0, "GUI_NODANGER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 210, 40, 20}, 1, 0, "GUI_NOWEAKER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 230, 40, 20}, 1, 0, "GUI_KEEPSABER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 270, 40, 20}, 1, 0, "GUI_AUTOSWITCH_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 290, 40, 20}, 1, 0, "GUI_NODANGER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 330, 40, 20}, 1, 0, "GUI_AUTORELOAD_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {320, 350, 40, 20}, 1, 0, "GUI_KEEPSABER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 170, 40, 20}, 1, 0, "GUI_AUTOPICKUP_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 190, 40, 20}, 1, 0, "GUI_NODANGER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 210, 40, 20}, 1, 0, "GUI_NOWEAKER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 230, 40, 20}, 1, 0, "GUI_KEEPSABER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 270, 40, 20}, 1, 0, "GUI_AUTOSWITCH_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 290, 40, 20}, 1, 0, "GUI_NODANGER_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 330, 40, 20}, 1, 0, "GUI_AUTOSWITCH_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, 0, 0, {360, 350, 40, 20}, 1, 0, "GUI_KEEPSABER_HINT", 0, 0, 0, {0}, 0},

    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {440, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 0XFFFFFFFF, 2, "GUI_CANCEL", 3, {0, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},

#ifdef QOL_IMPROVEMENTS
    {ELEMENT_CHECKBOX, 0, 0, "GUIEXT_SHOW_SABER_CROSSHAIR", 0, {30, 260, 270, 20}, 1, 0, "GUIEXT_SHOW_SABER_CROSSHAIR_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUIEXT_SHOW_FIST_CROSSHAIR", 0, {30, 290, 270, 20}, 1, 0, "GUIEXT_SHOW_FIST_CROSSHAIR_HINT", 0, 0, 0, {0}, 0},
    
    // 40
    {ELEMENT_SLIDER, 0, 0, (const char*)10, 50, { 30, 345, 235, 30 }, 1, 0, "GUIEXT_CROSSHAIR_SCALE_HINT", jkGuiGameplay_ScaleDraw, 0, slider_images, {0}, 0},
    {ELEMENT_TEXT,         0,            0, "GUIEXT_CROSSHAIR_SCALE",                 3, {30, 345-25, 235, 20}, 1,  0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT,         0,            0, slider_val_text,        3, {30, 345+30, 235, 20}, 1,  0, 0, 0, 0, 0, {0}, 0},
#endif /* QOL_IMPROVEMENTS */
 
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiGameplay_menu = {jkGuiGameplay_buttons, 0, 0xFF, 0xE1, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiGameplay_Startup()
{
    jkGui_InitMenu(&jkGuiGameplay_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiGameplay_Shutdown()
{
    ;
}

#ifdef QOL_IMPROVEMENTS
void jkGuiGameplay_ScaleDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    float tmp = ((float)jkGuiGameplay_buttons[40].selectedTextEntry)*0.2f;
    
    jk_snwprintf(slider_val_text, 5, L"%f", tmp);
    jkGuiGameplay_buttons[42].wstr = slider_val_text;
    
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    jkGuiRend_UpdateAndDrawClickable(&jkGuiGameplay_buttons[42], menu, 1);
}
#endif // QOL_IMPROVEMENTS

int jkGuiGameplay_Show()
{
    int v0; // esi

    jkGui_sub_412E20(&jkGuiGameplay_menu, 100, 104, 101);
    jkGuiGameplay_buttons[20].selectedTextEntry = sithWeapon_bAutoPickup & 1;
    jkGuiGameplay_buttons[21].selectedTextEntry = sithWeapon_bAutoPickup & 2;
    jkGuiGameplay_buttons[23].selectedTextEntry = sithWeapon_bAutoPickup & 8;
    jkGuiGameplay_buttons[25].selectedTextEntry = sithWeapon_bAutoSwitch & 2;
    jkGuiGameplay_buttons[22].selectedTextEntry = sithWeapon_bAutoPickup & 4;
    jkGuiGameplay_buttons[27].selectedTextEntry = sithWeapon_bAutoReload & 2;
    jkGuiGameplay_buttons[24].selectedTextEntry = sithWeapon_bAutoSwitch & 1;
    jkGuiGameplay_buttons[26].selectedTextEntry = sithWeapon_bAutoReload & 1;
    jkGuiGameplay_buttons[28].selectedTextEntry = sithWeapon_bMultiAutoPickup & 1;
    jkGuiGameplay_buttons[31].selectedTextEntry = sithWeapon_bMultiAutoPickup & 8;
    jkGuiGameplay_buttons[29].selectedTextEntry = sithWeapon_bMultiAutoPickup & 2;
    jkGuiGameplay_buttons[33].selectedTextEntry = sithWeapon_bMultiplayerAutoSwitch & 2;
    jkGuiGameplay_buttons[30].selectedTextEntry = sithWeapon_bMultiAutoPickup & 4;
    jkGuiGameplay_buttons[35].selectedTextEntry = sithWeapon_bMultiAutoReload & 2;
    jkGuiGameplay_buttons[32].selectedTextEntry = sithWeapon_bMultiplayerAutoSwitch & 1;
    jkGuiGameplay_buttons[34].selectedTextEntry = sithWeapon_bMultiAutoReload & 1;
    jkGuiGameplay_buttons[7].selectedTextEntry = sithWeapon_bAutoAim & 1;
    jkGuiGameplay_buttons[8].selectedTextEntry = jkPlayer_setCrosshair;
    jkGuiGameplay_buttons[9].selectedTextEntry = jkPlayer_setSaberCam;

#ifdef QOL_IMPROVEMENTS
    jkGuiGameplay_buttons[38].selectedTextEntry = jkPlayer_setCrosshairOnLightsaber;
    jkGuiGameplay_buttons[39].selectedTextEntry = jkPlayer_setCrosshairOnFist;
    jkGuiGameplay_buttons[40].selectedTextEntry = jkPlayer_crosshairScale * 5;
#endif /* QOL_IMPROVEMENTS */
    

    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiGameplay_menu, &jkGuiGameplay_buttons[36]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiGameplay_menu, &jkGuiGameplay_buttons[37]);
    jkGuiSetup_sub_412EF0(&jkGuiGameplay_menu, 0);
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiGameplay_menu);
    if ( v0 != -1 )
    {
        sithWeapon_bAutoPickup = jkGuiGameplay_buttons[20].selectedTextEntry != 0;
        if ( jkGuiGameplay_buttons[21].selectedTextEntry )
            sithWeapon_bAutoPickup |= 2u;
        if ( jkGuiGameplay_buttons[22].selectedTextEntry )
            sithWeapon_bAutoPickup |= 4u;
        if ( jkGuiGameplay_buttons[23].selectedTextEntry )
            sithWeapon_bAutoPickup |= 8u;
        sithWeapon_bAutoSwitch = jkGuiGameplay_buttons[24].selectedTextEntry != 0;
        if ( jkGuiGameplay_buttons[25].selectedTextEntry )
            sithWeapon_bAutoSwitch |= 2u;
        sithWeapon_bAutoReload = jkGuiGameplay_buttons[26].selectedTextEntry != 0;
        if ( jkGuiGameplay_buttons[27].selectedTextEntry )
            sithWeapon_bAutoReload |= 2u;
        sithWeapon_bMultiAutoPickup = jkGuiGameplay_buttons[28].selectedTextEntry != 0;
        if ( jkGuiGameplay_buttons[29].selectedTextEntry )
            sithWeapon_bMultiAutoPickup |= 2u;
        if ( jkGuiGameplay_buttons[30].selectedTextEntry )
            sithWeapon_bMultiAutoPickup |= 4u;
        if ( jkGuiGameplay_buttons[31].selectedTextEntry )
            sithWeapon_bMultiAutoPickup |= 8u;
        sithWeapon_bMultiplayerAutoSwitch = jkGuiGameplay_buttons[32].selectedTextEntry != 0;
        if ( jkGuiGameplay_buttons[33].selectedTextEntry )
            sithWeapon_bMultiplayerAutoSwitch |= 2u;
        sithWeapon_bMultiAutoReload = jkGuiGameplay_buttons[34].selectedTextEntry != 0;
        if ( jkGuiGameplay_buttons[35].selectedTextEntry )
            sithWeapon_bMultiAutoReload |= 2u;
        sithWeapon_bAutoAim = jkGuiGameplay_buttons[7].selectedTextEntry != 0;
        jkPlayer_setCrosshair = jkGuiGameplay_buttons[8].selectedTextEntry;
        jkPlayer_setSaberCam = jkGuiGameplay_buttons[9].selectedTextEntry;

#ifdef QOL_IMPROVEMENTS
        jkPlayer_setCrosshairOnLightsaber = jkGuiGameplay_buttons[38].selectedTextEntry;
        jkPlayer_setCrosshairOnFist = jkGuiGameplay_buttons[39].selectedTextEntry;
        jkPlayer_crosshairScale = ((float)jkGuiGameplay_buttons[40].selectedTextEntry)*0.2f;
#endif /* QOL_IMPROVEMENTS */
    
        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }
    return v0;
}
