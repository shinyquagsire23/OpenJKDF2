#include "jkGUISound.h"

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
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIDialog.h"
#include "Main/jkStrings.h"
#include "Devices/sithSoundMixer.h"
#include "Platform/wuRegistry.h"
#include "Win95/stdSound.h"

// Added
float jkGuiSound_cutsceneVolume = 1.0;

static int slider_images[2] = {JKGUI_BM_SLIDER_BACK, JKGUI_BM_SLIDER_THUMB};

static jkGuiElement jkGuiSound_elements[25] = {
    {ELEMENT_TEXT, 0, 0, 0, 3, {0, 410, 640, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 6, "GUI_SETUP", 3, {20, 20, 600, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 100, 2, "GUI_GENERAL", 3, {20, 80, 120, 40},  1, 0, "GUI_GENERAL_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 101, 2, "GUI_GAMEPLAY", 3, {140, 80, 120, 40}, 1, 0, "GUI_GAMEPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 102, 2, "GUI_DISPLAY", 3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 103, 2, "GUI_SOUND", 3, {380, 80, 120, 40}, 1, 0, "GUI_SOUND_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 104, 2, "GUI_CONTROLS", 3, {500, 80, 120, 40}, 1, 0, "GUI_CONTROLS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_CHECKBOX, 0, 0, "GUI_ENABLE3DSOUND", 0, {30, 150, 240, 40}, 1, 0, "GUI_ENABLE3DSOUND_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_LOWRESSOUNDS", 2, {30, 270, 240, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_MUSICVOLUME", 3, {340, 140, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER, 0, 0, (const char*)100, 0, {300, 160, 320, 30}, 1, 0, "GUI_MUSICVOLUME_HINT", 0, 0, slider_images, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_OFF", 2, {300, 190, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_MAX", 2, {580, 190, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_SFXVOLUME", 3, {340, 220, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER, 0, 0, (const char*)100, 0, {300, 245, 320, 30}, 1, 0, "GUI_SFXVOLUME_HINT", 0, 0, slider_images, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_OFF", 2, {300, 280, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_MAX", 2, {580, 280, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
#ifdef SDL2_RENDER
    {ELEMENT_TEXT, 0, 0, L"Cutscene Volume", 3, {340, 310, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER, 0, 0, (const char*)100, 0, {300, 335, 320, 30}, 1, 0, L"Set the volume of audio during cutscenes.", 0, 0, slider_images, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_OFF", 2, {310, 370, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, L"", 2, {450, 370, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_MAX", 2, {590, 370, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
#else
    {ELEMENT_TEXT, 0, 0, "GUI_DIGICHANNELS", 3, {340, 310, 220, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_SLIDER, 0, 0, (const char*)16, 0, {300, 335, 320, 30}, 1, 0, "GUI_DIGICHANNELS_HINT", 0, 0, slider_1, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_8", 2, {310, 370, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_16", 2, {450, 370, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_24", 2, {590, 370, 40, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
#endif
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {440, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 0XFFFFFFFF, 2, "GUI_CANCEL", 3, {0, 430, 200, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0}
};

static jkGuiMenu jkGuiSound_menu = {jkGuiSound_elements, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiSound_Startup()
{
    jkGui_InitMenu(&jkGuiSound_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);

    jkGuiSound_musicVolume = wuRegistry_GetFloat("musicVolume", jkGuiSound_musicVolume);
    jkGuiSound_sfxVolume = wuRegistry_GetFloat("sfxVolume", jkGuiSound_sfxVolume);
    jkGuiSound_numChannels = wuRegistry_GetInt("numChannels", jkGuiSound_numChannels);
    jkGuiSound_bLowResSound = wuRegistry_GetBool("bLowRes", jkGuiSound_bLowResSound);
    jkGuiSound_b3DSound = wuRegistry_GetBool("b3DSound", jkGuiSound_b3DSound);

    // Added
    jkGuiSound_cutsceneVolume = wuRegistry_GetFloat("cutsceneVolume", jkGuiSound_cutsceneVolume);

    jkGuiSound_b3DSound_2 = jkGuiSound_b3DSound;
    sithSoundMixer_UpdateMusicVolume(jkGuiSound_musicVolume); // TODO

    stdSound_SetMenuVolume(jkGuiSound_sfxVolume);
}

void jkGuiSound_Shutdown()
{
    wuRegistry_SaveFloat("musicVolume", jkGuiSound_musicVolume);
    wuRegistry_SaveFloat("sfxVolume", jkGuiSound_sfxVolume);
    wuRegistry_SaveInt("numChannels", jkGuiSound_numChannels);

    // Added
    wuRegistry_SaveFloat("cutsceneVolume", jkGuiSound_cutsceneVolume);

    // Added: clean reset
    jkGuiSound_cutsceneVolume = 1.0;
}

int jkGuiSound_Show()
{
    wchar_t *v0; // eax
    int v1; // esi
    wchar_t *v2; // eax
    wchar_t *v4; // [esp-4h] [ebp-8h]

    jkGui_sub_412E20(&jkGuiSound_menu, 102, 107, 103);
    jkGuiSound_elements[7].selectedTextEntry = jkGuiSound_b3DSound_2;
    jkGuiSound_elements[7].bIsVisible = jkGuiSound_b3DSound_3 != 0;
    jkGuiSound_elements[10].selectedTextEntry = (__int64)(jkGuiSound_musicVolume * 100.0);
    jkGuiSound_elements[14].selectedTextEntry = (__int64)(jkGuiSound_sfxVolume * 100.0);
#ifdef SDL2_RENDER
    jkGuiSound_elements[18].selectedTextEntry = (__int64)(jkGuiSound_cutsceneVolume * 100.0);
    jkGuiSound_numChannels = 256;
#else
    jkGuiSound_elements[18].selectedTextEntry = jkGuiSound_numChannels - 8;
#endif

    // START MOTS removed:
    if ( jkGuiSound_bLowResSound )
        v0 = jkStrings_GetUniStringWithFallback("GUI_LOWRESSOUNDS");
    else
        v0 = jkStrings_GetUniStringWithFallback("GUI_HIGHRESSOUNDS");

    jkGuiSound_elements[8].wstr = v0;
    // END MOTS removed

    jkGuiSetup_sub_412EF0(&jkGuiSound_menu, 0);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSound_menu, &jkGuiSound_elements[22]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSound_menu, &jkGuiSound_elements[23]);
    v1 = jkGuiRend_DisplayAndReturnClicked(&jkGuiSound_menu);
    if ( v1 != -1 )
    {
        jkGuiSound_musicVolume = (double)jkGuiSound_elements[10].selectedTextEntry * 0.01;
        jkGuiSound_sfxVolume = (double)jkGuiSound_elements[14].selectedTextEntry * 0.01;
        
#ifdef SDL2_RENDER
        jkGuiSound_cutsceneVolume = (double)jkGuiSound_elements[18].selectedTextEntry * 0.01;
        jkGuiSound_numChannels = 256;
        jkGuiSound_b3DSound_2 = jkGuiSound_elements[7].selectedTextEntry;
        jkGuiSound_b3DSound = jkGuiSound_b3DSound_2;
        wuRegistry_SaveBool("b3DSound", (HKEY)jkGuiSound_elements[7].selectedTextEntry);

        wuRegistry_SaveFloat("musicVolume", jkGuiSound_musicVolume);
        wuRegistry_SaveFloat("sfxVolume", jkGuiSound_sfxVolume);
        wuRegistry_SaveInt("numChannels", jkGuiSound_numChannels);
        wuRegistry_SaveFloat("cutsceneVolume", jkGuiSound_cutsceneVolume);
#else
        jkGuiSound_numChannels = jkGuiSound_elements[18].selectedTextEntry + 8;
        if ( jkGuiSound_b3DSound_3 && jkGuiSound_elements[7].selectedTextEntry != jkGuiSound_b3DSound_2 )
        {
            v4 = jkStrings_GetUniStringWithFallback("GUISOUND_MUSTRESTART");
            v2 = jkStrings_GetUniStringWithFallback("GUISOUND_WARNING");
            jkGuiDialog_ErrorDialog(v2, v4);
            jkGuiSound_b3DSound_2 = jkGuiSound_elements[7].selectedTextEntry;
            wuRegistry_SaveBool("b3DSound", (HKEY)jkGuiSound_elements[7].selectedTextEntry);
        }
#endif
        sithSoundMixer_UpdateMusicVolume(jkGuiSound_musicVolume);
        stdSound_SetMenuVolume(jkGuiSound_sfxVolume);
    }

    return v1;
}
