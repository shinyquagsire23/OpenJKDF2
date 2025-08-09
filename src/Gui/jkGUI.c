#include "jkGUI.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdString.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Primitives/rdVector.h"
#include "Win95/stdDisplay.h"
#include "Platform/stdControl.h"
#include "Win95/Window.h"
#include "Win95/stdGdi.h"
#include "Platform/wuRegistry.h"
#include "Win95/Windows.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUITitle.h"
#include "World/jkPlayer.h"
#include "Main/Main.h"
#include "Main/jkGame.h"
#include "Main/jkStrings.h"
#include "Cog/jkCog.h"
#include "General/stdMath.h"

#ifdef TARGET_TWL
#include <nds.h>
#endif

const char* jkGui_aBitmaps[35] = {
    "bkMain.bm",
    "bkSingle.bm",
    "bkMulti.bm",
    "bkSetup.bm",
    "bkEsc.bm",
    "bkLoading.bm",
    "bkFieldLog.bm",
    "bkDialog.bm",
    "bkEsc.bm",
    "bkForce.bm",
    "bkTally.bm",
    "bkBuildMulti.bm",
    "bkBuildLoad.bm",
    "up15.bm",
    "down15.bm",
    "check.bm",
    "objectivescheck.bm",
    "sliderThumb.bm",
    "sliderBack.bm",
    "sliderBack200.bm",
    "flOk.bm",
    "flRotLef.bm",
    "flRotRig.bm",
    "flRotUp.bm",
    "flRotDow.bm",
    "flPlus.bm",
    "flMinus.bm",
    "flTransLeft.bm",
    "flTransRight.bm",
    "flTransUp.bm",
    "flTransDown.bm",
    "flSpin.bm",
    "flReset.bm",
    "arrowLeft.bm",
    "arrowRight.bm"
};

#ifdef JKGUI_SMOL_SCREEN
#define JKGUI_NUM_FONTS (12+3)
#else
#define JKGUI_NUM_FONTS (12)
#endif

const char* jkGui_aFonts[JKGUI_NUM_FONTS] = {
#ifdef JKGUI_SMOL_SCREEN
    "msgfont.sft",
    "msgfont.sft",
#else
    "small0.sft",
    "small1.sft",
#endif
    "med0.sft",
    "med1.sft",
    "med2.sft",
    "large0.sft",
    "large1.sft",
    "large2.sft",
    "FLFont0.sft",
    "FLFont1.sft",
    "FLFont2.sft",
    "FLTitle.sft",
#ifdef JKGUI_SMOL_SCREEN
    "msgfont.sft",
    "msgfont.sft",
    "msgfont.sft",
#endif
};

static int jkGui_bInitialized;

void jkGui_InitMenu(jkGuiMenu *menu, stdBitmap *bgBitmap)
{
    if ( bgBitmap )
    {
        menu->palette = (uint8_t*)bgBitmap->palette;
        menu->texture = bgBitmap->mipSurfaces[0];
    }
    
    jkGuiElement* iter = menu->paElements;
    while ( iter->type != ELEMENT_END )
    {
#ifdef QOL_IMPROVEMENTS
        if (iter->wHintTextAlloced) {
            std_pHS->free((void*)iter->wHintTextAlloced);
        }
        if (iter->strAlloced) {
            std_pHS->free((void*)iter->strAlloced);
        }
        iter->hintText = iter->origHintText;
        iter->str = iter->origStr;
        iter->wHintTextAlloced = NULL;
        iter->strAlloced = NULL;
#endif
#ifdef JKGUI_SMOL_SCREEN
        if (!iter->bIsOrigStored) {
            iter->rectOrig = iter->rect;
            iter->bIsOrigStored = 1;
        }
        else {
            iter->rect = iter->rectOrig;
        }

        if (iter->type == ELEMENT_TEXTBUTTON || iter->type == ELEMENT_TEXT || iter->type == ELEMENT_LISTBOX) {
            iter->textType = 12;
        }
        iter->bIsSmolDirty = 1;
#endif

        if ( iter->hintText )
        {
            wchar_t* text = jkStrings_GetUniString(iter->hintText);
            if ( text ) {
                iter->wHintText = stdString_FastWCopy(text);
                iter->wHintTextAlloced = iter->wHintText;
            }
        }

        if ( !iter->type || iter->type == ELEMENT_TEXT || iter->type == ELEMENT_CHECKBOX )
        {
            if ( iter->str )
            {
                wchar_t* text = jkStrings_GetUniString(iter->str);
                if ( text ) {
                    iter->wstr = stdString_FastWCopy(text);
                    iter->strAlloced = (const char*)iter->wstr;
                }
            }
        }

        ++iter;
    }

#ifdef JKGUI_SMOL_SCREEN
    jkGui_SmolScreenFixup(menu, 1);
#endif
}

#ifdef JKGUI_SMOL_SCREEN
void jkGui_SmolScreenFixup(jkGuiMenu *menu, BOOL bForce) {
    jkGuiElement* iter = menu->paElements;
    
    while ( iter->type != ELEMENT_END )
    {
        if (!iter->bIsSmolDirty && !bForce) {
            iter++;
            continue;
        }

        int32_t dirtyWidth = iter->rect.width;
        int32_t dirtyHeight = iter->rect.height;

        iter->rect.x = ((int)(flex_t)iter->rect.x * (flex_t)0.4);
        iter->rect.y = ((int)(flex_t)iter->rect.y * (flex_t)0.4);
        iter->rect.width = ((int)(flex_t)iter->rect.width * (flex_t)0.4);
        iter->rect.height = ((int)(flex_t)iter->rect.height * (flex_t)0.4);

        if ((iter->type == ELEMENT_TEXTBUTTON || iter->type == ELEMENT_TEXT)) {
            iter->textType = 12;
            if (iter->rect.height && iter->rect.height < 11) {
                iter->rect.height = 11;
            }
        }
        if (iter->type == ELEMENT_PICBUTTON) {
            if (iter->rectOrig.width < 0) {
                iter->rect.width = dirtyWidth;
            }
            if (iter->rectOrig.height < 0) {
                iter->rect.height = dirtyHeight;
            }
        }
        iter++;
    }

    iter = menu->paElements;
    while ( iter->type != ELEMENT_END )
    {
        if (!iter->bIsSmolDirty && !bForce) {
            iter->bIsSmolDirty = 0;
            iter++;
            continue;
        }
        else {
            iter->bIsSmolDirty = 0;
        }

        iter++;
    }
}
#endif

int jkGui_MessageBeep()
{
    return jk_MessageBeep(0x30u);
}

int jkGui_Startup()
{
    char playerShortName[32];
    char tmp[128];

    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

    stdString_WcharToChar(playerShortName, jkPlayer_playerShortName, 31);
    playerShortName[31] = 0;
    wuRegistry_GetString("playerShortName", playerShortName, 32, playerShortName);
    stdString_CharToWchar(jkPlayer_playerShortName, playerShortName, 31);
    jkPlayer_playerShortName[31] = 0;

    stdPlatform_Printf("OpenJKDF2: %s playername is: %s\n", __func__, jkPlayer_playerShortName);
    for (int i = 0; i < JKGUI_NUM_FONTS; i++)
    {
        // TODO: Eviction caching for stdBitmap, rdMaterial
#if defined(TARGET_TWL) || defined(JKGUI_SMOL_SCREEN)
        int replace_lut[] = {0,1,0,1,1,2,3,4,0,1,1,2,0,1,1};
        if (/*openjkdf2_bIsLowMemoryPlatform &&*/ i >= 5) {
            jkGui_stdFonts[i] = jkGui_stdFonts[replace_lut[i]];
            continue;
        }
#endif
        stdString_snprintf(tmp, 128, "ui\\sft\\%s", jkGui_aFonts[i]);
        jkGui_stdFonts[i] = stdFont_Load(tmp, 1, 0);
        if (jkGui_stdFonts[i] == NULL) {

            stdPlatform_Printf("OpenJKDF2: %s Cannot load file %s from location %s\n", __func__, jkGui_aFonts[i], tmp);
            Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
        }
    }
#ifdef TARGET_TWL
    stdPlatform_PrintHeapStats();
#endif

    for (int i = 0; i < 35; i++)
    {
        // TODO: Eviction caching for stdBitmap, rdMaterial
#ifdef TARGET_TWL
        /*if (i >= 1 && i <= 6) {
            jkGui_stdBitmaps[i] = jkGui_stdBitmaps[0];
            continue;
        }
        if (i >= 7 && i <= 11) {
            jkGui_stdBitmaps[i] = jkGui_stdBitmaps[0];
            continue;
        }*/
#endif
        stdString_snprintf(tmp, 128, "ui\\bm\\%s", jkGui_aBitmaps[i]);
        jkGui_stdBitmaps[i] = stdBitmap_Load(tmp, 1, 0);
        if (jkGui_stdBitmaps[i] == NULL) {
            Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
        }
    }
    // TODO: Eviction caching for stdBitmap, rdMaterial
#ifdef TARGET_TWL
    stdPlatform_PrintHeapStats();
#endif

#ifdef JKGUI_SMOL_SCREEN
    stdVBuffer* texA = jkGui_stdFonts[1]->pBitmap->mipSurfaces[0];
    stdDisplay_VBufferLock(texA);
    for (int i = 0; i < texA->format.width * texA->format.height; i++) {
        if (!texA->surface_lock_alloc[i]) continue;

        // menu: E5=black, E4=dark red E0=red E1=lighter red?
        // menu: F3=gold, darker, FC=bright yellow, E6=brown
        // font: 87=outline alt 3f=outline, 68=interior 69=interior alt

        if (texA->surface_lock_alloc[i] == 0x3F) { // outline
            texA->surface_lock_alloc[i] = 0xE5;
        }
        else if (texA->surface_lock_alloc[i] == 0x87) { // outline
            texA->surface_lock_alloc[i] = 0xE6;
        }
        else if (texA->surface_lock_alloc[i] == 0x68) { // interior
            texA->surface_lock_alloc[i] = 0xFC;
        }
        else if (texA->surface_lock_alloc[i] == 0x69) { // interior
            texA->surface_lock_alloc[i] = 0xFB;
        }
        //texA->surface_lock_alloc[i] = 0xe6;
    }
    stdDisplay_VBufferUnlock(texA);

    stdVBuffer* texB = jkGui_stdFonts[0]->pBitmap->mipSurfaces[0];
    stdDisplay_VBufferLock(texB);
    for (int i = 0; i < texB->format.width * texB->format.height; i++) {
        if (!texB->surface_lock_alloc[i]) continue;

        if (texB->surface_lock_alloc[i] == 0x3F) {
            texB->surface_lock_alloc[i] = 0xE5;
        }
        else if (texB->surface_lock_alloc[i] == 0x87) {
            texB->surface_lock_alloc[i] = 0xE4;
        }
        else if (texB->surface_lock_alloc[i] == 0x68) {
            texB->surface_lock_alloc[i] = 0xE0;
        }
        else if (texB->surface_lock_alloc[i] == 0x69) {
            texB->surface_lock_alloc[i] = 0xE0;
        }
    }
    stdDisplay_VBufferUnlock(texB);
//#endif
#endif // JKGUI_SMOL_SCREEN

    Window_ShowCursorUnwindowed(Main_bWindowGUI == 0);
    jkGuiRend_SetPalette((uint8_t*)jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->palette);
    jkGui_bInitialized = 1;
    return 1;
}

void jkGui_Shutdown()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

    char playerShortName[32];

    for (int i = 0; i < JKGUI_NUM_FONTS; i++)
    {
#if defined(TARGET_TWL) || defined(JKGUI_SMOL_SCREEN)
        if (i >= 5) {
            continue;
        }
#endif
        stdFont_Free(jkGui_stdFonts[i]);
        jkGui_stdFonts[i] = NULL;
    }

    for (int i = 0; i < 35; i++)
    {
#ifdef TARGET_TWL
        /*if (i >= 1 && i <= 6) {
            continue;
        }
        if (i >= 7 && i <= 11) {
            continue;
        }*/
#endif
        stdBitmap_Free(jkGui_stdBitmaps[i]);
        jkGui_stdBitmaps[i] = NULL;
    }

    stdString_WcharToChar(playerShortName, jkPlayer_playerShortName, 31);
    playerShortName[31] = 0;
    wuRegistry_SetString("playerShortName", playerShortName);

#ifndef SDL2_RENDER
    stdDisplay_422A50();
#endif
    jkGui_bInitialized = 0;
}

int jkGui_SetModeMenu(const void *palette)
{
    signed int result; // eax
    int v2; // edi
    signed int v3; // edi
    int v4; // eax
    stdDeviceParams params; // [esp+Ch] [ebp-68h]
    render_pair mode; // [esp+20h] [ebp-54h]

    params.field_0 = 1;
    params.field_4 = 0;
    params.field_8 = 0;
    params.field_C = 1;
    params.field_10 = 1;
    mode.render_8bpp.bpp = 0;
    mode.render_8bpp.rBpp = 0x3F800000;
    mode.render_8bpp.width = Window_xSize;
    mode.render_8bpp.height = Window_ySize;
    mode.render_8bpp.rShift = 0;
    mode.render_8bpp.gShift = 0;
    mode.render_8bpp.bShift = 0;
    mode.render_8bpp.palBytes = 0;
    mode.render_rgb.bpp = 8;
    mode.render_rgb.rBpp = 0;
    mode.render_rgb.gBpp = 0;
    mode.render_rgb.bBpp = 0;
    mode.render_rgb.rShift = 0;
    mode.render_rgb.gShift = 0;
    mode.render_rgb.bShift = 0;
    mode.render_rgb.rBytes = 0;
    mode.render_rgb.gBytes = 0;
    mode.render_rgb.bBytes = 0;
    mode.field_48 = 0;
    mode.field_4C = 0;
    mode.field_50 = 0;
    ++jkGui_modesets;
    if ( jkGui_GdiMode )
        return 0;
    params.field_10 = Main_bWindowGUI == 0;
    v2 = stdDisplay_FindClosestDevice(&params);
    v3 = 1;
    if ( stdDisplay_bOpen )
    {
        if ( Video_dword_866D78 == v2 )
        {
            v3 = 0;
        }
        if ( stdDisplay_bOpen )
            stdDisplay_Close();
    }
    if ( !stdDisplay_bOpen && !stdDisplay_Open(v2) )
    {
        stdPrintf(pHS->errorPrint, ".\\Gui\\jkGUI.c", 400, "Error opening display device.\n", 0, 0, 0, 0);
        return 0;
    }

    if ( Main_bWindowGUI )
        Window_ShowCursorUnwindowed(0);
    else
        Window_ShowCursorUnwindowed(1);

    v4 = stdDisplay_FindClosestMode(&mode, Video_renderSurface, stdDisplay_numVideoModes);
    if ( !v3 && stdDisplay_bModeSet && v4 == Video_curMode && stdDisplay_bPaged == 1 || stdDisplay_SetMode(v4, palette, 1) )
    {
        jkGuiRend_Open(&Video_menuBuffer, &Video_otherBuf, 0);
        jkGui_GdiMode = 1;
        return 1;
    }
    else
    {
        stdPrintf(
            pHS->errorPrint,
            ".\\Gui\\jkGUI.c",
            426,
            "Unable to set video mode to %d x %d, %d bits-per-pixel.\n",
            mode.render_8bpp.width,
            mode.render_8bpp.height,
            mode.render_rgb.bpp,
            0);
        return 0;
    }
    return result;
}

void jkGui_SetModeGame()
{
    if ( jkGui_GdiMode )
    {
        if ( --jkGui_modesets <= 0 )
        {
            jkGuiRend_Close();
            jkGui_GdiMode = 0;
        }
    }
}

void jkGui_sub_412E20(jkGuiMenu *menu, int a2, int a3, int a4)
{
    for (int i = a2; i <= a3; i++)
    {
        jkGuiElement* element = jkGuiRend_MenuGetClickableById(menu, i);
        if ( element )
        {
#ifndef JKGUI_SMOL_SCREEN
            element->textType = 2;
#else
            element->textType = 12;
#endif
            element->type = ELEMENT_TEXTBUTTON;
        }
    }

    if ( a4 >= a2 && a4 <= a3 )
    {
        jkGuiElement* element = jkGuiRend_MenuGetClickableById(menu, a4);
        if ( element )
        {
#ifndef JKGUI_SMOL_SCREEN
            element->textType = 3;
#else
            element->textType = 13;
#endif
            element->type = ELEMENT_TEXT;
        }
    }
    menu->lastMouseOverClickable = 0;
    menu->lastMouseDownClickable = 0;
}

void jkGui_copies_string(char* out)
{
    _strncpy(jkGui_unkstr, out, 0x1Fu);
    jkGui_unkstr[31] = 0;
}

char* jkGui_sub_412EC0()
{
    return jkGui_unkstr;
}

wchar_t* jkGui_sub_412ED0()
{
    return jkGuiTitle_quicksave_related_func1(&jkCog_strings, jkGui_unkstr);
}
