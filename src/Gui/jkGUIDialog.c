#include "jkGUIDialog.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdString.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Main/jkStrings.h"
#include "Win95/stdDisplay.h"

jkGuiElement jkGuiDialog_Ok_buttons[4] = {
    {ELEMENT_TEXT, 0, 2, 0, 3, {0x82, 0x8C, 0x186, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, 0, 3, {0x82, 0xBE, 0x186, 0x5A}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {0x118, 0x122, 0xBE, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0}
};

static jkGuiMenu jkGuiDialog_Ok_menu  = {jkGuiDialog_Ok_buttons, 0xFFFFFFFF, 0xE1, 0xFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

jkGuiElement jkGuiDialog_OkCancel_buttons[5] = {
    {ELEMENT_TEXT, 0, 2, 0, 3, {0x82, 0x8C, 0x186, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, 0, 3, {0x82, 0xBE, 0x186, 0x5A}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {0x14A, 0x122, 0xBE, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 0xFFFFFFFF, 2, "GUI_CANCEL", 3, {0x82, 0x122, 0xBE, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0}
};

static jkGuiMenu jkGuiDialog_OkCancel_menu  = {jkGuiDialog_OkCancel_buttons, 0xFFFFFFFF, 0xE1, 0xFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiDialog_Startup()
{
    jkGui_InitMenu(&jkGuiDialog_OkCancel_menu, 0);
    jkGui_InitMenu(&jkGuiDialog_Ok_menu, 0);
}

void jkGuiDialog_Shutdown()
{
    ;
}

stdVBuffer *jkGuiDialog_sub_416900()
{
    stdVBuffer *v0; // eax
    stdVBuffer *v1; // esi

    v0 = stdDisplay_VBufferNew(&(*jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->mipSurfaces)->format, 0, 0, Video_menuBuffer.palette);
    v1 = v0;
    if ( v0 )
    {
        stdDisplay_VBufferCopy(v0, &Video_menuBuffer, 0, 0, 0, 0);
        stdDisplay_VBufferCopy(v1, *jkGui_stdBitmaps[JKGUI_BM_BK_DIALOG]->mipSurfaces, jkGui_stdBitmaps[JKGUI_BM_BK_DIALOG]->xPos, jkGui_stdBitmaps[JKGUI_BM_BK_DIALOG]->yPos, 0, 0);
    }
    return v1;
}

int jkGuiDialog_OkCancelDialog(wchar_t *stringA, wchar_t *stringB)
{
    int v2; // edi
    int v5; // esi

    v2 = 0;
    if ( !jkGui_GdiMode )
    {
        jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->palette);
        v2 = 1;
    }
    jkGuiDialog_OkCancel_buttons[0].wstr = stringA;
    jkGuiDialog_OkCancel_buttons[1].wstr = stringB;
    jkGuiDialog_OkCancel_menu.texture = jkGuiDialog_sub_416900();
    jkGuiDialog_OkCancel_menu.palette = 0;
    jkGuiDialog_OkCancel_buttons[2].wstr = jkStrings_GetUniStringWithFallback("GUI_OK");
    jkGuiDialog_OkCancel_buttons[3].bIsVisible = 1;
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiDialog_OkCancel_menu, &jkGuiDialog_OkCancel_buttons[2]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiDialog_OkCancel_menu, &jkGuiDialog_OkCancel_buttons[3]);
    v5 = jkGuiRend_DisplayAndReturnClicked(&jkGuiDialog_OkCancel_menu);
    stdDisplay_VBufferFree(jkGuiDialog_OkCancel_menu.texture);
    jkGuiDialog_OkCancel_menu.texture = 0;
    if ( v2 )
        jkGui_SetModeGame();
    return v5 == 1;
}

void jkGuiDialog_ErrorDialog(wchar_t *stringA, wchar_t *stringB)
{
    int v2; // edi

    v2 = 0;
    if ( !jkGui_GdiMode )
    {
        jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->palette);
        v2 = 1;
    }
    jkGuiDialog_Ok_buttons[0].wstr = stringA;
    jkGuiDialog_Ok_buttons[1].wstr = stringB;
    jkGuiDialog_Ok_menu.texture = jkGuiDialog_sub_416900();
    jkGuiDialog_Ok_menu.palette = 0;
    jkGuiDialog_Ok_buttons[2].wstr = jkStrings_GetUniStringWithFallback("GUI_OK");
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiDialog_Ok_menu, &jkGuiDialog_Ok_buttons[2]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiDialog_Ok_menu, &jkGuiDialog_Ok_buttons[2]);
    jkGuiRend_DisplayAndReturnClicked(&jkGuiDialog_Ok_menu);
    stdDisplay_VBufferFree(jkGuiDialog_Ok_menu.texture);
    jkGuiDialog_Ok_menu.texture = 0;
    if ( v2 )
        jkGui_SetModeGame();
}

int jkGuiDialog_YesNoDialog(wchar_t *stringA, wchar_t *stringB)
{
    int v2; // edi
    int v5; // esi

    v2 = 0;
    if ( !jkGui_GdiMode )
    {
        jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->palette);
        v2 = 1;
    }
    jkGuiDialog_OkCancel_buttons[0].wstr = stringA;
    jkGuiDialog_OkCancel_buttons[1].wstr = stringB;
    jkGuiDialog_OkCancel_menu.texture = jkGuiDialog_sub_416900();
    jkGuiDialog_OkCancel_menu.palette = 0;
    jkGuiDialog_OkCancel_buttons[2].wstr = jkStrings_GetUniStringWithFallback("GUI_YES");
    jkGuiDialog_OkCancel_buttons[3].wstr = jkStrings_GetUniStringWithFallback("GUI_NO");
    jkGuiDialog_OkCancel_buttons[3].bIsVisible = 1;
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiDialog_OkCancel_menu, &jkGuiDialog_OkCancel_buttons[2]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiDialog_OkCancel_menu, &jkGuiDialog_OkCancel_buttons[3]);
    v5 = jkGuiRend_DisplayAndReturnClicked(&jkGuiDialog_OkCancel_menu);
    stdDisplay_VBufferFree(jkGuiDialog_OkCancel_menu.texture);
    jkGuiDialog_OkCancel_menu.texture = 0;
    if ( v2 )
        jkGui_SetModeGame();
    return v5 == 1;
}
