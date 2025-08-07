#include "jkGUIRend.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Devices/sithSound.h"
#include "Primitives/rdVector.h"
#include "Win95/stdDisplay.h"
#include "Platform/stdControl.h"
#include "Win95/Window.h"
#include "Win95/stdGdi.h"
#include "Win95/stdSound.h"
#include "General/stdString.h"
#include "Primitives/rdRect.h"
#include "Gui/jkGUI.h"
#include "stdPlatform.h"
#include "jk.h"
#include "types.h"

#include <math.h>

static char *jkGuiRend_LoadedSounds[4] = {0};
static uint8_t jkGuiRend_palette[0x300] = {0};
static WindowDrawHandler_t jkGuiRend_idk2 = 0;
static WindowDrawHandler_t jkGuiRend_idk = 0;
static stdSound_buffer_t* jkGuiRend_DsoundHandles[4] = {0};
static jkGuiMenu *jkGuiRend_activeMenu = NULL;
static stdVBuffer* jkGuiRend_menuBuffer = NULL;
static stdVBuffer *jkGuiRend_texture_dword_8561E8 = NULL;

int32_t jkGuiRend_thing_five = 0;
int32_t jkGuiRend_thing_four = 0;
static int32_t jkGuiRend_bIsSurfaceValid = 0;
static int32_t jkGuiRend_bInitted = 0;
static int32_t jkGuiRend_bOpen = 0;
static int32_t jkGuiRend_HandlerIsSet = 0;
static int32_t jkGuiRend_fillColor = 0;
static int32_t jkGuiRend_paletteChecksum = 0;
static int32_t jkGuiRend_dword_85620C = 0;
static int32_t jkGuiRend_lastKeyScancode = 0;
static int32_t jkGuiRend_mouseX = 0;
static int32_t jkGuiRend_mouseY = 0;
static int32_t jkGuiRend_bShiftDown = 0;
static int32_t jkGuiRend_mouseXLatest = 0;
static int32_t jkGuiRend_mouseYLatest = 0;
static uint32_t jkGuiRend_mouseLatestMs = 0;
static HCURSOR jkGuiRend_hCursor = 0;

static int32_t jkGuiRend_CursorVisible = 1;
static jkGuiElementHandlers jkGuiRend_elementHandlers[8] = 
{
    {jkGuiRend_TextButtonEventHandler, jkGuiRend_TextButtonDraw, jkGuiRend_PlayClickSound},
    {jkGuiRend_PicButtonEventHandler, jkGuiRend_PicButtonDraw, jkGuiRend_PlayClickSound},
    {NULL, jkGuiRend_TextDraw, NULL},
    {NULL, jkGuiRend_CheckBoxDraw, jkGuiRend_DrawClickableAndUpdatebool},
    {jkGuiRend_ListBoxEventHandler, jkGuiRend_ListBoxDraw, jkGuiRend_ClickSound},
    {jkGuiRend_TextBoxEventHandler, jkGuiRend_TextBoxDraw, NULL},
    {jkGuiRend_SliderEventHandler, jkGuiRend_SliderDraw, NULL},
    {NULL, NULL, NULL},
};

void jkGuiRend_CopyVBuffer(jkGuiMenu *menu, rdRect *rect)
{
    if ( g_app_suspended && !jkGuiRend_bIsSurfaceValid )
    {
        if ( menu->texture )
            stdDisplay_VBufferCopy(jkGuiRend_menuBuffer, menu->texture, rect->x, rect->y, rect, 0);
    }
}

void jkGuiRend_SetPalette(uint8_t* pal)
{
    if (!pal) return; // Added

    _memcpy(jkGuiRend_palette, pal, 0x300); // TODO sizeof(jkGuiRend_palette)
}

void jkGuiRend_DrawRect(stdVBuffer *vbuf, rdRect *rect, int16_t color)
{
    int32_t v12; // edx
    int32_t v14; // edi
    int32_t v20; // ebx
    int32_t v21; // ebp
    char *v22; // ecx
    int32_t v23; // edi
    int32_t v24; // esi
    int32_t v26; // ecx
    int32_t v27; // edi
    int32_t v28; // ecx
    __int16 *v29; // esi
    int32_t v30; // edx
    __int16 *v31; // ecx
    int32_t v32; // edi
    char *v33; // ecx
    int32_t v34; // edx
    int32_t v35; // ebx
    int32_t v36; // [esp+10h] [ebp-8h]

    if ( !g_app_suspended || jkGuiRend_bIsSurfaceValid )
        return;

    int32_t x = rect->x;
    if ( rect->x < 0 )
    {
        int32_t w = rect->width;
        rect->x = 0;
        rect->width = x + w;
    }
    int32_t y = rect->y;
    if ( y < 0 )
    {
        int32_t h = rect->height;
        rect->y = 0;
        rect->height = y + h;
    }
    // Added: Just don't draw the rect if OOB
    if (rect->x > vbuf->format.width || rect->y > vbuf->format.height) {
        return;
    }

    if ( rect->width + rect->x > vbuf->format.width )
        rect->width = vbuf->format.width - rect->x;
    if ( rect->height + rect->y > vbuf->format.height )
        rect->height = vbuf->format.height - rect->y;

    if (!stdDisplay_VBufferLock(vbuf))
        return;

    v36 = rect->y * vbuf->format.width_in_pixels;
    v12 = rect->y + rect->height;
    v14 = vbuf->format.width_in_pixels * (v12 - 1);
    if ( vbuf->format.format.bpp == 8 )
    {
        if ( rect->x < rect->x + rect->width )
        {
            v21 = v36 - v14;
            v22 = &vbuf->surface_lock_alloc[rect->x + v14];
            v23 = rect->width;
            do
            {
                v22[v21] = color;
                *v22++ = color;
                --v23;
            }
            while ( v23 );
        }
    }
    else
    {
        if ( vbuf->format.format.bpp != 16 )
            goto LABEL_22;
        if ( rect->x < rect->x + rect->width )
        {
            int16_t* v18 = (int16_t *)&vbuf->surface_lock_alloc[2 * (rect->x + v14)];
            int16_t* v19 = (int16_t *)&vbuf->surface_lock_alloc[2 * (rect->x + v36)];
            v20 = rect->width;
            do
            {
                *v19 = color;
                *v18 = color;
                ++v19;
                ++v18;
                --v20;
            }
            while ( v20 );
        }
    }
LABEL_22:
    v24 = rect->x + rect->width - 1;
    if ( vbuf->format.format.bpp == 8 )
    {
        if ( rect->y < v12 )
        {
            v32 = rect->x - v24;
            v33 = &vbuf->surface_lock_alloc[rect->y * vbuf->format.width_in_pixels + v24];
            v34 = v12 - rect->y;
            do
            {
                v35 = vbuf->format.width_in_pixels;
                v33[v32] = color;
                *v33 = color;
                v33 += v35;
                --v34;
            }
            while ( v34 );
        }
    }
    else if ( vbuf->format.format.bpp == 16 )
    {
        uint16_t* as16Bit = (uint16_t*)vbuf->surface_lock_alloc;
        if ( rect->y < v12 )
        {
            v26 = vbuf->format.width_in_pixels;
            v27 = 2 * v26;
            v28 = rect->y * v26;
            v29 = (__int16 *)&as16Bit[v28 + v24];
            v30 = v12 - rect->y;
            v31 = (__int16 *)&as16Bit[v28 + rect->x];
            do
            {
                *v31 = color;
                *v29 = color;
                v31 = (__int16 *)((char *)v31 + v27);
                v29 = (__int16 *)((char *)v29 + v27);
                --v30;
            }
            while ( v30 );
            stdDisplay_VBufferUnlock(vbuf);
            return;
        }
    }

    stdDisplay_VBufferUnlock(vbuf);
}

void jkGuiRend_UpdateDrawMenu(jkGuiMenu *menu)
{
    if (!g_app_suspended || jkGuiRend_bIsSurfaceValid)
        return;

    int32_t idx = menu->clickableIdxIdk;
    if ( idx >= 0 )
    {
        jkGuiElement* clickable = menu->lastMouseOverClickable;
        if ( clickable && clickable->hintText && clickable->bIsVisible && !clickable->enableHover )
            menu->paElements[idx].str = clickable->hintText;
        else
            menu->paElements[idx].str = 0;
        jkGuiRend_UpdateAndDrawClickable(&menu->paElements[menu->clickableIdxIdk], menu, 1);
    }
}

void jkGuiRend_Paint(jkGuiMenu *menu)
{

    int32_t ret;
    
    jkGuiElement* lastFocused = menu->focusedElement;
    jkGuiElement* lastDown = menu->lastMouseDownClickable;

    if (!g_app_suspended || jkGuiRend_bIsSurfaceValid)
        return;
    
    stdControl_ShowCursor(0);
    stdDisplay_SetMasterPalette(jkGuiRend_palette);

#ifndef TARGET_TWL
    if ( menu->texture )
        stdDisplay_VBufferCopy(jkGuiRend_menuBuffer, menu->texture, 0, 0, 0, 0);
#endif

    jkGuiElement* clickable = &menu->paElements[0];
    int32_t clickableIdx = 0;
    while ( clickable->type != ELEMENT_END )
    {
        jkGuiRend_UpdateAndDrawClickable(clickable, menu, 0);
        clickable = &menu->paElements[++clickableIdx];
    }

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    menu->focusedElement = lastFocused;
    menu->lastMouseDownClickable = lastDown;
#endif
    
    jkGuiRend_FlipAndDraw(menu, 0);

    jkGuiRend_UpdateCursor();

}

void jkGuiRend_ElementSetClickShortcutScancode(jkGuiElement *element, int32_t scancode)
{
    element->clickShortcutScancode = scancode;
}

void jkGuiRend_MenuSetReturnKeyShortcutElement(jkGuiMenu *menu, jkGuiElement *element)
{
    menu->pReturnKeyShortcutElement = element;
}

void jkGuiRend_MenuSetEscapeKeyShortcutElement(jkGuiMenu *menu, jkGuiElement *element)
{
    menu->pEscapeKeyShortcutElement = element;
}

int32_t jkGuiRend_DisplayAndReturnClicked(jkGuiMenu *menu)
{
    int32_t msgret; // eax
    jkGuiMenu *lastActiveMenu;

    lastActiveMenu = jkGuiRend_activeMenu;
    ++jkGuiRend_thing_five;
    jkGuiRend_gui_sets_handler_framebufs(menu);

#ifdef QOL_IMPROVEMENTS
    jkGuiRend_FocusElementDir(menu, FOCUS_NONE);
#endif

    jkGuiRend_SetCursorVisible(1);
    while ( !menu->lastClicked )
    {
        msgret = Window_MessageLoop();
        if ( jkGuiRend_thing_four && jkGuiRend_thing_five )
        { 
            // Added: this makes the menu that appears when pressing ESC in jkGUISingleTally flicker,
            //        I think due to how we handle window message emulation.
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
            menu->lastClicked = -1;
#endif
        }
        else
        {
            jkGuiRend_thing_four = 0;
            if ( g_should_exit )
                jk_exit(msgret);
            if ( menu->idkFunc && !menu->lastClicked )
                menu->idkFunc(menu);
        }
    }
    jkGuiRend_sub_50FDB0();
    --jkGuiRend_thing_five;
    jkGuiRend_activeMenu = lastActiveMenu;
    return menu->lastClicked;
}

void jkGuiRend_sub_50FAD0(jkGuiMenu *menu)
{
    int32_t paletteChecksum;

    menu->focusedElement = 0;
    menu->lastMouseDownClickable = 0;
    menu->lastMouseOverClickable = 0;
    menu->lastClicked = 0;

    if ( menu->palette )
       jkGuiRend_SetPalette(menu->palette);

    paletteChecksum = 0;

    if ( jkGuiRend_palette )
    {
        for (int32_t i = 0; i < 0x300; i++)
        {
            paletteChecksum += i * jkGuiRend_palette[i];
        }
    }
    else
    {
        paletteChecksum = jkGuiRend_paletteChecksum;
    }

    if ( paletteChecksum != jkGuiRend_paletteChecksum )
    {
        jkGuiRend_paletteChecksum = paletteChecksum;
        if ( g_app_suspended && !jkGuiRend_bIsSurfaceValid)
        {
            stdDisplay_ClearRect(jkGuiRend_menuBuffer, jkGuiRend_fillColor, 0);
            jkGuiRend_FlipAndDraw(jkGuiRend_activeMenu, 0);
        }
    }

    stdDisplay_SetMasterPalette(jkGuiRend_palette);

    jkGuiElement* clickable = menu->paElements;
    int32_t idx = 0;
    while (clickable->type != ELEMENT_END)
    {
        _memset(&clickable->texInfo, 0, sizeof(clickable->texInfo));
        jkGuiRend_InvokeEvent(clickable, menu, JKGUI_EVENT_INIT, 0);
        clickable = &menu->paElements[++idx];
    }
    
    clickable = menu->paElements;
    idx = 0;
    if (clickable->type != ELEMENT_END )
    {
        idx = 0;
        while ( !jkGuiRend_sub_5103E0(&clickable[idx]) )
        {
            clickable = menu->paElements;
            ++idx;
            if ( menu->paElements[idx].type == ELEMENT_END )
            {
                jkGuiRend_UpdateMouse();
                jkGuiRend_ResetMouseLatestMs();
                return;
            }
        }
        menu->focusedElement = &menu->paElements[idx];
    }

    jkGuiRend_UpdateMouse();
    jkGuiRend_ResetMouseLatestMs();
}

void jkGuiRend_gui_sets_handler_framebufs(jkGuiMenu *menu)
{
    jkGuiRend_activeMenu = menu;
    jkGuiRend_sub_50FAD0(menu);
    if ( !jkGuiRend_HandlerIsSet )
    {
        Window_AddMsgHandler(jkGuiRend_WindowHandler);
        Window_GetDrawHandlers(&jkGuiRend_idk, &jkGuiRend_idk2);
        Window_SetDrawHandlers(jkGuiRend_DrawAndFlip, jkGuiRend_Invalidate);
    }
    ++jkGuiRend_HandlerIsSet;
    
#ifdef TARGET_TWL
    if ( menu->texture )
        stdDisplay_VBufferCopy(jkGuiRend_menuBuffer, menu->texture, 0, 0, 0, 0);
#endif
    
    jkGuiRend_Paint(menu);
}

int32_t jkGuiRend_Menuidk()
{
    if ( jkGuiRend_activeMenu->lastClicked )
    {
        jkGuiRend_sub_50FDB0();
        return jkGuiRend_activeMenu->lastClicked;
    }
    else
    {
        if ( jkGuiRend_activeMenu->idkFunc )
            jkGuiRend_activeMenu->idkFunc(jkGuiRend_activeMenu);
        return 0;
    }
}

void jkGuiRend_sub_50FDB0()
{
    if ( !--jkGuiRend_HandlerIsSet )
    {
        Window_RemoveMsgHandler(jkGuiRend_WindowHandler);
        Window_SetDrawHandlers(jkGuiRend_idk, jkGuiRend_idk2);
    }
    jkGuiRend_activeMenu = 0;
}

void jkGuiRend_Startup()
{
    jkGuiRend_bInitted = 1;
}

void jkGuiRend_Shutdown()
{
    jkGuiRend_bInitted = 0;

    // Added: Clean reset
#ifdef QOL_IMPROVEMENTS
    for (int32_t i = 0; i < 4; i++)
    {
        if ( jkGuiRend_DsoundHandles[i] )
            stdSound_BufferRelease(jkGuiRend_DsoundHandles[i]);
            
        if ( jkGuiRend_LoadedSounds[i] )
            std_pHS->free(jkGuiRend_LoadedSounds[i]);
    }
    
    memset(jkGuiRend_LoadedSounds, 0, sizeof(jkGuiRend_LoadedSounds));
    memset(jkGuiRend_palette, 0, sizeof(jkGuiRend_palette));
    memset(jkGuiRend_DsoundHandles, 0, sizeof(jkGuiRend_DsoundHandles));

    jkGuiRend_idk2 = 0;
    jkGuiRend_idk = 0;
    jkGuiRend_activeMenu = NULL;
    jkGuiRend_menuBuffer = NULL;
    jkGuiRend_texture_dword_8561E8 = NULL;

    jkGuiRend_thing_five = 0;
    jkGuiRend_thing_four = 0;
    jkGuiRend_bIsSurfaceValid = 0;
    jkGuiRend_bInitted = 0;
    jkGuiRend_bOpen = 0;
    jkGuiRend_HandlerIsSet = 0;
    jkGuiRend_fillColor = 0;
    jkGuiRend_paletteChecksum = 0;
    jkGuiRend_dword_85620C = 0;
    jkGuiRend_lastKeyScancode = 0;
    jkGuiRend_mouseX = 0;
    jkGuiRend_mouseY = 0;
    jkGuiRend_bShiftDown = 0;
    jkGuiRend_mouseXLatest = 0;
    jkGuiRend_mouseYLatest = 0;
    jkGuiRend_mouseLatestMs = 0;
    jkGuiRend_hCursor = 0;

    jkGuiRend_CursorVisible = 1;
#endif
}

void jkGuiRend_Open(stdVBuffer *menuBuffer, stdVBuffer *otherBuf, int32_t fillColor)
{
    jkGuiRend_menuBuffer = menuBuffer;
    jkGuiRend_texture_dword_8561E8 = otherBuf;
    jkGuiRend_fillColor = fillColor;
    jkGuiRend_bOpen = 1;
}

void jkGuiRend_Close()
{
    if (!jkGuiRend_bOpen) return;

    jkGuiRend_menuBuffer = 0;
    jkGuiRend_texture_dword_8561E8 = 0;
    jkGuiRend_bOpen = 0;
}

jkGuiElement* jkGuiRend_MenuGetClickableById(jkGuiMenu *menu, int32_t id)
{
    jkGuiElement *result;

    result = menu->paElements;
    if ( menu->paElements->type == ELEMENT_END )
        return 0;
    while ( result->hoverId != id )
    {
        ++result;
        if ( result->type == ELEMENT_END )
            return 0;
    }
    return result;
}

void jkGuiRend_PlayWav(char *fpath)
{
    int32_t bufferMaxSize, samplesPerSec, bStereo, bitsPerSample, seekOffset;

    if ( !fpath )
        return;

    for (int32_t i = 0; i < 4; i++)
    {
        if ( jkGuiRend_LoadedSounds[i] && !__strcmpi(jkGuiRend_LoadedSounds[i], fpath) )
        {
            stdSound_BufferReset(jkGuiRend_DsoundHandles[i]);
            
            // Added
            stdSound_BufferSetVolume(jkGuiRend_DsoundHandles[i], 1.0f);
            
            stdSound_BufferPlay(jkGuiRend_DsoundHandles[i], 0);
            return;
        }
    }

    stdSound_buffer_t* newHandle = sithSound_InitFromPath(fpath);

    if ( newHandle )
    {
        if ( jkGuiRend_DsoundHandles[3]) {
            stdSound_BufferRelease(jkGuiRend_DsoundHandles[3]);
            jkGuiRend_DsoundHandles[3] = NULL;
        }
            
        if ( jkGuiRend_LoadedSounds[3] ) {
            std_pHS->free(jkGuiRend_LoadedSounds[3]);
            jkGuiRend_LoadedSounds[3] = NULL;
        }

        for (int32_t i = 3; i >= 1; i--)
        {
            jkGuiRend_DsoundHandles[i] = jkGuiRend_DsoundHandles[i-1];
            jkGuiRend_LoadedSounds[i] = jkGuiRend_LoadedSounds[i-1];
        }

        jkGuiRend_DsoundHandles[0] = newHandle;
        char* soundPath = (char *)std_pHS->alloc(_strlen(fpath) + 1);
        _strcpy(soundPath, fpath);
        jkGuiRend_LoadedSounds[0] = soundPath;

        // Added
        stdSound_BufferSetVolume(newHandle, 1.0f);
            

        stdSound_BufferPlay(newHandle, 0);
    }
}

void jkGuiRend_SetCursorVisible(int32_t visible)
{
    jkGuiRend_CursorVisible = visible;
    jkGuiRend_UpdateCursor();
}

void jkGuiRend_UpdateCursor()
{
    int32_t ret;

    if ( jkGuiRend_CursorVisible )
    {
        ret = stdControl_ShowCursor(1);
        while ( ret > 0 )
        {
            ret = stdControl_ShowCursor(0);
        }
        if ( ret < 0 )
        {
            while ( stdControl_ShowCursor(1) < 0 )
                ;
        }
    }
    else
    {
        ret = stdControl_ShowCursor(0);
        while ( ret > -1 )
        {
            ret = stdControl_ShowCursor(0);
        }
        if ( ret > -1 )
        {
            while ( stdControl_ShowCursor(1) < -1 )
                ;
        }
    }
}

void jkGuiRend_UpdateSurface()
{
    if (!g_app_suspended || jkGuiRend_bIsSurfaceValid)
        return;

    stdDisplay_ClearRect(jkGuiRend_menuBuffer, jkGuiRend_fillColor, 0);
    jkGuiRend_FlipAndDraw(jkGuiRend_activeMenu, 0);
}

int jkGuiRend_DrawAndFlip(uint32_t a)
{
    stdDisplay_DrawAndFlipGdi(0);
    jkGuiRend_bIsSurfaceValid = 1;
    return 1;
}

int jkGuiRend_Invalidate(uint32_t a)
{
    stdDisplay_SetCooperativeLevel(0);
    jkGuiRend_bIsSurfaceValid = 0;
    jkGuiRend_InvalidateGdi();
    return 1;
}

int32_t jkGuiRend_DarrayNewStr(Darray *array, int32_t num, int32_t initVal)
{
    int32_t result;

    result = Darray_New(array, sizeof(jkGuiStringEntry), num);
    array->bInitialized = initVal;
    return result;
}

int32_t jkGuiRend_DarrayReallocStr(Darray *array, wchar_t *wStr, intptr_t id)
{
    jkGuiStringEntry *entry; // eax
    wchar_t *v7; // eax

    entry = (jkGuiStringEntry *)Darray_NewEntry(array);
    if (!entry)
        return 0;

    if ( array->bInitialized )
    {
        if ( wStr )
        {
            v7 = (wchar_t *)std_pHS->alloc(sizeof(wchar_t) * (_wcslen(wStr) + 1));
            wStr = _wcscpy(v7, wStr);
        }
    }
    entry->str = wStr;
    entry->id = id;
    return 1;
}

int32_t jkGuiRend_AddStringEntry(Darray *a1, const char *str, intptr_t id)
{
    jkGuiStringEntry *entry;

    entry = (jkGuiStringEntry *)Darray_NewEntry(a1);
    if (!entry)
        return 0;

    if ( str )
        entry->str = stdString_CstrCopy(str);
    else
        entry->str = 0;

    entry->id = id;
    return 1;
}

void jkGuiRend_SetClickableString(jkGuiElement *element, Darray *array)
{
    element->unistr = (jkGuiStringEntry *)Darray_GetIndex(array, 0);
}

wchar_t* jkGuiRend_GetString(Darray *array, int32_t idx)
{
    return ((jkGuiStringEntry*)Darray_GetIndex(array, idx))->str;
}

intptr_t jkGuiRend_GetId(Darray *array, int32_t idx)
{
    return ((jkGuiStringEntry*)Darray_GetIndex(array, idx))->id;
}

jkGuiStringEntry* jkGuiRend_GetStringEntry(Darray *array, int32_t idx)
{
    return (jkGuiStringEntry *)Darray_GetIndex(array, idx);
}

void jkGuiRend_DarrayFree(Darray *array)
{
    jkGuiRend_DarrayFreeEntry(array);
    Darray_Free(array);
}

void jkGuiRend_DarrayFreeEntry(Darray *array)
{
    wchar_t *str;

    if ( array->bInitialized )
    {
        for (int32_t i = 0; i < (int32_t)array->total; ++i )
        {
            str = jkGuiRend_GetString(array, i);
            if (str)
                std_pHS->free(str);
        }
    }
    Darray_ClearAll(array);
}

int32_t jkGuiRend_sub_5103E0(jkGuiElement *element)
{
    return (element->bIsVisible && !element->enableHover && (element->type == ELEMENT_LISTBOX || element->type == ELEMENT_TEXTBOX));
}

int32_t jkGuiRend_ElementHasHoverSound(jkGuiElement *element)
{
    if ( !element->bIsVisible || element->enableHover )
        return 0;

    switch ( element->type )
    {
        case ELEMENT_TEXTBUTTON:
        case ELEMENT_PICBUTTON:
        case ELEMENT_CHECKBOX:
        case ELEMENT_LISTBOX:
        case ELEMENT_TEXTBOX:
        case ELEMENT_SLIDER:
            return 1;
        default:
            return 0;
    }
    return 0;
}

void jkGuiRend_UpdateAndDrawClickable(jkGuiElement *clickable, jkGuiMenu *menu, BOOL forceRedraw)
{
    rdVector2i mousePos;

    if ( !g_app_suspended || jkGuiRend_bIsSurfaceValid )
        return;

    // Added
    if (!clickable) return;

    rdRect* drawRect = &clickable->rect;
    jkGuiRend_GetMousePos(&mousePos.x, &mousePos.y);
    if ( mousePos.x < clickable->rect.x - 16
      || mousePos.x > clickable->rect.width + clickable->rect.x + 16
      || mousePos.y < clickable->rect.y - 16
      || mousePos.y > clickable->rect.height + clickable->rect.y + 16 )
    {
        mousePos.x = 0;
    }
    else
    {
        stdControl_ShowCursor(0);
        mousePos.x = 1;
    }

    if ( clickable->bIsVisible )
    {
        jkGuiDrawFunc_t drawFunc = clickable->drawFuncOverride;
        if ( !drawFunc )
            drawFunc = jkGuiRend_elementHandlers[clickable->type].draw;
        jkGuiElement* lastSave = menu->lastMouseOverClickable;
        if ( clickable->enableHover )
            menu->lastMouseOverClickable = 0;
        drawFunc(clickable, menu, jkGuiRend_menuBuffer, forceRedraw);
        menu->lastMouseOverClickable = lastSave;
#if !defined(SDL2_RENDER)
        if ( forceRedraw )
            jkGuiRend_FlipAndDraw(menu, drawRect);
#endif
    }
    else if ( forceRedraw )
    {
        jkGuiRend_CopyVBuffer(menu, drawRect);
#if !defined(SDL2_RENDER)
        if ( forceRedraw )
            jkGuiRend_FlipAndDraw(menu, drawRect);
#endif
    }

    
    if ( clickable->bIsVisible )
        goto LABEL_47;
    if ( menu->lastMouseOverClickable == clickable )
        menu->lastMouseOverClickable = 0;
    jkGuiRend_RenderIdk2_alt(menu);
    if ( menu->lastMouseDownClickable == clickable )
        menu->lastMouseDownClickable = 0;
LABEL_47:
    if ( mousePos.x )
        stdControl_ShowCursor(1);

}

int32_t jkGuiRend_InvokeEvent(jkGuiElement *element, jkGuiMenu *menu, int32_t eventType, int32_t eventParam)
{
    jkGuiEventHandlerFunc_t fnEventHandler;

    if ( element && (!eventType || element->bIsVisible && !element->enableHover) && (fnEventHandler = jkGuiRend_elementHandlers[element->type].fnEventHandler) != 0 )
        return fnEventHandler(element, menu, eventType, eventParam);
    else
        return 0;
}

int32_t jkGuiRend_InvokeClicked(jkGuiElement *clickable, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, BOOL redraw)
{
    jkGuiClickHandlerFunc_t handler;

    if ( !clickable->bIsVisible || clickable->enableHover )
        return 0;

    handler = clickable->clickHandlerFunc;
    if ( !handler )
    {
        handler = jkGuiRend_elementHandlers[clickable->type].fnClickHandler;
    }

    if (handler)
        menu->lastClicked = handler(clickable, menu, mouseX, mouseY, redraw);

    return menu->lastClicked;
}

int jkGuiRend_PlayClickSound(jkGuiElement *element, jkGuiMenu *menu, int32_t a, int32_t b, BOOL c)
{
    jkGuiRend_PlayWav(menu->soundClick);
    return element->hoverId;
}

void jkGuiRend_RenderFocused(jkGuiMenu *menu, jkGuiElement *element)
{
    jkGuiElement *focusedElement; // edi

    focusedElement = menu->focusedElement;
    if ( element && element->bIsVisible && !element->enableHover && element->type >= ELEMENT_LISTBOX && element->type <= ELEMENT_TEXTBOX )
    {
        menu->focusedElement = element;
        if ( focusedElement )
        {
            if ( focusedElement == element )
                return;
            jkGuiRend_UpdateAndDrawClickable(focusedElement, menu, 1);
        }
        if ( focusedElement != element )
            jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
    }
}

void jkGuiRend_FocusNextElement(jkGuiMenu *menu)
{
    int32_t idx = 0;
    jkGuiElement* focusedElement = menu->focusedElement;
    if ( focusedElement )
        idx = focusedElement - menu->paElements;

    int32_t idxOther = idx + 1;
    if ( idx + 1 == idx )
        return;

    jkGuiElement* iter;
    while ( 1 )
    {
        iter = &menu->paElements[idxOther];
        if ( menu->paElements[idxOther].type != ELEMENT_END )
            break;
        idxOther = -1;
LABEL_12:
        if ( ++idxOther == idx )
            return;
    }
    if ( !iter->bIsVisible )
        goto LABEL_12;
    if ( iter->enableHover )
        goto LABEL_12;
    if ( iter->type < ELEMENT_LISTBOX || iter->type > ELEMENT_TEXTBOX )
        goto LABEL_12;

    jkGuiElement* element = &menu->paElements[idxOther];
    if ( element && jkGuiRend_sub_5103E0(element) )
    {
//#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
        menu->focusedElement = element;
//#endif
        if ( focusedElement )
        {
            if ( focusedElement != element )
            {
                jkGuiRend_UpdateAndDrawClickable(focusedElement, menu, 1);
                goto LABEL_22;
            }
        }
        else
        {
LABEL_22:
            if ( focusedElement != element )
                jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
        }
    }
}

void jkGuiRend_RenderIdk2_alt(jkGuiMenu *menu)
{
    int32_t idx = 0;
    jkGuiElement* focusedElement = menu->focusedElement;
    if ( focusedElement )
        idx = focusedElement - menu->paElements;

    int32_t idxOther = idx + 1;
    if ( idx + 1 == idx )
        return;

    jkGuiElement* iter;
    while ( 1 )
    {
        iter = &menu->paElements[idxOther];
        if ( menu->paElements[idxOther].type != ELEMENT_END )
        {
            if ( iter->bIsVisible && !iter->enableHover && !(iter->type < ELEMENT_LISTBOX || iter->type > ELEMENT_TEXTBOX))
                break;
        }
        else
        {
            idxOther = -1;
        }
        
        if ( ++idxOther == idx )
            return;
    }


    jkGuiElement* element = &menu->paElements[idxOther];
    if ( element && jkGuiRend_sub_5103E0(element) )
    {
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
        menu->focusedElement = element;
#endif
        if ( focusedElement )
        {
            if ( focusedElement != element )
            {
                jkGuiRend_UpdateAndDrawClickable(focusedElement, menu, 1);
                goto LABEL_22;
            }
        }
        else
        {
LABEL_22:
            if ( focusedElement != element )
                jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
        }
    }
}

void jkGuiRend_FocusPrevElement(jkGuiMenu *menu)
{
    jkGuiElement *focusedElement; // ebx
    int32_t idx; // edx
    int32_t idxOther; // eax
    jkGuiElement *paElements; // ecx
    int32_t v5; // esi
    jkGuiElement *v6; // ecx
    jkGuiElement *iter; // esi

    focusedElement = menu->focusedElement;
    if ( focusedElement )
        idx = focusedElement - menu->paElements;
    else
        idx = 0;
    idxOther = idx - 1;
    if ( idx - 1 == idx )
        return;
    while ( 1 )
    {
        if ( idxOther < 0 )
        {
            paElements = menu->paElements;
            idxOther = 0;
            while ( paElements->type != ELEMENT_END )
            {
                ++paElements;
                ++idxOther;
            }
        }
        else if ( menu->paElements[idxOther].bIsVisible && !menu->paElements[idxOther].enableHover && menu->paElements[idxOther].type >= ELEMENT_LISTBOX && menu->paElements[idxOther].type <= ELEMENT_TEXTBOX)
        {
            break;
        }

        if ( --idxOther == idx )
            return;
    }

    iter = &menu->paElements[idxOther];
    if ( iter && jkGuiRend_sub_5103E0(iter) )
    {
        menu->focusedElement = iter;
        if ( focusedElement )
        {
            if ( focusedElement != iter )
            {
                jkGuiRend_UpdateAndDrawClickable(focusedElement, menu, 1);
                goto LABEL_23;
            }
        }
        else
        {
LABEL_23:
            if ( focusedElement != iter )
                jkGuiRend_UpdateAndDrawClickable(iter, menu, 1);
        }
    }
}

void jkGuiRend_ClickableMouseover(jkGuiMenu *menu, jkGuiElement *element)
{
    jkGuiElement *lastMouseOverClickable; // eax

    lastMouseOverClickable = menu->lastMouseOverClickable;
    if ( lastMouseOverClickable != element && (!element || element->bIsVisible) )
    {
        menu->lastMouseOverClickable = element;
        if ( lastMouseOverClickable )
            jkGuiRend_UpdateAndDrawClickable(lastMouseOverClickable, menu, 1);
        if ( element )
            jkGuiRend_UpdateAndDrawClickable(menu->lastMouseOverClickable, menu, 1);
        jkGuiRend_UpdateDrawMenu(menu);
        if ( menu->lastMouseOverClickable && jkGuiRend_ElementHasHoverSound(menu->lastMouseOverClickable) )
        {
            jkGuiRend_PlayWav(menu->soundHover);
        }
    }
}

void jkGuiRend_MouseMovedCallback(jkGuiMenu *menu, int32_t x, int32_t y)
{
    int32_t v7; // edx
    jkGuiElement *v8; // ecx

    jkGuiElement* lastMouseOverClickable = menu->lastMouseOverClickable;
    if (lastMouseOverClickable 
        && lastMouseOverClickable->bIsVisible 
        && (x >= lastMouseOverClickable->rect.x) 
        && x < lastMouseOverClickable->rect.x + lastMouseOverClickable->rect.width 
        && (y >= lastMouseOverClickable->rect.y) 
        && y < lastMouseOverClickable->rect.y + lastMouseOverClickable->rect.height ) 
    {
        return;
    }


    v7 = 0;
    if ( menu->paElements->type == ELEMENT_END )
    {
        jkGuiRend_ClickableMouseover(menu, 0);
        return;
    }
 
    v8 = menu->paElements;
    while ( 1 )
    {
        if ( v8->bIsVisible )
        {
            if ( x >= v8->rect.x && x < v8->rect.x + v8->rect.width )
            {
                if ( y >= v8->rect.y && y < v8->rect.y + v8->rect.height )
                    break;
            }
        }
        ++v7;
        ++v8;
        if ( v8->type == ELEMENT_END )
        {
            jkGuiRend_ClickableMouseover(menu, 0);
            return;
        }
    }
    jkGuiRend_ClickableMouseover(menu, &menu->paElements[v7]);
}

void jkGuiRend_SetVisibleAndDraw(jkGuiElement *clickable, jkGuiMenu *menu, int32_t bVisible)
{
    if ( clickable->bIsVisible != bVisible )
    {
        clickable->bIsVisible = bVisible;
        jkGuiRend_UpdateAndDrawClickable(clickable, menu, 1);
    }
}

void jkGuiRend_ClickableHover(jkGuiMenu *menu, jkGuiElement *element, int32_t a3)
{
    int32_t v4; // ebx
    int32_t v5; // ebx
    int32_t v6; // edx
    int32_t v7; // ebx
    intptr_t v8; // ebp
    int32_t v9; // eax
    int32_t v10; // [esp+8h] [ebp-4h]
    int32_t a1a; // [esp+14h] [ebp+8h]

    v10 = 0;
    v4 = element->texInfo.maxTextEntries;
    if ( element->texInfo.numTextEntries > v4 )
    {
        v5 = v4 - 3;
        if ( v5 <= 1 )
            v5 = 1;
        jkGuiRend_PlayWav(menu->soundHover);
        v6 = v5;
        v7 = v5 - 1;
        if ( v6 )
        {
            while ( 1 )
            {
                v8 = element->texInfo.textScrollY;
                a1a = element->selectedTextEntry;
                element->selectedTextEntry = a3 + a1a;
                element->texInfo.textScrollY = a3 + v8;
                jkGuiRend_sub_510C60(element);
                if ( v8 == element->texInfo.textScrollY )
                    break;
                jkGuiRend_dword_85620C = a3;
                ++v10;
                jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
                v9 = v7--;
                if ( !v9 )
                    goto LABEL_10;
            }
            element->selectedTextEntry = a1a;
        }
        else
        {
            v8 = (intptr_t)menu;
        }
LABEL_10:
        if ( !v10 )
        {
            if ( a3 <= 0 )
                element->selectedTextEntry = v8;
            else
                element->selectedTextEntry = v8 + element->texInfo.maxTextEntries - 1;
        }
        jkGuiRend_dword_85620C = 0;
        jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
    }
}

void jkGuiRend_sub_510C60(jkGuiElement *element)
{
    jkGuiStringEntry *v1; // edx
    int32_t v4; // esi
    int32_t v5; // ecx
    int32_t v6; // edi
    int32_t v7; // edx
    int32_t v8; // ecx

    v1 = element->unistr;
    element->texInfo.numTextEntries = 0;
    if ( v1 && v1->str )
    {
        do
        {
            ;
        }
        while ( v1[++element->texInfo.numTextEntries].str );
    }

    if ( element->selectedTextEntry < 0 )
    {
        v4 = 0;
    }
    else
    {
        v4 = element->texInfo.numTextEntries - 1;
        if ( element->selectedTextEntry <= v4 )
            v4 = element->selectedTextEntry;
    }
    v5 = element->texInfo.numTextEntries;
    v6 = element->texInfo.maxTextEntries;
    element->selectedTextEntry = v4;
    if ( v5 <= v6 )
    {
        element->texInfo.textScrollY = 0;
    }
    else
    {
        v7 = element->texInfo.textScrollY;
        if ( v7 < 0 )
        {
            v8 = 0;
        }
        else
        {
            v8 = v5 - v6 + 2;
            if ( v7 <= v8 )
                v8 = element->texInfo.textScrollY;
        }

        // Added: prevent infloop?
        int32_t safety_switch = 0;
        while ( 1 )
        {
            while ( 1 )
            {
                element->texInfo.textScrollY = v8;
                if ( v4 >= v8 )
                    break;
                --v8;

                // Added: prevent infloop?
                if (++safety_switch >= 0x1000) {
                    break;
                }
            }
            if ( v4 < v8 + v6 - 2 )
                break;
            ++v8;

            // Added: prevent infloop?
            if (++safety_switch >= 0x1000) {
                break;
            }
        }
    }
}

int jkGuiRend_ClickSound(jkGuiElement *element, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, BOOL redraw)
{
    if ( !redraw )
        return 0;
    jkGuiRend_PlayWav(menu->soundClick);
    return element->hoverId;
}

void jkGuiRend_HoverOn(jkGuiElement *element, jkGuiMenu *menu, int32_t a3)
{
    element->selectedTextEntry += a3;
    jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
    jkGuiRend_PlayWav(menu->soundHover);
}

int jkGuiRend_ListBoxEventHandler(jkGuiElement *element, jkGuiMenu *menu, int32_t eventType, int32_t eventParam)
{
    int32_t result; // eax
    jkGuiElement *element_; // esi
    int32_t v6; // ecx
    int32_t v7; // eax
    int32_t v9; // edx
    int32_t v11; // ebp
    int32_t v12; // ebx
    int32_t selectedIdx; // eax
    int32_t v18; // edx
    int32_t v19; // edi
    stdFont** v20; // esi
    int32_t v21; // eax
    int32_t v22; // esi
    int32_t v23; // eax
    rdRect *v24; // eax
    int32_t v25; // edx
    int32_t v26; // edx
    int32_t v27; // esi
    int32_t v28; // eax
    int32_t a1a; // [esp+14h] [ebp+4h]
    int32_t mouseX, mouseY;

    if (eventType == JKGUI_EVENT_INIT)
    {
        // TODO is this an inlined func?
        v19 = 2;
        v20 = &menu->fonts[element->textType];
        do
        {
            if ( *v20 )
            {
                v21 = element->texInfo.textHeight;
                if ( v21 <= stdFont_GetHeight(*v20) )
                    v21 = stdFont_GetHeight(*v20);
                element->texInfo.textHeight = v21;
            }
            ++v20;
            --v19;
        }
        while ( v19 );
        v22 = element->texInfo.textHeight;
        v23 = (element->rect.height - 3) / v22;
        element->texInfo.maxTextEntries = v23;
        element->rect.height = v22 * v23 + 6;
        v24 = &element->texInfo.rect;
        v24->x = element->rect.x;
        v24->y = element->rect.y;
        v25 = element->rect.height;
        v24->width = element->rect.width;
        v24->height = v25;
        v26 = element->texInfo.rect.width;
        v27 = element->texInfo.rect.y - 2;
        v24->x = element->texInfo.rect.x - 2;
        v28 = element->texInfo.rect.height;
        element->texInfo.rect.y = v27;
        element->texInfo.rect.height = v28 + 4;
        element->texInfo.rect.width = v26 + 4;
        return 1;
    }
    else if ( eventType == JKGUI_EVENT_MOUSEDOWN )
    {
        jkGuiRend_GetMousePos(&mouseX, &mouseY);
        selectedIdx = (mouseY - element->rect.y - 3) / element->texInfo.textHeight;
        if ( selectedIdx >= 0 )
        {
            if ( selectedIdx < element->texInfo.maxTextEntries )
            {
                v18 = selectedIdx + element->texInfo.textScrollY;
                if ( element->texInfo.numTextEntries > element->texInfo.maxTextEntries )
                {
                    if ( !selectedIdx )
                    {
                        jkGuiRend_ClickableHover(menu, element, -1);
                        jkGuiRend_ResetMouseLatestMs();
                        return 0;
                    }
                    if ( selectedIdx == element->texInfo.maxTextEntries - 1 )
                    {
                        jkGuiRend_ClickableHover(menu, element, 1);
                        jkGuiRend_ResetMouseLatestMs();
                        return 0;
                    }
                    --v18;
                }
                element->selectedTextEntry = v18;
                jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
                jkGuiRend_PlayWav(menu->soundHover);
            }
        }
    }
    else if ( eventType == JKGUI_EVENT_KEYDOWN )
    {
        element_ = element;
        v6 = element->selectedTextEntry;
        v7 = element->texInfo.textHeight;
        v9 = v7 * (element->selectedTextEntry - element->texInfo.textScrollY);
        a1a = element->selectedTextEntry;
        v11 = v9 + element->rect.y + 4;
        v12 = element->rect.x + 1;
        if ( element_->texInfo.numTextEntries > element_->texInfo.maxTextEntries )
            v11 += v7;
        switch ( eventParam )
        {
            case VK_RETURN:
                if ( element_->clickHandlerFunc )
                    menu->lastClicked = element_->clickHandlerFunc(element_, menu, v12, v11, 1);
                break;
            case VK_ESCAPE:
                if ( element_->clickHandlerFunc )
                {
                    element_->texInfo.anonymous_18 = 1;
                    menu->lastClicked = element_->clickHandlerFunc(element_, menu, v12, v11, 0);
                    element_->texInfo.anonymous_18 = 0;
                }
                break;
            case VK_PRIOR:
                jkGuiRend_ClickableHover(menu, element_, -1);
                break;
            case VK_NEXT:
                jkGuiRend_ClickableHover(menu, element_, 1);
                break;
            case VK_UP:
                element_->selectedTextEntry = v6 - 1;
                jkGuiRend_UpdateAndDrawClickable(element_, menu, 1);
                jkGuiRend_PlayWav(menu->soundHover);
                break;
            case VK_DOWN:
                element_->selectedTextEntry = v6 + 1;
                jkGuiRend_UpdateAndDrawClickable(element_, menu, 1);
                jkGuiRend_PlayWav(menu->soundHover);
                break;
            default:
                break;
        }
        if ( element_->selectedTextEntry != a1a )
        {
            if ( element_->clickHandlerFunc )
            {
                menu->lastClicked = element_->clickHandlerFunc(element_, menu, v12, v11, 0);
                return 0;
            }
        }
    }
    return 0;
}

void jkGuiRend_ListBoxDraw(jkGuiElement *element_, jkGuiMenu *menu, stdVBuffer *vbuf, BOOL redraw)
{
    int32_t* bitmapIndices; // eax
    int32_t v10; // eax
    int32_t v11; // ecx
    int32_t v12; // edi
    int32_t mipLevel; // eax
    int32_t v15; // eax
    jkGuiStringEntry* v16; // ebp
    int32_t v17; // eax
    int32_t v19; // eax
    stdBitmap *topArrowBitmap; // [esp+10h] [ebp-20h]
    stdBitmap *bottomArrowBitmap; // [esp+14h] [ebp-1Ch]
    rdRect renderRect; // [esp+20h] [ebp-10h]
    int32_t element; // [esp+34h] [ebp+4h]

    bitmapIndices = element_->uiBitmaps;
    topArrowBitmap = menu->ui_structs[bitmapIndices[0]];
    bottomArrowBitmap = menu->ui_structs[bitmapIndices[1]];
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element_->texInfo.rect);
    if ( menu->focusedElement == element_ )
        jkGuiRend_DrawRect(vbuf, &element_->texInfo.rect, menu->fillColor);
    jkGuiRend_DrawRect(vbuf, &element_->rect, menu->fillColor);
    jkGuiRend_sub_510C60(element_);
    if ( element_->texInfo.numTextEntries > 0 )
    {
        v11 = element_->rect.x + 6;
        v12 = element_->rect.y + 3;
        element = element_->texInfo.textScrollY + element_->texInfo.maxTextEntries - 1;
        if ( element_->texInfo.numTextEntries > element_->texInfo.maxTextEntries )
            element = element_->texInfo.textScrollY + element_->texInfo.maxTextEntries - 3;
        if ( element >= element_->texInfo.numTextEntries - 1 )
            element = element_->texInfo.numTextEntries - 1;
        if ( element_->texInfo.numTextEntries > element_->texInfo.maxTextEntries )
        {
            if ( element_->texInfo.textScrollY )
                mipLevel = (jkGuiRend_dword_85620C < 0) + 1;
            else
                mipLevel = 0;
            if ( mipLevel < 0 )
            {
                mipLevel = 0;
            }
            else if ( mipLevel > topArrowBitmap->numMips - 1 )
            {
                mipLevel = topArrowBitmap->numMips - 1;
            }
            renderRect.y = 0;
            renderRect.x = 0;
            renderRect.width = topArrowBitmap->mipSurfaces[mipLevel]->format.width;
            renderRect.height = topArrowBitmap->mipSurfaces[mipLevel]->format.height;
            v15 = element_->texInfo.textHeight - renderRect.height;
            stdDisplay_VBufferCopy(vbuf, topArrowBitmap->mipSurfaces[mipLevel], v11 + (element_->rect.width - renderRect.width) / 2, v12 + v15 / 2, &renderRect, 1);
            v12 += element_->texInfo.textHeight;
        }
        for (int32_t i = element_->texInfo.textScrollY; i <= element; i++)
        {
            v16 = &element_->unistr[i];
            stdFont_sub_434EC0(
                vbuf,
                menu->fonts[element_->textType + (i == element_->selectedTextEntry)],
                v11,
                v12,
                element_->rect.width - 6,
                (int32_t*)menu->paddings,
                v16->str,
                1);
            v12 += element_->texInfo.textHeight;
        }
        if ( element_->texInfo.numTextEntries > element_->texInfo.maxTextEntries )
        {
            if ( element == element_->texInfo.numTextEntries - 1 )
                v17 = 0;
            else
                v17 = (jkGuiRend_dword_85620C > 0) + 1;
            if ( v17 < 0 )
            {
                v17 = 0;
            }
            else if ( v17 > bottomArrowBitmap->numMips - 1 )
            {
                v17 = bottomArrowBitmap->numMips - 1;
            }
            renderRect.y = 0;
            renderRect.x = 0;
            renderRect.width = bottomArrowBitmap->mipSurfaces[v17]->format.width;
            v19 = element_->texInfo.textHeight - bottomArrowBitmap->mipSurfaces[v17]->format.height;
            renderRect.height = bottomArrowBitmap->mipSurfaces[v17]->format.height;
            stdDisplay_VBufferCopy(vbuf, bottomArrowBitmap->mipSurfaces[v17], v11 + (element_->rect.width - renderRect.width) / 2, v12 + v19 / 2, &renderRect, 1);
        }
    }
}

void jkGuiRend_CheckBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, BOOL redraw)
{
    stdBitmap *checkboxBitmap; // ebp
    int32_t v5; // eax
    stdVBuffer *v6; // ecx
    int32_t v7; // eax
    int32_t v9; // edx
    int32_t v10; // ebx
    int32_t v11; // eax
    jkGuiElement *v14; // ebp
    int32_t v15; // eax
    int32_t v17; // ebx
    rdRect drawRect; // [esp+10h] [ebp-10h]
    int32_t a4a; // [esp+30h] [ebp+10h]

    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    checkboxBitmap = menu->ui_structs[menu->checkboxBitmapIdx];
    v6 = checkboxBitmap->mipSurfaces[(element->selectedTextEntry != 0) ? 1 : 0];
    v7 = (uint32_t)(element->rect.height - v6->format.height) / 2;
    if ( v7 < 0 )
        v7 = 0;
    stdDisplay_VBufferCopy(vbuf, v6, element->rect.x, element->rect.y + v7, 0, 1);
    if ( element->unistr )
    {
        v9 = element->rect.x;
        v10 = element->rect.width;
        drawRect.y = element->rect.y;
        v11 = element->rect.height;
        drawRect.x = v9;
        drawRect.height = v11;
        drawRect.width = v10;
        v14 = menu->lastMouseOverClickable;
        v15 = v6->format.width + 4;
        drawRect.width = v10 - v15;
        v17 = element->textType;
        drawRect.x = v15 + v9;
        stdFont_Draw3(vbuf, menu->fonts[v17 + (v14 == element)], element->rect.y, &drawRect, 2, element->wstr, 1);
    }
}

int jkGuiRend_DrawClickableAndUpdatebool(jkGuiElement *element, jkGuiMenu *menu, int32_t a, int32_t b, BOOL c)
{
    element->selectedTextEntry = element->selectedTextEntry == 0;
    jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
    return 0;
}

int jkGuiRend_WindowHandler(HWND hWnd, UINT a2, WPARAM wParam, LPARAM lParam, LRESULT * unused)
{
    int32_t ret;
    jkGuiElement *v8; // eax
    int32_t mouseX; // eax
    int32_t mouseY; // ecx
    rdRect Rect; // [esp+10h] [ebp-50h]
    struct tagPAINTSTRUCT Paint; // [esp+20h] [ebp-40h]

    if ( !g_app_suspended || jkGuiRend_bIsSurfaceValid )
        return 0;

    switch ( a2 )
    {
        case WM_LBUTTONDOWN:
        {
            jkGuiRend_activeMenu->lastMouseDownClickable = jkGuiRend_activeMenu->lastMouseOverClickable;
            jkGuiRend_RenderFocused(jkGuiRend_activeMenu, jkGuiRend_activeMenu->lastMouseOverClickable);
            if ( jkGuiRend_activeMenu->lastMouseDownClickable )
            {
                jkGuiRend_UpdateAndDrawClickable(jkGuiRend_activeMenu->lastMouseDownClickable, jkGuiRend_activeMenu, 1);
                jkGuiRend_InvokeEvent(jkGuiRend_activeMenu->lastMouseDownClickable, jkGuiRend_activeMenu, JKGUI_EVENT_MOUSEDOWN, wParam);
            }
            return 0;
        }

        case WM_LBUTTONUP:
        {
            if ( jkGuiRend_activeMenu->lastMouseDownClickable )
            {
                if ( jkGuiRend_activeMenu->lastMouseDownClickable == jkGuiRend_activeMenu->lastMouseOverClickable )
                {
                    BOOL redraw = 0;
                    uint32_t timeMs = stdPlatform_GetTimeMsec();
                    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
                    {
                        jk_GetCursorPos((LPPOINT)&Rect);
                        mouseX = Rect.x;
                        mouseY = Rect.y;
                    }
                    else
                    {
                        mouseX = jkGuiRend_mouseX;
                        mouseY = jkGuiRend_mouseY;
                    }
                    if ( mouseX > jkGuiRend_mouseXLatest - 4
                      && mouseX < jkGuiRend_mouseXLatest + 4
                      && mouseY > jkGuiRend_mouseYLatest - 4
                      && mouseY < jkGuiRend_mouseYLatest + 4
                      && timeMs < jkGuiRend_mouseLatestMs + 300 )
                    {
                        redraw = 1;
                    }
                    jkGuiRend_mouseXLatest = mouseX;
                    jkGuiRend_mouseYLatest = mouseY;
                    jkGuiRend_mouseLatestMs = timeMs;
                    jkGuiRend_InvokeClicked(jkGuiRend_activeMenu->lastMouseOverClickable, jkGuiRend_activeMenu, mouseX, mouseY, redraw);
                }
                if ( jkGuiRend_activeMenu->lastMouseDownClickable && jkGuiRend_activeMenu->lastMouseDownClickable->bIsVisible )
                {
                    jkGuiRend_UpdateAndDrawClickable(jkGuiRend_activeMenu->lastMouseDownClickable, jkGuiRend_activeMenu, 1);
                }
                jkGuiRend_activeMenu->lastMouseDownClickable = 0;
                return 0;
            }
            return 0;
        }

        case WM_MOUSEMOVE:
            mouseX = (uint16_t)(lParam & 0xFFFF);
            mouseY = lParam >> 16;
            jkGuiRend_mouseX = (uint16_t)lParam;
            jkGuiRend_mouseY = lParam >> 16;
            jkGuiRend_UpdateMouse();
            if ( jkGuiRend_activeMenu->lastMouseDownClickable )
                jkGuiRend_InvokeEvent(jkGuiRend_activeMenu->lastMouseDownClickable, jkGuiRend_activeMenu, JKGUI_EVENT_MOUSEMOVED, wParam);
            return 1;

        case WM_KEYFIRST:
            if ( wParam == VK_SHIFT || wParam == VK_LSHIFT || wParam == VK_RSHIFT )
                jkGuiRend_bShiftDown = 1;
            if ( wParam != VK_RETURN || (v8 = jkGuiRend_activeMenu->pReturnKeyShortcutElement) == 0 || v8->enableHover || !v8->bIsVisible )
            {
                if ( wParam != VK_ESCAPE || (v8 = jkGuiRend_activeMenu->pEscapeKeyShortcutElement) == 0 || v8->enableHover || !v8->bIsVisible )
                {
                    if ( wParam == VK_TAB )  // TAB
                    {
                        if ( jkGuiRend_bShiftDown )
                            jkGuiRend_FocusPrevElement(jkGuiRend_activeMenu);
                        else
                            jkGuiRend_FocusNextElement(jkGuiRend_activeMenu);
                        jkGuiRend_lastKeyScancode = lParam & 0xFF0000;
                        return 1;
                    }
                    v8 = jkGuiRend_activeMenu->paElements;
                    if ( jkGuiRend_activeMenu->paElements->type == ELEMENT_END )
                    {
LABEL_47:
                        jkGuiRend_lastKeyScancode = 0;
                        jkGuiRend_InvokeEvent(jkGuiRend_activeMenu->focusedElement, jkGuiRend_activeMenu, JKGUI_EVENT_KEYDOWN, wParam);
                        return 0;
                    }
                    while ( wParam != v8->clickShortcutScancode || v8->enableHover || !v8->bIsVisible )
                    {
                        ++v8;
                        if ( v8->type == ELEMENT_END )
                            goto LABEL_47;
                    }
                }
            }
            jkGuiRend_InvokeClicked(v8, jkGuiRend_activeMenu, v8->rect.x + 1, v8->rect.y + 1, 0);
            jkGuiRend_lastKeyScancode = lParam & 0xFF0000;
            return 1;

        case WM_KEYUP:
            if ( wParam == VK_SHIFT || wParam == VK_LSHIFT || wParam == VK_RSHIFT )
            {
                jkGuiRend_bShiftDown = 0;
                return 0;
            }
            break;

        case WM_CHAR:
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
            if ( (jkGuiRend_lastKeyScancode != 0xFF0000) & (uint8_t)lParam )
#endif
                jkGuiRend_InvokeEvent(jkGuiRend_activeMenu->focusedElement, jkGuiRend_activeMenu, JKGUI_EVENT_CHAR, wParam);
            jkGuiRend_lastKeyScancode = 0;
            return 0;

        case WM_PAINT:
        {
            ret = jk_GetUpdateRect(hWnd, (LPRECT)&Rect, 0);
            if ( ret )
                jk_BeginPaint(hWnd, &Paint);
            jkGuiRend_Paint(jkGuiRend_activeMenu);
            if ( ret )
            {
                jk_EndPaint(hWnd, (const PAINTSTRUCT *)&Paint);
                return 1;
            }
            return 1;
        }
        case WM_SETCURSOR:
        {
            if ( !jkGuiRend_hCursor )
            {
                jkGuiRend_hCursor = jk_LoadCursorA(stdGdi_GetHInstance(), (LPCSTR)0x91D);
            }
            jk_SetCursor(jkGuiRend_hCursor);
            return 1;
        }
    }
    return 0;
}

void jkGuiRend_UpdateMouse()
{
    int32_t mouseX; // eax
    int32_t mouseY; // ecx
    struct tagPOINT Point; // [esp+0h] [ebp-8h]

    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
    {
        jk_GetCursorPos(&Point);
        mouseX = Point.x;
        mouseY = Point.y;
    }
    else
    {
        mouseX = jkGuiRend_mouseX;
        mouseY = jkGuiRend_mouseY;
    }
    jkGuiRend_MouseMovedCallback(jkGuiRend_activeMenu, mouseX, mouseY);
}

void jkGuiRend_FlipAndDraw(jkGuiMenu *menu, rdRect *drawRect)
{
    rdRect *rect; // eax
    rdRect rectTmp; // [esp+4h] [ebp-10h]

    rect = drawRect;
    if ( !drawRect )
    {
        rectTmp.x = 0;
        rectTmp.y = 0;
        rect = &rectTmp;
        rectTmp.width = stdDisplay_pCurVideoMode->format.width;
        rectTmp.height = stdDisplay_pCurVideoMode->format.height;
    }
    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
    {
        if ( jkGuiRend_texture_dword_8561E8 )
            stdDisplay_VBufferCopy(jkGuiRend_texture_dword_8561E8, jkGuiRend_menuBuffer, rect->x, rect->y, rect, 0);
    }
    else
    {
        stdDisplay_DDrawGdiSurfaceFlip();
    }
}

void jkGuiRend_GetMousePos(int32_t *pX, int32_t *pY)
{
    struct tagPOINT Point; // [esp+0h] [ebp-8h]

    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
    {
        jk_GetCursorPos(&Point);
        *(struct tagPOINT *)pX = Point;
    }
    else
    {
        // Added: nullptr checks
        if (pX)
            *pX = jkGuiRend_mouseX;
        if (pY)
            *pY = jkGuiRend_mouseY;
    }
}

void jkGuiRend_ResetMouseLatestMs()
{
    jkGuiRend_mouseLatestMs = 0;
}

void jkGuiRend_InvalidateGdi()
{
    jk_InvalidateRect(stdGdi_GetHwnd(), 0, 1);
}

int jkGuiRend_SliderEventHandler(jkGuiElement *element, jkGuiMenu *menu, int32_t eventType, int32_t eventParam)
{
    int32_t result; // eax
    int32_t v7; // edi MAPDST
    int32_t v8; // ecx
    int32_t v9; // eax
    int32_t v10; // ecx
    int32_t v11; // ebx
    int32_t v12; // edi
    int32_t *bitmapIdices; // ebp
    int32_t backgroundIdx; // ecx
    stdBitmap *backgroundBitmap; // ecx
    stdBitmap *sliderThumbBitmap; // edx
    uint32_t v18; // ecx
    int32_t v19; // eax
    intptr_t v20; // ecx
    int32_t v21; // eax
    int32_t v22; // edx
    jkGuiElement *v23; // eax
    int32_t v24; // ecx MAPDST
    int32_t v26; // ecx
    jkGuiMenu *v27; // ST04_4
    jkGuiElement *v29; // eax
    int32_t v30; // ecx
    int32_t v31; // edx
    int32_t v32; // ecx
    uint8_t v33[16]; // [esp+0h] [ebp-1Ch]
    int32_t pY; // [esp+10h] [ebp-Ch]
    int32_t pX;

    switch ( eventType )
    {
        case JKGUI_EVENT_INIT:
            element->texInfo.textHeight = 0;
            return 0;
        case JKGUI_EVENT_2:
            result = 0;
            element->texInfo.textHeight = 0;
            return result;

        case JKGUI_EVENT_MOUSEMOVED:
            if ( !element->texInfo.textHeight )
                return 1;
        case JKGUI_EVENT_MOUSEDOWN:
            v7 = element->selectedTextEntry;
            v7 = element->selectedTextEntry;
            jkGuiRend_GetMousePos(&pX, &pY);
            v8 = element->rect.x;
            if ( pX < v8 - 32
              || (v9 = element->rect.width, pX > v9 + v8 + 32)
              || (v10 = element->rect.y, pY < v10 - 32)
              || pY > element->rect.height + v10 + 32 )
            {
                element->selectedTextEntry = element->texInfo.numTextEntries;
            }
            else
            {
                v11 = 0;
                v12 = element->rect.width;
                if ( v33 != (uint8_t*)-44 )
                    eventParam = 0;
                bitmapIdices = (int32_t *)element->uiBitmaps;
                backgroundIdx = *bitmapIdices;
                backgroundBitmap = menu->ui_structs[backgroundIdx];
                if ( backgroundBitmap )
                {
                    v12 = (*backgroundBitmap->mipSurfaces)->format.width;
                    v11 = (v9 - v12) / 2;
                }
                sliderThumbBitmap = menu->ui_structs[bitmapIdices[1]];
                if ( sliderThumbBitmap )
                {
                    v18 = (*sliderThumbBitmap->mipSurfaces)->format.width;
                    v12 -= v18;
                    if ( v33 != (uint8_t*)-44 )
                    {
                        v19 = element->rect.x + v11 + element->selectedTextEntry * v12 / (uint32_t)element->extraInt;
                        if ( pX >= v19 - 4 && pX < (int32_t)(v19 + v18 + 4) )
                            eventParam = 1;
                    }
                }
                v20 = (intptr_t)element->unistr;
                v21 = v20 * (pX - v11 - element->rect.x) / v12;
                if ( v21 < 0 )
                {
                    v21 = 0;
                    element->selectedTextEntry = v21;
                }
                else if ( v21 > v20 )
                {
                    element->selectedTextEntry = v20;
                }
                else {
                    element->selectedTextEntry = v21;
                }
                
            }

            if ( eventType == JKGUI_EVENT_MOUSEDOWN )
            {
                v22 = eventParam;
                element->texInfo.numTextEntries = v7;
                element->texInfo.textHeight = v22;
            }
            if ( v7 == element->selectedTextEntry )
                return 0;
            jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
            return 0;
        case JKGUI_EVENT_KEYDOWN:
            if ( eventParam == VK_LEFT )
            {
                v29 = element;
                v30 = element->selectedTextEntry - 1;
                element->selectedTextEntry = v30;
                v31 = v30;
                if ( v30 < 0 )
                {
                    v32 = 0;
                }
                else
                {
                    v32 = v29->extraInt;
                    if ( v31 <= (int32_t)v32 )
                        v32 = v31;
                }
                v29->extraInt = v32;
                jkGuiRend_UpdateAndDrawClickable(v29, menu, 1);
                return 0;
            }
            if ( eventParam != VK_RIGHT )
                return 0;
            v23 = element;
            v24 = element->selectedTextEntry + 1;
            element->selectedTextEntry = v24;
            if ( v24 < 0 )
            {
                v26 = 0;
            }
            else
            {
                v26 = v23->extraInt;
                if ( v24 <= v26 )
                {
                    v27 = menu;
                    v23->selectedTextEntry = v24;
                    jkGuiRend_UpdateAndDrawClickable(v23, v27, 1);
                    return 0;
                }
            }
            v23->otherDataPtr = v26;
            jkGuiRend_UpdateAndDrawClickable(v23, menu, 1);
            return 0;
        default:
            return 0;
    }
}

void jkGuiRend_SliderDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, BOOL redraw)
{
    uint32_t v6; // edi
    int32_t *bitmapIndices; // eax
    int32_t sliderThumbIdx; // ebx
    stdBitmap *sliderThumbBitmap; // ebx
    stdBitmap *sliderBackgroundBitmap; // ebp
    int32_t v12; // ebp
    int32_t v13; // ebx
    int32_t v14; // ebp
    int32_t v15; // ebx
    int32_t v16; // eax
    stdVBuffer **v17; // edx
    stdVBuffer *v18; // edi
    int32_t v19; // ecx
    uint32_t v20; // edi
    uint32_t blitX; // edx
    int32_t v22; // ecx
    int32_t v23; // eax
    int32_t v24; // ecx
    int32_t blitY; // edi
    int32_t v26; // ebp
    int32_t v27; // ecx
    int32_t v28; // ecx
    int32_t *bitmapIndices2; // edi
    stdBitmap *sliderBackgroundBitmap2; // edx
    int32_t v32; // ecx
    int32_t v33; // ebp
    stdBitmap *sliderThumbBitmap2; // ebx
    int32_t v35; // eax
    uint32_t blitX2; // esi
    int32_t blitY2; // edi
    stdVBuffer *v38; // edx
    int32_t v39; // ecx
    uint32_t v40; // ebp
    int32_t v41; // edx
    int32_t v42; // edx
    uint32_t v43; // [esp+10h] [ebp-5Ch]
    stdBitmap *v44; // [esp+14h] [ebp-58h]
    int32_t v45; // [esp+18h] [ebp-54h]
    uint32_t v46; // [esp+1Ch] [ebp-50h]
    int32_t v47; // [esp+24h] [ebp-48h]
    int32_t v48; // [esp+28h] [ebp-44h]
    rdRect drawRect; // [esp+2Ch] [ebp-40h]
    uint32_t blit_x; // [esp+3Ch] [ebp-30h]
    int32_t blit_y; // [esp+40h] [ebp-2Ch]
    int32_t v52; // [esp+44h] [ebp-28h]
    int32_t v53; // [esp+48h] [ebp-24h]
    int32_t v54; // [esp+50h] [ebp-1Ch]
    int32_t v55; // [esp+58h] [ebp-14h]
    int32_t v56; // [esp+64h] [ebp-8h]
    stdBitmap *elementa; // [esp+70h] [ebp+4h]
    BOOL redrawa; // [esp+7Ch] [ebp+10h]
    BOOL redrawb; // [esp+7Ch] [ebp+10h]
    int32_t elementb;

    v6 = 0;
    bitmapIndices = (int32_t *)element->uiBitmaps;
    v43 = 0;
    sliderThumbIdx = bitmapIndices[1];
    sliderThumbBitmap = menu->ui_structs[sliderThumbIdx];
    sliderBackgroundBitmap = menu->ui_structs[*bitmapIndices];
    v44 = sliderThumbBitmap;
    elementa = menu->ui_structs[*bitmapIndices];
    if (!sliderThumbBitmap || !sliderBackgroundBitmap) return;
    
    if ( element == menu->lastMouseOverClickable )
    {
        v6 = 1;
        v43 = 1;
    }
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    v12 = sliderBackgroundBitmap->numMips;
    if ( v6 > v12 - 1 )
        v6 = v12 - 1;
    v13 = sliderThumbBitmap->numMips;
    if ( v43 > v13 - 1 )
        v43 = v13 - 1;
    v46 = v6;
    v14 = element->rect.x;
    blit_x = v14;
    v15 = element->rect.y;
    blit_y = v15;
    v52 = element->rect.width;
    v16 = element->rect.height;
    v17 = elementa->mipSurfaces;
    v53 = v16;
    v18 = v17[v6];
    v19 = v18->format.height;
    v20 = v18->format.width;
    v45 = v19;
    redrawa = v20;
    blitX = v14;
    v22 = (v16 - v19) / 2;
    v47 = v22;
    v23 = v14 + (int32_t)(v52 - v20) / 2;
    v24 = v15 + v22;
    v54 = v24;
    if ( v14 <= v23 )
        blitX = v14 + (int32_t)(v52 - v20) / 2;
    blitY = v15;
    if ( v15 <= v24 )
        blitY = v24;
    v26 = v52 + v14;
    v27 = v23 + redrawa;
    v48 = v26;
    if ( v26 < (int32_t)(v23 + redrawa) )
        v27 = v26;
    v56 = v27 - blitX;
    v28 = v15 + v53;
    redrawb = v15 + v53;
    if ( v15 + v53 >= v45 + v54 )
        v28 = v45 + v54;
    drawRect.height = v28 - blitY;
    drawRect.x = blitX - v23;
    drawRect.width = v56;
    drawRect.y = blitY - v54;
    stdDisplay_VBufferCopy(vbuf, elementa->mipSurfaces[v46], blitX, blitY, &drawRect, 1);
    bitmapIndices2 = element->uiBitmaps;
    elementb = element->selectedTextEntry;
    sliderBackgroundBitmap2 = menu->ui_structs[*bitmapIndices2];
    v32 = 0;
    v33 = element->rect.width;
    if ( sliderBackgroundBitmap2 )
    {
        v33 = (*sliderBackgroundBitmap2->mipSurfaces)->format.width;
        v32 = (element->rect.width - v33) / 2;
    }
    sliderThumbBitmap2 = menu->ui_structs[bitmapIndices2[1]];
    if ( sliderThumbBitmap2 )
    {
        v33 -= (*sliderThumbBitmap2->mipSurfaces)->format.width;
        v32 += sliderThumbBitmap2->xPos;
    }
    if ( elementb < 0 )
    {
        elementb = 0;
    }
    else if ( elementb > (uint32_t)element->extraInt )
    {
        elementb = element->extraInt;
    }
    v35 = element->rect.x + v32 + v33 * elementb / (uint32_t)element->extraInt;
    blitX2 = blit_x;
    blitY2 = blit_y;
    v38 = v44->mipSurfaces[v43];
    v39 = blit_y + v47 + v44->yPos;
    v40 = v38->format.width;
    v55 = v38->format.height;
    if ( (int32_t)blit_x <= v35 )
        blitX2 = v35;
    if ( blit_y <= v39 )
        blitY2 = v39;
    v41 = v35 + v40;
    if ( v48 < (int32_t)(v35 + v40) )
        v41 = v48;
    v56 = v41 - blitX2;
    v42 = v39 + v55;
    if ( redrawb < v39 + v55 )
        v42 = redrawb;
    drawRect.width = v56;
    drawRect.height = v42 - blitY2;
    drawRect.x = blitX2 - v35;
    drawRect.y = blitY2 - v39;
    stdDisplay_VBufferCopy(vbuf, v44->mipSurfaces[v43], blitX2, blitY2, &drawRect, 1);
}

int jkGuiRend_TextBoxEventHandler(jkGuiElement *element, jkGuiMenu *menu, int32_t eventType, int32_t a4)
{
    jkGuiElement *v5; // esi
    jkGuiStringEntry *v7; // edi
    int32_t v8; // eax
    int32_t v11; // eax
    int32_t v12; // eax
    jkGuiMenu *v13; // ST08_4
    jkGuiElement *v14; // ST04_4
    jkGuiElement *v15; // esi
    uint32_t v16; // edi
    jkGuiMenu *v17; // ST08_4
    jkGuiMenu *v18; // ST08_4
    jkGuiElement *v19; // ST04_4
    jkGuiElement *v20; // esi
    size_t v21; // eax
    jkGuiMenu *v22; // ecx
    jkGuiElement *v23; // esi
    int32_t v24; // eax
    jkGuiElement *v25; // esi
    stdFont* v26; // eax
    int32_t v27; // eax
    int32_t *v28; // eax
    int32_t v29; // ebp
    int32_t v30; // ebx
    const wchar_t *v31; // edx

    if ( eventType == JKGUI_EVENT_INIT)
    {
        v25 = element;
        v26 = menu->fonts[element->textType];
        if ( v26 )
        {
            v27 = (*v26->pBitmap->mipSurfaces)->format.height + 3;
            if ( element->rect.height > v27 )
                v27 = element->rect.height;
            element->rect.height = v27;
        }
        v28 = &v25->texInfo.maxTextEntries;
        *v28 = v25->rect.x;
        v28[1] = v25->rect.y;
        v28[2] = v25->rect.width;
        v28[3] = v25->rect.height;
        v29 = v25->texInfo.anonymous_18;
        v30 = v25->texInfo.rect.x;
        v31 = (const wchar_t *)v25->unistr;
        *v28 = v25->texInfo.maxTextEntries - 2;
        v25->texInfo.textScrollY -= 2;
        v25->texInfo.anonymous_18 = v29 + 4;
        v25->texInfo.rect.x = v30 + 4;
        v25->texInfo.textHeight = _wcslen(v31);
        return 1;
    }

    else if ( eventType == JKGUI_EVENT_KEYDOWN )
    {
        switch ( a4 )
        {
            case VK_END:
                v20 = element;
                v21 = _wcslen((const wchar_t *)element->unistr);
                v22 = menu;
                v20->texInfo.textHeight = v21;
                jkGuiRend_UpdateAndDrawClickable(v20, v22, 1);
                return 0;
            case VK_HOME:
                v18 = menu;
                v19 = element;
                element->texInfo.textHeight = 0;
                jkGuiRend_UpdateAndDrawClickable(v19, v18, 1);
                return 0;
            case VK_LEFT:
                v12 = element->texInfo.textHeight;
                if ( v12 <= 0 )
                    return 0;
                v13 = menu;
                v14 = element;
                element->texInfo.textHeight = v12 - 1;
                jkGuiRend_UpdateAndDrawClickable(v14, v13, 1);
                return 0;
            case VK_RIGHT:
                v15 = element;
                v16 = element->texInfo.textHeight;
                if ( v16 >= _wcslen((const wchar_t *)element->unistr) )
                    return 0;
                v17 = menu;
                v15->texInfo.textHeight = v16 + 1;
                jkGuiRend_UpdateAndDrawClickable(v15, v17, 1);
                return 0;
            case VK_DELETE:
                v23 = element;
                v24 = element->texInfo.textHeight;
                if ( v24 >= 0 )
                {
                    stdString_WstrRemoveCharsAt((wchar_t *)element->unistr, v24, 1);
                    jkGuiRend_UpdateAndDrawClickable(v23, menu, 1);
                }
                return 0;
            default:
                return 0;
        }
    }
    else if ( eventType == JKGUI_EVENT_CHAR )
    {
        v5 = element;
        v7 = element->unistr;
        if ( (uint16_t)a4 == VK_BACK )
        {
            v8 = element->texInfo.textHeight;
            if ( v8 > 0 )
            {
                element->texInfo.textHeight = v8 - 1;
                stdString_WstrRemoveCharsAt((wchar_t *)v7, v8 - 1, 1);
            }
        }

        else if ( stdFont_sub_4355B0(menu->fonts[element->textType], a4) )
        {
            if ( _wcslen((const wchar_t *)v7) < v5->selectedTextEntry - 1 )
            {
                wchar_t tmp_wchar[2] = {(wchar_t)a4, 0}; // Added: ensure null terminator
                stdString_wstrncat((wchar_t *)v7, v5->selectedTextEntry, v5->texInfo.textHeight, tmp_wchar);
                v11 = v5->texInfo.textHeight + 1;
                if ( v11 >= v5->selectedTextEntry - 1 )
                    v11 = v5->selectedTextEntry - 1;
                v5->texInfo.textHeight = v11;
            }
        }
        jkGuiRend_UpdateAndDrawClickable(v5, menu, 1);
        return 0;
    }
    else
    {
        return 0;
    }
    
    return 0;
}

void jkGuiRend_TextBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, BOOL redraw)
{
    const wchar_t *v4; // edi
    int32_t v9; // ecx
    int32_t v10; // ecx
    const wchar_t *v11; // edi
    int32_t v14; // edx
    int32_t v15; // eax
    int32_t v16; // edx
    int32_t v17; // ecx
    int32_t v18; // edi
    rdRect rect; // [esp+10h] [ebp-10h]
    
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, (rdRect *)&element->texInfo.maxTextEntries);
    v4 = element->wstr;
    if ( menu->focusedElement == element )
        jkGuiRend_DrawRect(vbuf, (rdRect *)&element->texInfo.maxTextEntries, menu->fillColor);
    jkGuiRend_DrawRect(vbuf, &element->rect, menu->fillColor);
    if ( element->texInfo.textHeight == element->texInfo.numTextEntries )
    {
        element->texInfo.numTextEntries = 0;
    }
    if (element->texInfo.numTextEntries > element->texInfo.textHeight)
        element->texInfo.numTextEntries = element->texInfo.textHeight;
    v10 = element->texInfo.numTextEntries;
    v14 = element->texInfo.textHeight - v10 + 1;
    v11 = &v4[v10];
    while ( stdFont_sub_435810(menu->fonts[element->textType], v11, v14) > element->rect.width - 6 )
    {
        ++v11;
        v14 = element->texInfo.textHeight - element->texInfo.numTextEntries++;
    }
    stdFont_Draw1(vbuf, menu->fonts[element->textType], element->rect.x + 3, element->rect.y + 3, element->rect.width - 3, v11, 1);
    if ( menu->focusedElement == element )
    {
        v15 = stdFont_sub_435810(menu->fonts[element->textType], v11, element->texInfo.textHeight - element->texInfo.numTextEntries);
        v16 = element->rect.y;
        v17 = element->rect.x;
        rect.x = element->rect.x + v15 + 3;
        rect.width = element->rect.width;
        rect.y = v16 + 3;
        v18 = element->rect.height;
        rect.width = 1;
        rect.height = v18 - 5;
        if ( rect.x + 1 < element->rect.width + v17 )
            jkGuiRend_DrawRect(vbuf, &rect, menu->textBoxCursorColor);
    }
}

void jkGuiRend_TextDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *outBuf, BOOL redraw)
{
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);

    if ( element->unistr )
        stdFont_Draw3(outBuf, menu->fonts[element->textType], element->rect.y, &element->rect, element->selectedTextEntry, element->wstr, 1);
}

int jkGuiRend_PicButtonEventHandler(jkGuiElement *element, jkGuiMenu *menu, int32_t a, int32_t b)
{
    if ( a )
        return 0;

    stdBitmap* bitmap = menu->ui_structs[element->selectedTextEntry];
    if ( bitmap )
    {
#ifdef JKGUI_SMOL_SCREEN
        element->rect = element->rectOrig;
        element->bIsSmolDirty = 1;
#endif
        if ( element->rect.x < 0 )
            element->rect.x = bitmap->xPos;
        if ( element->rect.y < 0 )
            element->rect.y = bitmap->yPos;
        if ( element->rect.width < 0 )
            element->rect.width = bitmap->mipSurfaces[0]->format.width;
        if ( element->rect.height < 0 )
            element->rect.height = bitmap->mipSurfaces[0]->format.height;
#ifdef JKGUI_SMOL_SCREEN
        jkGui_SmolScreenFixup(menu, 0);
#endif
    }

    return 1;
}

void jkGuiRend_PicButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, BOOL redraw)
{
    int32_t v4; // ebx
    rdRect rect; // [esp+Ch] [ebp-10h]

    v4 = 0;
    if ( menu->lastMouseOverClickable == element )
    {
        v4 = (v4 & 0xFFFFFF00) | (menu->lastMouseDownClickable == element);
        ++v4;
    }

    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);

    stdBitmap* bitmap = menu->ui_structs[element->selectedTextEntry];
    if ( bitmap )
    {
        rect.x = 0;
        rect.y = 0;

        rect.width = element->rect.width;
        if ( rect.width >= bitmap->mipSurfaces[v4]->format.width )
            rect.width = bitmap->mipSurfaces[v4]->format.width;

        rect.height = element->rect.height;
        if ( rect.height >= bitmap->mipSurfaces[v4]->format.height )
            rect.height = bitmap->mipSurfaces[v4]->format.height;

        stdDisplay_VBufferCopy(vbuf, bitmap->mipSurfaces[v4], element->rect.x, element->rect.y, &rect, 1);
    }
}

int jkGuiRend_TextButtonEventHandler(jkGuiElement *element, jkGuiMenu *menu, int32_t eventType, int32_t b)
{
    int32_t v5; // edi
    stdFont **v6; // edx
    int32_t v7; // eax

    if ( eventType )
        return 0;
    v5 = 3;
    v6 = &menu->fonts[element->textType];
    do
    {
        if ( *v6 )
        {
            v7 = element->rect.height;
            if ( v7 <= stdFont_GetHeight(*v6))
                v7 = stdFont_GetHeight(*v6);
            element->rect.height = v7;
        }
        ++v6;
        --v5;
    }
    while ( v5 );
    return 1;
}

void jkGuiRend_TextButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, BOOL redraw)
{
    int32_t v4; // ebx
    int32_t v5; // ebp

    v4 = 0;
    if ( menu->lastMouseOverClickable == element )
    {
        v4 = (v4 & 0xFFFFFF00) | (menu->lastMouseDownClickable == element);
        ++v4;
    }
    v5 = element->selectedTextEntry;
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    stdFont_Draw3(vbuf, menu->fonts[element->textType + v4], element->rect.y, &element->rect, v5, element->wstr, 1);
}

// Added functions
void jkGuiRend_FocusElementDir(jkGuiMenu *pMenu, int32_t dir)
{
    int32_t idx = 0;
    jkGuiElement* focusedElement = pMenu->focusedElement;
    if (focusedElement && !focusedElement->bIsVisible) {
        focusedElement = NULL;
    }
    if (!focusedElement)
        focusedElement = pMenu->lastMouseOverClickable;
    if (focusedElement && !focusedElement->bIsVisible) {
        focusedElement = NULL;
    }
    if (!focusedElement)
    {
        focusedElement = pMenu->paElements;
        while ( 1 )
        {
            if ( focusedElement->type == ELEMENT_END ) {
                focusedElement = &pMenu->paElements[0];
                break;
            }

            if ( !focusedElement->bIsVisible ) {
                focusedElement++;
                continue;
            }
            
            if (focusedElement->type != ELEMENT_TEXTBUTTON
                && focusedElement->type != ELEMENT_PICBUTTON
                && focusedElement->type != ELEMENT_CHECKBOX
                && focusedElement->type != ELEMENT_LISTBOX
                && focusedElement->type != ELEMENT_TEXTBOX
                && focusedElement->type != ELEMENT_SLIDER
                && focusedElement->type != ELEMENT_CUSTOM) {
                focusedElement++;
                continue;
            }

            break;
        }
    }

    if (focusedElement->type == ELEMENT_LISTBOX) {
        //printf("listbox\n");
        int32_t prev_selected = focusedElement->selectedTextEntry;
        if (dir == FOCUS_UP)
        {
            jkGuiRend_lastKeyScancode = 0;
            jkGuiRend_InvokeEvent(focusedElement, pMenu, JKGUI_EVENT_KEYDOWN, VK_UP);
            if (prev_selected != focusedElement->selectedTextEntry) {
                return;
            }
        }
        else if (dir == FOCUS_DOWN)
        {
            jkGuiRend_lastKeyScancode = 0;
            jkGuiRend_InvokeEvent(focusedElement, pMenu, JKGUI_EVENT_KEYDOWN, VK_DOWN);
            if (prev_selected != focusedElement->selectedTextEntry) {
                return;
            }
        }
    }

    rdRect curFocus = focusedElement->rect;
    // Move the current focus rect position to position of the corresponding edge
    if (dir == FOCUS_LEFT || dir == FOCUS_RIGHT)
    {
        // A left edge or a right edge
        curFocus.y += curFocus.height/2;
    }
    else if (dir == FOCUS_UP || dir == FOCUS_DOWN)
    {
        // A top edge or a bottom edge
        curFocus.x += curFocus.width/2;
    }

    if (dir == FOCUS_DOWN) {
        curFocus.y += curFocus.height-1;
    }
    else if (dir == FOCUS_RIGHT) {
        curFocus.x += curFocus.width-1;
    }

    // We're iterating through every element to narrow down which element is the closest
    // in the direction we're focusing. The "best candidate" is the element that is currently
    // the closest, and gets replaced when a closer one is found.
    jkGuiElement* iter = pMenu->paElements;
    jkGuiElement* bestCandidate = focusedElement;

    rdRect bcRect = bestCandidate->rect;
    if (dir == FOCUS_RIGHT || dir == FOCUS_DOWN) {
        bcRect = (rdRect){-10000,-10000,0,0};
    }
    else {
        bcRect = (rdRect){10000,10000,0,0};
    }

    while ( 1 )
    {
        if ( iter->type == ELEMENT_END ) {
            if (bestCandidate == focusedElement) {
                //printf("Failed to find element.\n");
                //return;
            }
            break;
        }

        if ( !iter->bIsVisible ) {
            iter++;
            continue;
        }

        if (iter == focusedElement) {
            iter++;
            continue;
        }
        /*if ( iter->enableHover ) {
            iter++;
            continue;
        }*/
        

        if (iter->type != ELEMENT_LISTBOX && !iter->enableHover) {
            //iter++;
            //continue;
        }

        if (iter->type != ELEMENT_TEXTBUTTON
            && iter->type != ELEMENT_PICBUTTON
            && iter->type != ELEMENT_CHECKBOX
            && iter->type != ELEMENT_LISTBOX
            && iter->type != ELEMENT_TEXTBOX
            && iter->type != ELEMENT_SLIDER
            && iter->type != ELEMENT_CUSTOM) {
            iter++;
            continue;
        }

        rdRect rect = iter->rect;

        // Move the iter rect position to the opposing edge
        // (ie, FOCUS_RIGHT will jump from the right side of the 
        //  current element to the left side of the next element)
        if (dir == FOCUS_LEFT || dir == FOCUS_RIGHT)
        {
            // A left edge or a right edge
            rect.y += rect.height/2;
        }
        else if (dir == FOCUS_UP || dir == FOCUS_DOWN)
        {
            // A top edge or a bottom edge
            rect.x += rect.width/2;
        }

        if (dir == FOCUS_UP) {
            rect.y += rect.height;
        }
        else if (dir == FOCUS_LEFT) {
            rect.x += rect.width;
        }

        //printf("%u %u\n", abs(rect.y - curFocus.y), abs(bcRect.y - curFocus.y));
        //int bDistCloseX = abs(rect.x - curFocus.x) < abs(bcRect.x - curFocus.x);
        //int bDistCloseY = abs(rect.y - curFocus.y) < abs(bcRect.y - curFocus.y);
        int32_t distCur = sqrt((rect.x - curFocus.x)*(rect.x - curFocus.x) + (rect.y - curFocus.y)*(rect.y - curFocus.y));
        int32_t distBc = sqrt((bcRect.x - curFocus.x)*(bcRect.x - curFocus.x) + (bcRect.y - curFocus.y)*(bcRect.y - curFocus.y));
        int32_t bDistCloseX = distCur < distBc;
        int32_t bDistCloseY = bDistCloseX;
        BOOL containsPt = rdRect_ContainsPoint(&focusedElement->rect, rect.x, rect.y) || rdRect_ContainsPoint(&iter->rect, curFocus.x, curFocus.y); // In case elements overlap
        BOOL containsX = rect.x >= focusedElement->rect.x && rect.x <= focusedElement->rect.x + focusedElement->rect.width;
        // Most listboxes have action buttons under them, allow focusing to them with left/right
        BOOL isListbox = focusedElement->type == ELEMENT_LISTBOX;
        if (dir == FOCUS_LEFT)
        {
            if ((curFocus.x > rect.x || containsPt || isListbox) && bDistCloseX && bDistCloseY) {
                bestCandidate = iter;
            }
        }
        else if (dir == FOCUS_RIGHT)
        {
            if ((curFocus.x < rect.x || containsPt || isListbox) && bDistCloseX && bDistCloseY) {
                bestCandidate = iter;
            }
        }
        else if (dir == FOCUS_UP)
        {
            if ((curFocus.y > rect.y || containsPt) && bDistCloseX && bDistCloseY) {
                bestCandidate = iter;
            }
        }
        else if (dir == FOCUS_DOWN)
        {
            if ((curFocus.y < rect.y || containsPt) && bDistCloseX && bDistCloseY) {
                bestCandidate = iter;
            }
        }

        if (bestCandidate == iter) {
            bcRect = rect;
        }

#if 0
        if (bestCandidate == iter) {
            printf("* %u->%u, cur=%u %u, nxt=%u %u, %u %u%c\n", (int)(focusedElement - pMenu->paElements), (int)(bestCandidate - pMenu->paElements), curFocus.x, curFocus.y, rect.x, rect.y, distCur, distBc, bDistCloseX?'!':'x');
        }
        else {
            printf("%u->%u, cur=%u %u, nxt=%u %u, %u %u%c\n", (int)(focusedElement - pMenu->paElements), (int)(iter - pMenu->paElements), curFocus.x, curFocus.y, rect.x, rect.y, distCur, distBc, bDistCloseX?'!':'x');
        }
#endif
        
        iter++;
    }

    //printf("%u->%u, %u %u, %u %u\n", (int)(focusedElement - pMenu->paElements), (int)(bestCandidate - pMenu->paElements), focusedElement->rect.x, focusedElement->rect.y, bestCandidate->rect.x, bestCandidate->rect.y);

    jkGuiElement* element = bestCandidate;
    if (!element) {
        return;
    }
    if ((element->type == ELEMENT_LISTBOX || element->type == ELEMENT_TEXTBOX) && jkGuiRend_sub_5103E0(element))
    {
//#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
        pMenu->focusedElement = element;
        pMenu->lastMouseOverClickable = element;
//#endif
        if ( focusedElement )
        {
            if ( focusedElement != element )
            {
                jkGuiRend_UpdateAndDrawClickable(focusedElement, pMenu, 1);
                goto LABEL_22;
            }
        }
        else
        {
LABEL_22:
            if ( focusedElement != element )
                jkGuiRend_UpdateAndDrawClickable(element, pMenu, 1);
        }
    }
    else {
        // focusedElement is for textboxes and listboxes only
        pMenu->focusedElement = NULL;
        //jkGuiRend_MouseMovedCallback(pMenu, bestCandidate->rect.x, bestCandidate->rect.y);
        jkGuiRend_ClickableMouseover(pMenu, bestCandidate);
    }
}

// Added: controller support
// TODO: QOL ifdef?
void jkGuiRend_UpdateController()
{
    static int lastB1 = 0;
    static int keyboardShowedLastUpdate = 0;
    stdControl_bControlsActive = 1; // HACK
    stdControl_ReadControls();

    int val = 0;
    if (stdControl_ReadKey(KEY_JOY1_HLEFT, &val) && val) {
        jkGuiRend_FocusElementDir(jkGuiRend_activeMenu, FOCUS_LEFT);
        printf("left\n");
    }
    if (stdControl_ReadKey(KEY_JOY1_HRIGHT, &val) && val) {
        jkGuiRend_FocusElementDir(jkGuiRend_activeMenu, FOCUS_RIGHT);
        printf("right\n");
    }
    if (stdControl_ReadKey(KEY_JOY1_HUP, &val) && val) {
        jkGuiRend_FocusElementDir(jkGuiRend_activeMenu, FOCUS_UP);
        printf("up\n");
    }
    if (stdControl_ReadKey(KEY_JOY1_HDOWN, &val) && val) {
        jkGuiRend_FocusElementDir(jkGuiRend_activeMenu, FOCUS_DOWN);
        stdPlatform_Printf("down\n");
    }
    if (stdControl_ReadKey(KEY_JOY1_B1, &val) && val) {
        lastB1 = val;
        //jkGuiRend_InvokeEvent(jkGuiRend_activeMenu->focusedElement, jkGuiRend_activeMenu, JKGUI_EVENT_KEYDOWN, VK_RETURN);
        jkGuiRend_WindowHandler(0, WM_KEYFIRST, VK_RETURN, 0, 0);
        //if (jkGuiRend_activeMenu->lastMouseOverClickable && jkGuiRend_activeMenu->lastMouseOverClickable->clickHandlerFunc )
        //    jkGuiRend_activeMenu->lastClicked = jkGuiRend_activeMenu->lastMouseOverClickable->clickHandlerFunc(jkGuiRend_activeMenu->lastMouseOverClickable, jkGuiRend_activeMenu, jkGuiRend_mouseX, jkGuiRend_mouseY, 1);
        jkGuiRend_activeMenu->lastMouseDownClickable = jkGuiRend_activeMenu->lastMouseOverClickable;
        jkGuiRend_InvokeClicked(jkGuiRend_activeMenu->lastMouseOverClickable, jkGuiRend_activeMenu, jkGuiRend_mouseX, jkGuiRend_mouseY, 1);
        printf("a\n");
    }
    else if (lastB1 && !val) {
        lastB1 = 0;
        jkGuiRend_activeMenu->lastMouseDownClickable = 0;
    }
    if (stdControl_ReadKey(KEY_JOY1_B2, &val) && val) {
        jkGuiRend_WindowHandler(0, WM_KEYFIRST, VK_ESCAPE, 0, 0);
        stdPlatform_Printf("b\n");
        printf("b\n");
    }
    if (stdControl_ReadKey(KEY_JOY1_B3, &val) && val) {
        //jkGuiRend_WindowHandler(0, WM_KEYFIRST, VK_TAB, 0, 0);
        printf("x\n");
        if (jkGuiRend_activeMenu->pReturnKeyShortcutElement) {
            jkGuiRend_InvokeClicked(jkGuiRend_activeMenu->pReturnKeyShortcutElement, jkGuiRend_activeMenu, jkGuiRend_mouseX, jkGuiRend_mouseY, 1);
        }
    }

    if (jkGuiRend_activeMenu->lastMouseOverClickable && jkGuiRend_activeMenu->lastMouseOverClickable->type == ELEMENT_TEXTBOX) {
        keyboardShowedLastUpdate = 1;
        stdControl_ShowSystemKeyboard();
    }
    // Start Over to Escape sending
    if(stdControl_ReadKey(KEY_JOY1_B10, &val) && val) {
                jkGuiRend_WindowHandler(0, WM_KEYFIRST, VK_ESCAPE, 0, 0);

        stdPlatform_Printf("PLUS PRESSED \n");
    }

    else if (keyboardShowedLastUpdate) {
        stdControl_HideSystemKeyboard();
    }
}