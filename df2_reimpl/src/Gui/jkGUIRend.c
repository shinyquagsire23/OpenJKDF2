#include "jkGUIRend.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Primitives/rdVector.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdControl.h"
#include "Win95/Window.h"
#include "Win95/stdGdi.h"
#include "Win95/stdSound.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

static char *jkGuiRend_LoadedSounds[4];
static uint8_t jkGuiRend_palette[0x300];
static int jkGuiRend_idk2;
static int jkGuiRend_idk;
static LPDIRECTSOUNDBUFFER jkGuiRend_DsoundHandles[4];
static jkGuiMenu *jkGuiRend_activeMenu;
static stdVBuffer* jkGuiRend_menuBuffer;
static stdVBuffer *jkGuiRend_texture_dword_8561E8;

static int jkGuiRend_thing_five;
static int jkGuiRend_thing_four;
static int jkGuiRend_bIsSurfaceValid;
static int jkGuiRend_bInitted;
static int jkGuiRend_bOpen;
static int jkGuiRend_HandlerIsSet;
static int jkGuiRend_fillColor;
static int jkGuiRend_paletteChecksum;
static int jkGuiRend_dword_85620C;
static int jkGuiRend_lastKeyScancode;
static int jkGuiRend_mouseX;
static int jkGuiRend_mouseY;
static int jkGuiRend_bShiftDown;
static int jkGuiRend_mouseXLatest;
static int jkGuiRend_mouseYLatest;
static int jkGuiRend_mouseLatestMs;
static HCURSOR jkGuiRend_hCursor;

static int jkGuiRend_CursorVisible = 1;
static jkGuiElementHandlers jkGuiRend_elementHandlers[8] = 
{
    {jkGuiRend_TextButtonButtonDown, jkGuiRend_TextButtonDraw, jkGuiRend_PlayClickSound},
    {jkGuiRend_PicButtonButtonDown, jkGuiRend_PicButtonDraw, jkGuiRend_PlayClickSound},
    {NULL, jkGuiRend_TextDraw, NULL},
    {NULL, jkGuiRend_CheckBoxDraw, jkGuiRend_DrawClickableAndUpdatebool},
    {jkGuiRend_ListBoxButtonDown, jkGuiRend_ListBoxDraw, jkGuiRend_ClickSound},
    {jkGuiRend_TextBoxButtonDown, jkGuiRend_TextBoxDraw, NULL},
    {jkGuiRend_SliderButtonDown, jkGuiRend_SliderDraw, NULL},
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
    _memcpy(jkGuiRend_palette, pal, 0x300); // TODO sizeof(jkGuiRend_palette)
}

void jkGuiRend_DrawRect(stdVBuffer *vbuf, rdRect *rect, int16_t color)
{
    int v12; // edx
    int v14; // edi
    int v20; // ebx
    int v21; // ebp
    char *v22; // ecx
    int v23; // edi
    int v24; // esi
    int v26; // ecx
    int v27; // edi
    int v28; // ecx
    __int16 *v29; // esi
    int v30; // edx
    __int16 *v31; // ecx
    int v32; // edi
    char *v33; // ecx
    int v34; // edx
    int v35; // ebx
    int v36; // [esp+10h] [ebp-8h]

    if ( g_app_suspended && !jkGuiRend_bIsSurfaceValid )
    {
        int x = rect->x;
        if ( rect->x < 0 )
        {
            int w = rect->width;
            rect->x = 0;
            rect->width = x + w;
        }
        int y = rect->y;
        if ( y < 0 )
        {
            int h = rect->height;
            rect->y = 0;
            rect->height = y + h;
        }
        if ( rect->width + rect->x > vbuf->format.width )
            rect->width = vbuf->format.width - rect->x;
        if ( rect->height + rect->y > vbuf->format.height )
            rect->height = vbuf->format.height - rect->y;

        if ( stdDisplay_VBufferLock(vbuf) )
        {
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
            return;
        }
    }
}

void jkGuiRend_UpdateDrawMenu(jkGuiMenu *menu)
{
    if ( g_app_suspended && !jkGuiRend_bIsSurfaceValid)
    {
        int idx = menu->clickableIdxIdk;
        if ( idx >= 0 )
        {
            jkGuiElement* clickable = menu->lastMouseOverClickable;
            if ( clickable && clickable->hintText && clickable->bIsVisible && !clickable->anonymous_9 )
                menu->clickables[idx].str = clickable->hintText;
            else
                menu->clickables[idx].str = 0;
            jkGuiRend_UpdateAndDrawClickable(&menu->clickables[menu->clickableIdxIdk], menu, 1);
        }
    }
}

void jkGuiRend_Paint(jkGuiMenu *menu)
{
    int ret;
    
    if ( g_app_suspended && !jkGuiRend_bIsSurfaceValid )
    {
        stdControl_ShowCursor(0);
        stdDisplay_SetMasterPalette(jkGuiRend_palette);
        if ( menu->texture )
            stdDisplay_VBufferCopy(jkGuiRend_menuBuffer, menu->texture, 0, 0, 0, 0);

        jkGuiElement* clickable = &menu->clickables[0];
        int clickableIdx = 0;
        while ( clickable->type != ELEMENT_END )
        {
            jkGuiRend_UpdateAndDrawClickable(clickable, menu, 0);
            clickable = &menu->clickables[++clickableIdx];
        }
        jkGuiRend_FlipAndDraw(menu, 0);

        jkGuiRend_UpdateCursor();
    }
}

void jkGuiRend_SetElementIdk(jkGuiElement *element, int idk)
{
    element->elementIdk = idk;
}

void jkGuiRend_MenuSetLastElement(jkGuiMenu *menu, jkGuiElement *element)
{
    menu->clickables_end = element;
}

void jkGuiRend_SetDisplayingStruct(jkGuiMenu *menu, jkGuiElement *element)
{
    menu->field_48 = element;
}

int jkGuiRend_DisplayAndReturnClicked(jkGuiMenu *menu)
{
    int msgret; // eax
    jkGuiMenu *lastActiveMenu;

    lastActiveMenu = jkGuiRend_activeMenu;
    ++jkGuiRend_thing_five;
    jkGuiRend_gui_sets_handler_framebufs(menu);
    
    jkGuiRend_SetCursorVisible(1);
    while ( !menu->lastButtonUp )
    {
        msgret = Window_MessageLoop();
        if ( jkGuiRend_thing_four && jkGuiRend_thing_five )
        {
            menu->lastButtonUp = -1;
        }
        else
        {
            jkGuiRend_thing_four = 0;
            if ( g_should_exit )
                exit(msgret);
            if ( menu->idkFunc && !menu->lastButtonUp )
                menu->idkFunc(menu);
        }
    }
    jkGuiRend_sub_50FDB0();
    --jkGuiRend_thing_five;
    jkGuiRend_activeMenu = lastActiveMenu;
    return menu->lastButtonUp;
}

void jkGuiRend_sub_50FAD0(jkGuiMenu *menu)
{
    int paletteChecksum;

    menu->focusedElement = 0;
    menu->lastMouseDownClickable = 0;
    menu->lastMouseOverClickable = 0;
    menu->lastButtonUp = 0;

    if ( menu->palette )
       jkGuiRend_SetPalette(menu->palette);

    paletteChecksum = 0;

    if ( jkGuiRend_palette )
    {
        for (int i = 0; i < 0x300; i++)
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
            stdDisplay_streamidk(jkGuiRend_menuBuffer, jkGuiRend_fillColor, 0);
            jkGuiRend_FlipAndDraw(jkGuiRend_activeMenu, 0);
        }
    }

    stdDisplay_SetMasterPalette(jkGuiRend_palette);

    jkGuiElement* clickable = menu->clickables;
    int idx = 0;
    while (clickable->type != ELEMENT_END)
    {
        _memset(&clickable->texInfo, 0, sizeof(clickable->texInfo));
        jkGuiRend_InvokeButtonDown(clickable, menu, 0, 0);
        clickable = &menu->clickables[++idx];
    }
    
    clickable = menu->clickables;
    idx = 0;
    if (clickable->type != ELEMENT_END )
    {
        idx = 0;
        while ( !jkGuiRend_sub_5103E0(&clickable[idx]) )
        {
            clickable = menu->clickables;
            ++idx;
            if ( menu->clickables[idx].type == ELEMENT_END )
            {
                jkGuiRend_UpdateMouse();
                jkGuiRend_ResetMouseLatestMs();
                return;
            }
        }
        menu->focusedElement = &menu->clickables[idx];
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
        Window_gui_gets_vars(&jkGuiRend_idk, &jkGuiRend_idk2);
        Window_gui_sets_funcs((int)jkGuiRend_DrawAndFlip, (int)jkGuiRend_Invalidate);
    }
    ++jkGuiRend_HandlerIsSet;
    
    jkGuiRend_Paint(menu);
}

int jkGuiRend_Menuidk()
{
    if ( jkGuiRend_activeMenu->lastButtonUp )
    {
        jkGuiRend_sub_50FDB0();
        return jkGuiRend_activeMenu->lastButtonUp;
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
        Window_gui_sets_funcs(jkGuiRend_idk, jkGuiRend_idk2);
    }
    jkGuiRend_activeMenu = 0;
}

void jkGuiRend_Initialize()
{
    jkGuiRend_bInitted = 1;
}

void jkGuiRend_Shutdown()
{
    jkGuiRend_bInitted = 0;
}

void jkGuiRend_Open(stdVBuffer *menuBuffer, stdVBuffer *otherBuf, int fillColor)
{
    jkGuiRend_menuBuffer = menuBuffer;
    jkGuiRend_texture_dword_8561E8 = otherBuf;
    jkGuiRend_fillColor = fillColor;
    jkGuiRend_bOpen = 1;
}

void jkGuiRend_Close()
{
    if ( jkGuiRend_bOpen )
    {
        jkGuiRend_menuBuffer = 0;
        jkGuiRend_texture_dword_8561E8 = 0;
        jkGuiRend_bOpen = 0;
    }
}

jkGuiElement* jkGuiRend_MenuGetClickableById(jkGuiMenu *menu, int id)
{
    jkGuiElement *result;

    result = menu->clickables;
    if ( menu->clickables->type == ELEMENT_END )
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
    int bufferMaxSize, samplesPerSec, bStereo, bitsPerSample, seekOffset;
    char tmp[256];

    if ( !fpath )
        return;

    for (int i = 0; i < 4; i++)
    {
        if ( jkGuiRend_LoadedSounds[i] && !__strcmpi(jkGuiRend_LoadedSounds[i], fpath) )
        {
            stdSound_BufferReset(jkGuiRend_DsoundHandles[i]);
            stdSound_BufferPlay(jkGuiRend_DsoundHandles[i], 0);
            return;
        }
    }

    IDirectSoundBuffer* newHandle = 0;
    _sprintf(tmp, "sound%c%s", 92, fpath);

    int fd = std_pHS->fileOpen(tmp, "rb");
    if ( fd )
    {
        uint32_t bufferLen = stdSound_ParseWav(fd, &samplesPerSec, &bitsPerSample, &bStereo, &seekOffset);
        if ( bufferLen )
        {
            newHandle = stdSound_BufferCreate(bStereo, samplesPerSec, bitsPerSample, bufferLen);
            if ( newHandle )
            {
                void* bufferData = stdSound_BufferSetData(newHandle, bufferLen, &bufferMaxSize);
                if ( bufferData && bufferMaxSize == bufferLen )
                {
                    std_pHS->fileRead(fd, bufferData, bufferLen);
                    stdSound_BufferUnlock(newHandle, bufferData, bufferMaxSize);
                    std_pHS->fileClose(fd);
                }
                else
                {
                    if ( bufferData )
                        stdSound_BufferUnlock(newHandle, bufferData, bufferMaxSize);
                    stdSound_BufferRelease(newHandle);
                    newHandle = 0;
                    return;
                }
            }
        }
        else
        {
            std_pHS->fileClose(fd);
        }
    }

    if ( newHandle )
    {
        if ( jkGuiRend_DsoundHandles[3] )
            stdSound_BufferRelease(jkGuiRend_DsoundHandles[3]);
            
        if ( jkGuiRend_LoadedSounds[3] )
            std_pHS->free(jkGuiRend_LoadedSounds[3]);

        _memcpy(&jkGuiRend_DsoundHandles[1], jkGuiRend_DsoundHandles, 0xCu);
        _memcpy(&jkGuiRend_LoadedSounds[1], jkGuiRend_LoadedSounds, 0xCu);
        jkGuiRend_DsoundHandles[0] = newHandle;
        char* soundPath = (char *)std_pHS->alloc(_strlen(fpath) + 1);
        _strcpy(soundPath, fpath);
        jkGuiRend_LoadedSounds[0] = soundPath;
        stdSound_BufferPlay(newHandle, 0);
    }
}

void jkGuiRend_SetCursorVisible(int visible)
{
    jkGuiRend_CursorVisible = visible;
    jkGuiRend_UpdateCursor();
}

void jkGuiRend_UpdateCursor()
{
    int ret;

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
    if ( g_app_suspended )
    {
        if ( !jkGuiRend_bIsSurfaceValid )
        {
            stdDisplay_streamidk(jkGuiRend_menuBuffer, jkGuiRend_fillColor, 0);
            jkGuiRend_FlipAndDraw(jkGuiRend_activeMenu, 0);
        }
    }
}

void jkGuiRend_DrawAndFlip()
{
    stdDisplay_DrawAndFlipGdi();
    jkGuiRend_bIsSurfaceValid = 1;
}

void jkGuiRend_Invalidate()
{
    stdDisplay_SetCooperativeLevel();
    jkGuiRend_bIsSurfaceValid = 0;
    jkGuiRend_InvalidateGdi();
}

int jkGuiRend_DarrayNewStr(Darray *array, int num, int initVal)
{
    int result;

    result = Darray_New(array, sizeof(jkGuiStringEntry), num);
    array->bInitialized = initVal;
    return result;
}

int jkGuiRend_DarrayReallocStr(Darray *array, wchar_t *wStr, int id)
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
            v7 = (wchar_t *)std_pHS->alloc(2 * _wcslen(wStr) + 2);
            wStr = _wcscpy(v7, wStr);
        }
    }
    entry->str = wStr;
    entry->id = id;
    return 1;
}

int jkGuiRend_AddStringEntry(Darray *a1, const char *str, int id)
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

wchar_t* jkGuiRend_GetString(Darray *array, int idx)
{
    return ((jkGuiStringEntry*)Darray_GetIndex(array, idx))->str;
}

int jkGuiRend_GetId(Darray *array, int idx)
{
    return ((jkGuiStringEntry*)Darray_GetIndex(array, idx))->id;
}

jkGuiStringEntry* jkGuiRend_GetStringEntry(Darray *array, int idx)
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
        for (int i = 0; i < (signed int)array->total; ++i )
        {
            str = jkGuiRend_GetString(array, i);
            if (str)
                std_pHS->free(str);
        }
    }
    Darray_ClearAll(array);
}

int jkGuiRend_sub_5103E0(jkGuiElement *element)
{
    return (element->bIsVisible && !element->anonymous_9 && element->type >= 4 && element->type <= 5);
}

int jkGuiRend_ElementHasHoverSound(jkGuiElement *element)
{
    if ( !element->bIsVisible || element->anonymous_9 )
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

void jkGuiRend_UpdateAndDrawClickable(jkGuiElement *clickable, jkGuiMenu *menu, int forceRedraw)
{
    rdVector2i mousePos;

    if ( !g_app_suspended || jkGuiRend_bIsSurfaceValid )
        return;

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
        if ( clickable->anonymous_9 )
            menu->lastMouseOverClickable = 0;
        drawFunc(clickable, menu, jkGuiRend_menuBuffer, forceRedraw);
        menu->lastMouseOverClickable = lastSave;
        
        if ( forceRedraw )
            jkGuiRend_FlipAndDraw(menu, drawRect);
    }
    else if ( forceRedraw )
    {
        jkGuiRend_CopyVBuffer(menu, drawRect);

        if ( forceRedraw )
            jkGuiRend_FlipAndDraw(menu, drawRect);
    }

    
    if ( clickable->bIsVisible )
        goto LABEL_47;
    if ( menu->lastMouseOverClickable == clickable )
        menu->lastMouseOverClickable = 0;

    jkGuiRend_RenderIdk2(menu);
    if ( menu->lastMouseDownClickable == clickable )
        menu->lastMouseDownClickable = 0;
LABEL_47:
    if ( mousePos.x )
        stdControl_ShowCursor(1);
}

int jkGuiRend_InvokeButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, int a4)
{
    jkGuiButtonDownFunc_t handler;

    if ( element && (!a3 || element->bIsVisible && !element->anonymous_9) && (handler = jkGuiRend_elementHandlers[element->type].buttonDown) != 0 )
        return handler(element, menu, a3, a4);
    else
        return 0;
}

int jkGuiRend_InvokeButtonUp(jkGuiElement *clickable, jkGuiMenu *menu, int mouseX, int mouseY, int a5)
{
    jkGuiButtonUpFunc_t handler;

    if ( !clickable->bIsVisible || clickable->anonymous_9 )
        return 0;

    handler = clickable->func;
    if ( !handler )
    {
        handler = jkGuiRend_elementHandlers[clickable->type].buttonUp;
    }

    if (handler)
        menu->lastButtonUp = handler(clickable, menu, mouseX, mouseY, a5);

    return menu->lastButtonUp;
}

int jkGuiRend_PlayClickSound(jkGuiElement *element, jkGuiMenu *menu)
{
    jkGuiRend_PlayWav(menu->soundClick);
    return element->hoverId;
}

void jkGuiRend_RenderFocused(jkGuiMenu *menu, jkGuiElement *element)
{
    jkGuiElement *focusedElement; // edi

    focusedElement = menu->focusedElement;
    if ( element && element->bIsVisible && !element->anonymous_9 && element->type >= ELEMENT_LISTBOX && element->type <= ELEMENT_TEXTBOX )
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

void jkGuiRend_RenderIdk2(jkGuiMenu *menu)
{
    int idx = 0;
    jkGuiElement* focusedElement = menu->focusedElement;
    if ( focusedElement )
        idx = focusedElement - menu->clickables;

    int idxOther = idx + 1;
    if ( idx + 1 == idx )
        return;

    jkGuiElement* iter;
    while ( 1 )
    {
        iter = &menu->clickables[idxOther];
        if ( menu->clickables[idxOther].type != ELEMENT_END )
            break;
        idxOther = -1;
LABEL_12:
        if ( ++idxOther == idx )
            return;
    }
    if ( !iter->bIsVisible )
        goto LABEL_12;
    if ( iter->anonymous_9 )
        goto LABEL_12;
    if ( iter->type < ELEMENT_LISTBOX || iter->type > ELEMENT_TEXTBOX )
        goto LABEL_12;

    jkGuiElement* element = &menu->clickables[idxOther];
    if ( element && jkGuiRend_sub_5103E0(element) )
    {
        menu->focusedElement = element;
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

void jkGuiRend_RenderAll(jkGuiMenu *menu)
{
    jkGuiElement *focusedElement; // ebx
    int idx; // edx
    int idxOther; // eax
    jkGuiElement *clickables; // ecx
    int v5; // esi
    jkGuiElement *v6; // ecx
    jkGuiElement *iter; // esi

    focusedElement = menu->focusedElement;
    if ( focusedElement )
        idx = focusedElement - menu->clickables;
    else
        idx = 0;
    idxOther = idx - 1;
    if ( idx - 1 == idx )
        return;
    while ( 1 )
    {
        if ( idxOther < 0 )
        {
            clickables = menu->clickables;
            idxOther = 0;
            while ( clickables->type != ELEMENT_END )
            {
                ++clickables;
                ++idxOther;
            }
            goto LABEL_13;
        }
        v6 = &menu->clickables[idxOther];
        if ( v6->bIsVisible )
        {
            if ( !v6->anonymous_9 )
            {
                if ( v6->type >= ELEMENT_LISTBOX && v6->type <= ELEMENT_TEXTBOX )
                    break;
            }
        }
LABEL_13:
        if ( --idxOther == idx )
            return;
    }
    iter = &menu->clickables[idxOther];
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

void jkGuiRend_MouseMovedCallback(jkGuiMenu *menu, int x, int y)
{
    int v7; // edx
    jkGuiElement *v8; // ecx
    rdRect *v9; // eax
    int v10; // ecx

    jkGuiElement* lastMouseOverClickable = menu->lastMouseOverClickable;
    if ( !lastMouseOverClickable || !lastMouseOverClickable->bIsVisible || (x < lastMouseOverClickable->rect.x) || x >= lastMouseOverClickable->rect.x + lastMouseOverClickable->rect.width || (y < lastMouseOverClickable->rect.y) || y >= lastMouseOverClickable->rect.y + lastMouseOverClickable->rect.height )
    {
        v7 = 0;
        if ( menu->clickables->type == ELEMENT_END )
        {
            jkGuiRend_ClickableMouseover(menu, 0);
        }
        else
        {
            v8 = menu->clickables;
            while ( 1 )
            {
                v9 = &v8->rect;
                if ( v8->bIsVisible )
                {
                    if ( x >= v9->x && x < v9->x + v9->width )
                    {
                        v10 = v9->y;
                        if ( y >= v10 && y < v10 + v9->height )
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
            jkGuiRend_ClickableMouseover(menu, &menu->clickables[v7]);
        }
    }
}

void jkGuiRend_SetVisibleAndDraw(jkGuiElement *clickable, jkGuiMenu *menu, int bVisible)
{
    if ( clickable->bIsVisible != bVisible )
    {
        clickable->bIsVisible = bVisible;
        jkGuiRend_UpdateAndDrawClickable(clickable, menu, 1);
    }
}

void jkGuiRend_ClickableHover(jkGuiMenu *menu, jkGuiElement *element, int a3)
{
    int v4; // ebx
    int v5; // ebx
    int v6; // edx
    int v7; // ebx
    int v8; // ebp
    int v9; // eax
    int v10; // [esp+8h] [ebp-4h]
    int a1a; // [esp+14h] [ebp+8h]

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
            v8 = (int)menu;
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
    int v2; // ecx
    int v3; // ecx
    int v4; // esi
    int v5; // ecx
    int v6; // edi
    int v7; // edx
    int v8; // ecx

    v1 = element->unistr;
    element->texInfo.numTextEntries = 0;
    if ( v1 && v1->str )
    {
        do
        {
            v2 = element->texInfo.numTextEntries + 1;
            element->texInfo.numTextEntries = v2;
        }
        while ( v1[v2].str );
    }
    v3 = element->selectedTextEntry;
    if ( v3 < 0 )
    {
        v4 = 0;
    }
    else
    {
        v4 = element->texInfo.numTextEntries - 1;
        if ( v3 <= v4 )
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
        while ( 1 )
        {
            while ( 1 )
            {
                element->texInfo.textScrollY = v8;
                if ( v4 >= v8 )
                    break;
                --v8;
            }
            if ( v4 < v8 + v6 - 2 )
                break;
            ++v8;
        }
    }
}

int jkGuiRend_ClickSound(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int a5)
{
    if ( !a5 )
        return 0;
    jkGuiRend_PlayWav(menu->soundClick);
    return element->hoverId;
}

void jkGuiRend_HoverOn(jkGuiElement *element, jkGuiMenu *menu, int a3)
{
    element->selectedTextEntry += a3;
    jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
    jkGuiRend_PlayWav(menu->soundHover);
}

int jkGuiRend_ListBoxButtonDown(jkGuiElement *element, jkGuiMenu *menu, int mouseY, int mouseX)
{
    signed int result; // eax
    jkGuiElement *element_; // esi
    int v6; // ecx
    int v7; // eax
    int v8; // edi
    int v9; // edx
    int v10; // ebx
    int v11; // ebp
    int v12; // ebx
    int selectedIdx; // eax
    int maxTextEntries; // esi
    int v18; // edx
    signed int v19; // edi
    void *v20; // esi
    int v21; // eax
    int v22; // esi
    int v23; // eax
    rdRect *v24; // eax
    int v25; // edx
    int v26; // edx
    int v27; // esi
    int v28; // eax
    int a1a; // [esp+14h] [ebp+4h]

    if ( mouseY )
    {
        if ( mouseY == 1 )
        {
            jkGuiRend_GetMousePos(&mouseX, &mouseY);
            selectedIdx = (mouseY - element->rect.y - 3) / element->texInfo.textHeight;
            if ( selectedIdx >= 0 )
            {
                maxTextEntries = element->texInfo.maxTextEntries;
                if ( selectedIdx < maxTextEntries )
                {
                    v18 = selectedIdx + element->texInfo.textScrollY;
                    if ( element->texInfo.numTextEntries > maxTextEntries )
                    {
                        if ( !selectedIdx )
                        {
                            jkGuiRend_ClickableHover(menu, element, -1);
                            jkGuiRend_ResetMouseLatestMs();
                            return 0;
                        }
                        if ( selectedIdx == maxTextEntries - 1 )
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
        else
        {
            if ( mouseY != 4 )
                return 0;
            element_ = element;
            v6 = element->selectedTextEntry;
            v7 = element->texInfo.textHeight;
            v8 = element->rect.y;
            v9 = v7 * (element->selectedTextEntry - element->texInfo.textScrollY);
            v10 = element->rect.x;
            a1a = element->selectedTextEntry;
            v11 = v9 + v8 + 4;
            v12 = v10 + 1;
            if ( element_->texInfo.numTextEntries > element_->texInfo.maxTextEntries )
                v11 += v7;
            switch ( mouseX )
            {
                case 13:
                    if ( element_->func )
                        menu->lastButtonUp = element_->func(element_, menu, v12, v11, 1);
                    break;
                case 27:
                    if ( element_->func )
                    {
                        element_->texInfo.anonymous_18 = 1;
                        menu->lastButtonUp = element_->func(element_, menu, v12, v11, 0);
                        element_->texInfo.anonymous_18 = 0;
                    }
                    break;
                case 33:
                    jkGuiRend_ClickableHover(menu, element_, -1);
                    break;
                case 34:
                    jkGuiRend_ClickableHover(menu, element_, 1);
                    break;
                case 38:
                    element_->selectedTextEntry = v6 - 1;
                    jkGuiRend_UpdateAndDrawClickable(element_, menu, 1);
                    jkGuiRend_PlayWav(menu->soundHover);
                    break;
                case 40:
                    element_->selectedTextEntry = v6 + 1;
                    jkGuiRend_UpdateAndDrawClickable(element_, menu, 1);
                    jkGuiRend_PlayWav(menu->soundHover);
                    break;
                default:
                    break;
            }
            if ( element_->selectedTextEntry != a1a )
            {
                if ( element_->func )
                {
                    menu->lastButtonUp = element_->func(element_, menu, v12, v11, 0);
                    return 0;
                }
            }
        }
        result = 0;
    }
    else
    {
        v19 = 2;
        v20 = (char *)menu->anonymous_6 + 4 * element->field_8;
        do
        {
            if ( *(uint32_t *)v20 )
            {
                v21 = element->texInfo.textHeight;
                if ( v21 <= *(uint32_t *)(**(uint32_t **)(*(uint32_t *)(*(uint32_t *)v20 + 44) + 120) + 16) )
                    v21 = *(uint32_t *)(**(uint32_t **)(*(uint32_t *)(*(uint32_t *)v20 + 44) + 120) + 16);
                element->texInfo.textHeight = v21;
            }
            v20 = (char *)v20 + 4;
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
        result = 1;
    }
    return result;
}

void jkGuiRend_ListBoxDraw(jkGuiElement *element_, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    uint32_t *v6; // eax
    int v10; // eax
    int v11; // ecx
    int v12; // edi
    int mipLevel; // eax
    int v15; // eax
    jkGuiStringEntry* v16; // ebp
    int v17; // eax
    int v19; // eax
    stdBitmap *v20; // [esp+10h] [ebp-20h]
    stdBitmap *v21; // [esp+14h] [ebp-1Ch]
    rdRect renderRect; // [esp+20h] [ebp-10h]
    int element; // [esp+34h] [ebp+4h]

    v6 = element_->anonymous_13;
    v20 = menu->ui_structs[*v6];
    v21 = menu->ui_structs[v6[1]];
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
            else if ( mipLevel > v20->numMips - 1 )
            {
                mipLevel = v20->numMips - 1;
            }
            renderRect.y = 0;
            renderRect.x = 0;
            renderRect.width = v20->mipSurfaces[mipLevel]->format.width;
            renderRect.height = v20->mipSurfaces[mipLevel]->format.height;
            v15 = element_->texInfo.textHeight - renderRect.height;
            stdDisplay_VBufferCopy(vbuf, v20->mipSurfaces[mipLevel], v11 + (element_->rect.width - renderRect.width) / 2, v12 + v15 / 2, &renderRect, 1);
            v12 += element_->texInfo.textHeight;
        }
        for (int i = element_->texInfo.textScrollY; i <= element; i++)
        {
            v16 = &element_->unistr[i];
            stdFont_sub_434EC0(
                vbuf,
                *((uint32_t *)menu->anonymous_6 + element_->field_8 + (i == element_->selectedTextEntry)),
                v11,
                v12,
                element_->rect.width - 6,
                menu->anonymous_7,
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
            else if ( v17 > v21->numMips - 1 )
            {
                v17 = v21->numMips - 1;
            }
            renderRect.y = 0;
            renderRect.x = 0;
            renderRect.width = v21->mipSurfaces[v17]->format.width;
            v19 = element_->texInfo.textHeight - v21->mipSurfaces[v17]->format.height;
            renderRect.height = v21->mipSurfaces[v17]->format.height;
            stdDisplay_VBufferCopy(vbuf, v21->mipSurfaces[v17], v11 + (element_->rect.width - renderRect.width) / 2, v12 + v19 / 2, &renderRect, 1);
        }
    }
}

void jkGuiRend_CheckBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    stdBitmap *v4; // ebp
    int v5; // eax
    stdVBuffer *v6; // ecx
    signed int v7; // eax
    int v9; // edx
    int v10; // ebx
    int v11; // eax
    stdVBuffer **v12; // eax
    jkGuiElement *v14; // ebp
    int v15; // eax
    uint32_t *v16; // ecx
    int v17; // ebx
    rdRect drawRect; // [esp+10h] [ebp-10h]
    int a4a; // [esp+30h] [ebp+10h]

    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    v4 = menu->ui_structs[menu->anonymous_3];
    v6 = v4->mipSurfaces[(element->selectedTextEntry != 0) ? 1 : 0];
    v7 = (unsigned int)(element->rect.height - v6->format.height) / 2;
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
        v12 = v4->mipSurfaces;
        drawRect.width = v10;
        v14 = menu->lastMouseOverClickable;
        v15 = v6->format.width + 4;
        v16 = menu->anonymous_6;
        drawRect.width = v10 - v15;
        v17 = element->field_8;
        drawRect.x = v15 + v9;
        stdFont_Draw3(vbuf, v16[v17 + (v14 == element)], element->rect.y, &drawRect, 2, element->unistr, 1);
    }
}

int jkGuiRend_DrawClickableAndUpdatebool(jkGuiElement *element, jkGuiMenu *menu)
{
    element->selectedTextEntry = element->selectedTextEntry == 0;
    jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
    return 0;
}

int jkGuiRend_WindowHandler(HWND hWnd, unsigned int a2, int wParam, unsigned int lParam)
{
    int ret;
    jkGuiElement *v8; // eax
    int mouseX; // eax
    int mouseY; // ecx
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
                jkGuiRend_InvokeButtonDown(jkGuiRend_activeMenu->lastMouseDownClickable, jkGuiRend_activeMenu, 1, wParam);
            }
            return 0;
        }

        case WM_LBUTTONUP:
        {
            if ( jkGuiRend_activeMenu->lastMouseDownClickable )
            {
                if ( jkGuiRend_activeMenu->lastMouseDownClickable == jkGuiRend_activeMenu->lastMouseOverClickable )
                {
                    int redraw = 0;
                    int timeMs = stdPlatform_GetTimeMsec();
                    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
                    {
                        GetCursorPos((LPPOINT)&Rect);
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
                    jkGuiRend_InvokeButtonUp(jkGuiRend_activeMenu->lastMouseOverClickable, jkGuiRend_activeMenu, mouseX, mouseY, redraw);
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
            jkGuiRend_mouseX = (unsigned __int16)lParam;
            jkGuiRend_mouseY = lParam >> 16;
            jkGuiRend_UpdateMouse();
            if ( jkGuiRend_activeMenu->lastMouseDownClickable )
                jkGuiRend_InvokeButtonDown(jkGuiRend_activeMenu->lastMouseDownClickable, jkGuiRend_activeMenu, 3, wParam);
            return 1;

        case WM_KEYFIRST:
            if ( wParam == 0x10 || wParam == 0xA0 || wParam == 0xA1 )
                jkGuiRend_bShiftDown = 1;
            if ( wParam != 0xD || (v8 = jkGuiRend_activeMenu->clickables_end) == 0 || v8->anonymous_9 || !v8->bIsVisible )
            {
                if ( wParam != 0x1B || (v8 = jkGuiRend_activeMenu->field_48) == 0 || v8->anonymous_9 || !v8->bIsVisible )
                {
                    if ( wParam == 9 )  // TAB
                    {
                        if ( jkGuiRend_bShiftDown )
                            jkGuiRend_RenderAll(jkGuiRend_activeMenu);
                        else
                            jkGuiRend_RenderIdk2(jkGuiRend_activeMenu);
                        jkGuiRend_lastKeyScancode = lParam & 0xFF0000;
                        return 1;
                    }
                    v8 = jkGuiRend_activeMenu->clickables;
                    if ( jkGuiRend_activeMenu->clickables->type == ELEMENT_END )
                    {
LABEL_47:
                        jkGuiRend_lastKeyScancode = 0;
                        jkGuiRend_InvokeButtonDown(jkGuiRend_activeMenu->focusedElement, jkGuiRend_activeMenu, 4, wParam);
                        return 0;
                    }
                    while ( wParam != v8->elementIdk || v8->anonymous_9 || !v8->bIsVisible )
                    {
                        ++v8;
                        if ( v8->type == ELEMENT_END )
                            goto LABEL_47;
                    }
                }
            }
            jkGuiRend_InvokeButtonUp(v8, jkGuiRend_activeMenu, v8->rect.x + 1, v8->rect.y + 1, 0);
            jkGuiRend_lastKeyScancode = lParam & 0xFF0000;
            return 1;

        case WM_KEYUP:
            if ( wParam == 0x10 || wParam == 0xA0 || wParam == 0xA1 )
            {
                jkGuiRend_bShiftDown = 0;
                return 0;
            }
            break;

        case WM_CHAR:
            if ( (jkGuiRend_lastKeyScancode != 0xFF0000) & (uint8_t)lParam )
                jkGuiRend_InvokeButtonDown(jkGuiRend_activeMenu->focusedElement, jkGuiRend_activeMenu, 5, wParam);
            jkGuiRend_lastKeyScancode = 0;
            return 0;

        case WM_PAINT:
        {
            ret = GetUpdateRect(hWnd, (LPRECT)&Rect, 0);
            if ( ret )
                BeginPaint(hWnd, &Paint);
            jkGuiRend_Paint(jkGuiRend_activeMenu);
            if ( ret )
            {
                EndPaint(hWnd, &Paint);
                return 1;
            }
            return 1;
        }
        case WM_SETCURSOR:
        {
            if ( !jkGuiRend_hCursor )
            {
                jkGuiRend_hCursor = LoadCursorA(stdGdi_GetHInstance(), (LPCSTR)0x91D);
            }
            SetCursor(jkGuiRend_hCursor);
            return 1;
        }
    }
    return 0;
}

void jkGuiRend_UpdateMouse()
{
    int mouseX; // eax
    int mouseY; // ecx
    struct tagPOINT Point; // [esp+0h] [ebp-8h]

    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
    {
        GetCursorPos(&Point);
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
        stdDisplay_ddraw_surface_flip();
    }
}

void jkGuiRend_GetMousePos(int *pX, int *pY)
{
    struct tagPOINT Point; // [esp+0h] [ebp-8h]

    if ( stdDisplay_pCurDevice->video_device[0].windowedMaybe )
    {
        GetCursorPos(&Point);
        *(struct tagPOINT *)pX = Point;
    }
    else
    {
        *pX = jkGuiRend_mouseX;
        *pY = jkGuiRend_mouseY;
    }
}

void jkGuiRend_ResetMouseLatestMs()
{
    jkGuiRend_mouseLatestMs = 0;
}

void jkGuiRend_InvalidateGdi()
{
    InvalidateRect(stdGdi_GetHwnd(), 0, 1);
}

int jkGuiRend_SliderButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, signed int a4)
{
    signed int result; // eax
    int v7; // edi MAPDST
    int v8; // ecx
    int v9; // eax
    int v10; // ecx
    int v11; // ebx
    int v12; // edi
    int *v13; // ebp
    int v15; // ecx
    stdBitmap *v16; // ecx
    stdBitmap *v17; // edx
    unsigned int v18; // ecx
    int v19; // eax
    int v20; // ecx
    int v21; // eax
    signed int v22; // edx
    jkGuiElement *v23; // eax
    int v24; // ecx MAPDST
    jkGuiStringEntry *v26; // ecx
    jkGuiMenu *v27; // ST04_4
    jkGuiElement *v29; // eax
    int v30; // ecx
    int v31; // edx
    jkGuiStringEntry *v32; // ecx
    int v33; // [esp+0h] [ebp-1Ch]
    int v34; // [esp+10h] [ebp-Ch]


    switch ( a3 )
    {
        case 0:
            element->texInfo.textHeight = 0;
            return 0;
        case 1:
            goto LABEL_5;
        case 2:
            result = 0;
            element->texInfo.textHeight = 0;
            return result;
        case 3:
            if ( !element->texInfo.textHeight )
                return 1;
LABEL_5:
            v7 = element->selectedTextEntry;
            v7 = element->selectedTextEntry;
            jkGuiRend_GetMousePos((int *)&element, &v34);
            v8 = element->rect.x;
            if ( (signed int)element < v8 - 32
              || (v9 = element->rect.width, (signed int)element > v9 + v8 + 32)
              || (v10 = element->rect.y, v34 < v10 - 32)
              || v34 > element->rect.height + v10 + 32 )
            {
                element->selectedTextEntry = element->texInfo.numTextEntries;
            }
            else
            {
                v11 = 0;
                v12 = element->rect.width;
                if ( &v33 != (int *)-44 )
                    a4 = 0;
                v13 = (int *)element->anonymous_13;
                v15 = *v13;
                v16 = menu->ui_structs[v15];
                if ( v16 )
                {
                    v12 = (*v16->mipSurfaces)->format.width;
                    v11 = (v9 - v12) / 2;
                }
                v17 = menu->ui_structs[v13[1]];
                if ( v17 )
                {
                    v18 = (*v17->mipSurfaces)->format.width;
                    v12 -= v18;
                    if ( &v33 != (int *)-44 )
                    {
                        v19 = element->rect.x + v11 + element->selectedTextEntry * v12 / (uint32_t)element->unistr;
                        if ( (signed int)element >= v19 - 4 && (signed int)element < (signed int)(v19 + v18 + 4) )
                            a4 = 1;
                    }
                }
                v20 = (int)element->unistr;
                v21 = v20 * (signed int)((char *)element - v11 - element->rect.x) / v12;
                if ( v21 < 0 )
                {
                    v21 = 0;
                }
                else if ( v21 > v20 )
                {
                    element->selectedTextEntry = v20;
                    goto LABEL_24;
                }
                element->selectedTextEntry = v21;
            }
LABEL_24:
            if ( a3 == 1 )
            {
                v22 = a4;
                element->texInfo.numTextEntries = v7;
                element->texInfo.textHeight = v22;
            }
            if ( v7 == element->selectedTextEntry )
                return 0;
            jkGuiRend_UpdateAndDrawClickable(element, menu, 1);
            return 0;
        case 4:
            if ( a4 == 37 )
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
                    v32 = v29->unistr;
                    if ( v31 <= (signed int)v32 )
                        v32 = (jkGuiStringEntry *)v31;
                }
                v29->selectedTextEntry = (int)v32;
                jkGuiRend_UpdateAndDrawClickable(v29, menu, 1);
                return 0;
            }
            if ( a4 != 39 )
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
                v26 = v23->unistr;
                if ( v24 <= (signed int)v26 )
                {
                    v27 = menu;
                    v23->selectedTextEntry = v24;
                    jkGuiRend_UpdateAndDrawClickable(v23, v27, 1);
                    return 0;
                }
            }
            v23->selectedTextEntry = (int)v26;
            jkGuiRend_UpdateAndDrawClickable(v23, menu, 1);
            return 0;
        default:
            return 0;
    }
}

int jkGuiRend_SliderDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    unsigned int v6; // edi
    signed int *v7; // eax
    signed int v8; // ebx
    signed int result; // eax
    stdBitmap *v10; // ebx
    stdBitmap *v11; // ebp
    int v12; // ebp
    int v13; // ebx
    int v14; // ebp
    int v15; // ebx
    int v16; // eax
    stdVBuffer **v17; // edx
    stdVBuffer *v18; // edi
    int v19; // ecx
    unsigned int v20; // edi
    unsigned int blitX; // edx
    int v22; // ecx
    int v23; // eax
    int v24; // ecx
    int blitY; // edi
    int v26; // ebp
    int v27; // ecx
    int v28; // ecx
    uint32_t *v29; // edi
    stdBitmap *v31; // edx
    int v32; // ecx
    int v33; // ebp
    stdBitmap *v34; // ebx
    int v35; // eax
    unsigned int blitX2; // esi
    int blitY2; // edi
    stdVBuffer *v38; // edx
    int v39; // ecx
    unsigned int v40; // ebp
    int v41; // edx
    int v42; // edx
    unsigned int v43; // [esp+10h] [ebp-5Ch]
    stdBitmap *v44; // [esp+14h] [ebp-58h]
    int v45; // [esp+18h] [ebp-54h]
    unsigned int v46; // [esp+1Ch] [ebp-50h]
    int v47; // [esp+24h] [ebp-48h]
    int v48; // [esp+28h] [ebp-44h]
    rdRect drawRect; // [esp+2Ch] [ebp-40h]
    unsigned int blit_x; // [esp+3Ch] [ebp-30h]
    int blit_y; // [esp+40h] [ebp-2Ch]
    int v52; // [esp+44h] [ebp-28h]
    int v53; // [esp+48h] [ebp-24h]
    int v54; // [esp+50h] [ebp-1Ch]
    int v55; // [esp+58h] [ebp-14h]
    int v56; // [esp+64h] [ebp-8h]
    stdBitmap *elementa; // [esp+70h] [ebp+4h]
    jkGuiStringEntry *elementb; // [esp+70h] [ebp+4h]
    unsigned int redrawa; // [esp+7Ch] [ebp+10h]
    int redrawb; // [esp+7Ch] [ebp+10h]

    v6 = 0;
    v7 = (signed int *)element->anonymous_13;
    v43 = 0;
    v8 = v7[1];
    result = *v7;
    v10 = menu->ui_structs[v8];
    v11 = menu->ui_structs[result];
    v44 = v10;
    elementa = menu->ui_structs[result];
    if ( v10 && v11 )
    {
        if ( element == menu->lastMouseOverClickable )
        {
            v6 = 1;
            v43 = 1;
        }
        if ( redraw )
            jkGuiRend_CopyVBuffer(menu, &element->rect);
        v12 = v11->numMips;
        if ( v6 > v12 - 1 )
            v6 = v12 - 1;
        v13 = v10->numMips;
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
        v23 = v14 + (signed int)(v52 - v20) / 2;
        v24 = v15 + v22;
        v54 = v24;
        if ( v14 <= v23 )
            blitX = v14 + (signed int)(v52 - v20) / 2;
        blitY = v15;
        if ( v15 <= v24 )
            blitY = v24;
        v26 = v52 + v14;
        v27 = v23 + redrawa;
        v48 = v26;
        if ( v26 < (signed int)(v23 + redrawa) )
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
        v29 = element->anonymous_13;
        elementb = (jkGuiStringEntry *)element->selectedTextEntry;
        v31 = menu->ui_structs[*v29];
        v32 = 0;
        v33 = element->rect.width;
        if ( v31 )
        {
            v33 = (*v31->mipSurfaces)->format.width;
            v32 = (element->rect.width - v33) / 2;
        }
        v34 = menu->ui_structs[v29[1]];
        if ( v34 )
        {
            v33 -= (*v34->mipSurfaces)->format.width;
            v32 += v34->xPos;
        }
        if ( (signed int)elementb < 0 )
        {
            elementb = 0;
        }
        else if ( (signed int)elementb > (uint32_t)element->unistr )
        {
            elementb = element->unistr;
        }
        v35 = element->rect.x + v32 + v33 * (signed int)elementb / (uint32_t)element->unistr;
        blitX2 = blit_x;
        blitY2 = blit_y;
        v38 = v44->mipSurfaces[v43];
        v39 = blit_y + v47 + v44->yPos;
        v40 = v38->format.width;
        v55 = v38->format.height;
        if ( (signed int)blit_x <= v35 )
            blitX2 = v35;
        if ( blit_y <= v39 )
            blitY2 = v39;
        v41 = v35 + v40;
        if ( v48 < (signed int)(v35 + v40) )
            v41 = v48;
        v56 = v41 - blitX2;
        v42 = v39 + v55;
        if ( redrawb < v39 + v55 )
            v42 = redrawb;
        drawRect.width = v56;
        drawRect.height = v42 - blitY2;
        drawRect.x = blitX2 - v35;
        drawRect.y = blitY2 - v39;
        return stdDisplay_VBufferCopy(vbuf, v44->mipSurfaces[v43], blitX2, blitY2, &drawRect, 1);
    }
    return result;
}

int jkGuiRend_TextBoxButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, int a4)
{
    jkGuiElement *v5; // esi
    unsigned __int16 v6; // bx
    jkGuiStringEntry *v7; // edi
    int v8; // eax
    int v9; // ebp
    int v10; // ST08_4
    int v11; // eax
    int v12; // eax
    jkGuiMenu *v13; // ST08_4
    jkGuiElement *v14; // ST04_4
    jkGuiElement *v15; // esi
    unsigned int v16; // edi
    jkGuiMenu *v17; // ST08_4
    jkGuiMenu *v18; // ST08_4
    jkGuiElement *v19; // ST04_4
    jkGuiElement *v20; // esi
    size_t v21; // eax
    jkGuiMenu *v22; // ecx
    jkGuiElement *v23; // esi
    int v24; // eax
    jkGuiElement *v25; // esi
    int v26; // eax
    int v27; // eax
    int *v28; // eax
    int v29; // ebp
    int v30; // ebx
    const wchar_t *v31; // edx

    if ( a3 )
    {
        if ( a3 == 4 )
        {
            switch ( a4 )
            {
                case 35:
                    v20 = element;
                    v21 = _wcslen((const wchar_t *)element->unistr);
                    v22 = menu;
                    v20->texInfo.textHeight = v21;
                    jkGuiRend_UpdateAndDrawClickable(v20, v22, 1);
                    return 0;
                case 36:
                    v18 = menu;
                    v19 = element;
                    element->texInfo.textHeight = 0;
                    jkGuiRend_UpdateAndDrawClickable(v19, v18, 1);
                    return 0;
                case 37:
                    v12 = element->texInfo.textHeight;
                    if ( v12 <= 0 )
                        goto LABEL_23;
                    v13 = menu;
                    v14 = element;
                    element->texInfo.textHeight = v12 - 1;
                    jkGuiRend_UpdateAndDrawClickable(v14, v13, 1);
                    return 0;
                case 39:
                    v15 = element;
                    v16 = element->texInfo.textHeight;
                    if ( v16 >= _wcslen((const wchar_t *)element->unistr) )
                        goto LABEL_23;
                    v17 = menu;
                    v15->texInfo.textHeight = v16 + 1;
                    jkGuiRend_UpdateAndDrawClickable(v15, v17, 1);
                    return 0;
                case 46:
                    v23 = element;
                    v24 = element->texInfo.textHeight;
                    if ( v24 >= 0 )
                    {
                        stdString_wstrncpy((wchar_t *)element->unistr, v24, 1);
                        jkGuiRend_UpdateAndDrawClickable(v23, menu, 1);
                    }
                    goto LABEL_23;
                default:
LABEL_23:
                    return 0;
            }
        }
        else if ( a3 == 5 )
        {
            v5 = element;
            v6 = a4;
            v7 = element->unistr;
            if ( (uint16_t)a4 == 8 )
            {
                v8 = element->texInfo.textHeight;
                if ( v8 > 0 )
                {
                    element->texInfo.textHeight = v8 - 1;
                    stdString_wstrncpy((wchar_t *)v7, v8 - 1, 1);
                }
            }
            else if ( stdFont_sub_4355B0(*((uint32_t *)menu->anonymous_6 + element->field_8), a4) )
            {
                v9 = v5->selectedTextEntry;
                if ( _wcslen((const wchar_t *)v7) < v9 - 1 )
                {
                    v10 = v5->texInfo.textHeight;
                    element = (jkGuiElement *)v6;
                    stdString_wstrncat((wchar_t *)v7, v9, v10, (wchar_t *)&element);
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
    }
    else
    {
        v25 = element;
        v26 = *((uint32_t *)menu->anonymous_6 + element->field_8);
        if ( v26 )
        {
            v27 = *(uint32_t *)(**(uint32_t **)(*(uint32_t *)(v26 + 44) + 120) + 16) + 3;
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
    return 0;
}

void jkGuiRend_TextBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    jkGuiStringEntry *v4; // edi
    int v9; // ecx
    int v10; // ecx
    WCHAR *v11; // edi
    uint32_t *v12; // ecx
    int v13; // eax
    int v14; // edx
    int v15; // eax
    int v16; // edx
    int v17; // ecx
    int v18; // edi
    rdRect rect; // [esp+10h] [ebp-10h]

    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, (rdRect *)&element->texInfo.maxTextEntries);
    v4 = element->unistr;
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
    v11 = (WCHAR *)((char *)v4 + 2 * v10);
    if ( stdFont_sub_435810(*((uint32_t *)menu->anonymous_6 + element->field_8), v11, element->texInfo.textHeight - v10 + 1) > element->rect.width - 6 )
    {
        do
        {
            v12 = menu->anonymous_6;
            ++v11;
            v13 = element->field_8;
            v14 = element->texInfo.textHeight - element->texInfo.numTextEntries++;
        }
        while ( stdFont_sub_435810(v12[v13], v11, v14) > element->rect.width - 6 );
    }
    stdFont_Draw1(vbuf, *((stdFont **)menu->anonymous_6 + element->field_8), element->rect.x + 3, element->rect.y + 3, element->rect.width - 3, v11, 1);
    if ( menu->focusedElement == element )
    {
        v15 = stdFont_sub_435810(*((uint32_t *)menu->anonymous_6 + element->field_8), v11, element->texInfo.textHeight - element->texInfo.numTextEntries);
        v16 = element->rect.y;
        v17 = element->rect.x;
        rect.x = element->rect.x + v15 + 3;
        rect.width = element->rect.width;
        rect.y = v16 + 3;
        v18 = element->rect.height;
        rect.width = 1;
        rect.height = v18 - 5;
        if ( rect.x + 1 < element->rect.width + v17 )
            jkGuiRend_DrawRect(vbuf, &rect, menu->anonymous_1);
    }
}

void jkGuiRend_TextDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *outBuf, int redraw)
{
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);

    if ( element->unistr )
        stdFont_Draw3(outBuf, *((uint32_t *)menu->anonymous_6 + element->field_8), element->rect.y, &element->rect, element->selectedTextEntry, element->unistr, 1);
}

int jkGuiRend_PicButtonButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a, int b)
{
    if ( a )
        return 0;

    stdBitmap* bitmap = menu->ui_structs[element->selectedTextEntry];
    if ( bitmap )
    {
        if ( element->rect.x < 0 )
            element->rect.x = bitmap->xPos;
        if ( element->rect.y < 0 )
            element->rect.y = bitmap->yPos;
        if ( element->rect.width < 0 )
            element->rect.width = bitmap->mipSurfaces[0]->format.width;
        if ( element->rect.height < 0 )
            element->rect.height = bitmap->mipSurfaces[0]->format.height;
    }

    return 1;
}

void jkGuiRend_PicButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    int v4; // ebx
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

int jkGuiRend_TextButtonButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, int b)
{
    signed int v4; // edi
    char *v5; // edx
    int v6; // eax

    if ( a3 )
        return 0;
    v4 = 3;
    v5 = (char *)menu->anonymous_6 + 4 * element->field_8;
    do
    {
        if ( *(uint32_t *)v5 )
        {
            v6 = element->rect.height;
            if ( v6 <= *(uint32_t *)(**(uint32_t **)(*(uint32_t *)(*(uint32_t *)v5 + 44) + 120) + 16) )
                v6 = *(uint32_t *)(**(uint32_t **)(*(uint32_t *)(*(uint32_t *)v5 + 44) + 120) + 16);
            element->rect.height = v6;
        }
        v5 += 4;
        --v4;
    }
    while ( v4 );
    return 1;
}

void jkGuiRend_TextButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    int v4; // ebx
    int v5; // ebp

    v4 = 0;
    if ( menu->lastMouseOverClickable == element )
    {
        v4 = (v4 & 0xFFFFFF00) | (menu->lastMouseDownClickable == element);
        ++v4;
    }
    v5 = element->selectedTextEntry;
    if ( redraw )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    stdFont_Draw3(vbuf, *((uint32_t *)menu->anonymous_6 + v4 + element->field_8), element->rect.y, &element->rect, v5, element->unistr, 1);
}
