#include "jkGUITitle.h"

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
#include "Cog/jkCog.h"
#include "Main/jkStrings.h"
#include "Win95/stdDisplay.h"
#include "World/sithWorld.h"
#include "General/stdString.h"
#include "General/stdFnames.h"

static wchar_t jkGuiTitle_versionBuffer[32];
static float jkGuiTitle_loadPercent;

static jkGuiElement jkGuiTitle_elementsLoad[5] = {
    {ELEMENT_TEXT,  0,  2,  0,  3, {250, 50, 390, 80},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_CUSTOM,  0,  0, .extraInt = 0xE1,  0, {330, 131, 240, 20},  1,  0,  0, jkGuiTitle_LoadBarDraw,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  0, "GUI_LOADING",  3, {330, 152, 240, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_CUSTOM,  0,  8,  0,  0, {310, 200, 280, 275},  1,  0,  0, jkGuiTitle_UnkDraw,  0,  0, {0},  0},
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiTitle_menuLoad = {jkGuiTitle_elementsLoad, 0xFFFFFFFF, 0xFF, 0xE1, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static jkGuiElement jkGuiTitle_elementsLoadStatic[6] = {
    {ELEMENT_TEXT,  0,  2, "GUI_LOADING",  3, {60, 280, 520, 30},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_CUSTOM,  0,  0, .extraInt = 0xE1,  0, {220, 240, 200, 20},  1,  0,  0, jkGuiTitle_LoadBarDraw,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  1, "GUI_COPYRIGHT1",  3, {10, 420, 620, 30},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  1, "GUI_COPYRIGHT2",  3, {10, 440, 620, 30},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  0,  0,  3, {560, 440, 70, 30},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiTitle_menuLoadStatic = {jkGuiTitle_elementsLoadStatic, 0xFFFFFFFF, 0xFF, 0xE3, 0x0F, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void jkGuiTitle_Initialize()
{
    jkGui_InitMenu(&jkGuiTitle_menuLoadStatic, jkGui_stdBitmaps[0]);
    jkGui_InitMenu(&jkGuiTitle_menuLoad, jkGui_stdBitmaps[5]);
}

void jkGuiTitle_Shutdown()
{
    ;
}

char jkGuiTitle_sub_4189A0(char *a1)
{
    char *v1; // esi
    char result; // al

    v1 = a1;
    for ( result = *a1; result; ++v1 )
    {
        *v1 = _string_modify_idk(*v1);
        result = v1[1];
    }
    return result;
}

wchar_t* jkGuiTitle_quicksave_related_func1(stdStrTable *strTable, char *jkl_fname)
{
    wchar_t *retval;
    jkGuiStringEntry *texts;
    char key[64];
    char tmp[64];

    stdFnames_CopyShortName(key, 64, jkl_fname);
    jkGuiTitle_sub_4189A0(key);

    retval = stdStrTable_GetUniString(strTable, key);
    if ( !retval )
        retval = jkStrings_GetText(key);

    texts = jkGuiTitle_aTexts;
    _memset(jkGuiTitle_aTexts, 0, sizeof(jkGuiTitle_aTexts));

    for (int i = 0; i < 20; i++)
    {
        stdString_snprintf(tmp, 64, "%s_TEXT_%02d", key, i);
        texts->str = stdStrTable_GetUniString(&jkCog_strings, tmp);
        ++texts;
    }

    return retval;
}

void jkGuiTitle_UnkDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4)
{
    int v4; // esi
    jkGuiStringEntry *v5; // ecx
    wchar_t *v6; // ebx
    signed int result; // eax
    int v8; // ecx
    int v9; // edi
    int v10; // edx
    int v11; // edx
    signed int v12; // edi
    stdFont **v13; // edx
    int v14; // esi
    rdRect a4a; // [esp+10h] [ebp-10h] BYREF
    jkGuiStringEntry *v16; // [esp+30h] [ebp+10h]

    if ( a4 )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    v4 = element->rect.y;
    v5 = jkGuiTitle_aTexts;
    v16 = jkGuiTitle_aTexts;
    
    for (int i = 0; i < 20; i++)
    {
        v6 = v5->str;
        result = 0;
        if ( v5->str )
        {
            if ( *v6 == '^' )
            {
                result = 2;
                ++v6;
            }
            v8 = element->rect.width;
            v9 = element->rect.y;
            a4a.x = element->rect.x;
            v10 = element->rect.height;
            a4a.width = v8;
            v11 = v9 + v10 - v4;
            v12 = result;
            a4a.height = v11;
            v13 = menu->fonts;
            a4a.y = v4;
            stdFont_Draw3(vbuf, v13[result], v4, &a4a, 1, v6, 1);
            v14 = stdFont_sub_4357C0(menu->fonts[v12], v6, &a4a) + v4;
            result = (*menu->fonts[v12]->bitmap->mipSurfaces)->format.height;
            v4 = ((unsigned int)(3 * result) >> 2) + v14;
            v5 = v16;
        }
        v16 = ++v5;
    }
}

void jkGuiTitle_LoadBarDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4)
{
    int v6; // ebx
    int v7; // eax
    int v8; // edx
    int v9; // ecx
    int v10; // esi
    rdRect a4a; // [esp+10h] [ebp-10h] BYREF
    int a3a; // [esp+24h] [ebp+4h]

    if ( g_app_suspended )
    {
        v6 = element->selectedTextEntry;
        if ( v6 < 0 )
        {
            v6 = 0;
        }
        else if ( v6 > 100 )
        {
            v6 = 100;
        }
        a3a = element->extraInt;
        element->selectedTextEntry = v6;
        if ( a4 )
            jkGuiRend_CopyVBuffer(menu, &element->rect);
        jkGuiRend_DrawRect(vbuf, &element->rect, menu->fillColor);
        v7 = element->rect.x;
        v8 = element->rect.width;
        a4a.y = element->rect.y + 3;
        v9 = v6 * (element->rect.width - 6);
        a4a.x = v7 + 3;
        a4a.width = v8;
        v10 = element->rect.height - 6;
        a4a.height = v10;
        a4a.width = v9 / 100;
        if ( v9 / 100 > 0 && v10 > 0 )
            stdDisplay_VBufferFill(vbuf, a3a, &a4a);
    }
}

void jkGuiTitle_WorldLoadCallback(float percentage)
{
    double v1; // st7

    if ( jkGuiTitle_loadPercent != (__int64)percentage )
    {
        jkGuiTitle_loadPercent = (__int64)percentage;
        if ( jkGuiTitle_whichLoading == 1 )
        {
            v1 = (percentage - 60.0) * 0.050000001 * 100.0;
            if ( v1 <= 5.0 )
                v1 = 5.0;
            jkGuiTitle_elementsLoadStatic[1].selectedTextEntry = (__int64)v1;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiTitle_elementsLoadStatic[1], &jkGuiTitle_menuLoadStatic, 1);
        }
        else
        {
            jkGuiTitle_elementsLoad[1].selectedTextEntry = (__int64)percentage;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiTitle_elementsLoad[1], &jkGuiTitle_menuLoad, 1);
        }
#ifdef SDL2_RENDER
#ifdef PLATFORM_POSIX
    static uint64_t lastRefresh = 0;
    // Only update loading bar at 30fps, so that we don't waste time
    // during vsync.
    if (Linux_TimeUs() - lastRefresh < 32*1000) {
        return;
    }

    lastRefresh = Linux_TimeUs();
#endif
    stdDisplay_DDrawGdiSurfaceFlip();
#endif
    }
}

void jkGuiTitle_ShowLoadingStatic()
{
    wchar_t *guiVersionStr; // eax
    int verMajor; // [esp-Ch] [ebp-2Ch]
    int verMinor; // [esp-8h] [ebp-28h]
    int verRevision; // [esp-4h] [ebp-24h]
    //wchar_t v4[16]; // [esp+0h] [ebp-20h] BYREF
    // Added: removed undefined behavior, used to use the stack.....

    jkGui_SetModeMenu(jkGui_stdBitmaps[0]->palette);
    jkGuiTitle_whichLoading = 1;
    sithWorld_SetLoadPercentCallback(jkGuiTitle_WorldLoadCallback);
    verRevision = jkGuiTitle_verRevision;
    verMinor = jkGuiTitle_verMinor;
    verMajor = jkGuiTitle_verMajor;
    guiVersionStr = jkStrings_GetText("GUI_VERSION");
    jk_snwprintf(jkGuiTitle_versionBuffer, sizeof(jkGuiTitle_versionBuffer), guiVersionStr, verMajor, verMinor, verRevision);
    jkGuiTitle_elementsLoadStatic[4].wstr = jkGuiTitle_versionBuffer;
    jkGuiTitle_elementsLoadStatic[1].selectedTextEntry = 0;
    jkGuiRend_gui_sets_handler_framebufs(&jkGuiTitle_menuLoadStatic);
}

void jkGuiTitle_ShowLoading(char *a1, wchar_t *a2)
{
    wchar_t *v4; // ebx
    int v6; // edi
    char key[64]; // [esp+Ch] [ebp-80h] BYREF
    char v8[64]; // [esp+4Ch] [ebp-40h] BYREF

    jkGui_SetModeMenu(jkGui_stdBitmaps[0]->palette);
    jkGuiTitle_whichLoading = 2;
    jkGuiRend_SetCursorVisible(0);
    sithWorld_SetLoadPercentCallback(jkGuiTitle_WorldLoadCallback);
    jkGuiTitle_elementsLoad[1].selectedTextEntry = 0;
    stdFnames_CopyShortName(key, 64, a1);
    jkGuiTitle_sub_4189A0(key);
    v4 = stdStrTable_GetUniString(&jkCog_strings, key);
    if ( !v4 )
        v4 = jkStrings_GetText(key);

    _memset(jkGuiTitle_aTexts, 0, sizeof(jkGuiTitle_aTexts));

    for (v6 = 0; v6 < 20; v6++)
    {
        stdString_snprintf(v8, 64, "%s_TEXT_%02d", key, v6);
        jkGuiTitle_aTexts[v6].str = stdStrTable_GetUniString(&jkCog_strings, v8);
    }

    jkGuiTitle_elementsLoad[0].wstr = a2;
    if ( !a2 )
        jkGuiTitle_elementsLoad[0].wstr = v4;
    jkGuiRend_gui_sets_handler_framebufs(&jkGuiTitle_menuLoad);
}

void jkGuiTitle_LoadingFinalize()
{
    jkGui_SetModeGame();
    sithWorld_SetLoadPercentCallback(0);
    jkGuiRend_sub_50FDB0();
}
