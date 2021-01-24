#include "jkGUIObjectives.h"

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
#include "World/jkPlayer.h"
#include "Win95/stdDisplay.h"
#include "Cog/jkCog.h"

static jkGuiStringEntry jkGuiObjectives_aTexts[50];

static jkGuiElement jkGuiObjectives_elements[6] = {
    {ELEMENT_TEXT,  0, 11, "GUI_OBJECTIVES",  3, {0x32, 0x32, 0x1F4, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  9,  0,  3, {0x32, 0x50, 0x1F4, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_CUSTOM,  0,  8,  0,  0, {0x28, 0x6E, 0x208, 0x122},  1,  0,  0, jkGuiObjectives_CustomRender,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  8,  0,  3, {0x28, 0x190, 0x208, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_PICBUTTON,  1,  0,  0, 20, {-1, -1, -1, -1},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_END,  0,  0,  0,  0, {0},  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiObjectives_menu = {jkGuiObjectives_elements, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiObjectives_CustomRender(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int a4)
{
    signed int v6; // esi
    int v7; // ebp
    int v8; // eax
    int v9; // ecx
    stdFont **v10; // edx
    int v11; // ebp
    int v12; // ebp
    wchar_t *v13; // [esp-8h] [ebp-34h]
    int v14; // [esp+10h] [ebp-1Ch]
    int v15; // [esp+14h] [ebp-18h]
    WCHAR *v16; // [esp+18h] [ebp-14h]
    rdRect drawRect; // [esp+1Ch] [ebp-10h] BYREF
    int elementa; // [esp+30h] [ebp+4h]
    jkGuiStringEntry *a4a; // [esp+3Ch] [ebp+10h]

    if ( a4 )
        jkGuiRend_CopyVBuffer(menu, &element->rect);
    v6 = element->rect.y;
    v14 = 0;
    v7 = stdFont_sub_4357C0(menu->fonts[8], jkGuiObjectives_aTexts[0].str, &element->rect);
    elementa = 0;
    a4a = jkGuiObjectives_aTexts;
    do
    {
        v15 = (__int64)sithInventory_GetBinAmount(g_localPlayerThing, elementa + SITHBIN_GOAL00);
        if ( (v15 & 1) != 0 )
        {
            v16 = a4a->str;
            if ( a4a->str )
            {
                v8 = element->field_8;
                ++v14;
                v9 = element->rect.x + 30;
                drawRect.width = element->rect.width - 30;
                v10 = menu->fonts;
                drawRect.x = v9;
                drawRect.y = v6;
                drawRect.height = v7 + (*v10[v8]->bitmap->mipSurfaces)->format.height;
                v11 = (unsigned __int8)(v15 & 4 | 0x10) >> 1;
                stdFont_Draw2(vbuf, v10[v11], v9, v6, &drawRect, v16, 1);
                v12 = stdFont_sub_4357C0(menu->fonts[v11], a4a->str, &drawRect);
                stdDisplay_VBufferCopy(
                    vbuf,
                    jkGui_stdBitmaps[16]->mipSurfaces[(unsigned __int8)(v15 & 2) >> 1],
                    element->rect.x,
                    v6 + ((unsigned int)(v12 - (*jkGui_stdBitmaps[16]->mipSurfaces)->format.height) >> 1),
                    0,
                    1);
                v7 = (*menu->fonts[element->field_8]->bitmap->mipSurfaces)->format.height + v12;
                v6 += v7;
            }
        }
        ++elementa;
        ++a4a;
    }
    while ( (intptr_t)a4a < (intptr_t)&jkGuiObjectives_aTexts[50] );
    if ( !v14 )
    {
        v13 = jkStrings_GetText("GUI_NO_OBJECTIVES");
        stdFont_Draw1(vbuf, menu->fonts[element->field_8], element->rect.x + 30, element->rect.y, element->rect.width, v13, 1);
    }
}

int jkGuiObjectives_Show()
{
    int v0; // ebx
    int v1; // esi
    jkGuiStringEntry *v2; // edi
    wchar_t *v3; // eax
    int v4; // esi
    double v5; // st7
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t *v9; // [esp-4h] [ebp-90h]
    wchar_t v10[32]; // [esp+Ch] [ebp-80h] BYREF
    char key[64]; // [esp+4Ch] [ebp-40h] BYREF

    memset(jkGuiObjectives_aTexts, 0, sizeof(jkGuiObjectives_aTexts));
    v0 = (__int64)sithInventory_GetBinAmount(g_localPlayerThing, 99);
    if ( v0 )
    {
        v1 = 0;
        v2 = jkGuiObjectives_aTexts;
        do
        {
            stdString_snprintf(key, 64, "GOAL_%05d", v0 + v1);
            v3 = stdStrTable_GetUniString(&jkCog_strings, key);
            if ( v3 )
                v2->str = v3;
            ++v2;
            ++v1;
        }
        while ( (intptr_t)v2 < (intptr_t)&jkGuiObjectives_aTexts[50] );
    }
    v4 = (__int64)sithPlayer_GetBinAmt(SITHBIN_SECRETS);
    v5 = sithPlayer_GetBinAmt(SITHBIN_MAXSECRETS);
    if ( (int)(__int64)v5 <= 0 )
    {
        v9 = jkStrings_GetText("GUI_NO_SECRETS");
        v7 = jkStrings_GetText("GUI_SECRETS_FOUND");
        jk_snwprintf(v10, 0x20u, L"%ls %ls", v7, v9);
    }
    else
    {
        v6 = jkStrings_GetText("GUI_SECRETS_FOUND");
        jk_snwprintf(v10, 0x20u, L"%ls %d/%d", v6, v4, (unsigned int)(__int64)v5);
    }
    jkGuiObjectives_elements[3].wstr = v10;
    jkGuiObjectives_elements[1].wstr = jkGui_sub_412ED0();
    return jkGuiRend_DisplayAndReturnClicked(&jkGuiObjectives_menu);
}

void jkGuiObjectives_Initialize()
{
    jkGui_InitMenu(&jkGuiObjectives_menu, jkGui_stdBitmaps[6]);
}

void jkGuiObjectives_Shutdown()
{
    ;
}
