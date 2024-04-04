#include "jkGUIMouse.h"

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
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIControlSaveLoad.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"
#include "Main/jkStrings.h"
#include "Devices/sithControl.h"
#include "types.h"
#include "types_enums.h"

#include <math.h>
#include <float.h>

void jkGuiMouse_SensitivityDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

static const int jkGUIMouse_listbox_paddings = 0xAA;
static int jkGUIMouse_listbox_images[2] = {JKGUI_BM_UP_15, JKGUI_BM_DOWN_15};
static int jkGUIMouse_slider_images[2] = {JKGUI_BM_SLIDER_BACK_200, JKGUI_BM_SLIDER_THUMB};

#ifdef QOL_IMPROVEMENTS
static wchar_t slider_val_text[5] = {0};
#endif

static int jkGuiMouse_dword_530328 = -1;
static int jkGuiMouse_dword_53032C = -1;

#ifndef SDL2_RENDER
#define NUM_MOUSE_ENTRIES (7)
#else
#define NUM_MOUSE_ENTRIES (7+1)
#endif

static jkGuiMouseEntry jkGuiMouse_aEntries[NUM_MOUSE_ENTRIES+1] =
{
  { AXIS_MOUSE_X, "AXIS_MOUSE_X",  0, 0, NULL, 0, 0 },
  { AXIS_MOUSE_Y, "AXIS_MOUSE_Y",  0, 0, NULL, 0, 0  },
  { AXIS_MOUSE_Z, "AXIS_MOUSE_Z",  0, 0, NULL, 0, 0  },
  { KEY_MOUSE_B1, "KEY_MOUSE_B1",  0, 0, NULL, 0, 0  },
  { KEY_MOUSE_B2, "KEY_MOUSE_B2",  0, 0, NULL, 0, 0  },
  { KEY_MOUSE_B3, "KEY_MOUSE_B3",  0, 0, NULL, 0, 0  },
  { KEY_MOUSE_B4, "KEY_MOUSE_B4",  0, 0, NULL, 0, 0  },
#ifdef SDL2_RENDER
  { KEY_MOUSE_B5, "KEY_MOUSE_B5",  0, 0, NULL, 0, 0  },
  //{ KEY_MOUSE_B6, "KEY_MOUSE_B6",  0, 0, NULL, 0, 0  },
  //{ KEY_MOUSE_B7, "KEY_MOUSE_B7",  0, 0, NULL, 0, 0  },
  //{ KEY_MOUSE_B8, "KEY_MOUSE_B8",  0, 0, NULL, 0, 0  },
#endif
  { 0,   NULL,            0, 0, NULL, 0, 0  },
};

static jkGuiElement jkGuiMouse_aElements[26] =
{
    {ELEMENT_TEXT,        0,   0, NULL,                     3, {0, 410, 640, 20}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT,        0,   6, "GUI_SETUP",              3, {20, 20, 600, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  100, 2, "GUI_GENERAL",            3, {20, 80, 120, 40},  1, 0, "GUI_GENERAL_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  101, 2, "GUI_GAMEPLAY",           3, {140, 80, 120, 40}, 1, 0, "GUI_GAMEPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  102, 2, "GUI_DISPLAY",            3, {260, 80, 120, 40},  1, 0, "GUI_DISPLAY_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  103, 2, "GUI_SOUND",              3, {380, 80, 120, 40}, 1, 0, "GUI_SOUND_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  104, 2, "GUI_CONTROLS",           3, {500, 80, 120, 40}, 1, 0, "GUI_CONTROLS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  105, 2, "GUI_KEYBOARD",           3, {40, 120, 140, 40}, 1, 0, "GUI_KEYBOARD_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  106, 2, "GUI_MOUSE",              3, {180, 120, 140, 40},  1, 0, "GUI_MOUSE_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  107, 2, "GUI_JOYSTICK",           3, {320, 120, 140, 40}, 1, 0, "GUI_JOYSTICK_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON,  108, 2, "GUI_CONTROLOPTIONS",     3, {460, 120, 140,  40}, 1, 0, "GUI_CONTROLOPTIONS_HINT", 0, 0, 0, {0}, 0},
    {ELEMENT_LISTBOX,     0,   0, NULL,                     0, { 20, 170, 380, 141 }, 1, 0, "GUI_CONTROLSLIST_HINT", NULL, jkGuiMouse_ListClicked1, jkGUIMouse_listbox_images, {0}, 0},
    {ELEMENT_LISTBOX,     0,   0, NULL,                     0, { 420, 170, 200, 141 }, 1, 0, "GUI_CONTROLSLIST_HINT", NULL, jkGuiMouse_ListClicked2, jkGUIMouse_listbox_images, {0}, 0},
    {ELEMENT_LISTBOX,     0,   0, NULL,                     0, { 420, 170, 200, 141 }, 1, 0, "GUI_CONTROLSLIST_HINT", NULL, jkGuiMouse_ListClicked3, jkGUIMouse_listbox_images, {0}, 0},
    {ELEMENT_TEXTBUTTON,  0,   2, "GUI_ADD_CONTROL",        3, { 420, 190, 200, 40 }, 1, 0, "GUI_ADD_CONTROL_HINT", NULL, jkGuiMouse_AddEditControlsClicked, NULL, {0}, 0},
    {ELEMENT_TEXTBUTTON,  0,   2, "GUI_EDIT_CONTROL",       3, { 420, 190, 200, 40 }, 1, 0, "GUI_EDIT_CONTROL_HINT", NULL, jkGuiMouse_AddEditControlsClicked, NULL, {0}, 0},
    {ELEMENT_TEXTBUTTON,  0,   2, "GUI_REMOVE_CONTROL",     3, { 420, 230, 200, 40 }, 1, 0, "GUI_REMOVE_CONTROL_HINT", NULL, jkGuiMouse_RemoveClicked, NULL, {0}, 0},
    {ELEMENT_CHECKBOX,    0,   0, "GUI_REVERSE_AXIS",       0, { 320, 335, 300, 20 }, 1, 0, "GUI_REVERSE_HINT", NULL, NULL, NULL, {0}, 0},
    {ELEMENT_CHECKBOX,    0,   0, "GUI_CONTROL_RAW",        0, { 320, 365, 300, 20 }, 1, 0, "GUI_RAW_HINT", NULL, NULL, NULL, {0}, 0},
    {ELEMENT_TEXT,        0,   0, "GUI_SENSITIVITY",        2, { 50, 335, 170, 20 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0}, 
    {ELEMENT_SLIDER,      0,   0, (char *)200,             50, { 60, 355, 205, 30 }, 1, 0, "GUI_SENSITIVITY_HINT", jkGuiMouse_SensitivityDraw, NULL, jkGUIMouse_slider_images, {0}, 0},
    {ELEMENT_TEXTBUTTON,  1,   2, "GUI_OK",                 3, { 440, 430, 200, 40 }, 1, 0, NULL, NULL, jkGuiMouse_CancelOkClicked, NULL, {0}, 0},
    {ELEMENT_TEXTBUTTON, -1,   2, "GUI_CANCEL",             3, { 0, 430, 200, 40 }, 1, 0, NULL, NULL, jkGuiMouse_CancelOkClicked, NULL, {0}, 0},
    {ELEMENT_TEXTBUTTON,  0,   2, "GUI_RESTORE_DEFAULTS",   3, { 200, 430, 240, 40 }, 1, 0, NULL, NULL, jkGuiMouse_RestoreDefaultsClicked, NULL, {0}, 0},

#ifdef QOL_IMPROVEMENTS
    // 24
    {ELEMENT_TEXT,        0,   0, slider_val_text,        3, { 60, 385, 205, 20 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0}, 
#endif

    {ELEMENT_END,         0,   0, NULL,                     0, {0}, 0, 0, NULL, NULL, NULL, NULL, {0}, 0},
};

static jkGuiMenu jkGuiMouse_menu = {jkGuiMouse_aElements, 0, 225, 255, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, (intptr_t)&jkGUIMouse_listbox_paddings, NULL, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiMouse_SensitivityDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
#ifdef QOL_IMPROVEMENTS
    int val = jkGuiMouse_aElements[20].selectedTextEntry;
    
    jk_snwprintf(slider_val_text, 5, L"%u", val);
    jkGuiMouse_aElements[24].wstr = slider_val_text;
    
#endif
    jkGuiRend_SliderDraw(element, menu, vbuf, redraw);
    
    // Redraw text
    jkGuiRend_UpdateAndDrawClickable(&jkGuiMouse_aElements[24], menu, 1);
}

int jkGuiMouse_ListClicked1(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int redraw)
{
    signed int result; // eax

    jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, redraw);
    if ( pElement->texInfo.anonymous_18 )
    {
        jkGuiRend_PlayWav(pMenu->soundClick);
        result = -1;
    }
    else
    {
        if ( redraw )
            jkGuiMouse_dword_5566B0 = 1;
        jkGuiMouse_sub_416D40(pMenu, 1);
        result = 0;
    }
    return result;
}

void jkGuiMouse_sub_416D40(jkGuiMenu *pMenu, int a2)
{
    int v2; // ebx
    int v3; // eax
    int v4; // esi
    jkGuiMouseSubEntry *v5; // eax
    double v6; // st7
    jkGuiMenu *v7; // edi
    Darray *v8; // edi
    jkGuiElement *v9; // ebp
    jkGuiMouseSubEntry *v10; // eax
    int v11; // eax
    jkGuiMouseSubEntry *v12; // esi
    double v13; // st7
    unsigned int v14; // ecx
    int v15; // rax
    int v16; // eax
    jkGuiElement *v17; // eax
    int v18; // [esp+10h] [ebp-8h]

    int mouseX = 0;
    int mouseY = 0;

    while ( 1 )
    {
        v2 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, jkGuiMouse_aElements[11].selectedTextEntry);
        v3 = jkGuiMouse_dword_53032C;
        v18 = jkGuiMouse_aEntries[v2].inputFuncIdx;
        if ( v2 == jkGuiMouse_dword_53032C && jkGuiMouse_dword_5566B0 == jkGuiMouse_dword_530328 )
            break;
        v4 = 0;
        if ( jkGuiMouse_dword_53032C >= 0 && jkGuiMouse_aEntries[jkGuiMouse_dword_53032C].pSubEnt )
        {
            v5 = jkGuiMouse_aEntries[jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, jkGuiMouse_dword_53032C)].pSubEnt;
            if ( jkGuiMouse_aElements[20].bIsVisible )
            {
                // Adjusted: More granularity
                if ( jkGuiMouse_aElements[20].selectedTextEntry > 100 )
                    v6 = (double)(jkGuiMouse_aElements[20].selectedTextEntry - 100) * (3.0 / 100.0) - -1.0;
                else
                    v6 = (double)jkGuiMouse_aElements[20].selectedTextEntry * (1.0/100.0);
                v5->field_8 = v6;
            }
            if ( jkGuiMouse_aElements[18].bIsVisible )
                v5->bitflag = v5->bitflag & ~8u | (jkGuiMouse_aElements[18].selectedTextEntry != 0 ? 8 : 0);
            if ( jkGuiMouse_aElements[17].bIsVisible )
                v5->bitflag = v5->bitflag & ~4u | (jkGuiMouse_aElements[17].selectedTextEntry != 0 ? 0 : 4);
            v3 = jkGuiMouse_dword_53032C;
        }
        if ( !jkGuiMouse_dword_5566B0 )
        {
            v7 = pMenu;
            jkGuiMouse_aElements[13].bIsVisible = 0;
            jkGuiMouse_aElements[12].bIsVisible = 0;
            jkGuiMouse_aElements[15].bIsVisible = v18 != -1;
            jkGuiMouse_aElements[16].bIsVisible = v18 != -1;
            jkGuiMouse_aElements[14].bIsVisible = v18 == -1;
            jkGuiMouse_aElements[23].bIsVisible = 1;
            pMenu->focusedElement = &jkGuiMouse_aElements[11];
LABEL_30:
            if ( jkGuiMouse_dword_5566B0 || (v12 = jkGuiMouse_aEntries[v2].pSubEnt) == 0 || v2 >= 3 )
            {
                jkGuiMouse_aElements[17].bIsVisible = 0;
                jkGuiMouse_aElements[18].bIsVisible = 0;
                jkGuiMouse_aElements[19].bIsVisible = 0;
                jkGuiMouse_aElements[20].bIsVisible = 0;
            }
            else
            {
                v13 = v12->field_8;
                v14 = jkGuiMouse_aEntries[v2].flags;
                jkGuiMouse_aElements[17].bIsVisible = 1;
                jkGuiMouse_aElements[19].bIsVisible = 1;
                jkGuiMouse_aElements[18].bIsVisible = (v14 >> 3) & 1;
                jkGuiMouse_aElements[20].bIsVisible = 1;
                if ( v13 > 1.0 )
                    v15 = (__int64)ceilf(((v13 - 1.0) * (100.0 / 3.0)) + 100);
                else
                    v15 = (__int64)ceilf(((v13) * (100.0 / 1.0)));
                jkGuiMouse_aElements[20].selectedTextEntry = v15;
                v16 = ((unsigned int)v12->bitflag >> 3) & 1;
                jkGuiMouse_aElements[17].selectedTextEntry = ((unsigned int)~v12->bitflag >> 2) & 1;
                jkGuiMouse_aElements[18].selectedTextEntry = v16;
            }
            if ( a2 )
            {
                v17 = v7->lastMouseOverClickable;
                if ( v17 == &jkGuiMouse_aElements[15] || v17 == &jkGuiMouse_aElements[14] )
                    v7->lastMouseOverClickable = 0;
                jkGuiRend_Paint(v7);
                if ( !v7->lastMouseOverClickable )
                {
                    jkGuiRend_GetMousePos(&mouseX, &mouseY);
                    jkGuiRend_MouseMovedCallback(v7, mouseX, mouseY);
                }
            }
            jkGuiMouse_dword_53032C = v2;
            jkGuiMouse_dword_530328 = jkGuiMouse_dword_5566B0;
            return;
        }
        if ( v3 == v2 )
        {
            jkGuiMouse_aElements[23].bIsVisible = 0;
            jkGuiMouse_aElements[14].bIsVisible = 0;
            jkGuiMouse_aElements[15].bIsVisible = 0;
            jkGuiMouse_aElements[16].bIsVisible = 0;
            if ( v2 >= 3 )
            {
                jkGuiMouse_aElements[12].bIsVisible = 0;
                v8 = &jkGuiMouse_Darray_5566D0;
                v9 = &jkGuiMouse_aElements[13];
                v10 = jkGuiMouse_aEntries[v2].pSubEnt;
                if ( v10 && (v10->bitflag & 4) != 0 )
                    v18 |= 0x80000000;
            }
            else
            {
                jkGuiMouse_aElements[13].bIsVisible = 0;
                v8 = &jkGuiMouse_Darray_556698;
                v9 = &jkGuiMouse_aElements[12];
            }
            v11 = v8->total;
            v9->selectedTextEntry = 0;
            if ( v11 > 0 )
            {
                while ( jkGuiRend_GetId(v8, v4) != v18 )
                {
                    if ( ++v4 >= v8->total )
                        goto LABEL_29;
                }
                v9->selectedTextEntry = v4;
            }
LABEL_29:
            v7 = pMenu;
            v9->bIsVisible = 1;
            v7->focusedElement = v9;
            goto LABEL_30;
        }
        jkGuiMouse_dword_5566B0 = 0;
    }
}

int jkGuiMouse_ListClicked2(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    char *v5; // edx

    jkGuiRend_ClickSound(pClickedElement, pMenu, mouseX, mouseY, redraw);
    if ( pClickedElement->texInfo.anonymous_18 )
    {
        v5 = pMenu->soundClick;
        jkGuiMouse_dword_5566B0 = 0;
        jkGuiRend_PlayWav(v5);
    }
    if ( redraw )
    {
        jkGuiMouse_sub_417100(jkGuiMouse_aElements[11].selectedTextEntry, pClickedElement->selectedTextEntry);
        jkGuiMouse_dword_5566B0 = 0;
    }
    jkGuiMouse_sub_416D40(pMenu, 1);
    return 0;
}

void jkGuiMouse_sub_417100(int a1, int a2)
{
    int mapFlags; // ebx
    int v3; // esi
    int inputFuncIdx; // ebp
    int v5; // eax
    int dxKeyNum; // edi
    jkGuiMouseSubEntry *pSubEnt; // ecx
    stdControlKeyInfoEntry *v8; // eax
    char v9; // dl
    unsigned int v10; // ecx
    wchar_t *v11; // eax
    wchar_t *v12; // [esp-4h] [ebp-18h]
    float v13; // [esp+10h] [ebp-4h]

    v13 = 1.0;
    mapFlags = 0;
    v3 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, a1);
    inputFuncIdx = jkGuiRend_GetId(&jkGuiMouse_Darray_556698, a2) & ~0x80000000;
    v5 = jkGuiMouse_aEntries[v3].inputFuncIdx;
    dxKeyNum = jkGuiMouse_aEntries[v3].dxKeyNum;
    if ( v5 != -1 )
    {
        pSubEnt = jkGuiMouse_aEntries[v3].pSubEnt;
        if ( pSubEnt )
        {
            v13 = pSubEnt->field_8;
            mapFlags = pSubEnt->bitflag & 4;
        }
        sithControl_ShiftFuncKeyinfo(v5, jkGuiMouse_aEntries[v3].bindIdx);
    }
    v8 = sithControl_MapAxisFunc(inputFuncIdx, dxKeyNum, mapFlags);
    if ( v8 )
    {
        v9 = jkGuiMouse_aEntries[v3].flags;
        v10 = v8->flags & ~8u | 4;
        v8->flags = v10;
        if ( (v9 & 8) != 0 )
            v8->flags = v10 | 8;
        v8->binaryAxisVal = v13;
        jkGuiMouse_sub_417210();
    }
    else
    {
        v12 = jkStrings_GetUniStringWithFallback("ERR_CANNOT_BIND_CONTROL");
        v11 = jkStrings_GetUniStringWithFallback("ERROR");
        jkGuiDialog_ErrorDialog(v11, v12);
        jkGuiMouse_sub_416D40(&jkGuiMouse_menu, 0);
        jkGuiRend_Paint(&jkGuiMouse_menu);
    }
}

void jkGuiMouse_sub_417210()
{
    jkGuiMouseEntry* v0; // eax
    jkGuiMouseEntry* v2; // esi
    wchar_t *v3; // edi
    wchar_t *v4; // eax
    wchar_t v5[512]; // Added: 256 -> 512

    jkGuiRend_DarrayFreeEntry(&jkGuiMouse_Darray_5566B8);
    jkGuiRend_DarrayFreeEntry(&jkGuiMouse_Darray_556698);
    jkGuiRend_DarrayFreeEntry(&jkGuiMouse_Darray_5566D0);
    v0 = &jkGuiMouse_aEntries[0];
    for (int i = 0; i < NUM_MOUSE_ENTRIES; i++)
    {
        v0->inputFuncIdx = -1;
        v0->flags = 0;
        v0->bindIdx = 0; // original had [1]?
        v0->mouseEntryIdx = 0; // original had [1]?
        v0->pSubEnt = 0;
        v0++;
    }

    sithControl_EnumBindings(jkGuiMouse_EnumBindings, 0, 0, 1, 0);

    v2 = &jkGuiMouse_aEntries[0];
    for (int i = 0; i < NUM_MOUSE_ENTRIES; i++)
    {
        v3 = jkStrings_GetUniStringWithFallback(v2->displayStrKey);

        // Added
        if (!v3) v3 = L"";
        if ( v2->inputFuncIdx == -1 )
        {
            v4 = L"--";
        }
        else if ( i >= 3 )
        {
            v4 = jkGuiRend_GetString(&jkGuiMouse_Darray_5566D0, v2->mouseEntryIdx);
        }
        else
        {
            v4 = jkGuiRend_GetString(&jkGuiMouse_Darray_556698, v2->mouseEntryIdx);
        }

        // Added
        if (!v4) v4 = L"";
        jk_snwprintf(v5, 0x100u, L"%ls\t%ls", v3, v4);

        if ( i >= 3 || (stdControl_aJoysticks[v2->dxKeyNum].flags & 1) != 0 )
            jkGuiRend_DarrayReallocStr(&jkGuiMouse_Darray_5566B8, v5, i);
        ++v2;
    }

    jkGuiRend_DarrayReallocStr(&jkGuiMouse_Darray_5566B8, 0, 0);
    jkGuiRend_DarrayReallocStr(&jkGuiMouse_Darray_556698, 0, 0);
    jkGuiRend_DarrayReallocStr(&jkGuiMouse_Darray_5566D0, 0, 0);
    jkGuiRend_SetClickableString(&jkGuiMouse_aElements[11], &jkGuiMouse_Darray_5566B8);
    jkGuiRend_SetClickableString(&jkGuiMouse_aElements[12], &jkGuiMouse_Darray_556698);
    jkGuiRend_SetClickableString(&jkGuiMouse_aElements[13], &jkGuiMouse_Darray_5566D0);
}

int jkGuiMouse_EnumBindings(int a1, const char *a2, uint32_t a3, int a4, uint32_t a5, int a6, stdControlKeyInfoEntry* a7, Darray* a8)
{
    int v7; // ebx
    void *v8; // esi
    wchar_t *v9; // eax
    int v10; // ebp
    int v11; // edi
    int i; // esi
    jkGuiMouseEntry* v13; // eax
    wchar_t *v15; // [esp+10h] [ebp-224h]
    char v16[64]; // Added: 32 -> 64
    wchar_t v17[512]; // Added: 256 -> 512

    v7 = 0;
    v8 = &jkGuiMouse_pWStr_5566E8;
    if ( (a3 & 1) == 0 )
        return 1;
    v9 = jkStrings_GetUniString(a2);
    v15 = v9;
    if ( !v9 )
        return 1;
    v10 = a1;
    if ( (a3 & 2) != 0 )
    {
        _strncpy(v16, a2, 0x1Fu);
        v16[31] = 0;
        //a6 |= 1; // TODO: HACK
        if ( (a6 & 1) != 0 )
        {
            strncat(v16, "_A", 0x20u);
            v7 = 1;
        }
        else if ( (a6 & 4) != 0 )
        {
            strncat(v16, "_R", 0x20u);
            v10 = a1 | 0x80000000;
        }
        else
        {
            strncat(v16, "_K", 0x20u);
        }
        v8 = jkStrings_GetUniStringWithFallback(v16);
        if ( !v8 )
            return 1;
        v9 = v15;
    }
    jk_snwprintf(v17, 0xFFu, L"%ls%ls", v9, v8);
    if ( v7 )
    {
        v11 = jkGuiMouse_Darray_556698.total;
        for ( i = 0; i < v11; ++i )
        {
            if ( jkGuiRend_GetId(&jkGuiMouse_Darray_556698, i) == v10 )
                break;
        }
        if ( i == v11 )
        {
            jkGuiRend_DarrayReallocStr(&jkGuiMouse_Darray_556698, v17, v10);
        }
        else {
            v11 = i;
        }
    }
    else
    {
        v11 = jkGuiMouse_Darray_5566D0.total;
        for ( i = 0; i < v11; ++i )
        {
            if ( jkGuiRend_GetId(&jkGuiMouse_Darray_5566D0, i) == v10 )
                break;
        }
        if ( i == v11 )
        {
            jkGuiRend_DarrayReallocStr(&jkGuiMouse_Darray_5566D0, v17, v10);
        }
        else {
            v11 = i;
        }
    }

    if ( a7 )
    {
        for (int i = 0; i < NUM_MOUSE_ENTRIES; i++)
        {
            v13 = &jkGuiMouse_aEntries[i];
            if ( a5 == v13->dxKeyNum )
            {
                v13->inputFuncIdx = a1;
                v13->flags = a3;
                v13->bindIdx = a4; // [1] in orig?
                v13->mouseEntryIdx = v11; // [1] in orig?
                v13->pSubEnt = (jkGuiMouseSubEntry *)a7;
            }
        }
    }
    return 1;
}

int jkGuiMouse_ListClicked3(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    char *v5; // edx
    int v6; // esi
    int v7; // ebx
    unsigned int v8; // edi
    int v9; // eax
    int v10; // ecx
    int v11; // ebx
    int v12; // esi
    int v13; // edi
    wchar_t *v14; // eax
    wchar_t *v16; // [esp-4h] [ebp-14h]

    jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, redraw);
    if ( pElement->texInfo.anonymous_18 )
    {
        v5 = pMenu->soundClick;
        jkGuiMouse_dword_5566B0 = 0;
        jkGuiRend_PlayWav(v5);
    }
    if ( redraw )
    {
        v6 = pElement->selectedTextEntry;
        v7 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, jkGuiMouse_aElements[11].selectedTextEntry);
        v8 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566D0, v6);
        v9 = v7;
        v10 = jkGuiMouse_aEntries[v7].inputFuncIdx;
        v11 = jkGuiMouse_aEntries[v7].dxKeyNum;
        v12 = (v8 >> 29) & 4;
        v13 = v8 & 0x7FFFFFFF;
        if ( v10 != -1 )
            sithControl_ShiftFuncKeyinfo(v10, jkGuiMouse_aEntries[v9].bindIdx);
        if ( sithControl_MapFunc(v13, v11, v12) )
        {
            jkGuiMouse_sub_417210();
        }
        else
        {
            v16 = jkStrings_GetUniStringWithFallback("ERR_CANNOT_BIND_CONTROL");
            v14 = jkStrings_GetUniStringWithFallback("ERROR");
            jkGuiDialog_ErrorDialog(v14, v16);
            jkGuiMouse_sub_416D40(&jkGuiMouse_menu, 0);
            jkGuiRend_Paint(&jkGuiMouse_menu);
        }
        jkGuiMouse_dword_5566B0 = 0;
    }
    jkGuiMouse_sub_416D40(pMenu, 1);
    return 0;
}

int jkGuiMouse_AddEditControlsClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    jkGuiMouse_dword_5566B0 = 1;
    jkGuiRend_PlayWav(pMenu->soundClick);
    jkGuiMouse_sub_416D40(pMenu, 1);
    return 0;
}

int jkGuiMouse_RemoveClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    int v5; // eax

    v5 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, jkGuiMouse_aElements[11].selectedTextEntry);
    sithControl_ShiftFuncKeyinfo(jkGuiMouse_aEntries[v5].inputFuncIdx, jkGuiMouse_aEntries[v5].bindIdx);
    jkGuiRend_PlayWav(pMenu->soundClick);
    jkGuiMouse_sub_417210();
    jkGuiMouse_dword_53032C = -1;
    jkGuiMouse_dword_530328 = -1;
    jkGuiMouse_sub_416D40(pMenu, 1);
    return 0;
}

int jkGuiMouse_CancelOkClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    int v5; // esi
    int v6; // ebx
    unsigned int v7; // edi
    int v8; // eax
    int v9; // ecx
    int v10; // ebx
    int v11; // esi
    int v12; // edi
    wchar_t *v13; // eax
    wchar_t *v15; // [esp-10h] [ebp-14h]

    jkGuiRend_PlayWav(pMenu->soundClick);
    if ( !jkGuiMouse_dword_5566B0 )
        return pClickedElement->hoverId;
    if ( pClickedElement->hoverId == 1 )
    {
        if ( jkGuiMouse_aElements[13].bIsVisible )
        {
            v5 = jkGuiMouse_aElements[13].selectedTextEntry;
            v6 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, jkGuiMouse_aElements[11].selectedTextEntry);
            v7 = jkGuiRend_GetId(&jkGuiMouse_Darray_5566D0, v5);
            v8 = v6;
            v9 = jkGuiMouse_aEntries[v6].inputFuncIdx;
            v10 = jkGuiMouse_aEntries[v6].dxKeyNum;
            v11 = (v7 >> 29) & 4;
            v12 = v7 & ~0x80000000;
            if ( v9 != -1 )
                sithControl_ShiftFuncKeyinfo(v9, jkGuiMouse_aEntries[v8].bindIdx);
            if ( sithControl_MapFunc(v12, v10, v11) )
            {
                jkGuiMouse_sub_417210();
            }
            else
            {
                v15 = jkStrings_GetUniStringWithFallback("ERR_CANNOT_BIND_CONTROL");
                v13 = jkStrings_GetUniStringWithFallback("ERROR");
                jkGuiDialog_ErrorDialog(v13, v15);
                jkGuiMouse_sub_416D40(&jkGuiMouse_menu, 0);
                jkGuiRend_Paint(&jkGuiMouse_menu);
            }
        }
        else if ( jkGuiMouse_aElements[12].bIsVisible )
        {
            jkGuiMouse_sub_417100(jkGuiMouse_aElements[11].selectedTextEntry, jkGuiMouse_aElements[12].selectedTextEntry);
        }
    }
    jkGuiMouse_dword_5566B0 = 0;
    jkGuiMouse_sub_416D40(pMenu, 1);
    return 0;
}

int jkGuiMouse_RestoreDefaultsClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    wchar_t *v5; // eax
    wchar_t *v7; // [esp-4h] [ebp-8h]

    jkGuiRend_PlayWav(pMenu->soundClick);
    v7 = jkStrings_GetUniStringWithFallback("GUI_RESTORE_DEFAULTS_Q");
    v5 = jkStrings_GetUniStringWithFallback("GUI_RESTORE_DEFAULTS");
    if ( jkGuiDialog_YesNoDialog(v5, v7) )
        sithControl_sub_4D7670();
    jkGuiMouse_sub_417210();
    jkGuiMouse_dword_53032C = -1;
    jkGuiMouse_dword_530328 = -1;
    jkGuiMouse_sub_416D40(pMenu, 0);
    jkGuiRend_Paint(pMenu);
    return 0;
}

int jkGuiMouse_Show()
{
    int v0; // edi
    jkGuiMouseSubEntry *pSubEnt; // eax
    double v2; // st7

    jkGuiMouse_bOpen = stdControl_bOpen;
    jkGuiRend_DarrayNewStr(&jkGuiMouse_Darray_5566B8, 64, 1);
    jkGuiRend_DarrayNewStr(&jkGuiMouse_Darray_556698, 64, 1);
    jkGuiRend_DarrayNewStr(&jkGuiMouse_Darray_5566D0, 64, 1);
    jkGuiMouse_sub_417210();
    jkGui_sub_412E20(&jkGuiMouse_menu, 100, 104, 104);
    jkGui_sub_412E20(&jkGuiMouse_menu, 105, 108, 106);
    jkGuiMouse_aElements[12].bIsVisible = 1;
    jkGuiMouse_aElements[13].bIsVisible = 0;
    jkGuiMouse_aElements[11].selectedTextEntry = 0;
    jkGuiMouse_aElements[12].selectedTextEntry = 0;
    jkGuiMouse_aElements[13].selectedTextEntry = 0;
    jkGuiMouse_dword_5566B0 = 0;
    jkGuiMouse_dword_530328 = -1;
    jkGuiMouse_dword_53032C = -1;
    jkGuiMouse_sub_416D40(&jkGuiMouse_menu, 0);
    jkGuiRend_ElementSetClickShortcutScancode(&jkGuiMouse_aElements[14], VK_INSERT);
    jkGuiRend_ElementSetClickShortcutScancode(&jkGuiMouse_aElements[16], VK_DELETE);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMouse_menu, &jkGuiMouse_aElements[21]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMouse_menu, &jkGuiMouse_aElements[22]);
    jkGuiSetup_sub_412EF0(&jkGuiMouse_menu, 1);
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMouse_menu);
    pSubEnt = jkGuiMouse_aEntries[jkGuiRend_GetId(&jkGuiMouse_Darray_5566B8, jkGuiMouse_aElements[11].selectedTextEntry)].pSubEnt;
    if ( jkGuiMouse_aElements[20].bIsVisible )
    {
        if ( jkGuiMouse_aElements[20].selectedTextEntry > 100 )
            v2 = (double)(jkGuiMouse_aElements[20].selectedTextEntry - 100) * (3.0 / 100.0) - -1.0;
        else
            v2 = (double)jkGuiMouse_aElements[20].selectedTextEntry * (1.0/100.0);
        pSubEnt->field_8 = v2;
    }
    if ( jkGuiMouse_aElements[18].bIsVisible )
        pSubEnt->bitflag = pSubEnt->bitflag & ~8u | (jkGuiMouse_aElements[18].selectedTextEntry != 0 ? 8 : 0);
    if ( jkGuiMouse_aElements[17].bIsVisible )
        pSubEnt->bitflag = pSubEnt->bitflag & ~4u | (jkGuiMouse_aElements[17].selectedTextEntry != 0 ? 0 : 4);
    if ( v0 == 1 )
        jkPlayer_WriteConf(jkPlayer_playerShortName);
    else
        jkPlayer_ReadConf(jkPlayer_playerShortName);
    jkGuiRend_DarrayFree(&jkGuiMouse_Darray_5566B8);
    jkGuiRend_DarrayFree(&jkGuiMouse_Darray_556698);
    jkGuiRend_DarrayFree(&jkGuiMouse_Darray_5566D0);
    return v0;
}

void jkGuiMouse_Startup()
{
    jkGui_InitMenu(&jkGuiMouse_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiMouse_Shutdown()
{
    // Added: clean reset
    jkGuiMouse_dword_530328 = -1;
    jkGuiMouse_dword_53032C = -1;
}
