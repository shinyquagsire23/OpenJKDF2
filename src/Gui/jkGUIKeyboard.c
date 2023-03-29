#include "jkGUIKeyboard.h"

#include "Devices/sithControl.h"
#include "Platform/stdControl.h"
#include "General/Darray.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUISetup.h"
#include "Main/jkStrings.h"
#include "Main/jkHudInv.h"
#include "World/jkPlayer.h"

#include "jk.h"
#include "types_enums.h"

int jkGuiKeyboard_listbox_paddings[2] = {170, 0};
int jkGuiKeyboard_listbox_images[2] = {JKGUI_BM_UP_15, JKGUI_BM_DOWN_15};

static jkGuiElement jkGuiKeyboard_aElements[19] =
{
    { ELEMENT_TEXT,        0, 0, NULL, 3, { 0, 410, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXT,        0, 6, "GUI_SETUP", 3, { 20, 20, 600, 40 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  100, 2, "GUI_GENERAL", 3, { 20, 80, 120, 40 }, 1, 0, "GUI_GENERAL_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  101, 2, "GUI_GAMEPLAY", 3, { 140, 80, 120, 40 }, 1, 0, "GUI_GAMEPLAY_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  102, 2, "GUI_DISPLAY", 3, { 260, 80, 120, 40 }, 1, 0, "GUI_DISPLAY_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  103, 2, "GUI_SOUND", 3, { 380, 80, 120, 40 }, 1, 0, "GUI_SOUND_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  104, 2, "GUI_CONTROLS", 3, { 500, 80, 120, 40 }, 1, 0, "GUI_CONTROLS_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  105, 2, "GUI_KEYBOARD", 3, { 40, 120, 140, 40 }, 1, 0, "GUI_KEYBOARD_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  106, 2, "GUI_MOUSE", 3, { 180, 120, 140, 40 }, 1, 0, "GUI_MOUSE_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  107, 2, "GUI_JOYSTICK", 3, { 320, 120, 140, 40 }, 1, 0, "GUI_JOYSTICK_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  108, 2, "GUI_CONTROLOPTIONS", 3, { 460, 120, 140, 40 }, 1, 0, "GUI_CONTROLOPTIONS_HINT", NULL, NULL, NULL, {0}, 0},
    { ELEMENT_TEXT,        0, 2, (const char*)jkGuiKeyboard_wstr_555E18, 3, { 50, 220, 320, 80 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0},
    { ELEMENT_LISTBOX,     0, 0, NULL, 0, { 20, 170, 370, 216 }, 1, 0, "GUI_CONTROLSLIST_HINT", NULL, &jkGuiKeyboard_ControlListClicked, &jkGuiKeyboard_listbox_images, {0}, 0},
    { ELEMENT_TEXTBUTTON,  0, 2, "GUI_ADD_CONTROL", 3, { 420, 210, 210, 40 }, 1, 0, "GUI_ADD_CONTROL_HINT", NULL, &jkGuiKeyboard_AddControlClicked, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  0, 2, "GUI_REMOVE_CONTROL", 3, { 420, 250, 210, 40 }, 1, 0, "GUI_REMOVE_CONTROL_HINT", NULL, &jkGuiKeyboard_RemoveControlClicked, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  1, 2, "GUI_OK", 3, { 440, 430, 200, 40 }, 1, 0, NULL, NULL, &jkGuiKeyboard_OkClicked, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 0, 430, 200, 40 }, 1, 0, NULL, NULL, &jkGuiKeyboard_CancelClicked, NULL, {0}, 0},
    { ELEMENT_TEXTBUTTON,  0, 2, "GUI_RESTORE_DEFAULTS", 3, { 200, 430, 240, 40 }, 1, 0, NULL, NULL, &jkGuiKeyboard_RestoreDefaultsClicked, NULL, {0}, 0},
    { ELEMENT_END,         0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, {0}, 0}
};


static jkGuiMenu jkGuiKeyboard_menu = {jkGuiKeyboard_aElements, 0, 225, 255, 15, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, (intptr_t)jkGuiKeyboard_listbox_paddings, jkGuiKeyboard_sub_4123C0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

const char* jkGuiKeyboard_DIKNumToStr(unsigned int idx, char bIsIdxAxis)
{
    BOOL v2; // eax
    const char *pOutStr; // eax
    int v4; // ecx
    stdControlDikStrToNum *v5; // eax

    if ( (bIsIdxAxis & 1) != 0 )
    {
        if ( (idx & 0x80000000) != 0 )
            v2 = 0;
        else
            v2 = idx <= JK_NUM_AXES;
        if ( v2 )
            pOutStr = stdControl_aAxisNames[idx];
        else
            pOutStr = "AXIS_UNKNOWN";
    }
    else
    {
        v4 = 0;
        v5 = stdControl_aDikNumToStr;
        while ( idx != v5->val )
        {
            ++v5;
            ++v4;
            if ( v5 >= (stdControlDikStrToNum *)stdControl_aAxisNames )
                return "KEY_UNKNOWN";
        }
        pOutStr = stdControl_aDikNumToStr[v4].pStr;
    }
    return pOutStr;
}

int jkGuiKeyboard_sub_411E40(Darray *pDarr)
{
    int result; // eax
    int i; // edi
    jkGuiStringEntry *v3; // esi
    jkGuiKeyboardEntry *v4; // eax

    result = pDarr->total;
    for ( i = 0; i < result; v3->pKeyboardEntry = 0 )
    {
        v3 = jkGuiRend_GetStringEntry(pDarr, i);
        if ( v3->pKeyboardEntry )
            pHS->free(v3->pKeyboardEntry);
        result = pDarr->total;
        ++i;
    }
    return result;
}

int jkGuiKeyboard_RemoveControlClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    jkGuiKeyboardEntry *pEntry; // eax
    int v3; // ecx
    wchar_t *v5; // eax
    wchar_t *v6; // [esp-4h] [ebp-4h]

    if ( !jkGuiKeyboard_bOnceIdk )
    {
        jkGuiRend_PlayWav(pMenu->soundClick);
        pEntry = (jkGuiKeyboardEntry *)jkGuiRend_GetId(&jkGuiKeyboard_darrEntries, jkGuiKeyboard_aElements[12].selectedTextEntry);
        if ( pEntry )
        {
            v3 = pEntry->dxKeyNum;
            if ( v3 != -1 )
            {
                sithControl_ShiftFuncKeyinfo(pEntry->inputFuncIdx, v3);
                jkGuiKeyboard_sub_411F40(&jkGuiKeyboard_aElements[12], &jkGuiKeyboard_darrEntries);
                jkGuiRend_UpdateAndDrawClickable(&jkGuiKeyboard_aElements[12], &jkGuiKeyboard_menu, 1);
                return 0;
            }
        }
        v6 = jkStrings_GetUniStringWithFallback("ERR_REMOVING_CONTROL");
        v5 = jkStrings_GetUniStringWithFallback("ERROR");
        jkGuiDialog_ErrorDialog(v5, v6);
        jkGuiRend_Paint(&jkGuiKeyboard_menu);
        jkGui_MessageBeep();
    }
    return 0;
}

void jkGuiKeyboard_sub_411F40(jkGuiElement *pElement, Darray *pDarr)
{
    Darray *v2; // esi
    int v3; // ebp
    jkGuiStringEntry *v4; // esi
    jkGuiKeyboardEntry *v5; // ebx
    int v6; // edi
    int v7; // ebx
    int i; // esi
    jkGuiStringEntry *v9; // eax
    jkGuiStringEntry *v10; // edi
    jkGuiStringEntry *v11; // eax
    jkGuiKeyboardEntry *v12; // edx
    jkGuiStringEntry *v13; // esi
    wchar_t *v14; // eax
    size_t v15; // eax
    wchar_t *v16; // eax
    wchar_t *v17; // edi
    jkGuiKeyboardEntry *v18; // eax
    const wchar_t *v19; // [esp-4h] [ebp-24h]
    int v20; // [esp+10h] [ebp-10h]
    int v21; // [esp+14h] [ebp-Ch]
    jkGuiStringEntry v22; // [esp+18h] [ebp-8h]

    v2 = pDarr;
    v3 = 0;
    v21 = -1;
    v20 = 0;
    jkGuiRend_DarrayFreeEntry(pDarr);
    sithControl_EnumBindings(jkGuiKeyboard_EnumBindings, 1, 0, 0, pDarr);
    if ( pDarr->total > 0 )
    {
        do
        {
            v4 = jkGuiRend_GetStringEntry(&jkGuiKeyboard_darrEntries, v3);
            v5 = v4->pKeyboardEntry;
            if ( v5->inputFuncIdx == v21 )
            {
                v6 = v3 - 1;
                if ( v3 - 1 >= v20 )
                {
                    while ( v5->field_C != jkGuiRend_GetStringEntry(&jkGuiKeyboard_darrEntries, v6)->pKeyboardEntry->field_C )
                    {
                        if ( --v6 < v20 )
                            goto LABEL_14;
                    }
                    v7 = v6 + 1;
                    v22 = *v4;
                    for ( i = v3; i > v7; v10->pKeyboardEntry = v12 )
                    {
                        v9 = jkGuiRend_GetStringEntry(&jkGuiKeyboard_darrEntries, i--);
                        v10 = v9;
                        v11 = jkGuiRend_GetStringEntry(&jkGuiKeyboard_darrEntries, i);
                        v12 = v11->pKeyboardEntry;
                        v10->str = v11->str;
                    }
                    v13 = jkGuiRend_GetStringEntry(&jkGuiKeyboard_darrEntries, v7);
                    *v13 = v22;
                    v14 = __wcschr(v13->str, 9u);
                    if ( v14 )
                    {
                        v19 = v14;
                        v15 = _wcslen(v14);
                    }
                    else
                    {
                        v19 = L" ";
                        v15 = _wcslen(L" ");
                    }
                    v16 = (wchar_t *)pHS->alloc(sizeof(wchar_t) * (v15 + 1));
                    v17 = _wcscpy(v16, v19);
                    pHS->free(v13->str);
                    v13->str = v17;
                }
            }
            else
            {
                v21 = v5->inputFuncIdx;
                v20 = v3;
            }
LABEL_14:
            v2 = pDarr;
            ++v3;
        }
        while ( v3 < pDarr->total );
    }
    jkGuiRend_DarrayReallocStr(v2, 0, 0);
    jkGuiRend_SetClickableString(pElement, v2);
    v18 = (jkGuiKeyboardEntry *)jkGuiRend_GetId(&jkGuiKeyboard_darrEntries, jkGuiKeyboard_aElements[12].selectedTextEntry);
    if ( v18 )
        jkGuiRend_SetVisibleAndDraw(&jkGuiKeyboard_aElements[14], &jkGuiKeyboard_menu, v18->dxKeyNum != -1);
}

int jkGuiKeyboard_EnumBindings(int inputFuncIdx, const char *pInputFuncStr, uint32_t a3, int dxKeyNum, uint32_t a5, int flags, stdControlKeyInfoEntry *pControlEntry, Darray *pDarr)
{
    void *v8; // edi
    wchar_t *v9; // eax
    BOOL v10; // eax
    const char *v11; // ecx
    int v12; // ecx
    stdControlDikStrToNum *v13; // eax
    jkGuiKeyboardEntry *v14; // eax
    const char *v16; // [esp-8h] [ebp-240h]
    wchar_t *v17; // [esp+14h] [ebp-224h]
    char v18[32]; // [esp+18h] [ebp-220h] BYREF
    wchar_t wStr[256]; // [esp+38h] [ebp-200h] BYREF

    v8 = &jkGuiKeyboard_pWStr_55601C;
    v17 = jkStrings_GetUniString(pInputFuncStr);
    if ( v17 && (jkGuiKeyboard_dword_555E10 != 105 || (flags & 1) == 0) )
    {
        if ( (a3 & 2) == 0
          || ((_strncpy(v18, pInputFuncStr, 0x1Fu), v18[31] = 0, (flags & 1) == 0) ? ((flags & 4) == 0 ? (v16 = "_K") : (v16 = "_R"), strncat(v18, v16, 0x20u)) : strncat(v18, "_A", 0x20u),
              (v8 = jkStrings_GetUniStringWithFallback(v18)) != 0) )
        {
            if ( dxKeyNum == -1 )
            {
                v9 = L"--";
            }
            else
            {
                if ( (flags & 1) != 0 )
                {
                    if ( (a5 & 0x80000000) != 0 )
                        v10 = 0;
                    else
                        v10 = a5 <= JK_NUM_AXES;
                    if ( v10 )
                        v11 = stdControl_aAxisNames[a5];
                    else
                        v11 = "AXIS_UNKNOWN";
                }
                else
                {
                    v12 = 0;
                    v13 = stdControl_aDikNumToStr;
                    while ( a5 != v13->val )
                    {
                        ++v13;
                        ++v12;
                        if ( v13 >= &stdControl_aDikNumToStr[148] )
                        {
                            v11 = "KEY_UNKNOWN";
                            goto LABEL_25;
                        }
                    }
                    v11 = stdControl_aDikNumToStr[v12].pStr;
                }
LABEL_25:
                v9 = jkStrings_GetUniStringWithFallback(v11);
            }
            jk_snwprintf(wStr, 0xFFu, L"%ls%ls\t%ls", v17, v8, v9);

            v14 = (jkGuiKeyboardEntry *)pHS->alloc(sizeof(jkGuiKeyboardEntry));
            if ( v14 )
            {
                v14->inputFuncIdx = inputFuncIdx;
                v14->axisIdx = a5;
                v14->dxKeyNum = dxKeyNum;
                v14->field_C = flags & 5;
                v14->field_10 = flags & 4;
                v14->field_14 = a3 & 2;
            }
            jkGuiRend_DarrayReallocStr(pDarr, wStr, (intptr_t)v14);
        }
    }
    return 1;
}

int jkGuiKeyboard_AddControlClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    int v3; // esi
    jkGuiKeyboardEntry *v4; // eax
    wchar_t *v6; // esi
    wchar_t *v7; // eax
    wchar_t *v8; // eax
    wchar_t v9[256]; // [esp+0h] [ebp-200h] BYREF

    if ( jkGuiKeyboard_bOnceIdk )
        return 0;
    jkGuiRend_PlayWav(pMenu->soundClick);
    v3 = jkGuiKeyboard_aElements[12].selectedTextEntry;
    v4 = (jkGuiKeyboardEntry *)jkGuiRend_GetId(&jkGuiKeyboard_darrEntries, jkGuiKeyboard_aElements[12].selectedTextEntry);
    jkGuiKeyboard_flags = v4->field_10;
    jkGuiKeyboard_bOnceIdk = 1;
    jkGuiKeyboard_funcIdx = v4->inputFuncIdx;
    if ( jkGuiKeyboard_dword_555DE0 )
    {
        stdControl_ToggleCursor(1);
        stdControl_bControlsActive = 0;
    }
    else
    {
        stdControl_Open();
    }
    stdControl_ReadControls();
    stdControl_FinishRead();
    stdControl_Flush();
    v6 = jkGuiRend_GetString(&jkGuiKeyboard_darrEntries, v3);
    memset(v9, 0, sizeof(v9));
    v7 = __wcschr(v6, '\t');
    __wcsncpy(v9, v6, v7 - v6);
    v8 = jkStrings_GetUniStringWithFallback("GUI_HIT_KEY_TO_ATTACH");
    jk_snwprintf(jkGuiKeyboard_wstr_555E18, 0x100u, v8, v9);

    return 0;
}

void jkGuiKeyboard_sub_4123C0(jkGuiMenu *pMenu)
{
    int v1; // esi
    const wchar_t *v2; // ebp
    size_t v3; // ebx
    int v4; // edi
    jkGuiKeyboardEntry* v5; // eax
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t *v8; // eax
    wchar_t *v9; // [esp-4h] [ebp-41Ch]
    int v10; // [esp+10h] [ebp-408h] BYREF
    int v11; // [esp+14h] [ebp-404h]
    wchar_t v12[256]; // [esp+18h] [ebp-400h] BYREF
    wchar_t v13[256]; // [esp+218h] [ebp-200h] BYREF

    v1 = 0;
    if ( !jkGuiKeyboard_bOnceIdk )
        goto LABEL_35;
    stdControl_bControlsActive = 1;
    stdControl_ReadControls();
    v2 = 0;//(const wchar_t *)v10;
    v3 = 0;//v10;
    v4 = 0;
    v11 = 0;
    do
    {
        v10 = 0;
        stdControl_ReadKey(v4, &v10);
        if ( v10 && (KEY_IS_BUTTON(v4)) && !KEY_IS_MOUSE(v4) )
        {
            if ( v4 == 1 )
                goto LABEL_27;
            jkGuiKeyboard_bOnceIdk = 0;
            stdControl_ToggleCursor(0);
            if ( jkGuiKeyboard_darrEntries.total - 1 <= 0 )
                goto LABEL_23;
            while ( 1 )
            {
                v5 = (jkGuiKeyboardEntry *)jkGuiRend_GetId(&jkGuiKeyboard_darrEntries, v1);
                if ( v5 )
                {
                    if ( v5->axisIdx == v4 )
                        break;
                }
                if ( ++v1 >= jkGuiKeyboard_darrEntries.total - 1 )
                    goto LABEL_23;
            }
            for ( ; v1 >= 0; --v1 )
            {
                v2 = jkGuiRend_GetString(&jkGuiKeyboard_darrEntries, v1);
                v3 = __wcschr(v2, '\t') - v2;
                if ( v3 )
                    break;
            }
            memset(v12, 0, sizeof(v12));
            _wcsncpy(v12, v2, v3);
            v6 = jkStrings_GetUniStringWithFallback("GUI_ALREADY_BOUND_Q");
            jk_snwprintf(v13, 0x100u, v6, v12);
            v7 = jkStrings_GetUniStringWithFallback("GUI_ALREADY_BOUND");
            if ( jkGuiDialog_YesNoDialog(v7, v13) )
            {
                v4 = v11;
LABEL_23:
                if ( sithControl_MapFunc(jkGuiKeyboard_funcIdx, v4, jkGuiKeyboard_flags) )
                {
                    jkGuiKeyboard_sub_411F40(&jkGuiKeyboard_aElements[12], &jkGuiKeyboard_darrEntries);
                }
                else
                {
                    v9 = jkStrings_GetUniStringWithFallback("ERR_CANNOT_BIND_CONTROL");
                    v8 = jkStrings_GetUniStringWithFallback("ERROR");
                    jkGuiDialog_ErrorDialog(v8, v9);
                }
                jkGuiRend_Paint(&jkGuiKeyboard_menu);
LABEL_27:
                stdControl_FinishRead();
                stdControl_bControlsActive = jkGuiKeyboard_dword_555DE0 == 0;
                if ( jkGuiKeyboard_dword_555DE0 )
                    stdControl_ToggleCursor(0);
                else
                    stdControl_Close();
                jkGuiKeyboard_bOnceIdk = 0;
                return;
            }
            jkGuiRend_Paint(&jkGuiKeyboard_menu);
            stdControl_ToggleCursor(1);
            if ( jkGuiKeyboard_dword_555DE0 )
                stdControl_bControlsActive = 0;
            v4 = v11;
            jkGuiKeyboard_bOnceIdk = 1;
            v1 = 0;
        }
        v11 = ++v4;
    }
    while ( v4 < JK_NUM_KEYS );
    stdControl_FinishRead();
    stdControl_bControlsActive = jkGuiKeyboard_dword_555DE0 == 0;
    if ( !jkGuiKeyboard_bOnceIdk )
        goto LABEL_35;
    if ( jkGuiKeyboard_aElements[12].bIsVisible )
    {
        jkGuiKeyboard_aElements[11].bIsVisible = 1;
        jkGuiKeyboard_aElements[12].bIsVisible = 0;
        jkGuiRend_Paint(pMenu);
        jkGuiRend_SetCursorVisible(0);
        return;
    }
    if ( !jkGuiKeyboard_bOnceIdk )
    {
LABEL_35:
        if ( jkGuiKeyboard_aElements[11].bIsVisible )
        {
            jkGuiKeyboard_aElements[11].bIsVisible = 0;
            jkGuiKeyboard_aElements[12].bIsVisible = 1;
            jkGuiRend_Paint(pMenu);
            jkGuiRend_SetCursorVisible(1);
        }
    }
}

int jkGuiKeyboard_OkClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    if ( jkGuiKeyboard_bOnceIdk )
        return 0;
    jkGuiRend_PlayWav(pMenu->soundClick);
    return pElement->hoverId;
}

int jkGuiKeyboard_CancelClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    jkGuiRend_PlayWav(pMenu->soundClick);
    if ( !jkGuiKeyboard_bOnceIdk )
        return pElement->hoverId;
    jkGuiKeyboard_bOnceIdk = 0;
    if ( jkGuiKeyboard_dword_555DE0 )
        stdControl_ToggleCursor(0);
    else
        stdControl_Close();
    return 0;
}

int jkGuiKeyboard_ControlListClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    jkGuiKeyboardEntry *v6; // eax

    if ( jkGuiKeyboard_bOnceIdk )
        return 0;
    jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, redraw);
    v6 = (jkGuiKeyboardEntry *)jkGuiRend_GetId(&jkGuiKeyboard_darrEntries, pElement->selectedTextEntry);
    if ( v6 )
        jkGuiRend_SetVisibleAndDraw(&jkGuiKeyboard_aElements[14], pMenu, v6->dxKeyNum != -1);
    if ( redraw )
        jkGuiKeyboard_AddControlClicked(&jkGuiKeyboard_aElements[13], pMenu, mouseX, mouseY, redraw);
    return 0;
}

int jkGuiKeyboard_RestoreDefaultsClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    wchar_t *v3; // eax
    wchar_t *v4; // [esp-8h] [ebp-8h]

    if ( jkGuiKeyboard_bOnceIdk )
        return 0;
    jkGuiRend_PlayWav(pMenu->soundClick);
    v4 = jkStrings_GetUniStringWithFallback("GUI_RESTORE_DEFAULTS_Q");
    v3 = jkStrings_GetUniStringWithFallback("GUI_RESTORE_DEFAULTS");
    if ( jkGuiDialog_YesNoDialog(v3, v4) )
    {
        sithControl_sub_4D7350();
        jkHudInv_InputInit();
    }
    jkGuiKeyboard_sub_411F40(&jkGuiKeyboard_aElements[12], &jkGuiKeyboard_darrEntries);
    jkGuiRend_Paint(pMenu);
    return 0;
}

int jkGuiKeyboard_Show()
{
    int v0; // ebp
    int v1; // edi
    jkGuiStringEntry *v2; // esi
    jkGuiKeyboardEntry *v3; // eax

    jkGuiKeyboard_dword_555DE0 = stdControl_bOpen;
    jkGuiKeyboard_bOnceIdk = 0;
    jkGuiKeyboard_dword_555E10 = 105;
    jkGuiRend_DarrayNewStr(&jkGuiKeyboard_darrEntries, 100, 1);
    jkGuiKeyboard_sub_411F40(&jkGuiKeyboard_aElements[12], &jkGuiKeyboard_darrEntries);
    jkGuiKeyboard_aElements[12].selectedTextEntry = 0;
    jkGui_sub_412E20(&jkGuiKeyboard_menu, 100, 104, 104);
    jkGui_sub_412E20(&jkGuiKeyboard_menu, 105, 108, 105);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiKeyboard_menu, &jkGuiKeyboard_aElements[15]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiKeyboard_menu, &jkGuiKeyboard_aElements[16]);
    jkGuiRend_ElementSetClickShortcutScancode(&jkGuiKeyboard_aElements[13], VK_INSERT);
    jkGuiRend_ElementSetClickShortcutScancode(&jkGuiKeyboard_aElements[14], VK_DELETE);
    jkGuiSetup_sub_412EF0(&jkGuiKeyboard_menu, 1);
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiKeyboard_menu);
    if ( v0 == 1 )
        jkPlayer_WriteConf(jkPlayer_playerShortName);
    else
        jkPlayer_ReadConf(jkPlayer_playerShortName);
    jkGuiKeyboard_sub_411E40(&jkGuiKeyboard_darrEntries);
    jkGuiRend_DarrayFree(&jkGuiKeyboard_darrEntries);
    return v0;
}

void jkGuiKeyboard_Startup()
{
    jkGui_InitMenu(&jkGuiKeyboard_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiKeyboard_Shutdown()
{
    ;
}
