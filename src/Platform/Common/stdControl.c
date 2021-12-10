#include "Platform/stdControl.h"

#include "Engine/sithControl.h"
#include "Win95/Window.h"
#include "stdPlatform.h"

#include "jk.h"

const char *stdControl_aAxisNames[16] =
{
    "AXIS_JOY1_X",
    "AXIS_JOY1_Y",
    "AXIS_JOY1_Z",
    "AXIS_JOY1_R",
    "AXIS_JOY1_U",
    "AXIS_JOY1_V",
    "AXIS_JOY2_X",
    "AXIS_JOY2_Y",
    "AXIS_JOY2_Z",
    "AXIS_JOY2_R",
    "AXIS_JOY2_U",
    "AXIS_JOY2_V",
    "AXIS_MOUSE_X",
    "AXIS_MOUSE_Y",
    "AXIS_MOUSE_Z",
    " "
};

const stdControlDikStrToNum stdControl_aDikNumToStr[148] =
{
  { 1, "DIK_ESCAPE" },
  { 2, "DIK_1" },
  { 3, "DIK_2" },
  { 4, "DIK_3" },
  { 5, "DIK_4" },
  { 6, "DIK_5" },
  { 7, "DIK_6" },
  { 8, "DIK_7" },
  { 9, "DIK_8" },
  { 10, "DIK_9" },
  { 11, "DIK_0" },
  { 12, "DIK_MINUS" },
  { 13, "DIK_EQUALS" },
  { 14, "DIK_BACK" },
  { 15, "DIK_TAB" },
  { 16, "DIK_Q" },
  { 17, "DIK_W" },
  { 18, "DIK_E" },
  { 19, "DIK_R" },
  { 20, "DIK_T" },
  { 21, "DIK_Y" },
  { 22, "DIK_U" },
  { 23, "DIK_I" },
  { 24, "DIK_O" },
  { 25, "DIK_P" },
  { 26, "DIK_LBRACKET" },
  { 27, "DIK_RBRACKET" },
  { 28, "DIK_RETURN" },
  { 29, "DIK_LCONTROL" },
  { 30, "DIK_A" },
  { 31, "DIK_S" },
  { 32, "DIK_D" },
  { 33, "DIK_F" },
  { 34, "DIK_G" },
  { 35, "DIK_H" },
  { 36, "DIK_J" },
  { 37, "DIK_K" },
  { 38, "DIK_L" },
  { 39, "DIK_SEMICOLON" },
  { 40, "DIK_APOSTROPHE" },
  { 41, "DIK_GRAVE" },
  { 42, "DIK_LSHIFT" },
  { 43, "DIK_BACKSLASH" },
  { 44, "DIK_Z" },
  { 45, "DIK_X" },
  { 46, "DIK_C" },
  { 47, "DIK_V" },
  { 48, "DIK_B" },
  { 49, "DIK_N" },
  { 50, "DIK_M" },
  { 51, "DIK_COMMA" },
  { 52, "DIK_PERIOD" },
  { 53, "DIK_SLASH" },
  { 54, "DIK_RSHIFT" },
  { 55, "DIK_MULTIPLY" },
  { 56, "DIK_LMENU" },
  { 57, "DIK_SPACE" },
  { 58, "DIK_CAPITAL" },
  { 59, "DIK_F1" },
  { 60, "DIK_F2" },
  { 61, "DIK_F3" },
  { 62, "DIK_F4" },
  { 63, "DIK_F5" },
  { 64, "DIK_F6" },
  { 65, "DIK_F7" },
  { 66, "DIK_F8" },
  { 67, "DIK_F9" },
  { 68, "DIK_F10" },
  { 69, "DIK_NUMLOCK" },
  { 70, "DIK_SCROLL" },
  { 71, "DIK_NUMPAD7" },
  { 72, "DIK_NUMPAD8" },
  { 73, "DIK_NUMPAD9" },
  { 74, "DIK_SUBTRACT" },
  { 75, "DIK_NUMPAD4" },
  { 76, "DIK_NUMPAD5" },
  { 77, "DIK_NUMPAD6" },
  { 78, "DIK_ADD" },
  { 79, "DIK_NUMPAD1" },
  { 80, "DIK_NUMPAD2" },
  { 81, "DIK_NUMPAD3" },
  { 82, "DIK_NUMPAD0" },
  { 83, "DIK_DECIMAL" },
  { 87, "DIK_F11" },
  { 88, "DIK_F12" },
  { 100, "DIK_F13" },
  { 101, "DIK_F14" },
  { 102, "DIK_F15" },
  { 112, "DIK_KANA" },
  { 121, "DIK_CONVERT" },
  { 123, "DIK_NOCONVERT" },
  { 125, "DIK_YEN" },
  { 141, "DIK_NUMPADEQUALS" },
  { 144, "DIK_CIRCUMFLEX" },
  { 145, "DIK_AT" },
  { 146, "DIK_COLON" },
  { 147, "DIK_UNDERLINE" },
  { 148, "DIK_KANJI" },
  { 149, "DIK_STOP" },
  { 150, "DIK_AX" },
  { 151, "DIK_UNLABELED" },
  { 156, "DIK_NUMPADENTER" },
  { 157, "DIK_RCONTROL" },
  { 179, "DIK_NUMPADCOMMA" },
  { 181, "DIK_DIVIDE" },
  { 183, "DIK_SYSRQ" },
  { 184, "DIK_RMENU" },
  { 199, "DIK_HOME" },
  { 200, "DIK_UP" },
  { 201, "DIK_PRIOR" },
  { 203, "DIK_LEFT" },
  { 205, "DIK_RIGHT" },
  { 207, "DIK_END" },
  { 208, "DIK_DOWN" },
  { 209, "DIK_NEXT" },
  { 210, "DIK_INSERT" },
  { 211, "DIK_DELETE" },
  { 219, "DIK_LWIN" },
  { 220, "DIK_RWIN" },
  { 221, "DIK_APPS" },
  { 256, "KEY_JOY1_B1" },
  { 257, "KEY_JOY1_B2" },
  { 258, "KEY_JOY1_B3" },
  { 259, "KEY_JOY1_B4" },
  { 260, "KEY_JOY1_B5" },
  { 261, "KEY_JOY1_B6" },
  { 262, "KEY_JOY1_B7" },
  { 263, "KEY_JOY1_B8" },
  { 264, "KEY_JOY1_HLEFT" },
  { 265, "KEY_JOY1_HUP" },
  { 266, "KEY_JOY1_HRIGHT" },
  { 267, "KEY_JOY1_HDOWN" },
  { 268, "KEY_JOY2_B1" },
  { 269, "KEY_JOY2_B2" },
  { 270, "KEY_JOY2_B3" },
  { 271, "KEY_JOY2_B4" },
  { 272, "KEY_JOY2_B5" },
  { 273, "KEY_JOY2_B6" },
  { 274, "KEY_JOY2_B7" },
  { 275, "KEY_JOY2_B8" },
  { 276, "KEY_JOY2_HLEFT" },
  { 277, "KEY_JOY2_HUP" },
  { 278, "KEY_JOY2_HRIGHT" },
  { 279, "KEY_JOY2_HDOWN" },
  { 280, "KEY_MOUSE_B1" },
  { 281, "KEY_MOUSE_B2" },
  { 282, "KEY_MOUSE_B3" },
  { 283, "KEY_MOUSE_B4" }
};

void stdControl_Reset()
{
    stdControlJoystickEntry *v0; // eax

    stdControl_bReadMouse = 0;
    stdControl_joy_related = 0;
    stdControl_unk_55C828[0] = 0;
    stdControl_aAxisConnected[0] = 0x680;
    stdControl_unk_55C828[1] = 0;
    stdControl_aAxisConnected[1] = 0x680;

    v0 = stdControl_aJoysticks;
    for (int i = 0; i < 15; i++)
    {
        v0->flags &= ~2;
        ++v0;
    }
}

int stdControl_EnableAxis(unsigned int idx)
{
    int v3; // ecx

    if ( idx >= 0xF )
        return 0;

    if ( (stdControl_aJoysticks[idx].flags & 1) == 0 )
        return 0;
    stdControl_aJoysticks[idx].flags |= 2;
    if ( idx < 0xC )
    {
        stdControl_joy_related = 1;
        v3 = idx > 5;
        stdControl_unk_55C828[v3] = 1;
        switch ( idx - 6 * v3 )
        {
            case 0u:
                stdControl_aAxisConnected[v3] |= 1u;
                break;
            case 1u:
                stdControl_aAxisConnected[v3] |= 2u;
                break;
            case 2u:
                stdControl_aAxisConnected[v3] |= 4u;
                break;
            case 3u:
                stdControl_aAxisConnected[v3] |= 8u;
                break;
            case 4u:
                stdControl_aAxisConnected[v3] |= 0x10u;
                break;
            case 5u:
                stdControl_aAxisConnected[v3] |= 0x20u;
                break;
            default:
                return 1;
        }
    }
    else
    {
        stdControl_bReadMouse = 1;
    }
    return 1;
}

// readcontrols

float stdControl_ReadAxis(int axisNum)
{
    float result; // st7
    int v2; // ecx
    int v3; // edx
    int v4; // eax
    int v5; // edx
    double v7; // st6
    int v9; // [esp+8h] [ebp+4h]

    if ( !stdControl_bControlsActive )
        return 0.0;
    v2 = axisNum;
    v3 = stdControl_aJoysticks[axisNum].flags;
    if ( (v3 & 2) == 0 )
        return 0.0;
    v4 = *(&stdControl_aAxisPos.aEntries[0].dwXpos + axisNum) - stdControl_aJoysticks[axisNum].dwXoffs;
    v9 = v4;
    if ( !v4 )
        return 0.0;
    if ( (v3 & 8) == 0 )
    {
        v5 = stdControl_aJoysticks[v2].dwYoffs;
        if ( v5 )
        {
            if ( v4 < 0 )
                v4 = -v4;
            if ( v4 < v5 )
                return 0.0;
        }
    }
    result = stdControl_aJoysticks[v2].fRangeConversion * (double)v9;
    v7 = result;
    if ( v7 < 0.0 )
        v7 = -result;
    if ( v7 <= 0.0000099999997 )
        result = 0.0;
    if ( stdControl_bControlsIdle )
    {
        if ( result != 0.0 )
            stdControl_bControlsIdle = 0;
    }
    return result;
}

int stdControl_ReadAxisRaw(int axisNum)
{
    int result; // eax

    if ( !stdControl_bControlsActive )
        return 0;
    if ( (stdControl_aJoysticks[axisNum].flags & 2) == 0 )
        return 0;
    result = *(&stdControl_aAxisPos.aEntries[0].dwXpos + axisNum) - stdControl_aJoysticks[axisNum].dwXoffs;
    if ( !result )
        return 0;
    if ( stdControl_bControlsIdle )
        stdControl_bControlsIdle = 0;
    return result;
}

float stdControl_ReadKeyAsAxis(int keyNum)
{
    uint32_t v1; // eax
    float result; // st7

    if ( !stdControl_bControlsActive || stdControl_bDisableKeyboard )
        return 0.0;
    v1 = stdControl_aInput1[keyNum];
    if ( !v1 )
    {
        if ( stdControl_aKeyInfo[keyNum] )
        {
            v1 = stdControl_msDelta;
            goto LABEL_6;
        }
        return 0.0;
    }
LABEL_6:
    if ( v1 >= stdControl_msDelta )
        v1 = stdControl_msDelta;
    result = (double)v1 * stdControl_updateKHz;
    if ( stdControl_bControlsIdle )
    {
        if ( result != 0.0 )
            stdControl_bControlsIdle = 0;
    }
    return result;
}

int stdControl_ReadAxisAsKey(int axisNum)
{
    double v1; // st7

    v1 = stdControl_ReadAxis(axisNum);
    if ( v1 < 0.0 )
        v1 = -v1;
    return v1 > 0.5;
}

int stdControl_ReadKey(int keyNum, int *pOut)
{
    int result; // eax

    if ( !stdControl_bControlsActive || stdControl_bDisableKeyboard )
    {
        if ( pOut )
            *pOut = 0;
        result = 0;
    }
    else
    {
        if ( pOut )
            *pOut += stdControl_aInput2[keyNum];
        if ( stdControl_bControlsIdle )
        {
            if ( stdControl_aKeyInfo[keyNum] )
                stdControl_bControlsIdle = 0;
        }
        result = stdControl_aKeyInfo[keyNum];
    }
    return result;
}

void stdControl_FinishRead()
{
    ;
}

int stdControl_MessageHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused)
{
    if ( Msg != 0x112 )
        return 0;
    return wParam == 0xF100 || wParam == 0xF140;
}

void stdControl_SetMouseSensitivity(float xSensitivity, float ySensitivity)
{
    stdControl_mouseXSensitivity = xSensitivity;
    stdControl_mouseYSensitivity = ySensitivity;
    if ( (stdControl_aJoysticks[12].flags & 1) != 0 )
    {
        stdControl_aJoysticks[12].dwYoffs = 0;
        stdControl_aJoysticks[12].uMaxVal = (__int64)(xSensitivity * 250.0);
        stdControl_aJoysticks[12].uMinVal = -stdControl_aJoysticks[12].uMaxVal;
        stdControl_aJoysticks[12].flags |= 1u;
        stdControl_aJoysticks[12].dwXoffs = (2 * stdControl_aJoysticks[12].uMaxVal + 1) / 2 - stdControl_aJoysticks[12].uMaxVal;
        stdControl_aJoysticks[12].fRangeConversion = 1.0 / (double)(stdControl_aJoysticks[12].uMaxVal - stdControl_aJoysticks[12].dwXoffs);
    }
    if ( (stdControl_aJoysticks[13].flags & 1) != 0 )
    {
        stdControl_aJoysticks[13].dwYoffs = 0;
        stdControl_aJoysticks[13].uMaxVal = (__int64)(ySensitivity * 200.0);
        stdControl_aJoysticks[13].uMinVal = -stdControl_aJoysticks[13].uMaxVal;
        stdControl_aJoysticks[13].flags |= 1u;
        stdControl_aJoysticks[13].dwXoffs = (2 * stdControl_aJoysticks[13].uMaxVal + 1) / 2 - stdControl_aJoysticks[13].uMaxVal;
        stdControl_aJoysticks[13].fRangeConversion = 1.0 / (double)(stdControl_aJoysticks[13].uMaxVal - stdControl_aJoysticks[13].dwXoffs);
    }
}

// more

void stdControl_SetKeydown(int keyNum, int bDown, uint32_t readTime)
{
    uint32_t v3; // ecx
    int v4; // ecx

    // Added: bounds check
    if (keyNum >= 284 || keyNum < 0)
        return;

    if ( !bDown || stdControl_aKeyInfo[keyNum] )
    {
        if ( !bDown && stdControl_aKeyInfo[keyNum] )
        {
            v4 = stdControl_aInput1[keyNum];
            stdControl_aKeyInfo[keyNum] = 0;
            if ( !v4 )
                stdControl_aInput1[keyNum] = stdControl_msDelta;
            stdControl_aInput1[keyNum] += readTime - stdControl_curReadTime;
        }
    }
    else
    {
        v3 = stdControl_curReadTime - readTime;
        stdControl_aKeyInfo[keyNum] = 1;
        stdControl_aInput1[keyNum] = v3;
        ++stdControl_aInput2[keyNum];
    }
}

// readmouse

void stdControl_InitAxis(int index, int stickMin, int stickMax, float multiplier)
{
    int v4; // eax
    int v5; // esi
    double v6; // st7

    v4 = stickMin + (stickMax - stickMin + 1) / 2;
    v5 = index;
    stdControl_aJoysticks[v5].flags = stdControl_aJoysticks[index].flags | 1;
    stdControl_aJoysticks[v5].uMinVal = stickMin;
    stdControl_aJoysticks[v5].uMaxVal = stickMax;
    stdControl_aJoysticks[v5].dwXoffs = v4;
    v6 = (double)(stickMax - v4);
    stdControl_aJoysticks[v5].fRangeConversion = 1.0 / v6;
    if ( multiplier == 0.0 )
        stdControl_aJoysticks[index].dwYoffs = 0;
    else
        stdControl_aJoysticks[index].dwYoffs = (__int64)(multiplier * v6);
}
