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
  { DIK_ESCAPE,         "DIK_ESCAPE" },
  { DIK_1,              "DIK_1" },
  { DIK_2,              "DIK_2" },
  { DIK_3,              "DIK_3" },
  { DIK_4,              "DIK_4" },
  { DIK_5,              "DIK_5" },
  { DIK_6,              "DIK_6" },
  { DIK_7,              "DIK_7" },
  { DIK_8,              "DIK_8" },
  { DIK_9,              "DIK_9" },
  { DIK_0,              "DIK_0" },
  { DIK_MINUS,          "DIK_MINUS" },
  { DIK_EQUALS,         "DIK_EQUALS" },
  { DIK_BACK,           "DIK_BACK" },
  { DIK_TAB,            "DIK_TAB" },
  { DIK_Q,              "DIK_Q" },
  { DIK_W,              "DIK_W" },
  { DIK_E,              "DIK_E" },
  { DIK_R,              "DIK_R" },
  { DIK_T,              "DIK_T" },
  { DIK_Y,              "DIK_Y" },
  { DIK_U,              "DIK_U" },
  { DIK_I,              "DIK_I" },
  { DIK_O,              "DIK_O" },
  { DIK_P,              "DIK_P" },
  { DIK_LBRACKET,       "DIK_LBRACKET" },
  { DIK_RBRACKET,       "DIK_RBRACKET" },
  { DIK_RETURN,         "DIK_RETURN" },
  { DIK_LCONTROL,       "DIK_LCONTROL" },
  { DIK_A,              "DIK_A" },
  { DIK_S,              "DIK_S" },
  { DIK_D,              "DIK_D" },
  { DIK_F,              "DIK_F" },
  { DIK_G,              "DIK_G" },
  { DIK_H,              "DIK_H" },
  { DIK_J,              "DIK_J" },
  { DIK_K,              "DIK_K" },
  { DIK_L,              "DIK_L" },
  { DIK_SEMICOLON,      "DIK_SEMICOLON" },
  { DIK_APOSTROPHE,     "DIK_APOSTROPHE" },
  { DIK_GRAVE,          "DIK_GRAVE" },
  { DIK_LSHIFT,         "DIK_LSHIFT" },
  { DIK_BACKSLASH,      "DIK_BACKSLASH" },
  { DIK_Z,              "DIK_Z" },
  { DIK_X,              "DIK_X" },
  { DIK_C,              "DIK_C" },
  { DIK_V,              "DIK_V" },
  { DIK_B,              "DIK_B" },
  { DIK_N,              "DIK_N" },
  { DIK_M,              "DIK_M" },
  { DIK_COMMA,          "DIK_COMMA" },
  { DIK_PERIOD,         "DIK_PERIOD" },
  { DIK_SLASH,          "DIK_SLASH" },
  { DIK_RSHIFT,         "DIK_RSHIFT" },
  { DIK_MULTIPLY,       "DIK_MULTIPLY" },
  { DIK_LMENU,          "DIK_LMENU" },
  { DIK_SPACE,          "DIK_SPACE" },
  { DIK_CAPITAL,        "DIK_CAPITAL" },
  { DIK_F1,             "DIK_F1" },
  { DIK_F2,             "DIK_F2" },
  { DIK_F3,             "DIK_F3" },
  { DIK_F4,             "DIK_F4" },
  { DIK_F5,             "DIK_F5" },
  { DIK_F6,             "DIK_F6" },
  { DIK_F7,             "DIK_F7" },
  { DIK_F8,             "DIK_F8" },
  { DIK_F9,             "DIK_F9" },
  { DIK_F10,            "DIK_F10" },
  { DIK_NUMLOCK,        "DIK_NUMLOCK" },
  { DIK_SCROLL,         "DIK_SCROLL" },
  { DIK_NUMPAD7,        "DIK_NUMPAD7" },
  { DIK_NUMPAD8,        "DIK_NUMPAD8" },
  { DIK_NUMPAD9,        "DIK_NUMPAD9" },
  { DIK_SUBTRACT,       "DIK_SUBTRACT" },
  { DIK_NUMPAD4,        "DIK_NUMPAD4" },
  { DIK_NUMPAD5,        "DIK_NUMPAD5" },
  { DIK_NUMPAD6,        "DIK_NUMPAD6" },
  { DIK_ADD,            "DIK_ADD" },
  { DIK_NUMPAD1,        "DIK_NUMPAD1" },
  { DIK_NUMPAD2,        "DIK_NUMPAD2" },
  { DIK_NUMPAD3,        "DIK_NUMPAD3" },
  { DIK_NUMPAD0,        "DIK_NUMPAD0" },
  { DIK_DECIMAL,        "DIK_DECIMAL" },
  { DIK_F11,            "DIK_F11" },
  { DIK_F12,            "DIK_F12" },
  { DIK_F13,            "DIK_F13" },
  { DIK_F14,            "DIK_F14" },
  { DIK_F15,            "DIK_F15" },
  { DIK_KANA,           "DIK_KANA" },
  { DIK_CONVERT,        "DIK_CONVERT" },
  { DIK_NOCONVERT,      "DIK_NOCONVERT" },
  { DIK_YEN,            "DIK_YEN" },
  { DIK_NUMPADEQUALS,   "DIK_NUMPADEQUALS" },
  { DIK_CIRCUMFLEX,     "DIK_CIRCUMFLEX" },
  { DIK_AT,             "DIK_AT" },
  { DIK_COLON,          "DIK_COLON" },
  { DIK_UNDERLINE,      "DIK_UNDERLINE" },
  { DIK_KANJI,          "DIK_KANJI" },
  { DIK_STOP,           "DIK_STOP" },
  { DIK_AX,             "DIK_AX" },
  { DIK_UNLABELED,      "DIK_UNLABELED" },
  { DIK_NUMPADENTER,    "DIK_NUMPADENTER" },
  { DIK_RCONTROL,       "DIK_RCONTROL" },
  { DIK_NUMPADCOMMA,    "DIK_NUMPADCOMMA" },
  { DIK_DIVIDE,         "DIK_DIVIDE" },
  { DIK_SYSRQ,          "DIK_SYSRQ" },
  { DIK_RMENU,          "DIK_RMENU" },
  { DIK_HOME,           "DIK_HOME" },
  { DIK_UP,             "DIK_UP" },
  { DIK_PRIOR,          "DIK_PRIOR" },
  { DIK_LEFT,           "DIK_LEFT" },
  { DIK_RIGHT,          "DIK_RIGHT" },
  { DIK_END,            "DIK_END" },
  { DIK_DOWN,           "DIK_DOWN" },
  { DIK_NEXT,           "DIK_NEXT" },
  { DIK_INSERT,         "DIK_INSERT" },
  { DIK_DELETE,         "DIK_DELETE" },
  { DIK_LWIN,           "DIK_LWIN" },
  { DIK_RWIN,           "DIK_RWIN" },
  { DIK_APPS,           "DIK_APPS" },
  { KEY_JOY1_B1,        "KEY_JOY1_B1" },
  { KEY_JOY1_B2,        "KEY_JOY1_B2" },
  { KEY_JOY1_B3,        "KEY_JOY1_B3" },
  { KEY_JOY1_B4,        "KEY_JOY1_B4" },
  { KEY_JOY1_B5,        "KEY_JOY1_B5" },
  { KEY_JOY1_B6,        "KEY_JOY1_B6" },
  { KEY_JOY1_B7,        "KEY_JOY1_B7" },
  { KEY_JOY1_B8,        "KEY_JOY1_B8" },
  { KEY_JOY1_HLEFT,     "KEY_JOY1_HLEFT" },
  { KEY_JOY1_HUP,       "KEY_JOY1_HUP" },
  { KEY_JOY1_HRIGHT,    "KEY_JOY1_HRIGHT" },
  { KEY_JOY1_HDOWN,     "KEY_JOY1_HDOWN" },
  { KEY_JOY2_B1,        "KEY_JOY2_B1" },
  { KEY_JOY2_B2,        "KEY_JOY2_B2" },
  { KEY_JOY2_B3,        "KEY_JOY2_B3" },
  { KEY_JOY2_B4,        "KEY_JOY2_B4" },
  { KEY_JOY2_B5,        "KEY_JOY2_B5" },
  { KEY_JOY2_B6,        "KEY_JOY2_B6" },
  { KEY_JOY2_B7,        "KEY_JOY2_B7" },
  { KEY_JOY2_B8,        "KEY_JOY2_B8" },
  { KEY_JOY2_HLEFT,     "KEY_JOY2_HLEFT" },
  { KEY_JOY2_HUP,       "KEY_JOY2_HUP" },
  { KEY_JOY2_HRIGHT,    "KEY_JOY2_HRIGHT" },
  { KEY_JOY2_HDOWN,     "KEY_JOY2_HDOWN" },
  { KEY_MOUSE_B1,       "KEY_MOUSE_B1" },
  { KEY_MOUSE_B2,       "KEY_MOUSE_B2" },
  { KEY_MOUSE_B3,       "KEY_MOUSE_B3" },
  { KEY_MOUSE_B4,       "KEY_MOUSE_B4" }
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

int stdControl_MessageHandler(HWND hWnd, UINT Msg, WPARAM wParam, HWND lParam, LRESULT* unused)
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
