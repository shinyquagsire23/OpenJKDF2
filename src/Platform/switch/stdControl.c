#include "Platform/stdControl.h"

#include "Devices/sithControl.h"
#include "Win95/Window.h"
#include "stdPlatform.h"
#include "General/stdMath.h"

#include "jk.h"
#include "Main/jkCutscene.h"
// Switch-specific includes
#include <switch.h>
static int stdControl_bKeyboardBeingShown = 0;
// Switch controller state
static PadState switch_pad;
static bool switch_initialized = false;
const uint8_t stdControl_aSdlToDik[256] =
{
    0,
    0,
    0,
    0,
    DIK_A,
    DIK_B,
    DIK_C,
    DIK_D,
    DIK_E,
    DIK_F,
    DIK_G,
    DIK_H,
    DIK_I,
    DIK_J,
    DIK_K,
    DIK_L,
    DIK_M,
    DIK_N,
    DIK_O,
    DIK_P,
    DIK_Q,
    DIK_R,
    DIK_S,
    DIK_T,
    DIK_U,
    DIK_V,
    DIK_W,
    DIK_X,
    DIK_Y,
    DIK_Z,

    DIK_1,
    DIK_2,
    DIK_3,
    DIK_4,
    DIK_5,
    DIK_6,
    DIK_7,
    DIK_8,
    DIK_9,
    DIK_0,

    DIK_RETURN,
    DIK_ESCAPE,
    DIK_BACK,
    DIK_TAB,
    DIK_SPACE,

    DIK_MINUS,
    DIK_EQUALS,
    DIK_LBRACKET,
    DIK_RBRACKET,
    DIK_BACKSLASH,
    0,
    DIK_SEMICOLON,
    DIK_APOSTROPHE,
    DIK_GRAVE,
    DIK_COMMA,
    DIK_PERIOD,
    DIK_SLASH,

    DIK_CAPITAL,

    DIK_F1,
    DIK_F2,
    DIK_F3,
    DIK_F4,
    DIK_F5,
    DIK_F6,
    DIK_F7,
    DIK_F8,
    DIK_F9,
    DIK_F10,
    DIK_F11,
    DIK_F12,

    0,//DIK_PRINTSCREEN,
    DIK_SCROLL,
    DIK_PAUSE,
    0, // DIK_INSERT, this gets stuck down?
    DIK_HOME,
    DIK_PRIOR,
    DIK_DELETE,
    DIK_END,
    DIK_NEXT,
    DIK_RIGHT,
    DIK_LEFT,
    DIK_DOWN,
    DIK_UP,

    0,//DIK_NUMLOCKCLEAR,
    DIK_DIVIDE,
    DIK_MULTIPLY,
    DIK_SUBTRACT,
    DIK_ADD,
    DIK_NUMPADENTER,
    DIK_NUMPAD1,
    DIK_NUMPAD2,
    DIK_NUMPAD3,
    DIK_NUMPAD4,
    DIK_NUMPAD5,
    DIK_NUMPAD6,
    DIK_NUMPAD7,
    DIK_NUMPAD8,
    DIK_NUMPAD9,
    DIK_NUMPAD0,
    DIK_DECIMAL,

    DIK_BACKSLASH,
    0,//DIK_APPLICATION,
    DIK_POWER,
    DIK_NUMPADEQUALS,
    DIK_F13,
    DIK_F14,
    DIK_F15,
    0,//DIK_F16,
    0,//DIK_F17,
    0,//DIK_F18,
    0,//DIK_F19,
    0,//DIK_F20,
    0,//DIK_F21,
    0,//DIK_F22,
    0,//DIK_F23,
    0,//DIK_F24,
    0,//DIK_EXECUTE,
    0,//DIK_HELP,
    0,//DIK_MENU,
    0,//DIK_SELECT,
    0,//DIK_STOP,
    0,//DIK_AGAIN,
    0,//DIK_UNDO,
    0,//DIK_CUT,
    0,//DIK_COPY,
    0,//DIK_PASTE,
    0,//DIK_FIND,
    DIK_MUTE,
    DIK_VOLUMEUP,
    DIK_VOLUMEDOWN,
    0,
    0,
    0,
    DIK_NUMPADCOMMA,
    DIK_NUMPADEQUALS,

    0,//DIK_INTERNATIONAL1,
    0,//DIK_INTERNATIONAL2,
    0,//DIK_INTERNATIONAL3,
    0,//DIK_INTERNATIONAL4,
    0,//DIK_INTERNATIONAL5,
    0,//DIK_INTERNATIONAL6,
    0,//DIK_INTERNATIONAL7,
    0,//DIK_INTERNATIONAL8,
    0,//DIK_INTERNATIONAL9,
    0,//DIK_LANG1,
    0,//DIK_LANG2,
    0,//DIK_LANG3,
    0,//DIK_LANG4,
    0,//DIK_LANG5,
    0,//DIK_LANG6,
    0,//DIK_LANG7,
    0,//DIK_LANG8,
    0,//DIK_LANG9,

    0,//DIK_ALTERASE,
    0,//DIK_SYSREQ,
    0,//DIK_CANCEL,
    0,//DIK_CLEAR,
    DIK_PRIOR,
    0,//DIK_RETURN2,
    0,//DIK_SEPARATOR,
    0,//DIK_OUT,
    0,//DIK_OPER,
    0,//DIK_CLEARAGAIN,
    0,//DIK_CRSEL,
    0,//DIK_EXSEL,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,//DIK_KP_00,
    0,//DIK_KP_000,
    0,//DIK_THOUSANDSSEPARATOR,
    0,//DIK_DECIMALSEPARATOR,
    0,//DIK_CURRENCYUNIT,
    0,//DIK_CURRENCYSUBUNIT,
    0,//DIK_KP_LEFTPAREN,
    0,//DIK_KP_RIGHTPAREN,
    0,//DIK_KP_LEFTBRACE,
    0,//DIK_KP_RIGHTBRACE,
    0,//DIK_KP_TAB,
    0,//DIK_KP_BACKSPACE,
    0,//DIK_KP_A,
    0,//DIK_KP_B,
    0,//DIK_KP_C,
    0,//DIK_KP_D,
    0,//DIK_KP_E,
    0,//DIK_KP_F,
    0,//DIK_KP_XOR,
    0,//DIK_KP_POWER,
    0,//DIK_KP_PERCENT,
    0,//DIK_KP_LESS,
    0,//DIK_KP_GREATER,
    0,//DIK_KP_AMPERSAND,
    0,//DIK_KP_DBLAMPERSAND,
    0,//DIK_KP_VERTICALBAR,
    0,//DIK_KP_DBLVERTICALBAR,
    0,//DIK_KP_COLON,
    0,//DIK_KP_HASH,
    0,//DIK_KP_SPACE,
    0,//DIK_KP_AT,
    0,//DIK_KP_EXCLAM,
    0,//DIK_KP_MEMSTORE,
    0,//DIK_KP_MEMRECALL,
    0,//DIK_KP_MEMCLEAR,
    0,//DIK_KP_MEMADD,
    0,//DIK_KP_MEMSUBTRACT,
    0,//DIK_KP_MEMMULTIPLY,
    0,//DIK_KP_MEMDIVIDE,
    0,//DIK_KP_PLUSMINUS,
    0,//DIK_KP_CLEAR,
    0,//DIK_KP_CLEARENTRY,
    0,//DIK_KP_BINARY,
    0,//DIK_KP_OCTAL,
    0,//DIK_KP_DECIMAL,
    0,//DIK_KP_HEXADECIMAL,
    0,
    0,
    DIK_LCONTROL,
    DIK_LSHIFT,
    DIK_LMENU,
    0,//DIK_LGUI,
    DIK_RCONTROL,
    DIK_RSHIFT,
    DIK_RMENU,
    0,//DIK_RGUI,
};

uint8_t stdControl_aDebounce[256];

#define SDL2_MIN_BINARY_THRESH (-0x5000)
#define SDL2_MAX_BINARY_THRESH (0x5000)

#define QUIRK_NINTENDO_TRIGGER_AXIS_TO_BUTTON (1)
const char *stdControl_aAxisNames[JK_NUM_AXES+1] =
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

const stdControlDikStrToNum stdControl_aDikNumToStr[JK_TOTAL_NUM_KEYS] =
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
#ifdef SDL2_RENDER
  { KEY_JOY1_B9,        "KEY_JOY1_B9" },

  { KEY_JOY1_B10,       "KEY_JOY1_B10" },
  { KEY_JOY1_B11,        "KEY_JOY1_B11" },
  { KEY_JOY1_B12,        "KEY_JOY1_B12" },
  { KEY_JOY1_B13,        "KEY_JOY1_B13" },
  { KEY_JOY1_B14,        "KEY_JOY1_B14" },
  { KEY_JOY1_B15,        "KEY_JOY1_B15" },
  { KEY_JOY1_B16,        "KEY_JOY1_B16" },
  { KEY_JOY1_B17,        "KEY_JOY1_B17" },
  { KEY_JOY1_B18,        "KEY_JOY1_B18" },
  { KEY_JOY1_B19,        "KEY_JOY1_B19" },
  { KEY_JOY1_B20,        "KEY_JOY1_B20" },
  { KEY_JOY1_B21,        "KEY_JOY1_B21" },
  { KEY_JOY1_B22,        "KEY_JOY1_B22" },
  { KEY_JOY1_B23,        "KEY_JOY1_B23" },
  { KEY_JOY1_B24,        "KEY_JOY1_B24" },
  { KEY_JOY1_B25,        "KEY_JOY1_B25" },
  { KEY_JOY1_B26,        "KEY_JOY1_B26" },
  { KEY_JOY1_B27,        "KEY_JOY1_B27" },
  { KEY_JOY1_B28,        "KEY_JOY1_B28" },
  { KEY_JOY1_B29,        "KEY_JOY1_B29" },
  { KEY_JOY1_B30,        "KEY_JOY1_B30" },
  { KEY_JOY1_B31,        "KEY_JOY1_B31" },
  { KEY_JOY1_B32,        "KEY_JOY1_B32" },
#endif
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
#ifdef SDL2_RENDER
  { KEY_JOY2_B9,        "KEY_JOY2_B9" },

  { KEY_JOY2_B10,       "KEY_JOY2_B10" },
  { KEY_JOY2_B11,        "KEY_JOY2_B11" },
  { KEY_JOY2_B12,        "KEY_JOY2_B12" },
  { KEY_JOY2_B13,        "KEY_JOY2_B13" },
  { KEY_JOY2_B14,        "KEY_JOY2_B14" },
  { KEY_JOY2_B15,        "KEY_JOY2_B15" },
  { KEY_JOY2_B16,        "KEY_JOY2_B16" },
  { KEY_JOY2_B17,        "KEY_JOY2_B17" },
  { KEY_JOY2_B18,        "KEY_JOY2_B18" },
  { KEY_JOY2_B19,        "KEY_JOY2_B19" },
  { KEY_JOY2_B20,        "KEY_JOY2_B20" },
  { KEY_JOY2_B21,        "KEY_JOY2_B21" },
  { KEY_JOY2_B22,        "KEY_JOY2_B22" },
  { KEY_JOY2_B23,        "KEY_JOY2_B23" },
  { KEY_JOY2_B24,        "KEY_JOY2_B24" },
  { KEY_JOY2_B25,        "KEY_JOY2_B25" },
  { KEY_JOY2_B26,        "KEY_JOY2_B26" },
  { KEY_JOY2_B27,        "KEY_JOY2_B27" },
  { KEY_JOY2_B28,        "KEY_JOY2_B28" },
  { KEY_JOY2_B29,        "KEY_JOY2_B29" },
  { KEY_JOY2_B30,        "KEY_JOY2_B30" },
  { KEY_JOY2_B31,        "KEY_JOY2_B31" },
  { KEY_JOY2_B32,        "KEY_JOY2_B32" },
#endif
  { KEY_JOY2_HLEFT,     "KEY_JOY2_HLEFT" },
  { KEY_JOY2_HUP,       "KEY_JOY2_HUP" },
  { KEY_JOY2_HRIGHT,    "KEY_JOY2_HRIGHT" },
  { KEY_JOY2_HDOWN,     "KEY_JOY2_HDOWN" },
  { KEY_MOUSE_B1,       "KEY_MOUSE_B1" },
  { KEY_MOUSE_B2,       "KEY_MOUSE_B2" },
  { KEY_MOUSE_B3,       "KEY_MOUSE_B3" },
  { KEY_MOUSE_B4,       "KEY_MOUSE_B4" },
#ifdef SDL2_RENDER
  { KEY_MOUSE_B5,       "KEY_MOUSE_B5" }
#endif
};

// Control system startup
int stdControl_Startup()
{
#ifdef TARGET_NINTENDO_SWITCH
    stdControl_SwitchInit();
#endif
    return 1;
}

// Control system shutdown
void stdControl_Shutdown()
{
    // Nothing specific needed for Switch
}

// Open controls
int stdControl_Open()
{
    stdControl_bOpen = 1;
    stdControl_bControlsActive = 1;
    return 1;
}

// Close controls
int stdControl_Close()
{
    stdControl_bOpen = 0;
    stdControl_bControlsActive = 0;
    return 1;
}

void stdControl_InitSdlJoysticks(){
    stdControl_SwitchInit();
}

void stdControl_ToggleCursor(int a)
{
    if ( stdControl_bOpen )
    {
        if ( a )
        {
            if ( stdControl_mouseDirectInputDevice && stdControl_bReadMouse )
            {
                //stdControl_mouseDirectInputDevice->lpVtbl->Acquire(stdControl_mouseDirectInputDevice);
                stdControl_ShowCursor(0);
            }
            //if ( stdControl_keyboardIDirectInputDevice )
            //    stdControl_keyboardIDirectInputDevice->lpVtbl->Acquire(stdControl_keyboardIDirectInputDevice);
            stdControl_bControlsActive = 1;
        }
        else
        {
            if ( stdControl_mouseDirectInputDevice )
            {
                //stdControl_mouseDirectInputDevice->lpVtbl->Unacquire(stdControl_mouseDirectInputDevice);
                stdControl_ShowCursor(1);
            }
            //if ( stdControl_keyboardIDirectInputDevice )
            //    stdControl_keyboardIDirectInputDevice->lpVtbl->Unacquire(stdControl_keyboardIDirectInputDevice);
            stdControl_bControlsActive = 0;
        }
    }

    //SDL_SetRelativeMouseMode(!!a);
}
void stdControl_ShowSystemKeyboard() {
    if (stdControl_bKeyboardBeingShown) {
        return;
    }
    stdControl_bKeyboardBeingShown = 1;
}

void stdControl_HideSystemKeyboard() {
    if (!stdControl_bKeyboardBeingShown) {
        return;
    }
    stdControl_bKeyboardBeingShown = 0;
}
BOOL stdControl_IsSystemKeyboardShowing() {
    return stdControl_bKeyboardBeingShown;
}
// Flush controls
void stdControl_Flush()
{
    // Reset all key states
    memset(stdControl_aKeyInfo, 0, sizeof(stdControl_aKeyInfo));
    memset(stdControl_aAxisPos, 0, sizeof(stdControl_aAxisPos));
}

void stdControl_Reset()
{
    stdControlJoystickEntry *v0; // eax

    stdControl_bReadMouse = 0;
    stdControl_bHasJoysticks = 0;

    for (int i = 0; i < JK_NUM_JOYSTICKS; i++) {
        stdControl_aAxisEnabled[i] = 0;
        stdControl_aAxisConnected[i] = 0x680;
    }

    v0 = stdControl_aJoysticks;
    for (int i = 0; i < JK_NUM_AXES; i++)
    {
        v0->flags &= ~2;
        ++v0;
    }
}

// Switch-specific initialization
void stdControl_SwitchInit()
{
    if (!switch_initialized) {
        // Configure our supported input layout: single player with standard controller styles
        padConfigureInput(1, HidNpadStyleSet_NpadStandard);
        
        // Initialize the default gamepad (reads handheld mode inputs and first connected controller)
        padInitializeDefault(&switch_pad);
        
        switch_initialized = true;
        
        // Initialize joystick axes for Switch controllers
        // Left stick
        stdControl_InitAxis(AXIS_JOY1_X, -32768, 32767, 0.1);
        stdControl_InitAxis(AXIS_JOY1_Y, -32768, 32767, 0.1);
        
        // Right stick  
        stdControl_InitAxis(AXIS_JOY1_Z, -32768, 32767, 0.1);
        stdControl_InitAxis(AXIS_JOY1_R, -32768, 32767, 0.1);
        
        // Enable the axes
        stdControl_EnableAxis(AXIS_JOY1_X);
        stdControl_EnableAxis(AXIS_JOY1_Y);
        stdControl_EnableAxis(AXIS_JOY1_Z);
        stdControl_EnableAxis(AXIS_JOY1_R);
    }
}

int stdControl_EnableAxis(unsigned int idx)
{
    if ( idx >= JK_NUM_AXES )
        return 0;

    if ( (stdControl_aJoysticks[idx].flags & 1) == 0 )
        return 0;
    stdControl_aJoysticks[idx].flags |= 2;
    if ( idx < AXIS_MOUSE_X )
    {
        int controller_idx = idx / JK_JOYSTICK_AXIS_STRIDE;
        stdControl_bHasJoysticks = 1;
        stdControl_aAxisEnabled[controller_idx] = 1;
        switch (idx % JK_JOYSTICK_AXIS_STRIDE)
        {
            case 0u:
                stdControl_aAxisConnected[controller_idx] |= 1u;
                break;
            case 1u:
                stdControl_aAxisConnected[controller_idx] |= 2u;
                break;
            case 2u:
                stdControl_aAxisConnected[controller_idx] |= 4u;
                break;
            case 3u:
                stdControl_aAxisConnected[controller_idx] |= 8u;
                break;
            case 4u:
                stdControl_aAxisConnected[controller_idx] |= 0x10u;
                break;
            case 5u:
                stdControl_aAxisConnected[controller_idx] |= 0x20u;
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

flex_t stdControl_ReadAxis(int axisNum)
{
    flex_t result; // st7
    int v2; // ecx
    int v3; // edx
    int v4; // eax
    int v5; // edx
    int v9; // [esp+8h] [ebp+4h]

    if ( !stdControl_bControlsActive )
        return 0.0;

    // Added: OOB
    if (axisNum >= JK_NUM_AXES) {
        return 0.0;
    }

    v2 = axisNum;
    v3 = stdControl_aJoysticks[axisNum].flags;
    if ( (v3 & 2) == 0 )
        return 0.0;
    v4 = stdControl_aAxisPos[axisNum] - stdControl_aJoysticks[axisNum].dwXoffs;
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
    result = stdMath_ClipPrecision(stdControl_aJoysticks[v2].fRangeConversion * (flex_d_t)v9);
    if ( stdControl_bControlsIdle )
    {
        if ( result != 0.0 )
            stdControl_bControlsIdle = 0;
    }

    // Added: Scale to FPS
    //result = (result * (sithTime_TickHz / 50.0));
    return result;
}

int stdControl_ReadAxisRaw(int axisNum)
{
    int result; // eax

    if ( !stdControl_bControlsActive )
        return 0;
    // Added: OOB
    if (axisNum >= JK_NUM_AXES) {
        return 0;
    }
    if ( (stdControl_aJoysticks[axisNum].flags & 2) == 0 )
        return 0;
    result = stdControl_aAxisPos[axisNum] - stdControl_aJoysticks[axisNum].dwXoffs;
    if ( !result )
        return 0;
    if ( stdControl_bControlsIdle )
        stdControl_bControlsIdle = 0;

    return result;
}

// Switch-specific controller reading function
void stdControl_SwitchReadControls()
{
    
    if (!switch_initialized) {
        stdControl_SwitchInit();
    }
    
    // Scan the gamepad - should be done once per frame
    padUpdate(&switch_pad);
    
    // Get button states
    u64 kDown = padGetButtonsDown(&switch_pad);
    u64 kUp = padGetButtonsUp(&switch_pad);
    
    // Map Switch buttons to game keys
    // Face buttons (A, B, X, Y)
    stdControl_SetKeydown(KEY_JOY1_B1, (kDown & HidNpadButton_A) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B2, (kDown & HidNpadButton_B) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B3, (kDown & HidNpadButton_X) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B4, (kDown & HidNpadButton_Y) != 0, stdControl_curReadTime);
    

    // Shoulder buttons
    stdControl_SetKeydown(KEY_JOY1_B5, (kDown & HidNpadButton_L) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B6, (kDown & HidNpadButton_R) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B7, (kDown & HidNpadButton_ZL) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B8, (kDown & HidNpadButton_ZR) != 0, stdControl_curReadTime);
    
    // Start/Select
    stdControl_SetKeydown(KEY_JOY1_B9, (kDown & HidNpadButton_Plus) != 0, stdControl_curReadTime);
    if(kDown & HidNpadButton_Minus) {
        jkGuiRend_WindowHandler(0, WM_KEYFIRST, VK_ESCAPE, 0, 0);
        jkGuiRend_WindowHandler(0, WM_CHAR, VK_ESCAPE, 0, 0);
          if ( jkCutscene_isRendering )
                {
                     jkCutscene_sub_421410();
                }
    }
    stdControl_SetKeydown(KEY_JOY1_B10, (kDown & HidNpadButton_Minus) != 0, stdControl_curReadTime);
    
    // Stick clicks
    stdControl_SetKeydown(KEY_JOY1_B11, (kDown & HidNpadButton_StickL) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_B12, (kDown & HidNpadButton_StickR) != 0, stdControl_curReadTime);
    
    // D-Pad
    stdControl_SetKeydown(KEY_JOY1_HLEFT, (kDown & HidNpadButton_Left) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_HUP, (kDown & HidNpadButton_Up) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_HRIGHT, (kDown & HidNpadButton_Right) != 0, stdControl_curReadTime);
    stdControl_SetKeydown(KEY_JOY1_HDOWN, (kDown & HidNpadButton_Down) != 0, stdControl_curReadTime);
    
    // Read analog sticks
    HidAnalogStickState leftStick = padGetStickPos(&switch_pad, 0);  // Left stick
    HidAnalogStickState rightStick = padGetStickPos(&switch_pad, 1); // Right stick
    
    // Update axis positions (convert from -32768 to 32767 range)
    stdControl_aAxisPos[AXIS_JOY1_X] = leftStick.x;
    stdControl_aAxisPos[AXIS_JOY1_Y] = -leftStick.y;  // Invert Y axis
    stdControl_aAxisPos[AXIS_JOY1_Z] = rightStick.x;  // Right stick X
    stdControl_aAxisPos[AXIS_JOY1_R] = -rightStick.y; // Right stick Y (inverted)
}
static int _cursorState = 0;
// Added: SDL2
void stdControl_SetSDLKeydown(int keyNum, int bDown, uint32_t readTime)
{
    if (keyNum < 0 || keyNum >= 256)
        return;

    if (!stdControl_aSdlToDik[keyNum])
        return;

    if (bDown) {
        //stdControl_bControlsIdle = 0;
    }

    stdControl_SetKeydown(stdControl_aSdlToDik[keyNum], bDown, readTime);
}
int stdControl_ShowCursor(int a)
{
    if (a)
    {
        _cursorState++;
    }
    else
    {
        _cursorState--;
    }
    return _cursorState;
}
// Main entry point for reading controls
void stdControl_ReadControls()
{
#ifdef TARGET_SWITCH
    stdControl_SwitchReadControls();
#endif
}

flex_t stdControl_ReadKeyAsAxis(int keyNum)
{
    uint32_t v1; // eax
    flex_t result; // st7

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
    result = (flex_d_t)v1 * stdControl_updateKHz;
    if ( stdControl_bControlsIdle )
    {
        if ( result != 0.0 )
            stdControl_bControlsIdle = 0;
    }
    return result;
}

int stdControl_ReadAxisAsKey(int axisNum)
{
    flex_d_t v1; // st7

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

void stdControl_SetMouseSensitivity(flex_t xSensitivity, flex_t ySensitivity)
{
    stdControl_mouseXSensitivity = xSensitivity;
    stdControl_mouseYSensitivity = ySensitivity;
    if ( (stdControl_aJoysticks[AXIS_MOUSE_X].flags & 1) != 0 )
    {
        stdControl_aJoysticks[AXIS_MOUSE_X].dwYoffs = 0;
        stdControl_aJoysticks[AXIS_MOUSE_X].uMaxVal = (__int64)(xSensitivity * 250.0);
        stdControl_aJoysticks[AXIS_MOUSE_X].uMinVal = -stdControl_aJoysticks[AXIS_MOUSE_X].uMaxVal;
        stdControl_aJoysticks[AXIS_MOUSE_X].flags |= 1u;
        stdControl_aJoysticks[AXIS_MOUSE_X].dwXoffs = (2 * stdControl_aJoysticks[AXIS_MOUSE_X].uMaxVal + 1) / 2 - stdControl_aJoysticks[AXIS_MOUSE_X].uMaxVal;
        stdControl_aJoysticks[AXIS_MOUSE_X].fRangeConversion = 1.0 / (flex_d_t)(stdControl_aJoysticks[AXIS_MOUSE_X].uMaxVal - stdControl_aJoysticks[AXIS_MOUSE_X].dwXoffs);
    }
    if ( (stdControl_aJoysticks[AXIS_MOUSE_Y].flags & 1) != 0 )
    {
        stdControl_aJoysticks[AXIS_MOUSE_Y].dwYoffs = 0;
        stdControl_aJoysticks[AXIS_MOUSE_Y].uMaxVal = (__int64)(ySensitivity * 200.0);
        stdControl_aJoysticks[AXIS_MOUSE_Y].uMinVal = -stdControl_aJoysticks[AXIS_MOUSE_Y].uMaxVal;
        stdControl_aJoysticks[AXIS_MOUSE_Y].flags |= 1u;
        stdControl_aJoysticks[AXIS_MOUSE_Y].dwXoffs = (2 * stdControl_aJoysticks[AXIS_MOUSE_Y].uMaxVal + 1) / 2 - stdControl_aJoysticks[AXIS_MOUSE_Y].uMaxVal;
        stdControl_aJoysticks[AXIS_MOUSE_Y].fRangeConversion = 1.0 / (flex_d_t)(stdControl_aJoysticks[AXIS_MOUSE_Y].uMaxVal - stdControl_aJoysticks[AXIS_MOUSE_Y].dwXoffs);
    }
}

// more

void stdControl_SetKeydown(int keyNum, int bDown, uint32_t readTime)
{
    uint32_t v3; // ecx
    int v4; // ecx

    // Added: bounds check
    if (keyNum >= JK_NUM_KEYS || keyNum < 0)
        return;

    // Added: Prevent idle if not applicable
    if (bDown && !stdControl_aKeyInfo[keyNum]) {
        stdControl_bControlsIdle = 0;
    }
    if (!bDown && stdControl_aKeyInfo[keyNum]) {
        stdControl_bControlsIdle = 0;
    }

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

void stdControl_InitAxis(int index, int stickMin, int stickMax, flex_t multiplier)
{
    int v4; // eax
    int v5; // esi
    flex_d_t v6; // st7

    // Added: OOB
    if (index >= JK_NUM_AXES) {
        return;
    }

    v4 = stickMin + (stickMax - stickMin + 1) / 2;
    v5 = index;
    stdControl_aJoysticks[v5].flags = stdControl_aJoysticks[index].flags | 1;
    stdControl_aJoysticks[v5].uMinVal = stickMin;
    stdControl_aJoysticks[v5].uMaxVal = stickMax;
    stdControl_aJoysticks[v5].dwXoffs = v4;
    v6 = (flex_d_t)(stickMax - v4);
    stdControl_aJoysticks[v5].fRangeConversion = 1.0 / v6;
    if ( multiplier == 0.0 )
        stdControl_aJoysticks[index].dwYoffs = 0;
    else
        stdControl_aJoysticks[index].dwYoffs = (__int64)(multiplier * v6);
}
