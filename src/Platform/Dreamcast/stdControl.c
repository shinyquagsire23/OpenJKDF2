// Dreamcast (KallistiOS) input backend: maple keyboard, mouse and controller.
//
// The shared key/axis logic and name tables live in src/Platform/Common/stdControl.c;
// this file is the device layer. KOS keyboard scancodes are USB-HID values, the same
// space SDL scancodes use, so the SDL->DIK table is reused verbatim for the keyboard.
//
//  - Keyboard: held keys feed in-game controls (HID scancode -> DIK); the typed-text
//    and special keys for menus are posted from Window_Dreamcast.c.
//  - Controller: treated as joystick 0 (face buttons, triggers, dpad, analog stick).
//  - Mouse: relative motion -> look axes, buttons -> KEY_MOUSE_B*.

#include "Platform/stdControl.h"

#include "Devices/sithControl.h"
#include "Win95/Window.h"
#include "stdPlatform.h"

#include "jk.h"

#include <dc/maple.h>
#include <dc/maple/controller.h>
#include <dc/maple/keyboard.h>
#include <dc/maple/mouse.h>

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

uint8_t stdControl_aDebounce[JK_NUM_KEYS];
int stdControl_bControllerEscapeKey = 0;
int stdControl_bControllerEscapeKey_last = 0;
static int stdControl_aJoystickNumAxes[JK_NUM_JOYSTICKS] = {0};
static int stdControl_bKeyboardBeingShown = 0;

void stdControl_SetSDLKeydown(int keyNum, int bDown, uint32_t readTime)
{
    if (keyNum < 0 || keyNum >= 256)
        return;
    if (!stdControl_aSdlToDik[keyNum])
        return;
    stdControl_SetKeydown(stdControl_aSdlToDik[keyNum], bDown, readTime);
}

int stdControl_Startup()
{
    _memset(stdControl_aInput1, 0, sizeof(int) * JK_NUM_KEYS);
    _memset(stdControl_aKeyInfo, 0, sizeof(int) * JK_NUM_KEYS);
    _memset(stdControl_aJoysticks, 0, sizeof(stdControlJoystickEntry) * JK_NUM_AXES);
    _memset(stdControl_aAxisPos, 0, sizeof(int) * JK_NUM_AXES);
    _memset(stdControl_aDebounce, 0, sizeof(stdControl_aDebounce));

    for (int i = 0; i < JK_NUM_JOYSTICKS; i++) {
        stdControl_aJoystickExists[i] = 0;
        stdControl_aJoystickMaxButtons[i] = 0;
        stdControl_aJoystickEnabled[i] = 0;
        stdControl_aJoystickNumAxes[i] = 0;
    }

    // Mouse axes (matches the SDL2/TWL ranges).
    stdControl_InitAxis(AXIS_MOUSE_X, -250, 250, 0.0);
    stdControl_InitAxis(AXIS_MOUSE_Y, -200, 200, 0.0);
    stdControl_InitAxis(AXIS_MOUSE_Z, -20, 20, 0.0);

    stdControl_Reset();
    stdControl_bStartup = 1;
    return 1;
}

void stdControl_Shutdown() {}
int  stdControl_Open()  { return 1; }
int  stdControl_Close() { return 1; }
void stdControl_Flush() {}

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

static int _cursorState = 0;

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

void stdControl_ToggleMouse()
{
    if ( stdControl_bReadMouse )
    {
        stdControl_bReadMouse = 0;
        stdControl_ShowCursor(1);
    }
    else
    {
        stdControl_bReadMouse = 1;
        stdControl_ShowCursor(0);
    }
}
void stdControl_FreeSdlJoysticks() {}
void stdControl_InitSdlJoysticks() {}
void stdControl_ShowSystemKeyboard() {}
void stdControl_HideSystemKeyboard() {}

void stdControl_ReadControls()
{
    flex_d_t khz;

    if (!stdControl_bControlsActive)
        return;

    // Present the Dreamcast controller as joystick 0.
    stdControl_bHasJoysticks = 1;
    stdControl_aJoystickNumAxes[0] = 1;
    stdControl_aJoystickMaxButtons[0] = 7;
    stdControl_aAxisEnabled[0] = 1;
    stdControl_aAxisEnabled[1] = 1;
    stdControl_aJoystickExists[0] = 1;
    sithWeapon_controlOptions &= ~(1 << 5); // Enable joystick

    stdControl_InitAxis(AXIS_JOY1_X, -0x7FFF, 0x7FFF, 0.2);
    stdControl_InitAxis(AXIS_JOY1_Y, -0x7FFF, 0x7FFF, 0.2);

    stdControl_bControlsIdle = 1;
    stdControl_curReadTime = stdPlatform_GetTimeMsec();
    stdControl_msDelta = stdControl_curReadTime - stdControl_msLast;
    khz = (stdControl_msDelta != 0) ? (1.0 / (flex_d_t)(stdControl_msDelta)) : 1.0;
    stdControl_updateKHz = khz;
    stdControl_updateHz = khz * 1000.0;

    // Keyboard: feed every held key through the HID-scancode -> DIK table.
    if (!stdControl_bDisableKeyboard) {
        maple_device_t* kbd_dev = maple_enum_type(0, MAPLE_FUNC_KEYBOARD);
        if (kbd_dev) {
            kbd_state_t* kbd = kbd_get_state(kbd_dev);
            if (kbd) {
                for (int i = 0; i < 256 && i < KBD_MAX_KEYS; i++) {
                    int down = (kbd->key_states[i].value & KEY_STATE_IS_DOWN) ? 1 : 0;
                    stdControl_SetSDLKeydown(i, down, stdControl_curReadTime);
                }
            }
        }
    }

    // Controller -> joystick 0.
    maple_device_t* cont_dev = maple_enum_type(0, MAPLE_FUNC_CONTROLLER);
    if (cont_dev) {
        cont_state_t* st = (cont_state_t*)maple_dev_status(cont_dev);
        if (st) {
            uint32_t b = st->buttons;
            stdControl_SetKeydown(KEY_JOY1_B1, !!(b & CONT_A),     stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_B2, !!(b & CONT_B),     stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_B3, !!(b & CONT_X),     stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_B4, !!(b & CONT_Y),     stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_B10, st->ltrig > 64,    stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_B11, st->rtrig > 64,    stdControl_curReadTime);

            stdControl_SetKeydown(KEY_JOY1_HLEFT,  !!(b & CONT_DPAD_LEFT),  stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_HUP,    !!(b & CONT_DPAD_UP),    stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_HRIGHT, !!(b & CONT_DPAD_RIGHT), stdControl_curReadTime);
            stdControl_SetKeydown(KEY_JOY1_HDOWN,  !!(b & CONT_DPAD_DOWN),  stdControl_curReadTime);

            // Analog stick (-128..127) -> joystick axis range.
            stdControl_aAxisPos[AXIS_JOY1_X] = (st->joyx * 0x7FFF) / 128;
            stdControl_aAxisPos[AXIS_JOY1_Y] = (st->joyy * 0x7FFF) / 128;
        }
    }

    stdControl_ReadMouse();
    stdControl_msLast = stdControl_curReadTime;
}

void stdControl_ReadMouse()
{
    if (!stdControl_bReadMouse)
        return;

    int dx = 0, dy = 0, dz = 0, bLeft = 0, bRight = 0;
    maple_device_t* mdev = maple_enum_type(0, MAPLE_FUNC_MOUSE);
    if (mdev) {
        mouse_state_t* m = (mouse_state_t*)maple_dev_status(mdev);
        if (m) {
            dx = m->dx; dy = m->dy; dz = m->dz;
            bLeft  = !!(m->buttons & MOUSE_LEFTBUTTON);
            bRight = !!(m->buttons & MOUSE_RIGHTBUTTON);
        }
    }

    // Look axes: combine the maple mouse delta with any Window-posted relative
    // motion (e.g. future controller look), then consume it.
    stdControl_aAxisPos[AXIS_MOUSE_X] = Window_lastXRel + dx;
    stdControl_aAxisPos[AXIS_MOUSE_Y] = Window_lastYRel + dy;
    stdControl_aAxisPos[AXIS_MOUSE_Z] = Window_mouseWheelY + dz;

    if (dx || dy || dz || Window_lastXRel || Window_lastYRel)
        stdControl_bControlsIdle = 0;

    stdControl_dwLastMouseX = stdControl_aAxisPos[AXIS_MOUSE_X];
    stdControl_dwLastMouseY = stdControl_aAxisPos[AXIS_MOUSE_Y];

    Window_lastXRel = 0;
    Window_lastYRel = 0;
    Window_mouseWheelX = 0;
    Window_mouseWheelY = 0;

    stdControl_SetKeydown(KEY_MOUSE_B1, bLeft  || Window_bMouseLeft,  stdControl_curReadTime);
    stdControl_SetKeydown(KEY_MOUSE_B2, bRight || Window_bMouseRight, stdControl_curReadTime);
}

BOOL stdControl_IsSystemKeyboardShowing() {
    return stdControl_bKeyboardBeingShown;
}