
#ifndef IDIRECTINPUTDEVICEA_H
#define IDIRECTINPUTDEVICEA_H

#include <QObject>
#include <unicorn/unicorn.h>
#include "dlls/winutils.h"
#include "dlls/nmm.h"
#include "dlls/user32.h"

#include "dlls/dinput/IDirectInputA.h"

/****************************************************************************
 *
 *      DirectInput keyboard scan codes
 *
 ****************************************************************************/
#define DIK_ESCAPE          0x01
#define DIK_1               0x02
#define DIK_2               0x03
#define DIK_3               0x04
#define DIK_4               0x05
#define DIK_5               0x06
#define DIK_6               0x07
#define DIK_7               0x08
#define DIK_8               0x09
#define DIK_9               0x0A
#define DIK_0               0x0B
#define DIK_MINUS           0x0C    /* - on main keyboard */
#define DIK_EQUALS          0x0D
#define DIK_BACK            0x0E    /* backspace */
#define DIK_TAB             0x0F
#define DIK_Q               0x10
#define DIK_W               0x11
#define DIK_E               0x12
#define DIK_R               0x13
#define DIK_T               0x14
#define DIK_Y               0x15
#define DIK_U               0x16
#define DIK_I               0x17
#define DIK_O               0x18
#define DIK_P               0x19
#define DIK_LBRACKET        0x1A
#define DIK_RBRACKET        0x1B
#define DIK_RETURN          0x1C    /* Enter on main keyboard */
#define DIK_LCONTROL        0x1D
#define DIK_A               0x1E
#define DIK_S               0x1F
#define DIK_D               0x20
#define DIK_F               0x21
#define DIK_G               0x22
#define DIK_H               0x23
#define DIK_J               0x24
#define DIK_K               0x25
#define DIK_L               0x26
#define DIK_SEMICOLON       0x27
#define DIK_APOSTROPHE      0x28
#define DIK_GRAVE           0x29    /* accent grave */
#define DIK_LSHIFT          0x2A
#define DIK_BACKSLASH       0x2B
#define DIK_Z               0x2C
#define DIK_X               0x2D
#define DIK_C               0x2E
#define DIK_V               0x2F
#define DIK_B               0x30
#define DIK_N               0x31
#define DIK_M               0x32
#define DIK_COMMA           0x33
#define DIK_PERIOD          0x34    /* . on main keyboard */
#define DIK_SLASH           0x35    /* / on main keyboard */
#define DIK_RSHIFT          0x36
#define DIK_MULTIPLY        0x37    /* * on numeric keypad */
#define DIK_LMENU           0x38    /* left Alt */
#define DIK_SPACE           0x39
#define DIK_CAPITAL         0x3A
#define DIK_F1              0x3B
#define DIK_F2              0x3C
#define DIK_F3              0x3D
#define DIK_F4              0x3E
#define DIK_F5              0x3F
#define DIK_F6              0x40
#define DIK_F7              0x41
#define DIK_F8              0x42
#define DIK_F9              0x43
#define DIK_F10             0x44
#define DIK_NUMLOCK         0x45
#define DIK_SCROLL          0x46    /* Scroll Lock */
#define DIK_NUMPAD7         0x47
#define DIK_NUMPAD8         0x48
#define DIK_NUMPAD9         0x49
#define DIK_SUBTRACT        0x4A    /* - on numeric keypad */
#define DIK_NUMPAD4         0x4B
#define DIK_NUMPAD5         0x4C
#define DIK_NUMPAD6         0x4D
#define DIK_ADD             0x4E    /* + on numeric keypad */
#define DIK_NUMPAD1         0x4F
#define DIK_NUMPAD2         0x50
#define DIK_NUMPAD3         0x51
#define DIK_NUMPAD0         0x52
#define DIK_DECIMAL         0x53    /* . on numeric keypad */
#define DIK_OEM_102         0x56    /* <> or \| on RT 102-key keyboard (Non-U.S.) */
#define DIK_F11             0x57
#define DIK_F12             0x58
#define DIK_F13             0x64    /*                     (NEC PC98) */
#define DIK_F14             0x65    /*                     (NEC PC98) */
#define DIK_F15             0x66    /*                     (NEC PC98) */
#define DIK_KANA            0x70    /* (Japanese keyboard)            */
#define DIK_ABNT_C1         0x73    /* /? on Brazilian keyboard */
#define DIK_CONVERT         0x79    /* (Japanese keyboard)            */
#define DIK_NOCONVERT       0x7B    /* (Japanese keyboard)            */
#define DIK_YEN             0x7D    /* (Japanese keyboard)            */
#define DIK_ABNT_C2         0x7E    /* Numpad . on Brazilian keyboard */
#define DIK_NUMPADEQUALS    0x8D    /* = on numeric keypad (NEC PC98) */
#define DIK_PREVTRACK       0x90    /* Previous Track (DIK_CIRCUMFLEX on Japanese keyboard) */
#define DIK_AT              0x91    /*                     (NEC PC98) */
#define DIK_COLON           0x92    /*                     (NEC PC98) */
#define DIK_UNDERLINE       0x93    /*                     (NEC PC98) */
#define DIK_KANJI           0x94    /* (Japanese keyboard)            */
#define DIK_STOP            0x95    /*                     (NEC PC98) */
#define DIK_AX              0x96    /*                     (Japan AX) */
#define DIK_UNLABELED       0x97    /*                        (J3100) */
#define DIK_NEXTTRACK       0x99    /* Next Track */
#define DIK_NUMPADENTER     0x9C    /* Enter on numeric keypad */
#define DIK_RCONTROL        0x9D
#define DIK_MUTE            0xA0    /* Mute */
#define DIK_CALCULATOR      0xA1    /* Calculator */
#define DIK_PLAYPAUSE       0xA2    /* Play / Pause */
#define DIK_MEDIASTOP       0xA4    /* Media Stop */
#define DIK_VOLUMEDOWN      0xAE    /* Volume - */
#define DIK_VOLUMEUP        0xB0    /* Volume + */
#define DIK_WEBHOME         0xB2    /* Web home */
#define DIK_NUMPADCOMMA     0xB3    /* , on numeric keypad (NEC PC98) */
#define DIK_DIVIDE          0xB5    /* / on numeric keypad */
#define DIK_SYSRQ           0xB7
#define DIK_RMENU           0xB8    /* right Alt */
#define DIK_PAUSE           0xC5    /* Pause */
#define DIK_HOME            0xC7    /* Home on arrow keypad */
#define DIK_UP              0xC8    /* UpArrow on arrow keypad */
#define DIK_PRIOR           0xC9    /* PgUp on arrow keypad */
#define DIK_LEFT            0xCB    /* LeftArrow on arrow keypad */
#define DIK_RIGHT           0xCD    /* RightArrow on arrow keypad */
#define DIK_END             0xCF    /* End on arrow keypad */
#define DIK_DOWN            0xD0    /* DownArrow on arrow keypad */
#define DIK_NEXT            0xD1    /* PgDn on arrow keypad */
#define DIK_INSERT          0xD2    /* Insert on arrow keypad */
#define DIK_DELETE          0xD3    /* Delete on arrow keypad */
#define DIK_LWIN            0xDB    /* Left Windows key */
#define DIK_RWIN            0xDC    /* Right Windows key */
#define DIK_APPS            0xDD    /* AppMenu key */
#define DIK_POWER           0xDE    /* System Power */
#define DIK_SLEEP           0xDF    /* System Sleep */
#define DIK_WAKE            0xE3    /* System Wake */
#define DIK_WEBSEARCH       0xE5    /* Web Search */
#define DIK_WEBFAVORITES    0xE6    /* Web Favorites */
#define DIK_WEBREFRESH      0xE7    /* Web Refresh */
#define DIK_WEBSTOP         0xE8    /* Web Stop */
#define DIK_WEBFORWARD      0xE9    /* Web Forward */
#define DIK_WEBBACK         0xEA    /* Web Back */
#define DIK_MYCOMPUTER      0xEB    /* My Computer */
#define DIK_MAIL            0xEC    /* Mail */
#define DIK_MEDIASELECT     0xED    /* Media Select */

const uint8_t sdltodx[256] =
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
    DIK_INSERT,
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

struct DIDEVICEOBJECTDATA {
    uint32_t  dwOfs;
    uint32_t  dwData;
    uint32_t  dwTimeStamp;
    uint32_t  dwSequence;
};

typedef struct DIMOUSESTATE
{
    uint32_t lX;
    uint32_t lY;
    uint32_t lZ;
    uint8_t bButtons[4];
} DIMOUSESTATE;

extern uint8_t keyboard_arr[256];

class IDirectInputDeviceA : public QObject
{
Q_OBJECT

public:
    InputDeviceType devicetype;

    Q_INVOKABLE IDirectInputDeviceA() : devicetype(InputDeviceType_None) {}

    /*** Base ***/
    Q_INVOKABLE void QueryInterface(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void AddRef(void* this_ptr){}
    Q_INVOKABLE void Release(void* this_ptr){}
    
    /*** IDirectInputDevice ***/
    Q_INVOKABLE void GetCapabilities(dinputdevice_ext* obj, void* LPDIDEVCAPS)
    {
        printf("STUB: IDirectInputDeviceA::GetCapabilities\n");
    }
    
    Q_INVOKABLE void EnumObjects(dinputdevice_ext* obj, void* LPDIENUMDEVICEOBJECTSCALLBACKA, void* b, uint32_t c)
    {
        printf("STUB: IDirectInputDeviceA::GetProperty\n");
    }
    
    Q_INVOKABLE uint32_t GetProperty(dinputdevice_ext* obj, uint8_t* refGUID, void* LPDIPROPHEADER)
    {
        printf("STUB: IDirectInputDeviceA::\n");
        
        return DI_OK;
    }
    
    Q_INVOKABLE uint32_t SetProperty(dinputdevice_ext* obj, uint8_t* refGUID, void* LPCDIPROPHEADER)
    {
        printf("STUB: IDirectInputDeviceA::SetProperty\n");
        
        return DI_OK;
    }
    
    Q_INVOKABLE uint32_t Acquire(dinputdevice_ext* obj)
    {
        printf("STUB: IDirectInputDeviceA::Acquire\n");
        
        if (obj->type == InputDeviceType_Mouse)
        {
            SDL_SetRelativeMouseMode(SDL_TRUE);
        }
        
        return DI_OK;
    }
    
    Q_INVOKABLE uint32_t Unacquire(dinputdevice_ext* obj)
    {
        printf("STUB: IDirectInputDeviceA::Unacquire\n");
        
        if (obj->type == InputDeviceType_Mouse)
        {
            SDL_SetRelativeMouseMode(SDL_FALSE);
        }
        
        return DI_OK;
    }
    
    Q_INVOKABLE uint32_t GetDeviceState(dinputdevice_ext* obj, uint32_t cbData, void* lpvData)
    {
        //printf("STUB: IDirectInputDeviceA::GetDeviceState (%s)\n", obj->type == InputDeviceType_Keyboard ? "KEYBOARD" : "MOUSE");
        
        memset(lpvData, 0, cbData);
        if (obj->type == InputDeviceType_Keyboard)
        {
            uint8_t* keys = (uint8_t*)lpvData;

            /*while (user32->keystate_changed.size())
            {
                auto change = user32->keystate_changed.front();
                
                int scancode = change.first;
                bool state = change.second;
                
                keyboard_arr[sdltodx[scancode]] = state ? 1 : 0;
                
                user32->keystate_changed.pop();
            }*/
            
            memcpy(keys, keyboard_arr, cbData);
            
            return DI_OK;
        }
        else if (obj->type == InputDeviceType_Mouse)
        {
            DIMOUSESTATE *state = (DIMOUSESTATE*)lpvData;
            state->lX = user32->mousestate.x;
            state->lY = user32->mousestate.y;
            state->lZ = 0;

            if (user32->mousestate.lbutton)
                state->bButtons[0] = 0x80;
            else
                state->bButtons[0] = 0x0;
            //if (user32->mousestate.rbutton)
                //state->bButtons[0] |= 2;

            //printf("%x %x %x\n", user32->mousestate.lbutton, user32->mousestate.rbutton, state->bButtons[0]);
            user32->mousestate.x = 0;
            user32->mousestate.y = 0;
            return DI_OK;
        }
        
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetDeviceData(dinputdevice_ext* obj, uint32_t cgObjectData, struct DIDEVICEOBJECTDATA* rgdod, uint32_t* pdwInOut, uint32_t dwFlags)
    {
        //printf("STUB: IDirectInputDeviceA::GetDeviceData %p (%s)\n", rgdod, obj->type == InputDeviceType_Keyboard ? "KEYBOARD" : "MOUSE");
        
        if (!rgdod)
        {
            *pdwInOut = 0;
            return DI_OK;
        }
        
        if (obj->type == InputDeviceType_Mouse)
        {
            rgdod[0].dwOfs = 0xC;
            rgdod[0].dwData = user32->mousestate.lbutton ? 1 : 0;
            rgdod[0].dwTimeStamp = nmm->timeGetTime();
            
            rgdod[1].dwOfs = 0xD;
            rgdod[1].dwData = user32->mousestate.rbutton ? 1 : 0;
            rgdod[1].dwTimeStamp = nmm->timeGetTime();
            
            *pdwInOut = 2;
            return DI_OK;
        }
        
        uint32_t written = 0;
        for (uint32_t i = 0; i < *pdwInOut; i++, written++)
        {
            if (!user32->keystate_changed.size()) break;

            auto change = user32->keystate_changed.front();
            int scancode = change.first;
            bool state = change.second;
            
            rgdod[i].dwOfs = sdltodx[scancode];
            rgdod[i].dwData = state ? 1 : 0;
            rgdod[i].dwTimeStamp = nmm->timeGetTime();
            
            keyboard_arr[sdltodx[scancode]] = state ? 1 : 0;
            
            user32->keystate_changed.pop();
        }
        
        //printf("%x changes\n", written);
        
        *pdwInOut = written;
        return 1;
    }
    
    Q_INVOKABLE uint32_t SetDataFormat(dinputdevice_ext* obj, void* LPCDIDATAFORMAT)
    {
        printf("STUB: IDirectInputDeviceA::SetDataFormat\n");
        
        return DI_OK;
    }
    
    Q_INVOKABLE uint32_t SetEventNotification(dinputdevice_ext* obj, uint32_t HANDLE)
    {
        printf("STUB: IDirectInputDeviceA::SetEventNotification\n");
        
        return DI_OK;
    }
    
    Q_INVOKABLE uint32_t SetCooperativeLevel(dinputdevice_ext* obj, uint32_t hWnd, uint32_t c)
    {
        printf("STUB: IDirectInputDeviceA::SetCooperativeLevel\n");
        
        return DI_OK;
    }
    
    Q_INVOKABLE void GetObjectInfo(dinputdevice_ext* obj, void* LPDIDEVICEOBJECTINSTANCEA, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectInputDeviceA::GetObjectInfo\n");
    }
    
    Q_INVOKABLE void GetDeviceInfo(dinputdevice_ext* obj, void* LPDIDEVICEINSTANCEA)
    {
        printf("STUB: IDirectInputDeviceA::GetDeviceInfo\n");
    }
    
    Q_INVOKABLE void RunControlPanel(dinputdevice_ext* obj, uint32_t hWnd, uint32_t a)
    {
        printf("STUB: IDirectInputDeviceA::RunControlPanel\n");
    }
    
    Q_INVOKABLE void Initialize(dinputdevice_ext* obj, uint32_t hInst, uint32_t a, uint8_t* refGUID)
    {
        printf("STUB: IDirectInputDeviceA::Initialize\n");
    }
//    Q_INVOKABLE uint32_t ();
};

extern IDirectInputDeviceA* idirectinputdevicea;

#endif // IDIRECTINPUTDEVICEA_H
