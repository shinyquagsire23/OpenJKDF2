#include "user32.h"

#include "dlls/gdi32.h"
#include "vm.h"
#include "nmm.h"
#include "main.h"

#include "3rdparty/imgui/imgui.h"
#include "3rdparty/imgui/imgui_impl_sdl.h"

uint32_t User32::LoadIconA(uint32_t hInstance, uint32_t b)
{
    printf("STUB: LoadIconA(%x, %x)\n", hInstance, b);
    return 0;
}

uint32_t User32::LoadCursorA(uint32_t a, uint32_t b)
{
    printf("STUB: LoadCursorA(%x, %x)\n", a, b);
    return 0;
}

uint32_t User32::RegisterClassExA(struct WNDCLASSEXA* lpwcx)
{
    lpfnWndProcStr[std::string(lpwcx->lpszClassName.translated())] = lpwcx->lpfnWndProc;
    
    printf("Register class %s, %s\n", lpwcx->lpszMenuName.translated(), lpwcx->lpszClassName.translated());
    return 444;
}


uint32_t User32::FindWindowA(uint32_t a, vm_ptr<char*> b)
{
    return 0;
}

uint32_t User32::GetSystemMetrics(uint32_t metric)
{        
    switch (metric)
    {
        case 0: //hres
            return 1280;
        case 1: //vres
            return 1024;
        case 15:
        case 32:
            return 0;
        default:
            printf("Unknown metric %x\n", metric);
            return 16;
    }
}

uint32_t User32::CreateWindowExA(uint32_t a, char* lpClassName, char* lpWindowName, uint32_t dwStyle, uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t i, uint32_t j, uint32_t hInstance, uint32_t l)
{
    uint32_t hWnd = hWndCnt++;
    
    lpfnWndProc[hWnd] = lpfnWndProcStr[std::string(lpClassName)];
    
    printf("User32::CreateWindowExA, %s %s %u,%u %ux%u %x %x %x %x\n", lpClassName, lpWindowName, x, y, width, height, hWnd, hInstance, lpfnWndProcStr[std::string(lpClassName)], lpfnWndProc[hWnd]);
    
    
    activeWindow = hWnd;
    SendMessage(hWnd, WM_CREATE);
    return hWnd;
}

uint32_t User32::ShowWindow(uint32_t hWnd, uint32_t show)
{
    SendMessage(hWnd, WM_ACTIVATE, WA_ACTIVE);
    SendMessage(hWnd, WM_ACTIVATEAPP, 1);
    SendMessage(hWnd, WM_SHOWWINDOW, 0);
    return 0;
}

uint32_t User32::MoveWindow(uint32_t hWnd, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
{
    printf("STUB: User32.dll::MoveWindow(%x, %u %u %u %u %u\n", hWnd, a, b, c, d, e);
    return 1;
}

uint32_t User32::UpdateWindow(uint32_t hWnd)
{
    SendMessage(hWnd, WM_PAINT);
    return 1;
}

uint32_t User32::GetActiveWindow()
{
    return activeWindow;
}

uint32_t User32::GetLastActivePopup(uint32_t hWnd)
{
    return 123;
}

void User32::MessageBoxA(uint32_t hWnd, vm_ptr<char*> lpText, vm_ptr<char*> lpCaption, uint32_t uType)
{
    printf("MessageBoxA: [%s] %s\n", lpText.translated(), lpCaption.translated());
}

void User32::MessageBoxW(uint32_t hWnd, uint32_t lpText, uint32_t lpCaption, uint32_t uType)
{
    std::string text = vm_read_wstring(lpText);
    std::string caption = vm_read_wstring(lpCaption);
    
    printf("MessageBoxW: [%s] %s\n", caption.c_str(), text.c_str());
}

uint32_t User32::GetDC(uint32_t a)
{
    return 0xefab;
}
  
uint32_t User32::ReleaseDC(uint32_t a, uint32_t b)
{
    return 1;
}
    
uint32_t User32::EnumDisplaySettingsA(uint32_t a, uint32_t b, uint32_t c)
{
    return 1;
}
    
uint32_t User32::ChangeDisplaySettingsA(uint32_t a, uint32_t b)
{
    return 0;
}

uint32_t User32::SetWindowPos(uint32_t hWnd, uint32_t hWndInsertAfter, uint32_t x, uint32_t y, uint32_t cx, uint32_t cy, uint32_t uFlags)    
{
    //SendMessage(hWnd, WM_WINDOWPOSCHANGING);

    return 1;
}

uint32_t User32::GetDesktopWindow()    
{
    return 0xabcd;
}

uint32_t User32::ShowCursor(bool show)
{
    static int count;
    
    return show ? ++count : --count;
}


/*
void handleKeyDown()
{
    if(CURRENT_ITEM_DRAGGED != -1) return;

    const Uint8* keystate = SDL_GetKeyboardState(NULL);
    const Uint32 modstate = SDL_GetModState();

    //continuous-response keys
    if (keystate[SDL_SCANCODE_UP])
    {
        button_move_up();
    }
    else if (keystate[SDL_SCANCODE_RIGHT])
    {
        button_move_right();
    }
    else if (keystate[SDL_SCANCODE_LEFT])
    {
        button_move_left();
    }
    else if (keystate[SDL_SCANCODE_DOWN])
    {
        button_move_down();
    }

    if (modstate & (KMOD_LSHIFT | KMOD_RSHIFT))
    {
        button_push();
    }

    if (keystate[SDL_SCANCODE_SPACE])
    {
        button_fire();
    }
}

void handleTouchEvent(SDL_TouchFingerEvent* event)
{
    if (event->type == SDL_FINGERUP)
        ui_touch_up();
    else if (event->type == SDL_FINGERDOWN)
        ui_touch_down();
    else
    {
        ui_set_mouse_abs((int)(event->x*SDL_WIDTH), (int)(event->y*SDL_HEIGHT));
    }
}*/

const uint8_t sdltouser32[256] =
{
    0,
    0,
    0,
    0,
    0x41,
    0x42,
    0x43,
    0x44,
    0x45,
    0x46,
    0x47,
    0x48,
    0x49,
    0x4A,
    0x4B,
    0x4C,
    0x4D,
    0x4E,
    0x4F,
    0x50,
    0x51,
    0x52,
    0x53,
    0x54,
    0x55,
    0x56,
    0x57,
    0x58,
    0x59,
    0x5A,

    0x31,
    0x32,
    0x33,
    0x34,
    0x35,
    0x36,
    0x37,
    0x38,
    0x39,
    0x30,

    0x0D,
    0x1B,
    0x08,
    0x09,
    0x20,

    0xBD,
    0,
    0,//LBRACKET,
    0,//RBRACKET,
    0,//BACKSLASH,
    0,
    0,//SEMICOLON,
    0,//APOSTROPHE,
    0,//GRAVE,
    0,//COMMA,
    0,//PERIOD,
    0,//SLASH,

    0,//CAPITAL,

    0x70,//F1,
    0x71,//F2,
    0x72,//F3,
    0x73,//F4,
    0x74,//F5,
    0x75,//F6,
    0x76,//F7,
    0x77,//F8,
    0x78,//F9,
    0x79,//F10,
    0x7A,//F11,
    0x7B,//F12,

    0,//PRINTSCREEN,
    0,//SCROLL,
    0,//PAUSE,
    0,//INSERT,
    0,//HOME,
    0,//PRIOR,
    0,//DELETE,
    0,//END,
    0,//NEXT,
    0x27,//RIGHT,
    0x25,//LEFT,
    0x28,//DOWN,
    0x26,//UP,

    0,//NUMLOCKCLEAR,
    0,//DIVIDE,
    0,//MULTIPLY,
    0,//SUBTRACT,
    0,//ADD,
    0,//NUMPADENTER,
    0,//NUMPAD1,
    0,//NUMPAD2,
    0,//NUMPAD3,
    0,//NUMPAD4,
    0,//NUMPAD5,
    0,//NUMPAD6,
    0,//NUMPAD7,
    0,//NUMPAD8,
    0,//NUMPAD9,
    0,//NUMPAD0,
    0,//DECIMAL,

    0,//BACKSLASH,
    0,//APPLICATION,
    0,//POWER,
    0,//NUMPADEQUALS,
    0x7C,//F13,
    0x7D,//F14,
    0x7E,//F15,
    0x7F,//F16,
    0x80,//F17,
    0x81,//F18,
    0x82,//F19,
    0x83,//F20,
    0x84,//F21,
    0x85,//F22,
    0x86,//F23,
    0x87,//F24,
    0,//EXECUTE,
    0,//HELP,
    0,//MENU,
    0,//SELECT,
    0,//STOP,
    0,//AGAIN,
    0,//UNDO,
    0,//CUT,
    0,//COPY,
    0,//PASTE,
    0,//FIND,
    0,//MUTE,
    0,//VOLUMEUP,
    0,//VOLUMEDOWN,
    0,
    0,
    0,
    0,//NUMPADCOMMA,
    0,//NUMPADEQUALS,

    0,//INTERNATIONAL1,
    0,//INTERNATIONAL2,
    0,//INTERNATIONAL3,
    0,//INTERNATIONAL4,
    0,//INTERNATIONAL5,
    0,//INTERNATIONAL6,
    0,//INTERNATIONAL7,
    0,//INTERNATIONAL8,
    0,//INTERNATIONAL9,
    0,//LANG1,
    0,//LANG2,
    0,//LANG3,
    0,//LANG4,
    0,//LANG5,
    0,//LANG6,
    0,//LANG7,
    0,//LANG8,
    0,//LANG9,

    0,//ALTERASE,
    0,//SYSREQ,
    0,//CANCEL,
    0,//CLEAR,
    0,//PRIOR,
    0,//RETURN2,
    0,//SEPARATOR,
    0,//OUT,
    0,//OPER,
    0,//CLEARAGAIN,
    0,//CRSEL,
    0,//EXSEL,
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
    0,//KP_00,
    0,//KP_000,
    0,//THOUSANDSSEPARATOR,
    0,//DECIMALSEPARATOR,
    0,//CURRENCYUNIT,
    0,//CURRENCYSUBUNIT,
    0,//KP_LEFTPAREN,
    0,//KP_RIGHTPAREN,
    0,//KP_LEFTBRACE,
    0,//KP_RIGHTBRACE,
    0,//KP_TAB,
    0,//KP_BACKSPACE,
    0,//KP_A,
    0,//KP_B,
    0,//KP_C,
    0,//KP_D,
    0,//KP_E,
    0,//KP_F,
    0,//KP_XOR,
    0,//KP_POWER,
    0,//KP_PERCENT,
    0,//KP_LESS,
    0,//KP_GREATER,
    0,//KP_AMPERSAND,
    0,//KP_DBLAMPERSAND,
    0,//KP_VERTICALBAR,
    0,//KP_DBLVERTICALBAR,
    0,//KP_COLON,
    0,//KP_HASH,
    0,//KP_SPACE,
    0,//KP_AT,
    0,//KP_EXCLAM,
    0,//KP_MEMSTORE,
    0,//KP_MEMRECALL,
    0,//KP_MEMCLEAR,
    0,//KP_MEMADD,
    0,//KP_MEMSUBTRACT,
    0,//KP_MEMMULTIPLY,
    0,//KP_MEMDIVIDE,
    0,//KP_PLUSMINUS,
    0,//KP_CLEAR,
    0,//KP_CLEARENTRY,
    0,//KP_BINARY,
    0,//KP_OCTAL,
    0,//KP_DECIMAL,
    0,//KP_HEXADECIMAL,
    0,
    0,
    0,//LCONTROL,
    0,//LSHIFT,
    0,//LMENU,
    0,//LGUI,
    0,//RCONTROL,
    0,//RSHIFT,
    0,//RMENU,
    0,//RGUI,
};

/* function to handle key press events */
void handleKey(SDL_Keysym *keysym, int msg, uint32_t lpMask)
{
    user32->keystate_changed.push(std::pair<int, bool>(keysym->scancode, msg == WM_KEYDOWN ? true : false));
    
    if (sdltouser32[keysym->scancode])
    {
        user32->SendMessage(user32->GetActiveWindow(), msg, sdltouser32[keysym->scancode], lpMask | keysym->scancode << 16);
        
        if (msg == WM_KEYDOWN)
        {
            char val = SDL_GetKeyName(keysym->sym)[0];
            switch (keysym->sym)
            {
                case SDLK_BACKSPACE:
                    val = 0x8;
                    break;
                case SDLK_RETURN:
                case SDLK_RETURN2:
                    val = keysym->mod & KMOD_SHIFT ? 0xA : 0xD;
                    break;
                case SDLK_ESCAPE:
                    val = 0x1B;
                    break;
                case SDLK_TAB:
                    val = 0x9;
                    break;
                    
                case SDLK_SPACE:
                    val = ' ';
                    break;
                default:
                    val = SDL_GetKeyName(keysym->sym)[0];
                    break;
            }
            user32->SendMessage(user32->GetActiveWindow(), WM_CHAR, val, lpMask | keysym->scancode << 16);
        }
    }
    return;
}

bool mouseMoveRet = true;

void handleMouseMove(SDL_MouseMotionEvent *event, int mouseOffsX, int mouseOffsY)
{
    //printf("Mouse pos %i,%i\n", event->x, event->y);
    //TODO hwnd to imgui
    uint32_t pos = ((event->x - mouseOffsX) & 0xFFFF) | (((event->y - mouseOffsY) << 16) & 0xFFFF0000);
    user32->mousePosX = event->x - mouseOffsX;
    user32->mousePosY = event->y - mouseOffsY;

    if (mouseMoveRet)
    {
        user32->SendMessage(user32->GetActiveWindow(), WM_MOUSEMOVE, 0/*TODO*/, pos);
        mouseMoveRet = false;
    }
}

bool update_input(int mouseOffsX, int mouseOffsY)
{
    uint16_t left, right;
    uint32_t pos, msgl, msgr;
    SDL_MouseButtonEvent* mevent;
    mouse_state* mstate = &user32->mousestate;

    while (SDL_PollEvent(&event))
    {
        ImGui_ImplSDL2_ProcessEvent(&event);
        switch (event.type)
        {
            case SDL_KEYDOWN:
                handleKey(&event.key.keysym, WM_KEYDOWN, 0x1);
                break;
            case SDL_KEYUP:
                handleKey(&event.key.keysym, WM_KEYUP, 0xc0000001);
                break;
            case SDL_MOUSEMOTION:
                handleMouseMove(&event.motion, mouseOffsX, mouseOffsY);
                //user32->SendMessage(user32->GetActiveWindow(), WM_PAINT);

                mstate->x = event.motion.xrel * 2;
                mstate->y = event.motion.yrel * 2;
                //mstate->lbutton = !!(event.motion.state & SDL_BUTTON_LMASK);
                //mstate->rbutton = !!(event.motion.state & SDL_BUTTON_RMASK);
                break;
            case SDL_MOUSEBUTTONDOWN:
            case SDL_MOUSEBUTTONUP:
                mevent = (SDL_MouseButtonEvent*)&event;
                if (mevent->button == SDL_BUTTON_LEFT)
                {
                    mstate->lbutton = (event.type == SDL_MOUSEBUTTONDOWN ? true : false);
                }
                else if (mevent->button == SDL_BUTTON_RIGHT)
                {
                    mstate->rbutton = (event.type == SDL_MOUSEBUTTONDOWN ? true : false);
                }
                
                if (event.type == SDL_MOUSEBUTTONDOWN)
                {
                    left = mstate->lbutton ? 1 : 0;
                    right = mstate->rbutton ? 2 : 0;
                }
                else
                {
                    left = mstate->lbutton ? 0 : 1;
                    right = mstate->rbutton ? 0 : 2;
                }

                //TODO hwnd to imgui
                pos = ((mevent->x - mouseOffsX) & 0xFFFF) | (((mevent->y - mouseOffsY) << 16) & 0xFFFF0000);
                msgl = (event.type == SDL_MOUSEBUTTONDOWN ? WM_LBUTTONDOWN : WM_LBUTTONUP);
                msgr = (event.type == SDL_MOUSEBUTTONDOWN ? WM_RBUTTONDOWN : WM_RBUTTONUP);

                printf("mouse button %x %x %x\n", left, right, pos);
                
                if (left)
                    user32->SendMessage(user32->GetActiveWindow(), msgl, left | right, pos);
                if (right)
                    user32->SendMessage(user32->GetActiveWindow(), msgr, left | right, pos);
                break;
            /*case SDL_FINGERMOTION:
            case SDL_FINGERDOWN:
            case SDL_FINGERUP:
                //handleTouchEvent((SDL_TouchFingerEvent*)&event);
                break;*/
            case SDL_QUIT:
                printf("Quit!\n");
                vm_stop();
                return true;
            default:
                break;
        }
    }
    /*handleKeyDown();

    if(SDL_GetMouseState(NULL, NULL) & SDL_BUTTON(SDL_BUTTON_LEFT))
        mouse_left();

    if(SDL_GetMouseState(NULL, NULL) & SDL_BUTTON(SDL_BUTTON_RIGHT))
        mouse_right();*/

    return false;
}

uint32_t last_ms = 0;

uint32_t User32::PeekMessageA(struct tagMSG* lpMsg, uint32_t hWnd, uint16_t wMsgFilterMin, uint16_t wMsgFilterMax, uint16_t wRemoveMsg)
{
    //printf("User32::PeekMessage(hwnd %x lpfnWndProc %x)\n", hWnd, lpfnWndProc[hWnd]);
    //TODO tie hwnd to imgui
    if (update_input(mouseOffsX, mouseOffsY)) stopping = true;

    //HACK: Always update framebuf?
    uint32_t ms = nmm->timeGetTime();
    if (ms - last_ms > 16)
    {
        uint32_t hdcSrc = gdi32->selectedHdcSrc;
        struct color rop = {0};
        gdi32->BitBlt(0xefab,0,0,0,0,hdcSrc,0,0,rop);
        last_ms = ms;
    }

    if (messages.size())
    {
        *lpMsg = messages.front();
        if (wRemoveMsg)
        {
            vm_call_func(lpfnWndProc[hWnd], lpMsg->hWnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
            messages.pop();
        }
        return 1;
    }

    return 0;
}

uint32_t User32::GetMessageA(struct tagMSG* lpMsg, uint32_t hWnd, uint16_t wMsgFilterMin, uint16_t wMsgFilterMax)
{
    if (messages.size())
    {
        //if (lpMsg)
            *lpMsg = messages.front();
        messages.pop();
        return 1;
    }

    return 0;
}

uint32_t User32::TranslateMessage(struct tagMSG* lpMsg)
{
    
    return 1;
}

uint32_t User32::DispatchMessageA(struct tagMSG* lpMsg)
{
    //printf("Dispatch %x %x %x %x\n", lpMsg->hWnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
    vm_call_func(lpfnWndProc[lpMsg->hWnd], lpMsg->hWnd, lpMsg->message, lpMsg->wParam, lpMsg->lParam);
    
    if (lpMsg->message == WM_MOUSEMOVE)
    {
        mouseMoveRet = true;
    }
    
    return 1;
}

uint32_t User32::DefWindowProcA(uint32_t hWnd, uint32_t msg, uint32_t wParam, uint32_t lParam)
{
    //printf("STUB: DefWindowProcA(0x%04x, 0x%08x, 0x%04x, 0x%08x)\n", hWnd, msg, wParam, lParam);

    return 1;
}

uint32_t User32::SetFocus(uint32_t hWnd)
{
    return hWnd;
}

uint32_t User32::SetActiveWindow(uint32_t hWnd)
{
    return hWnd;
}

/*uint32_t User32::(uint32_t )
{
}*/
