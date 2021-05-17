#ifndef USER32_H
#define USER32_H

#include <QObject>
#include <queue>
#include "vm.h"
#include "loaders/exe.h"

#include <SDL2/SDL.h>

typedef struct tagRECT
{
    uint32_t left;
    uint32_t top;
    uint32_t right;
    uint32_t bottom;
} tagRECT;

struct tagMSG
{
    uint32_t hWnd;
    uint32_t message;
    uint32_t wParam;
    uint32_t lParam;
    uint32_t time;
    uint32_t x;
    uint32_t y;
};

struct WNDCLASSEXA
{
    uint32_t cbSize;
    uint32_t style;
    uint32_t lpfnWndProc;
    uint32_t cbClsExtra;
    uint32_t cbWndExtra;
    uint32_t hInstance;
    uint32_t hIcon;
    uint32_t hCursor;
    uint32_t hbrBackground;
    vm_ptr<char*> lpszMenuName;
    vm_ptr<char*> lpszClassName;
    uint32_t hIconSm;
};

struct WNDCLASSA
{
    uint32_t style;
    uint32_t lpfnWndProc;
    uint32_t cbClsExtra;
    uint32_t cbWndExtra;
    uint32_t hInstance;
    uint32_t hIcon;
    uint32_t hCursor;
    uint32_t hbrBackground;
    vm_ptr<char*> lpszMenuName;
    vm_ptr<char*> lpszClassName;
};


#define WM_NULL             0x00
#define WM_CREATE           0x01
#define WM_DESTROY          0x02
#define WM_MOVE             0x03
#define WM_SIZE             0x05
#define WM_ACTIVATE         0x06
#define WM_SETFOCUS         0x07
#define WM_KILLFOCUS        0x08
#define WM_ENABLE           0x0A
#define WM_SETREDRAW        0x0B
#define WM_SETTEXT          0x0C
#define WM_GETTEXT          0x0D
#define WM_GETTEXTLENGTH    0x0E
#define WM_PAINT            0x0F
#define WM_CLOSE            0x10
#define WM_QUERYENDSESSION  0x11
#define WM_QUIT             0x12
#define WM_QUERYOPEN        0x13
#define WM_ERASEBKGND       0x14
#define WM_SYSCOLORCHANGE   0x15
#define WM_ENDSESSION       0x16
#define WM_SYSTEMERROR      0x17
#define WM_SHOWWINDOW       0x18
#define WM_CTLCOLOR         0x19
#define WM_WININICHANGE     0x1A
#define WM_SETTINGCHANGE    0x1A
#define WM_DEVMODECHANGE    0x1B
#define WM_ACTIVATEAPP      0x1C
#define WM_FONTCHANGE       0x1D
#define WM_TIMECHANGE       0x1E
#define WM_CANCELMODE       0x1F
#define WM_SETCURSOR        0x20
#define WM_MOUSEACTIVATE    0x21
#define WM_CHILDACTIVATE    0x22
#define WM_QUEUESYNC        0x23
#define WM_GETMINMAXINFO    0x24
#define WM_PAINTICON        0x26
#define WM_ICONERASEBKGND   0x27
#define WM_NEXTDLGCTL       0x28
#define WM_SPOOLERSTATUS    0x2A
#define WM_DRAWITEM         0x2B
#define WM_MEASUREITEM      0x2C
#define WM_DELETEITEM       0x2D
#define WM_VKEYTOITEM       0x2E
#define WM_CHARTOITEM       0x2F

#define WM_SETFONT 0x30
#define WM_GETFONT 0x31
#define WM_SETHOTKEY 0x32
#define WM_GETHOTKEY 0x33
#define WM_QUERYDRAGICON 0x37
#define WM_COMPAREITEM 0x39
#define WM_COMPACTING 0x41
#define WM_WINDOWPOSCHANGING 0x46
#define WM_WINDOWPOSCHANGED 0x47
#define WM_POWER 0x48
#define WM_COPYDATA 0x4A
#define WM_CANCELJOURNAL 0x4B
#define WM_NOTIFY 0x4E
#define WM_INPUTLANGCHANGEREQUEST 0x50
#define WM_INPUTLANGCHANGE 0x51
#define WM_TCARD 0x52
#define WM_HELP 0x53
#define WM_USERCHANGED 0x54
#define WM_NOTIFYFORMAT 0x55
#define WM_CONTEXTMENU 0x7B
#define WM_STYLECHANGING 0x7C
#define WM_STYLECHANGED 0x7D
#define WM_DISPLAYCHANGE 0x7E
#define WM_GETICON 0x7F
#define WM_SETICON 0x80

#define WM_NCCREATE 0x81
#define WM_NCDESTROY 0x82
#define WM_NCCALCSIZE 0x83
#define WM_NCHITTEST 0x84
#define WM_NCPAINT 0x85
#define WM_NCACTIVATE 0x86
#define WM_GETDLGCODE 0x87
#define WM_NCMOUSEMOVE 0xA0
#define WM_NCLBUTTONDOWN 0xA1
#define WM_NCLBUTTONUP 0xA2
#define WM_NCLBUTTONDBLCLK 0xA3
#define WM_NCRBUTTONDOWN 0xA4
#define WM_NCRBUTTONUP 0xA5
#define WM_NCRBUTTONDBLCLK 0xA6
#define WM_NCMBUTTONDOWN 0xA7
#define WM_NCMBUTTONUP 0xA8
#define WM_NCMBUTTONDBLCLK 0xA9

#define WM_KEYFIRST 0x100
#define WM_KEYDOWN 0x100
#define WM_KEYUP 0x101
#define WM_CHAR 0x102
#define WM_DEADCHAR 0x103
#define WM_SYSKEYDOWN 0x104
#define WM_SYSKEYUP 0x105
#define WM_SYSCHAR 0x106
#define WM_SYSDEADCHAR 0x107
#define WM_KEYLAST 0x108

#define WM_IME_STARTCOMPOSITION 0x10D
#define WM_IME_ENDCOMPOSITION 0x10E
#define WM_IME_COMPOSITION 0x10F
#define WM_IME_KEYLAST 0x10F

#define WM_INITDIALOG 0x110
#define WM_COMMAND 0x111
#define WM_SYSCOMMAND 0x112
#define WM_TIMER 0x113
#define WM_HSCROLL 0x114
#define WM_VSCROLL 0x115
#define WM_INITMENU 0x116
#define WM_INITMENUPOPUP 0x117
#define WM_MENUSELECT 0x11F
#define WM_MENUCHAR 0x120
#define WM_ENTERIDLE 0x121

#define WM_CTLCOLORMSGBOX 0x132
#define WM_CTLCOLOREDIT 0x133
#define WM_CTLCOLORLISTBOX 0x134
#define WM_CTLCOLORBTN 0x135
#define WM_CTLCOLORDLG 0x136
#define WM_CTLCOLORSCROLLBAR 0x137
#define WM_CTLCOLORSTATIC 0x138

#define WM_MOUSEFIRST 0x200
#define WM_MOUSEMOVE 0x200
#define WM_LBUTTONDOWN 0x201
#define WM_LBUTTONUP 0x202
#define WM_LBUTTONDBLCLK 0x203
#define WM_RBUTTONDOWN 0x204
#define WM_RBUTTONUP 0x205
#define WM_RBUTTONDBLCLK 0x206
#define WM_MBUTTONDOWN 0x207
#define WM_MBUTTONUP 0x208
#define WM_MBUTTONDBLCLK 0x209
#define WM_MOUSEWHEEL 0x20A
#define WM_MOUSEHWHEEL 0x20E

#define WM_PARENTNOTIFY 0x210
#define WM_ENTERMENULOOP 0x211
#define WM_EXITMENULOOP 0x212
#define WM_NEXTMENU 0x213
#define WM_SIZING 0x214
#define WM_CAPTURECHANGED 0x215
#define WM_MOVING 0x216
#define WM_POWERBROADCAST 0x218
#define WM_DEVICECHANGE 0x219

#define WM_MDICREATE 0x220
#define WM_MDIDESTROY 0x221
#define WM_MDIACTIVATE 0x222
#define WM_MDIRESTORE 0x223
#define WM_MDINEXT 0x224
#define WM_MDIMAXIMIZE 0x225
#define WM_MDITILE 0x226
#define WM_MDICASCADE 0x227
#define WM_MDIICONARRANGE 0x228
#define WM_MDIGETACTIVE 0x229
#define WM_MDISETMENU 0x230
#define WM_ENTERSIZEMOVE 0x231
#define WM_EXITSIZEMOVE 0x232
#define WM_DROPFILES 0x233
#define WM_MDIREFRESHMENU 0x234

#define WM_IME_SETCONTEXT 0x281
#define WM_IME_NOTIFY 0x282
#define WM_IME_CONTROL 0x283
#define WM_IME_COMPOSITIONFULL 0x284
#define WM_IME_SELECT 0x285
#define WM_IME_CHAR 0x286
#define WM_IME_KEYDOWN 0x290
#define WM_IME_KEYUP 0x291

#define WM_MOUSEHOVER 0x2A1
#define WM_NCMOUSELEAVE 0x2A2
#define WM_MOUSELEAVE 0x2A3

#define WM_CUT 0x300
#define WM_COPY 0x301
#define WM_PASTE 0x302
#define WM_CLEAR 0x303
#define WM_UNDO 0x304

#define WM_RENDERFORMAT 0x305
#define WM_RENDERALLFORMATS 0x306
#define WM_DESTROYCLIPBOARD 0x307
#define WM_DRAWCLIPBOARD 0x308
#define WM_PAINTCLIPBOARD 0x309
#define WM_VSCROLLCLIPBOARD 0x30A
#define WM_SIZECLIPBOARD 0x30B
#define WM_ASKCBFORMATNAME 0x30C
#define WM_CHANGECBCHAIN 0x30D
#define WM_HSCROLLCLIPBOARD 0x30E
#define WM_QUERYNEWPALETTE 0x30F
#define WM_PALETTEISCHANGING 0x310
#define WM_PALETTECHANGED 0x311

#define WM_HOTKEY 0x312
#define WM_PRINT 0x317
#define WM_PRINTCLIENT 0x318

#define WM_HANDHELDFIRST 0x358
#define WM_HANDHELDLAST 0x35F
#define WM_PENWINFIRST 0x380
#define WM_PENWINLAST 0x38F
#define WM_COALESCE_FIRST 0x390
#define WM_COALESCE_LAST 0x39F
#define WM_DDE_FIRST 0x3E0
#define WM_DDE_INITIATE 0x3E0
#define WM_DDE_TERMINATE 0x3E1
#define WM_DDE_ADVISE 0x3E2
#define WM_DDE_UNADVISE 0x3E3
#define WM_DDE_ACK 0x3E4
#define WM_DDE_DATA 0x3E5
#define WM_DDE_REQUEST 0x3E6
#define WM_DDE_POKE 0x3E7
#define WM_DDE_EXECUTE 0x3E8
#define WM_DDE_LAST 0x3E8

#define WM_USER 0x400
#define WM_APP 0x8000

#define WA_ACTIVE 2

typedef struct mouse_state
{
    bool lbutton;
    bool rbutton;
    uint32_t x;
    uint32_t y;
} mouse_state;

class User32 : public QObject
{
Q_OBJECT

private:
    uint32_t hWndCnt;
    uint32_t activeWindow;
    std::map<std::string, uint32_t> lpfnWndProcStr;
    std::map<uint32_t, uint32_t> lpfnWndProc;
    std::queue<struct tagMSG> messages;
    int mouseOffsX, mouseOffsY;
public:

    bool stopping;
    std::queue<std::pair<int, bool> > keystate_changed;
    mouse_state mousestate;
    int mousePosX, mousePosY;

    Q_INVOKABLE User32() : hWndCnt(1), mouseOffsX(0), mouseOffsY(0), stopping(false), mousePosX(0), mousePosY(0)
    {
//        WM_MOUSEACTIVATE
        mousestate.lbutton = false;
        mousestate.rbutton = false;
        mousestate.x = 0;
        mousestate.y = 0;
    }
    
    void SendMessage(uint32_t hWnd, uint32_t msg, uint32_t wParam = 0, uint32_t lParam = 0, uint32_t x = 0, uint32_t y = 0)
    {
        struct tagMSG gen_msg;
        gen_msg.hWnd = hWnd;
        gen_msg.message = msg;
        gen_msg.wParam = wParam;
        gen_msg.lParam = lParam;
        gen_msg.x = x;
        gen_msg.y = y;
        messages.push(gen_msg);
    }
    
    void SetMouseOffset(int x, int y)
    {
        mouseOffsX = x;
        mouseOffsY = y;
    }
    
    Q_INVOKABLE uint32_t LoadIconA(uint32_t hInstance, uint32_t b);
    Q_INVOKABLE uint32_t LoadCursorA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t RegisterClassExA(struct WNDCLASSEXA* lpwcx);
    Q_INVOKABLE uint32_t FindWindowA(uint32_t a, vm_ptr<char*> b);
    Q_INVOKABLE uint32_t GetSystemMetrics(uint32_t metric);
    uint32_t CreateWindowExA(uint32_t a, char* b, char* c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i, uint32_t j, uint32_t hInstance, uint32_t l);
    Q_INVOKABLE uint32_t ShowWindow(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t MoveWindow(uint32_t hWnd, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e);
    Q_INVOKABLE uint32_t UpdateWindow(uint32_t a);
    Q_INVOKABLE uint32_t GetActiveWindow();
    Q_INVOKABLE uint32_t GetLastActivePopup(uint32_t hWnd);
    Q_INVOKABLE void MessageBoxA(uint32_t hWnd, vm_ptr<char*> lpText, vm_ptr<char*> lpCaption, uint32_t uType);
    Q_INVOKABLE void MessageBoxW(uint32_t hWnd, uint32_t lpText, uint32_t lpCaption, uint32_t uType);
    Q_INVOKABLE uint32_t GetDC(uint32_t a);
    Q_INVOKABLE uint32_t ReleaseDC(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t EnumDisplaySettingsA(uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t ChangeDisplaySettingsA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t SetWindowPos(uint32_t hWnd, uint32_t hWndInsertAfter, uint32_t x, uint32_t y, uint32_t cx, uint32_t cy, uint32_t uFlags);
    Q_INVOKABLE uint32_t GetDesktopWindow();
    Q_INVOKABLE uint32_t ShowCursor(bool show);
    Q_INVOKABLE uint32_t PeekMessageA(struct tagMSG* lpMsg, uint32_t hWnd, uint16_t wMsgFilterMin, uint16_t wMsgFilterMax, uint16_t wRemoveMsg);
    Q_INVOKABLE uint32_t GetMessageA(struct tagMSG* lpMsg, uint32_t hWnd, uint16_t wMsgFilterMin, uint16_t wMsgFilterMax);
    Q_INVOKABLE uint32_t TranslateMessage(struct tagMSG* lpMsg);
    Q_INVOKABLE uint32_t DispatchMessageA(struct tagMSG* lpMsg);
    Q_INVOKABLE uint32_t DefWindowProcA(uint32_t hWnd, uint32_t msg, uint32_t wParam, uint32_t lParam);
    Q_INVOKABLE uint32_t SetFocus(uint32_t hWnd);
    Q_INVOKABLE uint32_t SetActiveWindow(uint32_t hWnd);
    Q_INVOKABLE uint32_t ValidateRect(uint32_t hWnd, void *lpRect)
    {
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetUpdateRect(uint32_t hWnd, void *lpRect, bool bErase)
    {
        return 0;
    }

    Q_INVOKABLE uint32_t LoadStringA(uint32_t hInstance, uint32_t uID, char* lpBuffer, uint32_t bufferMax)
    {
        uint32_t resId = (uID >> 4) + 1;
        uint32_t strIdx = uID & 0xF;
        
        ResourceData* resPtr = resource_id_map[RT_STRING][resId];
        std::string val = "";
        intptr_t wstring_ptr = (intptr_t)vm_ptr_to_real_ptr(resPtr->ptr);
        for (uint32_t i = 0; i < strIdx+1; i++)
        {
            uint16_t len = *(uint16_t*)wstring_ptr;
            val = from_wstring((void*)wstring_ptr);
            wstring_ptr += (len + 1) * sizeof(uint16_t);
        }
        
        printf("STUB: LoadStringA(%x, (resid %x, idx %x), ..., %x, `%s')\n", hInstance, resId, strIdx, bufferMax, val.c_str());
        
        strncpy(lpBuffer, val.c_str(), bufferMax);
        return strlen(lpBuffer);
    }

    Q_INVOKABLE uint32_t SetWindowLongA(uint32_t hWnd, uint32_t nIndex, uint32_t dwNewLong)
    {
        printf("STUB: SetWindowLong(%x, %x, %x)\n", hWnd, nIndex, dwNewLong);
        return 1;
    }
    
    Q_INVOKABLE uint32_t SetCapture(uint32_t hWnd)
    {
        printf("STUB: User32::SetCapture %x\n", hWnd);
        
        //SDL_CaptureMouse(SDL_TRUE);
        
        return GetActiveWindow();
    }
    
    Q_INVOKABLE uint32_t ReleaseCapture()
    {
        SDL_CaptureMouse(SDL_FALSE);
        return 1;
    }
    
    Q_INVOKABLE uint32_t RegisterWindowMessageA(char* str)
    {
        printf("STUB: User32::RegisterWindowMessageA(\"%s\")\n", str);
        
        return 0xC000;
    }
    
    Q_INVOKABLE uint32_t RegisterClassA(struct WNDCLASSA* lpwc)
    {
        std::string classname = std::string(lpwc->lpszClassName.translated());
        lpfnWndProcStr[classname] = lpwc->lpfnWndProc;
        
        printf("Register hInst %x %x class %s, %s, lpfnWndProc %x\n", lpwc->hInstance, lpwc->style, lpwc->lpszMenuName.translated(), classname.c_str(), lpwc->lpfnWndProc);
        
        return 1;
    }
    
    Q_INVOKABLE uint32_t UnregisterClassA(char* a, uint32_t b)
    {
        printf("STUB: User32::UnregisterClassA(\"%s\", %x)\n", a, b);
        return 0;
    }
    
    Q_INVOKABLE uint32_t GetWindowRect(uint32_t hWnd, tagRECT* rect)
    {
        printf("STUB: User32::GetWindowRect(%x, ...)\n", hWnd);
        
        rect->left = 0;
        rect->right = 0;
        rect->top = 0;
        rect->bottom = 0;
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t LoadBitmapA(uint32_t hInstance, char* str)
    {
        printf("STUB: USER32.dll::LoadBitmapA(%x, \"%s\")\n", hInstance, str);
        
        return 0xabbb;
    }
    
    Q_INVOKABLE uint32_t MapVirtualKeyA(uint32_t uCode, uint32_t uMapType)
    {
        printf("STUB: User32.dll::MapVirtualKeyA(%u, %u)\n", uCode, uMapType);

        return 16;
    }
    
    Q_INVOKABLE uint32_t GetKeyNameTextA(uint32_t lParam, char* lpString, int cchSize)
    {
        printf("STUB: User32.dll::GetKeyNameTextA(%x, %p, %x)\n", lParam, lpString, cchSize);
        
        if ((lParam >> 16) == 0)
            strncpy(lpString, "right", cchSize);
        else if ((lParam >> 16) == 1)
            strncpy(lpString, "left", cchSize);
        
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetMenu(uint32_t hWnd)
    {
        printf("STUB: User32.dll::GetMenu(%x)\n", hWnd);
        return 0xaccac;
    }
    
    Q_INVOKABLE uint32_t CheckMenuItem(uint32_t hMenu, uint32_t uIDCheckItem, uint32_t uCheck)
    {
        printf("STUB: User32.dll::CheckMenuItem(%x, %x, %x)\n", hMenu, uIDCheckItem, uCheck);
        return 0xbccac;
    }
    
    Q_INVOKABLE uint32_t EnableMenuItem(uint32_t hMenu, uint32_t uIDEnableItem, uint32_t uEnable)
    {
        printf("STUB: User32.dll::EnableMenuItem(%x, %x, %x)\n", hMenu, uIDEnableItem, uEnable);
        return 0xbccac;
    }
    
    Q_INVOKABLE uint32_t DeleteMenu(uint32_t hMenu, uint32_t uPosition, uint32_t uFlags)
    {
        printf("STUB: User32.dll::DeleteMenu(%x, %x, %x)\n", hMenu, uPosition, uFlags);
        return 0;
    }
    
    Q_INVOKABLE uint32_t DrawMenuBar(uint32_t hMenu)
    {
        printf("STUB: User32.dll::DrawMenuBar(%x)\n", hMenu);
        return 0;
    }
    
    Q_INVOKABLE uint32_t DestroyWindow(uint32_t hWnd)
    {
        printf("STUB: User32.dll::DestroyWindow(%x)\n", hWnd);
        return 0;
    }
    
    Q_INVOKABLE uint32_t SetCursor(uint32_t hCursor)
    {
        return 0;
    }
    
    Q_INVOKABLE uint32_t BeginPaint(uint32_t hWnd, uint32_t lpPaint)
    {
        printf("STUB: User32.dll::BeginPaint(%x, %x)\n", hWnd, lpPaint);
        return 0xabc123d;
    }
    
    Q_INVOKABLE uint32_t EndPaint(uint32_t hWnd, uint32_t lpPaint)
    {
        printf("STUB: User32.dll::EndPaint(%x, %x)\n", hWnd, lpPaint);
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetCursorPos(uint32_t* lpPos)
    {
        printf("STUB: User32.dll::GetCursorPos(...)\n");
        lpPos[0] = mousePosX;
        lpPos[1] = mousePosY;
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetSysColor(uint32_t nIndex)
    {
        printf("STUB: User32.dll::GetSysColor(%u)\n", nIndex);
        return 0;
    }
    
    Q_INVOKABLE uint32_t GetSysColorBrush(uint32_t nIndex)
    {
        printf("STUB: User32.dll::GetSysColorBrush(%u)\n", nIndex);
        
        return 0x8127AAA;
        
    }
    
    Q_INVOKABLE uint32_t SetWindowsHookExA(uint32_t idHook, uint32_t lpfn, uint32_t hmod, uint32_t dwThreadId)
    {
        printf("STUB: User32.dll::SetWindowsHookExA(%x, %x, %x, %x)\n", idHook, lpfn, hmod, dwThreadId);
        return 0x8123AAA;
    }
    
    Q_INVOKABLE uint32_t SetRectEmpty(void* lpRect)
    {
        printf("STUB: User32.dll::SetRectEmpty(...)\n");
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetClassInfoA(uint32_t hInstance, char* lpClassName, struct WNDCLASSA* lpWndClass)
    {
        printf("STUB: User32.dll::GetClassInfoA(%x, \"%s\", ...)\n", hInstance, lpClassName);
        return 1;
    }
    
    Q_INVOKABLE uint32_t LoadMenuA(uint32_t hInstance, char* lpMenuName)
    {
        printf("STUB: User32.dll::LoadMenuA(%x, \"%s\", ...)\n", hInstance, lpMenuName);
        return 0x8123AAB;
    }
    
    Q_INVOKABLE uint32_t OffsetRect(void* lpRect, int dx, int dy)
    {
        printf("STUB: User32.dll::OffsetRect(..., %x, %x)\n", dx, dy);
        return 1;
    }
    
    Q_INVOKABLE uint32_t LoadAcceleratorsA(uint32_t hInstance, char* lpTableName)
    {
        printf("STUB: User32.dll::LoadAcceleratorsA(%x, \"%s\")\n", hInstance, lpTableName);
        return 0x8123AAC;
    }
    
    Q_INVOKABLE uint32_t GetDlgItem(uint32_t hDlg, int nIDDlgItem)
    {
        printf("STUB: User32.dll::GetDlgItem(%x, %x)\n", hDlg, nIDDlgItem);
        return 0x8123AAD;
    }
    
    Q_INVOKABLE uint32_t GetTopWindow(uint32_t hWnd)
    {
        printf("STUB: User32.dll::GetTopWindow(%x)\n", hWnd);
        return 0;
    }
    
    Q_INVOKABLE uint32_t IsDialogMessageA(uint32_t a, uint32_t b)
    {
        return 0;
    }
//    Q_INVOKABLE uint32_t ();
};

extern User32 *user32;

#endif // USER32_H
