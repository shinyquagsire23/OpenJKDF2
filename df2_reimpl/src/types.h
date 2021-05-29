#ifndef TYPES_H
#define TYPES_H

#ifdef WIN32
#include <windows.h>
#include <io.h>
#endif

#include <stdarg.h>

#include <stdint.h>
#include <stddef.h>
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"

// TODO find some headers for these
#define LPDDENUMCALLBACKA void*
#define LPDIRECTDRAW void*
#define LPDIRECTINPUTA void*
#define LPDIRECTPLAYLOBBYA void*
#define LPDIRECTSOUND void*

#ifdef WIN32
typedef intptr_t stdFile_t;
#else
typedef intptr_t stdFile_t;
#endif

typedef struct IDirectSoundBuffer IDirectSoundBuffer;
typedef IDirectSoundBuffer* LPDIRECTSOUNDBUFFER;

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct jkEpisode jkEpisode;
typedef struct jkEpisodeEntry jkEpisodeEntry;

typedef struct sithAdjoin sithAdjoin;
typedef struct sithAIClass sithAIClass;
typedef struct sithAIClassEntry sithAIClassEntry;
typedef struct sithCog sithCog;
typedef struct sithCogMsg sithCogMsg;
typedef struct sithSector sithSector;
typedef struct sithSound sithSound;
typedef struct sithSurface sithSurface;
typedef struct sithThing sithThing;
typedef struct sithWorld sithWorld;

typedef struct stdBitmap stdBitmap;
typedef struct stdStrTable stdStrTable;
typedef struct stdConffileArg stdConffileArg;
typedef struct stdHashTable stdHashTable;
typedef struct stdVBuffer stdVBuffer;
typedef struct stdGob stdGob;
typedef struct stdGobFile stdGobFile;

typedef struct rdClipFrustum rdClipFrustum;
typedef struct rdColormap rdColormap;
typedef struct rdDDrawSurface rdDDrawSurface;
typedef struct rdEdge rdEdge;
typedef struct rdKeyframe rdKeyframe;
typedef struct rdMaterial rdMaterial;
typedef struct rdParticle rdParticle;
typedef struct rdProcEntry rdProcEntry;
typedef struct rdPuppet rdPuppet;
typedef struct rdSprite rdSprite;
typedef struct rdSurface rdSurface;
typedef struct rdVertexIdxInfo rdVertexIdxInfo;
typedef struct sithUnk3SearchEntry sithUnk3SearchEntry;
typedef struct sithPlayingSound sithPlayingSound;
typedef struct sithSoundClass sithSoundClass;
typedef struct sithAI sithAI;
typedef struct sithAICommand sithAICommand;
typedef struct sithActor sithActor;
typedef struct sithSurfaceInfo sithSurfaceInfo;
typedef struct sithSoundClass sithSoundClass;
typedef struct sithSoundClassEntry sithSoundClassEntry;

typedef struct common_functions common_functions;

typedef struct Darray Darray;

#ifdef LINUX
#define __stdcall
#define __cdecl
typedef int HKEY;
typedef char* LPCSTR;
typedef uint32_t DWORD;
typedef uint32_t* LPDWORD;
typedef uint32_t LSTATUS;
typedef uint8_t BYTE;
typedef uint8_t* LPBYTE;
typedef int REGSAM;
typedef HKEY* PHKEY;
typedef char* LPSTR;
typedef void* LPSECURITY_ATTRIBUTES;
typedef int HRESULT;
typedef void** LPVOID;
typedef uint32_t HINSTANCE;
typedef void* LPUNKNOWN;
typedef int HDC;
typedef int BOOL;
typedef uint32_t UINT;
typedef void* LPPALETTEENTRY;
typedef int* HGDIOBJ;
typedef int HFONT;
typedef int COLORREF;
typedef int HBITMAP;
typedef void BITMAPINFO;
typedef int HANDLE;
typedef int HPALETTE;
typedef void PALETTEENTRY;
typedef int LOGPALETTE;
typedef void RGBQUAD;
typedef void* LPCVOID;
typedef uint32_t SIZE_T;
typedef int HWND;
typedef uint16_t WORD;
typedef int16_t SHORT;
typedef int LONG;
typedef wchar_t WCHAR;

typedef int8_t __int8;
typedef int16_t __int16;
typedef int32_t __int32;
typedef int64_t __int64;

typedef uint32_t* GUID;
typedef GUID* LPGUID;
typedef int IUnknown;
typedef uint16_t WPARAM;
typedef uint32_t LRESULT;
typedef int HCURSOR;
typedef int* LPARAM;

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

#define HKEY_LOCAL_MACHINE 0

typedef struct COORD
{
    int x;
    int y;
} COORD;

typedef struct RECT
{
    int x;
    int y;
    int w;
    int h;
} RECT;

typedef struct tagPOINT
{
  LONG x;
  LONG y;
} tagPOINT;

typedef tagPOINT POINT;
typedef POINT* LPPOINT;

typedef struct tagPAINTSTRUCT
{
  HDC hdc;
  BOOL fErase;
  RECT rcPaint;
  BOOL fRestore;
  BOOL fIncUpdate;
  BYTE rgbReserved[32];
} tagPAINTSTRUCT;

typedef RECT* LPRECT;
#endif

#endif // TYPES_H
