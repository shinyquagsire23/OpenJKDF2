#ifndef TYPES_H
#define TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef GHIDRA_IMPORT
typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef uint32_t intptr_t;
typedef uint32_t size_t;
#define _SITHCOGYACC_H
#define JK_H
#endif

#ifdef JKM_TYPES
#define JKM_LIGHTING
#define JKM_BONES
#endif

#include "engine_config.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#endif

#include <stdarg.h>

#include <stdint.h>
#include <stddef.h>

#include "Primitives/rdRect.h"

#ifdef QOL_IMPROVEMENTS
#define SITH_MAX_SYNC_THINGS (128)
#else
#define SITH_MAX_SYNC_THINGS (16)
#endif

#define SITHCOGVM_MAX_STACKSIZE (64)

#define RDCACHE_MAX_TRIS (0x400)
#define RDCACHE_MAX_VERTICES (0x8000)

#if defined(JK_NO_MMAP)
//#define RDCACHE_MAX_TRIS (0x2000)
//#define RDCACHE_MAX_VERTICES (0x10000)
#endif

#define STD3D_MAX_VERTICES (RDCACHE_MAX_TRIS)
#define STD3D_MAX_TRIS (RDCACHE_MAX_TRIS)

// TODO find some headers for these
#define LPDDENUMCALLBACKA void*
#define LPDIRECTDRAW void*
#define LPDIRECTINPUTA void*
#define LPDIRECTPLAYLOBBYA void*
#define LPDIRECTSOUND void*

#if defined(_MSC_VER)
#define ALIGNED_(x) __declspec(align(x))
#else
#if defined(__GNUC__)
#define ALIGNED_(x) __attribute__ ((aligned(x)))
#else
#define ALIGNED_(x) __attribute__ ((aligned(x)))
#endif
#endif

typedef struct GUID_idk
{
    uint32_t a,b,c,d;
} GUID_idk;

#ifdef LINUX
#define __stdcall
#define __cdecl
typedef int HKEY;
typedef char* LPCSTR;
typedef wchar_t* LPCWSTR;
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
typedef int PAINTSTRUCT;

#ifndef GHIDRA_IMPORT
typedef int8_t __int8;
typedef int16_t __int16;
typedef int32_t __int32;
typedef int64_t __int64;
#endif

typedef struct GUID
{
    uint32_t a,b,c,d;
} GUID;

typedef GUID* LPGUID;
typedef int IUnknown;
typedef uint16_t WPARAM;
typedef uint32_t LRESULT;
typedef int HCURSOR;
typedef int LPARAM;
typedef int WNDPROC;

typedef int CONSOLE_CURSOR_INFO;

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

#ifdef WIN32
typedef intptr_t stdFile_t;
#else
typedef intptr_t stdFile_t;
#endif

#ifdef ARCH_64BIT
//typedef int64_t cog_int_t;
//typedef double cog_flex_t;
typedef int32_t cog_int_t;
typedef float cog_flex_t;
#else
typedef int32_t cog_int_t;
typedef float cog_flex_t;
#endif

typedef struct IDirectSound3DBuffer IDirectSound3DBuffer;
typedef struct IDirectSoundBuffer IDirectSoundBuffer;
typedef IDirectSoundBuffer* LPDIRECTSOUNDBUFFER;
typedef IDirectSound3DBuffer* LPDIRECTSOUND3DBUFFER;

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct jkEpisode jkEpisode;
typedef struct jkEpisodeEntry jkEpisodeEntry;

typedef struct sithAdjoin sithAdjoin;
typedef struct sithAIClass sithAIClass;
typedef struct sithAIClassEntry sithAIClassEntry;
typedef struct sithCog sithCog;
typedef struct sithCogMsg sithCogMsg;
typedef struct sithCogSectorLink sithCogSectorLink;
typedef struct sithPuppet sithPuppet;
typedef struct sithSector sithSector;
typedef struct sithSound sithSound;
typedef struct sithSurface sithSurface;
typedef struct sithThing sithThing;
typedef struct sithWorld sithWorld;
typedef struct sithAnimclass sithAnimclass;

typedef struct stdBitmap stdBitmap;
typedef struct stdStrTable stdStrTable;
typedef struct stdConffileArg stdConffileArg;
typedef struct stdHashTable stdHashTable;
typedef struct stdVBuffer stdVBuffer;
typedef struct stdGob stdGob;
typedef struct stdGobFile stdGobFile;
typedef struct stdPalEffect stdPalEffect;
typedef struct stdPalEffectRequest stdPalEffectRequest;
typedef struct stdFont stdFont;

typedef struct rdClipFrustum rdClipFrustum;
typedef struct rdColormap rdColormap;
typedef struct rdColor24 rdColor24;
typedef struct rdDDrawSurface rdDDrawSurface;
typedef struct rdEdge rdEdge;
typedef struct rdFace rdFace;
typedef struct rdHierarchyNode rdHierarchyNode;
typedef struct rdKeyframe rdKeyframe;
typedef struct rdMaterial rdMaterial;
typedef struct rdMesh rdMesh;
typedef struct rdParticle rdParticle;
typedef struct rdProcEntry rdProcEntry;
typedef struct rdPuppet rdPuppet;
typedef struct rdSprite rdSprite;
typedef struct rdSurface rdSurface;
typedef struct rdThing rdThing;
typedef struct rdVertexIdxInfo rdVertexIdxInfo;
typedef struct sithCollisionSearchEntry sithCollisionSearchEntry;
typedef struct sithPlayingSound sithPlayingSound;
typedef struct sithSoundClass sithSoundClass;
typedef struct sithAI sithAI;
typedef struct sithAICommand sithAICommand;
typedef struct sithActor sithActor;
typedef struct sithActorEntry sithActorEntry;
typedef struct sithActorInstinct sithActorInstinct;
typedef struct sithCamera sithCamera;
typedef struct sithCogScript sithCogScript;
typedef struct sithCogSymboltable sithCogSymboltable;
typedef struct sithSurfaceInfo sithSurfaceInfo;
typedef struct sithSoundClass sithSoundClass;
typedef struct sithSoundClassEntry sithSoundClassEntry;
typedef struct sithEvent sithEvent;
typedef struct sithEventInfo sithEventInfo;
typedef struct sithCollisionEntry sithCollisionEntry;
typedef struct sithCollisionSectorEntry sithCollisionSectorEntry;
typedef struct sithMap sithMap;
typedef struct sithMapView sithMapView;
typedef struct sithPlayerInfo sithPlayerInfo;
typedef struct sithAnimclassEntry sithAnimclassEntry;
typedef struct stdALBuffer stdALBuffer;
typedef struct stdNullSoundBuffer stdNullSoundBuffer;
typedef struct rdTri rdTri;
typedef struct rdLine rdLine;
typedef struct rdGeoset rdGeoset;
typedef struct rdMeshinfo rdMeshinfo;
typedef struct rdLight rdLight;
typedef struct rdModel3 rdModel3;
typedef struct rdCanvas rdCanvas;

typedef struct sithGamesave_Header sithGamesave_Header;
typedef struct jkGuiStringEntry jkGuiStringEntry;
typedef struct jkGuiKeyboardEntry jkGuiKeyboardEntry;

typedef struct videoModeStruct videoModeStruct;
typedef struct HostServices HostServices;
typedef struct stdDebugConsoleCmd stdDebugConsoleCmd;

typedef struct Darray Darray;

typedef struct stdControlKeyInfoEntry stdControlKeyInfoEntry;

#ifndef SDL2_RENDER
typedef IDirectSoundBuffer stdSound_buffer_t;
typedef IDirectSound3DBuffer stdSound_3dBuffer_t;
#else // OPENAL_SOUND

#ifdef OPENAL_SOUND
typedef stdALBuffer stdSound_buffer_t;
typedef stdALBuffer stdSound_3dBuffer_t;
#endif

#ifdef NULL_SOUND
typedef stdNullSoundBuffer stdSound_buffer_t;
typedef stdNullSoundBuffer stdSound_3dBuffer_t;
#endif 

#endif // OPENAL_SOUND

typedef rdModel3* (*model3Loader_t)(const char *, int);
typedef int (*model3Unloader_t)(rdModel3*);
typedef rdKeyframe* (*keyframeLoader_t)(const char*);
typedef int (*keyframeUnloader_t)(rdKeyframe*);
typedef void (*sithRender_weapRendFunc_t)(sithThing*);
typedef int (*sithMultiHandler_t)();
typedef int (*stdPalEffectSetPaletteFunc_t)(uint8_t*);
typedef int (*sithAICommandFunc_t)(sithActor *actor, sithAIClassEntry *a8, sithActorInstinct *a3, int b, intptr_t a4);
typedef int (*sithControlEnumFunc_t)(int inputFuncIdx, const char *pInputFuncStr, uint32_t a3, int dxKeyNum, uint32_t a5, int a6, stdControlKeyInfoEntry* pControlEntry, Darray* pDarr);
typedef int (*sithCollisionHitHandler_t)(sithThing *, sithSurface *, sithCollisionSearchEntry *);
typedef void (*rdPuppetTrackCallback_t)(sithThing*, int32_t, uint32_t);

// Define some maximums here
#define SITHBIN_NUMBINS (200)

// Constants
typedef int32_t rdGeoMode_t;
enum RD_GEOMODE
{
    RD_GEOMODE_NOTRENDERED = 0,
    RD_GEOMODE_VERTICES = 1,
    RD_GEOMODE_WIREFRAME = 2,
    RD_GEOMODE_SOLIDCOLOR = 3,
    RD_GEOMODE_TEXTURED = 4,
    RD_GEOMODE_5_UNK = 5
};

typedef int32_t rdLightMode_t;
enum RD_LIGHTMODE
{
    RD_LIGHTMODE_FULLYLIT = 0,
    RD_LIGHTMODE_NOTLIT = 1,
    RD_LIGHTMODE_DIFFUSE = 2,
    RD_LIGHTMODE_GOURAUD = 3,
    RD_LIGHTMODE_4_UNK = 4,
    RD_LIGHTMODE_5_UNK = 5,
    RD_LIGHTMODE_6_UNK = 6
};

typedef int32_t rdTexMode_t;
enum RD_TEXTUREMODE
{
    RD_TEXTUREMODE_AFFINE = 0,
    RD_TEXTUREMODE_PERSPECTIVE = 1,
    RD_TEXTUREMODE_2_UNK = 2,
    RD_TEXTUREMODE_3_UNK = 3,
    RD_TEXTUREMODE_4_UNK = 4
};

typedef uint32_t sithCogFlags_t;
enum SithCogFlag
{
    SITH_COG_DEBUG = 0x1,
    SITH_COG_DISABLED = 0x2,
    SITH_COG_PULSE_SET = 0x4,
    SITH_COG_TIMER_SET = 0x8,
    SITH_COG_PAUSED = 0x10,
    SITH_COG_CLASS = 0x20,
    SITH_COG_LOCAL = 0x40,
    SITH_COG_SERVER = 0x80,
    SITH_COG_GLOBAL = 0x100,
    SITH_COG_NO_SYNC = 0x200,
};

typedef int SITH_MESSAGE;
enum SITH_MESSAGE_E
{
    SITH_MESSAGE_0 = 0,
    SITH_MESSAGE_ACTIVATE = 1,
    SITH_MESSAGE_REMOVED = 2,
    SITH_MESSAGE_STARTUP = 3,
    SITH_MESSAGE_TIMER = 4,
    SITH_MESSAGE_BLOCKED = 5,
    SITH_MESSAGE_ENTERED = 6,
    SITH_MESSAGE_EXITED = 7,
    SITH_MESSAGE_CROSSED = 8,
    SITH_MESSAGE_SIGHTED = 9,
    SITH_MESSAGE_DAMAGED = 10,
    SITH_MESSAGE_ARRIVED = 11,
    SITH_MESSAGE_KILLED = 12,
    SITH_MESSAGE_PULSE = 13,
    SITH_MESSAGE_TOUCHED = 14,
    SITH_MESSAGE_CREATED = 15,
    SITH_MESSAGE_LOADING = 16,
    SITH_MESSAGE_SELECTED = 17,
    SITH_MESSAGE_DESELECTED = 18,
    SITH_MESSAGE_AUTOSELECT = 19,
    SITH_MESSAGE_CHANGED = 20,
    SITH_MESSAGE_DEACTIVATED = 21,
    SITH_MESSAGE_SHUTDOWN = 22,
    SITH_MESSAGE_RESPAWN = 23,
    SITH_MESSAGE_AIEVENT = 24,
    SITH_MESSAGE_SKILL = 25,
    SITH_MESSAGE_TAKEN = 26,
    SITH_MESSAGE_USER0 = 27,
    SITH_MESSAGE_USER1 = 28,
    SITH_MESSAGE_USER2 = 29,
    SITH_MESSAGE_USER3 = 30,
    SITH_MESSAGE_USER4 = 31,
    SITH_MESSAGE_USER5 = 32,
    SITH_MESSAGE_USER6 = 33,
    SITH_MESSAGE_USER7 = 34,
    SITH_MESSAGE_NEWPLAYER = 35,
    SITH_MESSAGE_FIRE = 36,
    SITH_MESSAGE_JOIN = 37,
    SITH_MESSAGE_LEAVE = 38,
    SITH_MESSAGE_SPLASH = 39,
    SITH_MESSAGE_TRIGGER = 40,
    SITH_MESSAGE_MAX = 41,
};

typedef uint32_t sithWeaponFlags_t;
enum SITH_WF_E
{
    SITH_WF_NO_DAMAGE_TO_SHOOTER = 0x1,
    SITH_WF_2 = 0x2,
    SITH_WF_EXPLODE_ON_SURFACE_HIT = 0x4,
    SITH_WF_EXPLODE_ON_THING_HIT = 0x8,
    SITH_WF_10 = 0x10,
    SITH_WF_20 = 0x20,
    SITH_WF_40 = 0x40,
    SITH_WF_ATTACH_TO_WALL = 0x80,
    SITH_WF_EXPLODE_AT_TIMER_TIMEOUT = 0x100,
    SITH_WF_EXPLODE_WHEN_DAMAGED = 0x200,
    SITH_WF_IMPACT_SOUND_FX = 0x400,
    SITH_WF_ATTACH_TO_THING = 0x800,
    SITH_WF_PROXIMITY = 0x1000, // "Weapon will explode when something touches its sphere."
    SITH_WF_INSTANT_IMPACT = 0x2000,
    SITH_WF_DAMAGE_DECAY = 0x4000,
    SITH_WF_OBJECT_TRAIL = 0x8000,
    SITH_WF_10000 = 0x10000, // short throw? unsure
    SITH_WF_20000 = 0x20000,
    SITH_WF_TRIGGER_AI_AWARENESS = 0x40000,
    SITH_WF_RICOCHET_OFF_SURFACE = 0x80000,
    SITH_WF_100000 = 0x100000,
    SITH_WF_TRIGGER_AIEVENT = 0x200000,
    SITH_WF_EXPLODES_ON_WORLD_FLOOR_HIT = 0x400000,
    SITH_WF_MOPHIA_BOMB = 0x800000, // Jones specific
};

// All the typedefs
typedef struct rdVector2i
{
    int x;
    int y;
} rdVector2i;

typedef struct rdVector3i
{
    int x;
    int y;
    int z;
} rdVector3i;

typedef struct rdVector2
{
    float x;
    float y;
} rdVector2;

typedef struct rdVector3
{
    float x;
    float y;
    float z;
} rdVector3;

typedef struct rdVector4
{
    float x;
    float y;
    float z;
    float w;
} rdVector4;

typedef struct rdMatrix33
{
    rdVector3 rvec;
    rdVector3 lvec;
    rdVector3 uvec;
} rdMatrix33;

typedef struct rdMatrix34
{
    rdVector3 rvec;
    rdVector3 lvec;
    rdVector3 uvec;
    rdVector3 scale;
} rdMatrix34;

typedef struct rdMatrix44
{
    rdVector4 vA;
    rdVector4 vB;
    rdVector4 vC;
    rdVector4 vD;
} rdMatrix44;

typedef struct rdLight
{
    uint32_t id;
    uint32_t type;
    uint32_t active;
    rdVector3 direction;
    float intensity;
#ifdef JKM_LIGHTING
    float intensityR;
    float intensityG;
    float intensityB;
#endif
    uint32_t color;
    uint32_t dword20;
    uint32_t dword24;
    float falloffMin;
    float falloffMax;
} rdLight;


typedef struct sithCameraRenderInfo
{
    uint32_t field_0;
    float field_4;
    float field_8;
    rdColormap* colormap;
} sithCameraRenderInfo;

typedef struct rdCamera
{
    int projectType;
    rdCanvas* canvas;
    rdMatrix34 view_matrix;
    float fov;
    float fov_y;
    float screenAspectRatio;
    float orthoScale;
    rdClipFrustum *cameraClipFrustum;
    void (*project)(rdVector3 *, rdVector3 *);
    void (*projectLst)(rdVector3 *, rdVector3 *, unsigned int);
    float ambientLight;
    int numLights;
    rdLight* lights[64];
    rdVector3 lightPositions[64];
    float attenuationMin;
    float attenuationMax;
} rdCamera;

#pragma pack(push, 4)
typedef struct sithCamera
{
    uint32_t cameraPerspective;
    uint32_t dword4;
    float fov;
    float aspectRatio;
    sithThing* primaryFocus;
    sithThing* secondaryFocus;
    sithSector* sector;
    rdVector3 vec3_3;
    rdVector3 vec3_4;
    rdMatrix34 viewMat;
    rdVector3 vec3_1;
    rdVector3 vec3_2;
    rdCamera rdCam;
#ifdef JKM_TYPES
    float unk1;
    float unk2;
    float unk3;
    float unk4;
    float unk5;
#endif
} sithCamera;
#pragma pack(pop)


typedef struct rdClipFrustum
{
  rdVector3 field_0;
  float orthoLeft;
  float orthoTop;
  float orthoRight;
  float orthoBottom;
  float farTop;
  float bottom;
  float farLeft;
  float right;
  float nearTop;
  float nearLeft;
} rdClipFrustum;


typedef struct rdProcEntry
{
    uint32_t extraData;
    int type;
    rdGeoMode_t geometryMode;
    rdLightMode_t lightingMode;
    rdTexMode_t textureMode;
    uint32_t anonymous_4;
    uint32_t anonymous_5;
    uint32_t numVertices;
    rdVector3* vertices;
    rdVector2* vertexUVs;
    float* vertexIntensities;
#ifdef JKM_LIGHTING
    float* paRedIntensities;
    float* paGreenIntensities;
    float* paBlueIntensities;
#endif
    rdMaterial* material;
    uint32_t wallCel;
    float ambientLight;
    float light_level_static;
    float extralight;
    rdColormap* colormap;
    uint32_t light_flags;
    int32_t x_min;
    uint32_t x_max;
    int32_t y_min;
    uint32_t y_max;
    float z_min;
    float z_max;
    int y_min_related;
    int y_max_related;
    uint32_t vertexColorMode;
} rdProcEntry;

typedef struct v11_struct
{
  int mipmap_related;
  int field_4;
  rdMaterial *material;
} v11_struct;

typedef struct rdTri
{
  int v1;
  int v2;
  int v3;
  int flags;
  rdDDrawSurface *texture; // DirectDrawSurface*
} rdTri;

typedef struct rdLine
{
    int v1;
    int v2;
    int flags;
} rdLine;

typedef float D3DVALUE;

#pragma pack(push, 4)
typedef struct D3DVERTEX_orig
{
  union ALIGNED_(4)
  {
    D3DVALUE x;
    float dvX;
  };
  #pragma pack(push, 4)
  union
  {
    D3DVALUE y;
    D3DVALUE dvY;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE z;
    D3DVALUE dvZ;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE nx;
    D3DVALUE dvNX;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE ny;
    D3DVALUE dvNY;
    uint32_t color;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE nz;
    D3DVALUE dvNZ;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE tu;
    D3DVALUE dvTU;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE tv;
    D3DVALUE dvTV;
  };
  #pragma pack(pop)
} D3DVERTEX_orig;
#pragma pack(pop)

#pragma pack(push, 4)
typedef struct D3DVERTEX_ext
{
  union ALIGNED_(4)
  {
    D3DVALUE x;
    float dvX;
  };
  #pragma pack(push, 4)
  union
  {
    D3DVALUE y;
    D3DVALUE dvY;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE z;
    D3DVALUE dvZ;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE nx;
    D3DVALUE dvNX;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE ny;
    D3DVALUE dvNY;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE nz;
    D3DVALUE dvNZ;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE tu;
    D3DVALUE dvTU;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    D3DVALUE tv;
    D3DVALUE dvTV;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  uint32_t color;
  #pragma pack(pop)
  #pragma pack(push, 4)
  float lightLevel;
  #pragma pack(pop)
} D3DVERTEX_ext;
#pragma pack(pop)

// TODO: Differentiate by renderer, not SDL2
#ifdef SDL2_RENDER
typedef D3DVERTEX_ext D3DVERTEX;
#else
typedef D3DVERTEX_orig D3DVERTEX;
#endif

/* 174 */
typedef DWORD D3DCOLORMODEL;

/* 176 */
#pragma pack(push, 4)
typedef struct D3DTRANSFORMCAPS
{
  DWORD dwSize;
  DWORD dwCaps;
} D3DTRANSFORMCAPS;
#pragma pack(pop)

/* 178 */
#pragma pack(push, 4)
typedef struct D3DLIGHTINGCAPS
{
  DWORD dwSize;
  DWORD dwCaps;
  DWORD dwLightingModel;
  DWORD dwNumLights;
} D3DLIGHTINGCAPS;
#pragma pack(pop)

/* 180 */
#pragma pack(push, 4)
typedef struct D3DPrimCaps
{
  DWORD dwSize;
  DWORD dwMiscCaps;
  DWORD dwRasterCaps;
  DWORD dwZCmpCaps;
  DWORD dwSrcBlendCaps;
  DWORD dwDestBlendCaps;
  DWORD dwAlphaCmpCaps;
  DWORD dwShadeCaps;
  DWORD dwTextureCaps;
  DWORD dwTextureFilterCaps;
  DWORD dwTextureBlendCaps;
  DWORD dwTextureAddressCaps;
  DWORD dwStippleWidth;
  DWORD dwStippleHeight;
} D3DPrimCaps;
#pragma pack(pop)

#pragma pack(push, 4)
typedef struct D3DDeviceDesc
{
  DWORD dwSize;
  DWORD dwFlags;
  D3DCOLORMODEL dcmColorModel;
  DWORD dwDevCaps;
  D3DTRANSFORMCAPS dtcTransformCaps;
  BOOL bClipping;
  D3DLIGHTINGCAPS dlcLightingCaps;
  D3DPrimCaps dpcLineCaps;
  D3DPrimCaps dpcTriCaps;
  DWORD dwDeviceRenderBitDepth;
  DWORD dwDeviceZBufferBitDepth;
  DWORD dwMaxBufferSize;
  DWORD dwMaxVertexCount;
  DWORD dwMinTextureWidth;
  DWORD dwMinTextureHeight;
  DWORD dwMaxTextureWidth;
  DWORD dwMaxTextureHeight;
  DWORD dwMinStippleWidth;
  DWORD dwMaxStippleWidth;
  DWORD dwMinStippleHeight;
  DWORD dwMaxStippleHeight;
} D3DDeviceDesc;
#pragma pack(pop)

typedef struct ALIGNED_(16) d3d_device
{
  uint32_t hasColorModel;
  uint32_t dpcTri_hasperspectivecorrectttexturing;
  uint32_t hasZBuffer;
  uint32_t supportsColorKeyedTransparency;
  uint32_t hasAlpha;
  uint32_t hasAlphaFlatStippled;
  uint32_t hasModulateAlpha;
  uint32_t hasOnlySquareTexs;
  char gap20[4];
  uint32_t dcmColorModel;
  uint32_t availableBitDepths;
  uint32_t zCaps;
  uint32_t dword30;
  uint32_t dword34;
  uint32_t dword38;
  uint32_t dword3C;
  uint32_t dwMaxBufferSize;
  uint32_t dwMaxVertexCount;
  char deviceName[128];
  char deviceDescription[128];
  ALIGNED_(16) D3DDeviceDesc device_desc;
  DWORD d3d_this;
} d3d_device;


typedef struct rdDDrawSurface
{
    void* lpVtbl; // IDirectDrawSurfaceVtbl *lpVtbl
    uint32_t direct3d_tex;
    uint8_t surface_desc[0x6c];
    uint32_t texture_id;
    uint32_t texture_loaded;
    uint32_t is_16bit;
    uint32_t width;
    uint32_t height;
    uint32_t texture_area;
    uint32_t gpu_accel_maybe;
    rdDDrawSurface* tex_prev;
    rdDDrawSurface* tex_next;
#ifdef SDL2_RENDER
    uint32_t emissive_texture_id;
    uint32_t displacement_texture_id;
    float emissive_factor[3];
    float displacement_factor;
    void* emissive_data;
    void* albedo_data;
    void* displacement_data;
    int skip_jkgm;
#endif
} rdDDrawSurface;

typedef struct rdTexformat
{
    uint32_t is16bit;
    uint32_t bpp;
    uint32_t r_bits;
    uint32_t g_bits;
    uint32_t b_bits;
    uint32_t r_shift;
    uint32_t g_shift;
    uint32_t b_shift;
    uint32_t r_bitdiff;
    uint32_t g_bitdiff;
    uint32_t b_bitdiff;
    uint32_t unk_40;
    uint32_t unk_44;
    uint32_t unk_48;
} rdTexformat;

typedef struct stdVBufferTexFmt
{
    int32_t width;
    int32_t height;
    uint32_t texture_size_in_bytes;
    uint32_t width_in_bytes;
    uint32_t width_in_pixels;
    rdTexformat format;
} stdVBufferTexFmt;

#ifdef SDL2_RENDER
typedef struct SDL_Surface SDL_Surface;
#endif

typedef struct stdVBuffer
{
    uint32_t bSurfaceLocked;
    uint32_t lock_cnt;
    uint32_t gap8;
    stdVBufferTexFmt format;
    void* palette;
    char* surface_lock_alloc;
    uint32_t transparent_color;
    union
    {
    rdDDrawSurface *ddraw_surface;
#ifdef SDL2_RENDER
    SDL_Surface* sdlSurface;
#endif
    };
    void* ddraw_palette; // LPDIRECTDRAWPALETTE
    uint8_t desc[0x6c];
} stdVBuffer;

typedef struct rdColor24
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
} rdColor24;

typedef struct rdColormap
{
    char colormap_fname[32];
    uint32_t flags;
    rdVector3 tint;
    rdColor24 colors[256];
    void* lightlevel;
    void* lightlevelAlloc;
    void* transparency;
    void* transparencyAlloc;
    void* dword340;
    void* dword344;
    void* rgb16Alloc;
    void* dword34C;
} rdColormap;

typedef struct rdColormapHeader
{
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    rdVector3 tint;
    uint32_t field_18;
    uint32_t field_1C;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
} rdColormapHeader;


typedef struct rdTexture
{
    uint32_t alpha_en;
    uint32_t unk_0c;
    uint32_t color_transparent;
    uint32_t width_bitcnt;
    uint32_t width_minus_1;
    uint32_t height_minus_1;
    uint32_t num_mipmaps;
    stdVBuffer *texture_struct[4];
    rdDDrawSurface alphaMats[4];
    rdDDrawSurface opaqueMats[4];
} rdTexture;

typedef struct rdTextureHeader
{
    uint32_t width;
    uint32_t height;
    uint32_t alpha_en;
    uint32_t unk_0c;
    uint32_t unk_10;
    uint32_t num_mipmaps;
} rdTextureHeader;

typedef struct rdTexinfoExtHeader
{
    uint32_t unk_00;
    uint32_t height;
    uint32_t alpha_en;
    uint32_t unk_0c;
} rdTexinfoExtHeader;

typedef struct rdTexinfoHeader
{
    uint32_t texture_type;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t field_14;
} rdTexinfoHeader;

typedef struct rdTexinfo
{
    rdTexinfoHeader header;
    uint32_t texext_unk00;
    rdTexture *texture_ptr;
} rdTexinfo;

typedef struct rdMaterialHeader
{
    uint8_t magic[4];
    uint32_t revision;
    uint32_t type;
    uint32_t num_texinfo;
    uint32_t num_textures;
    rdTexformat tex_format;
} rdMaterialHeader;

typedef struct rdMaterial
{
    uint32_t tex_type;
    char mat_fpath[32];
#ifdef SDL2_RENDER
    char mat_full_fpath[256];
#endif
    uint32_t id;
    rdTexformat tex_format;
    rdColor24 *palette_alloc;
    uint32_t num_texinfo;
    uint32_t celIdx;
    rdTexinfo *texinfos[16];
    uint32_t num_textures;
    rdTexture* textures;
} rdMaterial;

typedef struct sithEventInfo sithEventInfo; 
typedef struct sithEvent sithEvent;

typedef int (*sithEventHandler_t)(int, sithEventInfo*);

typedef struct sithEventInfo
{
    int cogIdx;
    int timerIdx;
    float field_10;
    float field_14;
} sithEventInfo;

typedef struct sithEvent
{
    uint32_t endMs;
    int taskNum;
    sithEventInfo timerInfo;
    sithEvent* nextTimer;
} sithEvent;

typedef struct sithEventTask
{
    sithEventHandler_t pfProcess;
    uint32_t startMode;
    uint32_t rate;
    uint32_t creationMs;
    uint32_t field_10;
} sithEventTask;


typedef struct sithPlayingSound
{
    stdSound_buffer_t* pSoundBuf;
    stdSound_buffer_t* p3DSoundObj;
    sithSound* sound;
    int flags;
    int idx;
    float vol_2;
    float anonymous_5;
    float maxPosition;
    float anonymous_7;
    float volumeVelocity;
    float volume;
    float pitch;
    float pitchVel;
    float nextPitch;
    float distance;
    rdVector3 posRelative;
    sithThing* thing;
    rdVector3 pos;
    int refid;
} sithPlayingSound;

typedef struct sithSound
{
    char sound_fname[32];
    int id;
    int isLoaded;
    uint32_t bufferBytes;
    uint32_t sampleRateHz;
    int bitsPerSample;
    int bStereo; // stdSound_buffer_t*
    uint32_t sound_len;
    int seekOffset;
    int field_40;
    int infoLoaded;
    void* dsoundBuffer2; // stdSound_buffer_t*
} sithSound;

typedef int (*sithControl_handler_t)(sithThing*, float);

typedef void (*sithSaveHandler_t)();

typedef struct sithGamesave_Header
{
    int version;
    char episodeName[128];
    char jklName[128];
    float playerHealth;
    float playerMaxHealth;
    float binAmts[200];
    wchar_t saveName[256];
} sithGamesave_Header;

typedef struct sithMapViewConfig
{
    int numArr;
    float *unkArr;
    int *paColors;
    int playerColor;
    int playerLineColor;
    int actorColor;
    int actorLineColor;
    int itemColor;
    int weaponColor;
    int otherColor;
    int bRotateOverlayMap;
    int aTeamColors[5];
} sithMapViewConfig;

typedef struct sithMapView
{
    sithMapViewConfig config;
    sithWorld *world;
} sithMapView;

typedef struct rdEdge
{
    uint32_t field_0;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t field_14;
    uint32_t field_18;
    uint32_t field_1C;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    rdEdge* prev;
    rdEdge* next;
} rdEdge;

typedef struct rdVertexIdxInfo
{
    uint32_t numVertices;
    int* vertexPosIdx;
    int* vertexUVIdx;
    rdVector3* vertices;
    rdVector2* vertexUVs;
    float* paDynamicLight;
    float* intensities;
#ifdef JKM_LIGHTING
    float* paRedIntensities;
    float* paGreenIntensities;
    float* paBlueIntensities;
#endif
} rdVertexIdxInfo;

typedef struct rdMeshinfo
{
    uint32_t numVertices;
    int* vertexPosIdx;
    int* vertexUVIdx;
    rdVector3* verticesProjected;
    rdVector2* vertexUVs;
    float* paDynamicLight;
    float* intensities;
#ifdef JKM_LIGHTING
    float* paRedIntensities;
    float* paGreenIntensities;
    float* paBlueIntensities;
#endif
    rdVector3* verticesOrig;
} rdMeshinfo;

typedef struct rdFace
{
    uint32_t num;
    uint32_t type;
    rdGeoMode_t geometryMode;
    rdLightMode_t lightingMode;
    rdTexMode_t textureMode;
    uint32_t numVertices;
    int* vertexPosIdx;
    int* vertexUVIdx;
    rdMaterial* material;
    uint32_t wallCel;
    rdVector2 clipIdk;
    float extraLight;
    rdVector3 normal;
} rdFace;

typedef struct sithSurfaceInfo
{
    rdFace face;
    float* intensities;
    uint32_t lastTouchedMs;
} sithSurfaceInfo;

struct rdSurface
{
  uint32_t index; // -14
  uint32_t flags; // -13
  sithThing *parent_thing; // -12
  uint32_t signature; // -11
  rdMaterial* material; // -10
  sithSurface *sithSurfaceParent; // -9
  sithSector* sector; // -8
  rdVector2 field_1C;
  rdVector3 field_24;
  uint32_t field_30;
  uint32_t field_34;
  uint32_t wallCel;
  float field_3C;
  float field_40;
  float field_44;
  float field_48;
};

typedef struct sithSurface
{
    uint32_t field_0;
    uint32_t field_4;
    sithSector* parent_sector;
    sithAdjoin* adjoin;
    uint32_t surfaceFlags;
    sithSurfaceInfo surfaceInfo;
} sithSurface;

typedef int (*rdMaterialUnloader_t)(rdMaterial*);
typedef rdMaterial* (*rdMaterialLoader_t)(const char*, int, int);

typedef int (*WindowDrawHandler_t)(uint32_t);
typedef int (*WindowHandler_t)(HWND, UINT, WPARAM, LPARAM, LRESULT *);

typedef struct wm_handler
{
  WindowHandler_t handler;
  int32_t exists;
} wm_handler;

typedef int (*DebugConsolePrintFunc_t)(const char*);
typedef int (*DebugConsolePrintUniStrFunc_t)(const wchar_t*);
typedef int (*DebugConsoleCmd_t)(stdDebugConsoleCmd* cmd, const char* extra);

typedef struct stdDebugConsoleCmd
{
    char cmdStr[32];
    DebugConsoleCmd_t cmdFunc;
    uint32_t extra;
} stdDebugConsoleCmd;

typedef struct jkDevLogEnt
{
    wchar_t text[128];
    int timeMsExpiration;
    int field_104;
    int drawWidth;
    int field_10C;
    int bDrawEntry;
} jkDevLogEnt;

#ifdef LINUX
typedef uint32_t MCIDEVICEID;
#endif


typedef struct stdDeviceParams
{
  int field_0;
  int field_4;
  int field_8;
  int field_C;
  int field_10;
} stdDeviceParams;

typedef struct video_device
{
  int device_active;
  int hasGUID;
  int has3DAccel;
  int hasNoGuid;
  int windowedMaybe;
  int dwVidMemTotal;
  int dwVidMemFree;
} video_device;

typedef struct stdVideoMode
{
  int field_0;
  float widthMaybe;
  stdVBufferTexFmt format;
} stdVideoMode;

typedef struct stdVideoDevice
{
  char driverDesc[128];
  char driverName[128];
  video_device video_device[14];
  GUID guid;
  int max_modes;
  stdVideoMode *stdVideoMode;
  uint32_t gap2A0;
  int field_2A4;
} stdVideoDevice;

typedef struct render_8bpp
{
  int bpp;
  int rBpp;
  int width;
  int height;
  int rShift;
  int gShift;
  int bShift;
  int palBytes;
} render_8bpp;

typedef struct render_rgb
{
  int bpp;
  int rBpp;
  int gBpp;
  int bBpp;
  int rShift;
  int gShift;
  int bShift;
  int rBytes;
  int gBytes;
  int bBytes;
} render_rgb;

typedef struct render_pair
{
  render_8bpp render_8bpp;
  render_rgb render_rgb;
  uint32_t field_48;
  uint32_t field_4C;
  uint32_t field_50;
} render_pair;

typedef struct jkViewSize
{
  int xMin;
  int yMin;
  float xMax;
  float yMax;
} jkViewSize;

typedef struct videoModeStruct
{
  int modeIdx;
  int descIdx;
  int Video_8605C8;
  int field_C;
  int field_10;
  int field_14;
  int field_18;
  int field_1C;
  int field_20;
  int field_24;
  int field_28;
  HKEY b3DAccel;
  uint32_t viewSizeIdx;
  jkViewSize aViewSizes[11];
  int Video_8606A4;
  int Video_8606A8;
#ifndef JKM_TYPES
  int geoMode;
  int lightMode;
#else
  int lightMode;
  int geoMode;
#endif
  int texMode;
  HKEY Video_8606B8;
  HKEY Video_8606BC;
#ifdef JKM_TYPES
  int Video_motsNew1;
#endif
  int Video_8606C0;
} videoModeStruct;

typedef struct stdConsole
{
    uint32_t dword0;
    uint32_t dword4;
    uint32_t dword8;
    uint32_t dwordC;
    uint32_t dword10;
    uint32_t dword14;
    uint32_t dword18;
    char char1C;
    char gap1D;
    char field_1E;
    char field_1F;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint8_t byte6C;
    uint8_t byte6D;
    uint8_t byte6E;
    uint8_t byte6F;
    uint16_t word70;
    uint16_t word72;
    uint16_t word74;
    uint8_t byte76;
    uint8_t field_77;
    void* buffer;
    uint32_t field_7C;
    uint32_t bufferLen;
    uint32_t dword84;
    uint32_t dword88;
    uint32_t dword8C;
} stdConsole;

// sithCogVM

typedef struct net_msg
{
    uint32_t timeMs;
    uint32_t flag_maybe;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t timeMs2;
    uint32_t field_14;
    uint32_t field_18;
    uint32_t thingIdx;
    uint32_t msg_size;
    uint16_t cogMsgId;
    uint16_t msgId;
} net_msg;

typedef struct sithCogMsg_Pair
{
    uint32_t thingIdx;
    uint32_t msgId;
} sithCogMsg_Pair;

typedef struct sithCogMsg
{
    net_msg netMsg;
    uint32_t pktData[512];
} sithCogMsg;

typedef int (__cdecl *cogMsg_Handler)(sithCogMsg*);
typedef void (*cogSymbolFunc_t)(sithCog *);

typedef struct sithCogCallstack
{
    uint32_t pc;
    uint32_t script_running;
    uint32_t waketimeMs;
    uint32_t trigId;
} sithCogCallstack;

typedef struct sithCogStackvar
{
    uint32_t type;
    union
    {
        cog_int_t data[3];
        cog_flex_t dataAsFloat[3];
        intptr_t dataAsPtrs[3];
        char* dataAsName;
        cogSymbolFunc_t dataAsFunc;
    };
} sithCogStackvar;

typedef struct sithCog
{
    sithCogScript* cogscript;
    sithCogFlags_t flags;
    int selfCog;
    uint32_t script_running;
    uint32_t execPos;
    uint32_t wakeTimeMs;
    uint32_t pulsePeriodMs;
    uint32_t nextPulseMs;
    uint32_t field_20;
    uint32_t senderId;
    uint32_t senderRef;
    uint32_t senderType;
    uint32_t sourceRef;
    uint32_t sourceType;
    uint32_t trigId;
    float params[4];
    float returnEx;
    sithCogCallstack callstack[4];
    uint32_t calldepth;
    sithCogSymboltable* pSymbolTable;
    sithCogStackvar stack[SITHCOGVM_MAX_STACKSIZE];
    uint32_t stackPos;
    char cogscript_fpath[32];
    char field_4BC[4096];
    sithCogStackvar* heap;
    int numHeapVars;
} sithCog;

// end sithCogVm

typedef struct sithCogSectorLink
{
    sithSector* sector;
    sithCog* cog;
    int linkid;
    int mask;
} sithCogSectorLink;

typedef struct sithCogThingLink
{
    sithThing* thing;
    int signature;
    sithCog* cog;
    int linkid;
    int mask;
} sithCogThingLink;

typedef struct sithCogSurfaceLink
{
    sithSurface* surface;
    sithCog* cog;
    int linkid;
    int mask;
} sithCogSurfaceLink;

// jkEpisode
typedef int jkEpisodeTypeFlags_t;

typedef struct jkEpisode
{
    char name[32];
    wchar_t unistr[32];
    int field_60;
    int field_64;
    int field_68;
    int field_6C;
    int field_70;
    int field_74;
    int field_78;
    int field_7C;
    int field_80;
    int field_84;
    int field_88;
    int field_8C;
    int field_90;
    int field_94;
    int field_98;
    int field_9C;
    jkEpisodeTypeFlags_t type;
} jkEpisode;

typedef struct jkEpisodeEntry
{
    int lineNum;
    int cdNum;
    int level;
    int type;
    char fileName[32];
    int lightpow;
    int darkpow;
    int gotoA;
    int gotoB;
} jkEpisodeEntry;

enum jkEpisodeLoadType
{
    JK_EPISODE_SINGLEPLAYER = 1,
    JK_EPISODE_DEATHMATCH = 2,
    JK_EPISODE_4_UNK = 4,
    JK_EPISODE_SPECIAL_CTF = 8,
    JK_EPISODE_ALL = 0xFFFF
};

typedef struct jkEpisodeLoad
{
    jkEpisodeTypeFlags_t type;
    int numSeq;
    int field_8;
    jkEpisodeEntry* paEntries;
} jkEpisodeLoad;
//end jkEpisode

// jkRes
typedef struct HostServicesBasic
{
    float some_float;
    int (*messagePrint)(const char *, ...);
    int (*statusPrint)(const char *, ...);
    int (*warningPrint)(const char *, ...);
    int (*errorPrint)(const char *, ...);
    int (*debugPrint)(const char *, ...);
    void (*assert)(const char *, const char *, int);
    int unk_0;
    void *(*alloc)(unsigned int);
    void (*free)(void *);
    void *(*realloc)(void *, unsigned int);
    uint32_t (*getTimerTick)();
    stdFile_t (*fileOpen)(const char *, const char *);
    int (*fileClose)(stdFile_t);
    size_t (*fileRead)(stdFile_t, void *, size_t);
    char *(*fileGets)(stdFile_t, char *, size_t);
    size_t (*fileWrite)(stdFile_t, void *, size_t);
    int (*feof)(stdFile_t);
    int (*ftell)(stdFile_t);
    int (*fseek)(stdFile_t, int, int);
    int (*fileSize)(stdFile_t);
    int (*filePrintf)(stdFile_t, const char*, ...);
    wchar_t* (*fileGetws)(stdFile_t, wchar_t *, size_t);
} HostServicesBasic;

typedef struct HostServices
{
    uint32_t some_float;
    int (*messagePrint)(const char *, ...);
    int (*statusPrint)(const char *, ...);
    int (*warningPrint)(const char *, ...);
    int (*errorPrint)(const char *, ...);
    int (*debugPrint)(const char *, ...);
    void (*assert)(const char *, const char *, int);
    uint32_t unk_0;
    void *(*alloc)(unsigned int);
    void (*free)(void *);
    void *(*realloc)(void *, unsigned int);
    uint32_t (*getTimerTick)();
    stdFile_t (*fileOpen)(const char *, const char *);
    int (*fileClose)(stdFile_t);
    size_t (*fileRead)(stdFile_t, void *, size_t);
    char *(*fileGets)(stdFile_t, char *, size_t);
    size_t (*fileWrite)(stdFile_t, void *, size_t);
    int (*feof)(stdFile_t);
    int (*ftell)(stdFile_t);
    int (*fseek)(stdFile_t, int, int);
    int (*fileSize)(stdFile_t);
    int (*filePrintf)(stdFile_t, const char*, ...);
    wchar_t* (*fileGetws)(stdFile_t, wchar_t *, size_t);
    void* (*allocHandle)(size_t);
    void (*freeHandle)(void*);
    void* (*reallocHandle)(void*, size_t);
    uint32_t (*lockHandle)(uint32_t);
    void (*unlockHandle)(uint32_t);
} HostServices;

typedef struct jkResGob
{
  char name[128];
  int numGobs;
  stdGob *gobs[64];
} jkResGob;

typedef struct jkRes
{
    jkResGob gobs[5];
} jkRes;

typedef struct jkResFile
{
  int bOpened;
  char fpath[128];
  int useLowLevel;
  stdFile_t fsHandle;
  stdGobFile *gobHandle;
} jkResFile;

// end jkRes

#ifdef JKM_LIGHTING
typedef struct sithArchLightMesh
{
    float* aMono;
    float* aRed;
    float* aGreen;
    float* aBlue;
    int numVertices;
} sithArchLightMesh;

typedef struct sithArchLight
{
    int numMeshes;
    sithArchLightMesh* aMeshes;
} sithArchLight;
#endif

typedef void (__cdecl *sithWorldProgressCallback_t)(float);

typedef struct sithWorld
{
    uint32_t level_type_maybe;
    char map_jkl_fname[32];
    char episodeName[32];
    int numColormaps;
    rdColormap* colormaps;
    int numSectors;
    sithSector* sectors;
    int numMaterialsLoaded;
    int numMaterials;
    rdMaterial* materials;
    rdVector2* materials2;
    uint32_t numModelsLoaded;
    uint32_t numModels;
    rdModel3* models;
    int numSpritesLoaded;
    int numSprites;
    rdSprite* sprites;
    int numParticlesLoaded;
    int numParticles;
    rdParticle* particles;
    int numVertices;
    rdVector3* vertices;
    rdVector3* verticesTransformed;
    int* alloc_unk98;
    float* verticesDynamicLight;
    int* alloc_unk9c;
    int numVertexUVs;
    rdVector2* vertexUVs;
    int numSurfaces;
    sithSurface* surfaces;
    int numAdjoinsLoaded;
    int numAdjoins;
    sithAdjoin* adjoins;
    int numThingsLoaded;
    int numThings;
    sithThing* things;
    int numTemplatesLoaded;
    int numTemplates;
    sithThing* templates;
    float worldGravity;
    uint32_t field_D8;
    float ceilingSky;
    float horizontalDistance;
    float horizontalPixelsPerRev;
    rdVector2 horizontalSkyOffs;
    rdVector2 ceilingSkyOffs;
    rdVector4 mipmapDistance;
    rdVector4 lodDistance;
    float perspectiveDistance;
    float gouradDistance;
    sithThing* cameraFocus;
    sithThing* playerThing;
    uint32_t field_128;
    int numSoundsLoaded;
    int numSounds;
    sithSound* sounds;
    int numSoundClassesLoaded;
    int numSoundClasses;
    sithSoundClass* soundclasses;
    int numCogScriptsLoaded;
    int numCogScripts;
    sithCogScript* cogScripts;
    int numCogsLoaded;
    int numCogs;
    sithCog* cogs;
    int numAIClassesLoaded;
    int numAIClasses;
    sithAIClass* aiclasses;
    int numKeyframesLoaded;
    int numKeyframes;
    rdKeyframe* keyframes;
    int numAnimClassesLoaded;
    int numAnimClasses;
    sithAnimclass* animclasses;
#ifdef JKM_LIGHTING
    int numArchLights;
    //int sizeArchLights;
    sithArchLight* aArchlights;
#endif
} sithWorld;

typedef int (*sithWorldSectionParser_t)(sithWorld*, int);

typedef struct sithWorldParser
{
    char section_name[32];
    sithWorldSectionParser_t funcptr;
} sithWorldParser;


typedef struct sithItemDescriptor
{
    uint32_t flags;
    char fpath[128];
    float ammoMin;
    float ammoMax;
    sithCog* cog;
    uint32_t field_90;
    uint32_t field_94;
    stdBitmap* hudBitmap;
} sithItemDescriptor;

typedef struct sithItemInfo
{
    float ammoAmt;
    int field_4;
    int state;
    float activatedTimeSecs;
    float activationDelaySecs;
    float binWait;
} sithItemInfo;

typedef struct sithKeybind {
    int enabled;
    int binding;
    int idk;
} sithKeybind;

typedef struct sithMap
{
  int numArr;
  float* unkArr;
  int* anonymous_1;
  int playerColor;
  int actorColor;
  int itemColor;
  int weaponColor;
  int otherColor;
  int teamColors[5];
} sithMap;

typedef struct rdPolyLine 
{
    char fname[32];
    float length;
    float baseRadius;
    float tipRadius;
    rdGeoMode_t geometryMode;
    rdLightMode_t lightingMode;
    rdTexMode_t textureMode;
    rdFace edgeFace;
    rdFace tipFace;
    rdVector2* extraUVTipMaybe;
    rdVector2* extraUVFaceMaybe;
}
rdPolyLine;

typedef struct rdThing
{
    int type;
    union
    {
        rdModel3* model3;
        rdCamera* camera;
        rdLight* light;
        rdSprite* sprite3;
        rdParticle* particlecloud;
        rdPolyLine* polyline;
#ifdef GHIDRA_IMPORT
    } containedObj;
#else
    };
#endif
    rdGeoMode_t desiredGeoMode;
    rdLightMode_t desiredLightMode;
    rdTexMode_t desiredTexMode;
    rdPuppet* puppet;
    uint32_t field_18;
    uint32_t frameTrue;
    rdMatrix34 *hierarchyNodeMatrices;
    rdVector3* hierarchyNodes2;
    int* amputatedJoints;
    uint32_t wallCel;
    uint32_t geosetSelect;
    rdGeoMode_t curGeoMode;
    rdLightMode_t curLightMode;
    rdTexMode_t curTexMode;
    uint32_t clippingIdk;
    sithThing* parentSithThing;
} rdThing;

typedef struct rdPuppetTrack
{
    int status;
    int field_4;
    int lowPri;
    int highPri;
    float speed;
    float noise;
    float playSpeed;
    float fadeSpeed;
    uint32_t nodes[64];
    float field_120;
    float field_124;
    rdKeyframe *keyframe;
    rdPuppetTrackCallback_t callback;
    int field_130;
} rdPuppetTrack;

typedef struct rdPuppet
{
    uint32_t paused;
    rdThing *rdthing;
    rdPuppetTrack tracks[4];
} rdPuppet;

typedef struct sithPlayerInfo
{
    wchar_t player_name[32];
    wchar_t multi_name[32];
    uint32_t flags;
    uint32_t net_id;
    sithItemInfo iteminfo[200];
    int curItem;
    int curWeapon;
    int curPower;
    int field_1354;
    sithThing* playerThing;
    rdMatrix34 field_135C;
    sithSector* field_138C;
    uint32_t respawnMask;
    uint32_t palEffectsIdx1;
    uint32_t palEffectsIdx2;
    uint32_t teamNum;
    int32_t numKills;
    int32_t numKilled;
    int32_t numSuicides;
    int32_t score;
    int32_t lastUpdateMs;
} sithPlayerInfo;


typedef struct jkPlayerInfo
{
    uint32_t field_0;
    rdThing rd_thing;
    rdThing povModel;
    float length;
    uint32_t field_98;
    rdPolyLine polyline;
    rdThing polylineThing;
    int32_t field_1A4;
    float damage;
    float field_1AC;
    float field_1B0;
    uint32_t field_1B4;
    uint32_t numDamagedThings;
    sithThing* damagedThings[6];
    uint32_t numDamagedSurfaces;
    sithSurface* damagedSurfaces[6];
    uint32_t lastSparkSpawnMs;
#ifdef JKM_TYPES
    uint32_t jkmUnk1;
    uint8_t pad1[0x8];
    sithThing* actorThing;
    uint8_t pad1_2[0x54];
#endif // JKM_TYPES
    sithThing* wall_sparks;
    sithThing* blood_sparks;
    sithThing* saber_sparks;
#ifndef JKM_TYPES
    sithThing* actorThing;
#endif

#ifdef JKM_TYPES
    uint8_t pad2[0x8];
#endif // JKM_TYPES
    uint32_t maxTwinkles;
    uint32_t twinkleSpawnRate;
    uint32_t bRenderTwinkleParticle;
    uint32_t nextTwinkleRandMs;
    uint32_t nextTwinkleSpawnMs;
    uint32_t numTwinkles;
    uint32_t field_21C;
    int shields;
    uint32_t field_224;
#ifdef JKM_TYPES
    uint8_t pad3[0x10];
#endif // JKM_TYPES
} jkPlayerInfo;

typedef struct jkPlayerMpcInfo
{
  wchar_t name[32];
  char model[32];
  char soundClass[32];
  uint8_t gap80[32];
  char sideMat[32];
  char tipMat[32];
#ifdef JKM_TYPES
  int unk1;
#endif
  int jediRank;
#ifdef JKM_TYPES
  int personality;
  int unk2;
#endif
} jkPlayerMpcInfo;

typedef int (*sithCollision_collisionHandler_t)(sithThing*, sithThing*, sithCollisionSearchEntry*, int);
typedef int (*sithCollision_searchHandler_t)(sithThing*, sithThing*);

typedef struct sithCollisionEntry
{
    sithCollision_collisionHandler_t handler;
    sithCollision_searchHandler_t search_handler;
    uint32_t inverse;
} sithCollisionEntry;

typedef struct sithCollisionSearchEntry
{
    uint32_t hitType;
    sithThing* receiver;
    sithSurface* surface;
    rdFace* face;
    rdMesh* sender;
    rdVector3 hitNorm;
    float distance;
    uint32_t hasBeenEnumerated;
} sithCollisionSearchEntry;

typedef struct sithCollisionSectorEntry
{
    sithSector* sectors[64];
} sithCollisionSectorEntry;

typedef struct sithCollisionSearchResult
{
    sithCollisionSearchEntry collisions[128];
} sithCollisionSearchResult;


typedef struct sithSector
{
    uint32_t id;
    float ambientLight;
    float extraLight;
    rdColormap* colormap;
    rdVector3 tint;
    uint32_t numVertices;
    int* verticeIdxs;
    uint32_t numSurfaces;
    sithSurface* surfaces;
    sithAdjoin* adjoins;
    sithThing* thingsList;
    uint32_t flags;
    rdVector3 center;
    rdVector3 thrust;
    sithSound* sectorSound;
    float sectorSoundVol;
    rdVector3 collidebox_onecorner;
    rdVector3 collidebox_othercorner;
    rdVector3 boundingbox_onecorner;
    rdVector3 boundingbox_othercorner;
    float radius;
    uint32_t field_8C;
    uint32_t field_90;
    rdClipFrustum* clipFrustum;
} sithSector;

typedef struct sithSectorEntry
{
    sithSector *sector;
    sithThing *thing;
    rdVector3 pos;
    int field_14;
    float field_18;
} sithSectorEntry;

typedef struct sithSectorAlloc
{
    int field_0;
    float field_4[3];
    rdVector3 field_10[3];
    rdVector3 field_34[3];
    sithThing* field_58[3];
} sithSectorAlloc;

// sithThing start

typedef struct sithActorInstinct
{
    int field_0;
    int nextUpdate;
    float param0;
    float param1;
    float param2;
    float param3;
} sithActorInstinct;

typedef struct sithActor
{
    sithThing *thing;
    sithAIClass *aiclass;
    int flags;
    sithActorInstinct instincts[16];
    uint32_t numAIClassEntries;
    int nextUpdate;
    rdVector3 lookVector;
    rdVector3 movePos;
    rdVector3 field_1AC;
    float field_1B8;
    float moveSpeed;
    sithThing* field_1C0;
    rdVector3 field_1C4;
#ifdef JKM_TYPES
    int unk1;
#endif
    sithThing* field_1D0;
    rdVector3 field_1D4;
    int field_1E0;
    rdVector3 field_1E4;
    float field_1F0;
    int field_1F4;
    rdVector3 field_1F8;
    int field_204;
    rdVector3 blindAimError;
    sithThing *thingidk;
    rdVector3 movepos;
    int field_224;
    rdVector3 field_228;
    float field_234;
    int field_238;
    rdVector3 field_23C;
    int field_248;
    rdVector3 position;
    rdVector3 lookOrientation;
    float field_264;
    int field_268;
    int field_26C;
    int mood0;
    int mood1;
    int mood2;
    int field_27C;
    int field_280;
    int field_284;
    int field_288;
    int field_28C;
    rdVector3 *framesAlloc;
    int loadedFrames;
    int sizeFrames;
} sithActor;

typedef struct sithThingParticleParams
{
    uint32_t typeFlags;
    uint32_t count;
    rdMaterial* material;
    float elementSize;
    float growthSpeed;
    float minSize;
    float range;
    float pitchRange;
    float yawRange;
    float rate;
    float field_28;
    float field_2C;
    uint32_t field_30;
    uint32_t field_34;
    rdVector3 field_38;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
} sithThingParticleParams;

typedef struct sithThingExplosionParams
{
    uint32_t typeflags;
    uint32_t lifeLeftMs;
    float range;
    float force;
    uint32_t blastTime;
    float maxLight;
    uint32_t field_18;
    float damage;
    uint32_t damageClass;
    int flashR;
    int flashG;
    int flashB;
    sithThing* debrisTemplates[4];
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
    uint32_t field_80;
} sithThingExplosionParams;

typedef struct sithBackpackItem
{
    int16_t binIdx;
    int16_t field_2;
    float value;
} sithBackpackItem;

typedef struct sithThingItemParams
{
    uint32_t typeflags;
    rdVector3 position;
    sithSector* sector;
    uint32_t respawn;
    uint32_t respawnTime;
    int16_t numBins;
    int16_t field_1E;
    sithBackpackItem contents[12];
    uint32_t field_80;
} sithThingItemParams;

typedef struct sithThingWeaponParams
{
    sithWeaponFlags_t typeflags;
    uint32_t damageClass;
    float unk8;
    float damage;
    sithThing* explodeTemplate;
    sithThing* fleshHitTemplate;
    uint32_t numDeflectionBounces;
    float rate;
    float mindDamage;
    sithThing* trailThing;
    float elementSize;
    float trailCylRadius;
    float trainRandAngle;
    uint32_t field_34;
    float range;
    float force;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
    uint32_t field_80;
    uint32_t field_84;
    uint32_t field_88;
    uint32_t field_8C;
} sithThingWeaponParams;

typedef struct sithThingActorParams
{
    uint32_t typeflags;
    float health;
    float maxHealth;
    uint32_t msUnderwater;
    float jumpSpeed;
    float extraSpeed;
    float maxThrust;
    float maxRotThrust;
    sithThing* templateWeapon;
    sithThing* templateWeapon2;
    sithThing* templateExplode;
    rdVector3 eyePYR;
    rdVector3 eyeOffset;
    float minHeadPitch;
    float maxHeadPitch;
    rdVector3 fireOffset;
    rdVector3 lightOffset;
    float lightIntensity;
    rdVector3 saberBladePos;
    float timeLeftLengthChange;
    uint32_t field_1A8;
    uint32_t field_1AC;
    float chance;
    float fov;
    float error;
    uint32_t field_1BC;
    sithPlayerInfo *playerinfo;
    uint32_t field_1C4;
    uint32_t field_1C8;
    uint32_t field_1CC;
#ifdef JKM_TYPES
    uint32_t unk_1D0;
#endif
} sithThingActorParams;

typedef struct sithThingPhysParams
{
    uint32_t physflags;
#ifdef JKM_TYPES
    //uint32_t unk_4;
#endif
    rdVector3 vel;
    rdVector3 angVel;
    rdVector3 acceleration;
    rdVector3 field_1F8;
    float mass;
    float height;
    float airDrag;
    float surfaceDrag;
    float staticDrag;
    float maxRotVel;
    float maxVel;
    float orientSpeed;
    float buoyancy;
    rdVector3 addedVelocity;
    rdVector3 velocityMaybe;
    float physicsRolloverFrames;
    float field_74;
    float field_78;
} sithThingPhysParams;

typedef struct sithThingFrame
{
    rdVector3 pos;
    rdVector3 rot;
} sithThingFrame;

typedef struct sithThingTrackParams
{
    uint32_t sizeFrames;
    uint32_t loadedFrames;
    sithThingFrame *aFrames;
    uint32_t field_C;
    rdVector3 vel;
    float field_1C;
    float field_20;
    rdMatrix34 field_24;
    float field_54;
    rdVector3 field_58;
    rdVector3 field_64;
    rdVector3 orientation;
} sithThingTrackParams;

typedef struct sithThing
{
    uint32_t thingflags;
    uint32_t thingIdx;
    uint32_t thing_id;
#ifdef JKM_TYPES
    uint32_t unk;
#endif // JKM_TYPES
    uint32_t type;
    uint32_t moveType;
    uint32_t thingtype;
    int lifeLeftMs;
    uint32_t timer;
    uint32_t pulse_end_ms;
    uint32_t pulse_ms;
    uint32_t collide;
    float moveSize;
    float collideSize;
#ifdef JKM_TYPES
    uint32_t unk2;
#endif // JKM_TYPES
    uint32_t attach_flags;
    rdVector3 field_38;
    sithSurfaceInfo* attachedSufaceInfo;
    float field_48;
    rdVector3 field_4C;
    union
    {
        sithThing* attachedThing;
        sithSurface* attachedSurface;
#ifdef GHIDRA_IMPORT
    } attached;
#else
    };
#endif
    sithSector* sector;
    sithThing* nextThing;
    sithThing* prevThing;
    sithThing* attachedParentMaybe;
    sithThing* childThing;
    sithThing* parentThing;
    uint32_t signature;
    sithThing* templateBase;
    sithThing* pTemplate;
    sithThing* prev_thing;
    uint32_t child_signature;
    rdMatrix34 lookOrientation;
    rdVector3 position;
    rdThing rdthing;
    rdVector3 screenPos;
    float light;
    float lightMin;
    int isVisible;
    sithSoundClass* soundclass;
    sithAnimclass* animclass;
    sithPuppet* puppet;
    union
    {
        sithThingActorParams actorParams;
        sithThingWeaponParams weaponParams;
        sithThingItemParams itemParams;
        sithThingExplosionParams explosionParams;
        sithThingParticleParams particleParams;
#ifdef GHIDRA_IMPORT
    } typeParams;
#else
    };
#endif
    union
    {
        sithThingPhysParams physicsParams;
        sithThingTrackParams trackParams;
#ifdef GHIDRA_IMPORT
    } physParams;
#else
    };
#endif
    float field_24C;
    uint32_t field_250;
    int curframe;
    uint32_t field_258;
    int goalframe;
    uint32_t field_260;
    float waggle;
    rdVector3 field_268;
    sithAIClass* aiclass;
    sithActor* actor;
    char template_name[32];
    sithCog* class_cog;
    sithCog* capture_cog;
    jkPlayerInfo* playerInfo;
    uint32_t jkFlags;
    float userdata;
#ifdef JKM_TYPES
    int idk1;
#endif

#ifdef JKM_LIGHTING
    int archlightIdx;
#endif
} sithThing;

typedef int (__cdecl *sithThing_handler_t)(sithThing*);
// end sithThing

typedef struct jkGuiSaveLoad_Entry
{
  sithGamesave_Header saveHeader;
  char fpath[128];
} jkGuiSaveLoad_Entry;

typedef struct Darray
{
  void *alloc;
  uint32_t entrySize;
  uint32_t size;
  int32_t total;
  int dword10;
  int bInitialized;
} Darray;

typedef void (*jkGuiDrawFunc_t)(jkGuiElement*, jkGuiMenu*, stdVBuffer*, int);
typedef int (*jkGuiButtonDownFunc_t)(jkGuiElement*, jkGuiMenu*, int, int);
typedef int (*jkGuiButtonUpFunc_t)(jkGuiElement*, jkGuiMenu*, int, int, int);

typedef struct jkGuiElementHandlers
{
  jkGuiButtonDownFunc_t buttonDown;
  jkGuiDrawFunc_t draw;
  jkGuiButtonUpFunc_t buttonUp;
} jkGuiElementHandlers;

typedef struct jkGuiTexInfo
{
  int textHeight;
  int numTextEntries;
  int maxTextEntries;
  int textScrollY;
  int anonymous_18;
  rdRect rect;
} jkGuiTexInfo;

typedef struct jkGuiElement
{
    int type;
    int hoverId;
    int field_8;
    union
    {
      const char* str;
      jkGuiStringEntry *unistr;
      wchar_t* wstr;
      int extraInt;
    };
    union
    {
        int selectedTextEntry;
        int boxChecked;
        intptr_t otherDataPtr;
    };
    rdRect rect;
    int bIsVisible;
    int anonymous_9;
    union
    {
        const char* hintText;
        wchar_t* wHintText;
    };
    jkGuiDrawFunc_t drawFuncOverride;
    jkGuiButtonUpFunc_t func;
    void *anonymous_13;
    jkGuiTexInfo texInfo;
    int elementIdk;
} jkGuiElement;

typedef struct jkGuiStringEntry
{
    wchar_t *str;
    union
    {
        intptr_t id;
        jkGuiKeyboardEntry* pKeyboardEntry;
        char* c_str;
    };
} jkGuiStringEntry;

typedef struct jkGuiMenu
{
  jkGuiElement *clickables;
  int clickableIdxIdk;
  int anonymous_1;
  int fillColor;
  int anonymous_3;
  stdVBuffer *texture;
  uint8_t* palette;
  stdBitmap **ui_structs;
  stdFont** fonts;
  intptr_t anonymous_7;
  void (__cdecl *idkFunc)(jkGuiMenu *);
  char *soundHover;
  char *soundClick;
  jkGuiElement *focusedElement;
  jkGuiElement *lastMouseDownClickable;
  jkGuiElement *lastMouseOverClickable;
  int lastButtonUp;
  jkGuiElement* clickables_end;
  jkGuiElement* field_48;
} jkGuiMenu;

typedef struct stdPalEffect
{
    rdVector3i filter;
    rdVector3 tint;
    rdVector3i add;
    float fade;
} stdPalEffect;

typedef struct stdPalEffectsState
{
  int bEnabled;
  int field_4;
  int field_8;
  int field_C;
  int field_10;
  stdPalEffect effect;
  int field_3C;
  int field_40;
  int field_44;
  int field_48;
} stdPalEffectsState;

typedef struct stdPalEffectRequest
{
  int isValid;
  int idx;
  stdPalEffect effect;
} stdPalEffectRequest;

typedef struct stdConffileArg
{
    char* key;
    char* value;
} stdConffileArg;

typedef struct stdConffileEntry
{
    int numArgs;
#ifdef JKM_LIGHTING
    stdConffileArg args[256];
#else
    stdConffileArg args[128];
#endif
} stdConffileEntry;

typedef struct stdMemoryAlloc stdMemoryAlloc;

typedef struct stdMemoryAlloc
{
    uint32_t num;
    void* alloc;
    uint32_t size;
    char* filePath;
    uint32_t lineNum;
    stdMemoryAlloc* next;
    stdMemoryAlloc* prev;
    uint32_t magic;
} stdMemoryAlloc;

typedef struct stdMemoryInfo
{
    uint32_t allocCur;
    uint32_t nextNum;
    uint32_t allocMax;
    stdMemoryAlloc allocTop;
} stdMemoryInfo;

typedef struct sith_cog_parser_node sith_cog_parser_node;

typedef struct sith_cog_parser_node 
{
    int child_loop_depth;
    int parent_loop_depth;
    sith_cog_parser_node *parent;
    sith_cog_parser_node *child;
    int opcode;
    int value;
    rdVector3 vector;
} sith_cog_parser_node;

// jkHud

typedef struct jkHudBitmap
{
    stdBitmap **pBitmap;
    char *path8bpp;
    char *path16bpp;
} jkHudBitmap;

typedef struct jkHudFont
{
    stdFont **pFont;
    char *path8bpp;
    char *path16bpp;
#ifdef JKM_TYPES
    char *pathS8bpp;
    char *pathS16bpp;
#endif // JKM_TYPES
} jkHudFont;

typedef struct jkHudTeamScore
{
    int field_0;
    int score;
    int field_8;
    int field_C;
} jkHudTeamScore;

typedef struct jkHudPlayerScore
{
    wchar_t playerName[32];
    wchar_t modelName[32];
    int score;
    int teamNum;
} jkHudPlayerScore;

typedef struct rdScreenPoint
{
    uint32_t x;
    uint32_t y;
    float z;
} rdScreenPoint;

typedef struct jkHudInvInfo
{
  uint32_t field_0;
  int field_4;
  int field_8[2];
  int field_10[2];
  int field_18;
  int field_1C;
  int rend_timeout_5secs;
  int field_24;
  int field_28;
  rdRect drawRect;
  int field_3C;
} jkHudInvInfo;

typedef struct jkHudInvScroll
{
    uint32_t blitX;
    int scroll;
    int maxItemRend;
    int field_C;
    int field_10;
    int rendIdx;
} jkHudInvScroll;

typedef void* DPLCONNECTION;

typedef struct sith_dplay_connection
{
  wchar_t name[128];
  GUID guid;
  DPLCONNECTION *connection;
  int connectionSize;
} sith_dplay_connection;

#pragma pack(push, 4)
typedef struct jkMultiEntry
{
    GUID_idk guidInstance;
    int maxPlayers;
    int numPlayers;
    wchar_t serverName[32];
    char episodeGobName[32];
    char mapJklFname[32];
    wchar_t wPassword[32];
    int sessionFlags;
    int checksumSeed;
    int field_E0;
    int multiModeFlags;
    int tickRateMs;
    int maxRank;
} jkMultiEntry;
#pragma pack(pop)

typedef struct jkMultiEntry2
{
    wchar_t field_0[128];
    wchar_t field_100[128];
    char field_200[256];
    char field_300[256];
} jkMultiEntry2;

typedef struct jkMultiEntry3
{
    int field_0;
    wchar_t serverName[32];
    char episodeGobName[32];
    char mapJklFname[128];
    int maxPlayers;
    wchar_t wPassword[32];
    int sessionFlags;
    int multiModeFlags;
    int maxRank;
    int timeLimit;
    int scoreLimit;
    int tickRateMs;
} jkMultiEntry3;

typedef struct jkMultiEntry4
{
    char episodeGobName[32];
    char mapJklFname[32];
    int field_40;
    int field_44;
    int field_48;
    int field_4C;
    int field_50;
    int field_54;
    int field_58;
    int field_5C;
    int field_60;
    int field_64;
    int field_68;
    int field_6C;
    int field_70;
    int field_74;
    int field_78;
    int field_7C;
    int field_80;
    int field_84;
    int field_88;
    int field_8C;
    int field_90;
    int field_94;
    int field_98;
    int field_9C;
    wchar_t sessionName[32];
    int tickRateMs;
} jkMultiEntry4;

typedef struct stdControlKeyInfoEntry
{
    int dxKeyNum;
    uint32_t flags;
    float binaryAxisVal;
} stdControlKeyInfoEntry;

typedef struct stdControlKeyInfo
{
    uint32_t numEntries;
    stdControlKeyInfoEntry aEntries[8];
} stdControlKeyInfo;

typedef struct stdControlJoystickEntry
{
    int flags;
    int uMinVal;
    int uMaxVal;
    int dwXoffs;
    int dwYoffs;
    float fRangeConversion;
} stdControlJoystickEntry;

typedef struct stdControlStickEntry
{
    int dwXpos;
    int dwYpos;
    int dwZpos;
    int dwRpos;
    int dwUpos;
    int dwVpos;
} stdControlStickEntry;

typedef struct stdControlDikStrToNum
{
    int val;
    const char *pStr;
} stdControlDikStrToNum;

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
#define DIK_CIRCUMFLEX      0x90
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

#define JK_JOYSTICK_AXIS_STRIDE (6)
#define JK_NUM_JOYSTICKS        (2)
#define JK_NUM_MOUSE_AXES       (3)
#define JK_NUM_AXES             ((JK_JOYSTICK_AXIS_STRIDE * JK_NUM_JOYSTICKS) + JK_NUM_MOUSE_AXES)

#ifndef SDL2_RENDER
#define JK_NUM_MOUSE_BUTTONS     (4)
#define JK_NUM_EXT_MOUSE_BUTTONS (0)
#define JK_NUM_JOY_BUTTONS       (8)
#define JK_NUM_EXT_JOY_BUTTONS   (0)
#define JK_NUM_HAT_BUTTONS       (4)
#else
#define JK_NUM_MOUSE_BUTTONS     (4)
#define JK_NUM_EXT_MOUSE_BUTTONS (28)
#define JK_NUM_JOY_BUTTONS       (8)
#define JK_NUM_EXT_JOY_BUTTONS   (24)
#define JK_NUM_HAT_BUTTONS       (4)
#endif

#define JK_JOYSTICK_BUTTON_STRIDE       (JK_NUM_JOY_BUTTONS + JK_NUM_HAT_BUTTONS)
#define JK_JOYSTICK_EXT_BUTTON_STRIDE   (JK_NUM_EXT_JOY_BUTTONS)
#define JK_NUM_EXTENDED_KEYS ((JK_JOYSTICK_BUTTON_STRIDE * JK_NUM_JOYSTICKS) + JK_NUM_MOUSE_BUTTONS + JK_NUM_EXT_MOUSE_BUTTONS + (JK_JOYSTICK_EXT_BUTTON_STRIDE * JK_NUM_JOYSTICKS))

#define JK_NUM_KEYS_ORIG        (0x100 + JK_NUM_EXTENDED_KEYS) // original game had an off-by-one?
#define JK_NUM_KEYS             (0x100 + JK_NUM_EXTENDED_KEYS)

// JK specific keys
#define JK_EXTENDED_KEY_START   (0x100)
#define KEY_JOY1_B1             (JK_EXTENDED_KEY_START + 0)
#define KEY_JOY1_B2             (JK_EXTENDED_KEY_START + 1)
#define KEY_JOY1_B3             (JK_EXTENDED_KEY_START + 2)
#define KEY_JOY1_B4             (JK_EXTENDED_KEY_START + 3)
#define KEY_JOY1_B5             (JK_EXTENDED_KEY_START + 4)
#define KEY_JOY1_B6             (JK_EXTENDED_KEY_START + 5)
#define KEY_JOY1_B7             (JK_EXTENDED_KEY_START + 6)
#define KEY_JOY1_B8             (JK_EXTENDED_KEY_START + 7)
#define KEY_JOY1_HLEFT          (JK_EXTENDED_KEY_START + JK_NUM_JOY_BUTTONS + 0)
#define KEY_JOY1_HUP            (JK_EXTENDED_KEY_START + JK_NUM_JOY_BUTTONS + 1)
#define KEY_JOY1_HRIGHT         (JK_EXTENDED_KEY_START + JK_NUM_JOY_BUTTONS + 2)
#define KEY_JOY1_HDOWN          (JK_EXTENDED_KEY_START + JK_NUM_JOY_BUTTONS + 3)

#define KEY_JOY2_STARTIDX       (JK_EXTENDED_KEY_START + JK_JOYSTICK_BUTTON_STRIDE)
#define KEY_JOY2_B1             (KEY_JOY2_STARTIDX + 0)
#define KEY_JOY2_B2             (KEY_JOY2_STARTIDX + 1)
#define KEY_JOY2_B3             (KEY_JOY2_STARTIDX + 2)
#define KEY_JOY2_B4             (KEY_JOY2_STARTIDX + 3)
#define KEY_JOY2_B5             (KEY_JOY2_STARTIDX + 4)
#define KEY_JOY2_B6             (KEY_JOY2_STARTIDX + 5)
#define KEY_JOY2_B7             (KEY_JOY2_STARTIDX + 6)
#define KEY_JOY2_B8             (KEY_JOY2_STARTIDX + 7)
#define KEY_JOY2_HLEFT          (KEY_JOY2_STARTIDX + JK_NUM_JOY_BUTTONS + 0)
#define KEY_JOY2_HUP            (KEY_JOY2_STARTIDX + JK_NUM_JOY_BUTTONS + 1)
#define KEY_JOY2_HRIGHT         (KEY_JOY2_STARTIDX + JK_NUM_JOY_BUTTONS + 2)
#define KEY_JOY2_HDOWN          (KEY_JOY2_STARTIDX + JK_NUM_JOY_BUTTONS + 3)

#define KEY_MOUSE_STARTIDX      (JK_EXTENDED_KEY_START + (JK_JOYSTICK_BUTTON_STRIDE * 2))
#define KEY_MOUSE_B1            (KEY_MOUSE_STARTIDX + 0)
#define KEY_MOUSE_B2            (KEY_MOUSE_STARTIDX + 1)
#define KEY_MOUSE_B3            (KEY_MOUSE_STARTIDX + 2)
#define KEY_MOUSE_B4            (KEY_MOUSE_STARTIDX + 3)
#define JK_ORIG_EXT_END         (KEY_MOUSE_B4 + 1)

#define KEY_MOUSE_B5            (JK_ORIG_EXT_END + 0)
#define KEY_MOUSE_B6            (JK_ORIG_EXT_END + 1)
#define KEY_MOUSE_B7            (JK_ORIG_EXT_END + 2)
#define KEY_MOUSE_B8            (JK_ORIG_EXT_END + 3)

#define JK_EXT_MOUSE_END        (KEY_MOUSE_B5 + JK_NUM_EXT_MOUSE_BUTTONS)

#define KEY_IS_MOUSE(x) ((x >= KEY_MOUSE_B1 && x <= KEY_MOUSE_B4) || (x >= KEY_MOUSE_B5 && x < JK_EXT_MOUSE_END))
#define KEY_IS_JOY_BUTTON(x) ((x >= KEY_JOY1_B1 && x < KEY_MOUSE_STARTIDX) || (x >= (KEY_JOY1_B9 - 1) && x < KEY_JOY2_EXT_ENDIDX))
#define KEY_IS_BUTTON(x) (KEY_IS_JOY_BUTTON(x) || x < JK_EXTENDED_KEY_START)

// QOL added:
#define KEY_JOY1_EXT_STARTIDX   (JK_EXT_MOUSE_END)
#define KEY_JOY1_B9             (KEY_JOY1_EXT_STARTIDX + 0)
#define KEY_JOY1_B10            (KEY_JOY1_EXT_STARTIDX + 1)
#define KEY_JOY1_B11            (KEY_JOY1_EXT_STARTIDX + 2)
#define KEY_JOY1_B12            (KEY_JOY1_EXT_STARTIDX + 3)
#define KEY_JOY1_B13            (KEY_JOY1_EXT_STARTIDX + 4)
#define KEY_JOY1_B14            (KEY_JOY1_EXT_STARTIDX + 5)
#define KEY_JOY1_B15            (KEY_JOY1_EXT_STARTIDX + 6)
#define KEY_JOY1_B16            (KEY_JOY1_EXT_STARTIDX + 7)
#define KEY_JOY1_B17            (KEY_JOY1_EXT_STARTIDX + 8)
#define KEY_JOY1_B18            (KEY_JOY1_EXT_STARTIDX + 9)
#define KEY_JOY1_B19            (KEY_JOY1_EXT_STARTIDX + 10)
#define KEY_JOY1_B20            (KEY_JOY1_EXT_STARTIDX + 11)
#define KEY_JOY1_B21            (KEY_JOY1_EXT_STARTIDX + 12)
#define KEY_JOY1_B22            (KEY_JOY1_EXT_STARTIDX + 13)
#define KEY_JOY1_B23            (KEY_JOY1_EXT_STARTIDX + 14)
#define KEY_JOY1_B24            (KEY_JOY1_EXT_STARTIDX + 15)
#define KEY_JOY1_B25            (KEY_JOY1_EXT_STARTIDX + 16)
#define KEY_JOY1_B26            (KEY_JOY1_EXT_STARTIDX + 17)
#define KEY_JOY1_B27            (KEY_JOY1_EXT_STARTIDX + 18)
#define KEY_JOY1_B28            (KEY_JOY1_EXT_STARTIDX + 19)
#define KEY_JOY1_B29            (KEY_JOY1_EXT_STARTIDX + 20)
#define KEY_JOY1_B30            (KEY_JOY1_EXT_STARTIDX + 21)
#define KEY_JOY1_B31            (KEY_JOY1_EXT_STARTIDX + 22)
#define KEY_JOY1_B32            (KEY_JOY1_EXT_STARTIDX + 23)

#define KEY_JOY2_EXT_STARTIDX   (JK_EXT_MOUSE_END + JK_JOYSTICK_EXT_BUTTON_STRIDE)
#define KEY_JOY2_B9             (KEY_JOY2_EXT_STARTIDX + 0)
#define KEY_JOY2_B10            (KEY_JOY2_EXT_STARTIDX + 1)
#define KEY_JOY2_B11            (KEY_JOY2_EXT_STARTIDX + 2)
#define KEY_JOY2_B12            (KEY_JOY2_EXT_STARTIDX + 3)
#define KEY_JOY2_B13            (KEY_JOY2_EXT_STARTIDX + 4)
#define KEY_JOY2_B14            (KEY_JOY2_EXT_STARTIDX + 5)
#define KEY_JOY2_B15            (KEY_JOY2_EXT_STARTIDX + 6)
#define KEY_JOY2_B16            (KEY_JOY2_EXT_STARTIDX + 7)
#define KEY_JOY2_B17            (KEY_JOY2_EXT_STARTIDX + 8)
#define KEY_JOY2_B18            (KEY_JOY2_EXT_STARTIDX + 9)
#define KEY_JOY2_B19            (KEY_JOY2_EXT_STARTIDX + 10)
#define KEY_JOY2_B20            (KEY_JOY2_EXT_STARTIDX + 11)
#define KEY_JOY2_B21            (KEY_JOY2_EXT_STARTIDX + 12)
#define KEY_JOY2_B22            (KEY_JOY2_EXT_STARTIDX + 13)
#define KEY_JOY2_B23            (KEY_JOY2_EXT_STARTIDX + 14)
#define KEY_JOY2_B24            (KEY_JOY2_EXT_STARTIDX + 15)
#define KEY_JOY2_B25            (KEY_JOY2_EXT_STARTIDX + 16)
#define KEY_JOY2_B26            (KEY_JOY2_EXT_STARTIDX + 17)
#define KEY_JOY2_B27            (KEY_JOY2_EXT_STARTIDX + 18)
#define KEY_JOY2_B28            (KEY_JOY2_EXT_STARTIDX + 19)
#define KEY_JOY2_B29            (KEY_JOY2_EXT_STARTIDX + 20)
#define KEY_JOY2_B30            (KEY_JOY2_EXT_STARTIDX + 21)
#define KEY_JOY2_B31            (KEY_JOY2_EXT_STARTIDX + 22)
#define KEY_JOY2_B32            (KEY_JOY2_EXT_STARTIDX + 23)
#define KEY_JOY2_EXT_ENDIDX     (KEY_JOY2_EXT_STARTIDX + JK_JOYSTICK_EXT_BUTTON_STRIDE)

// Axis idxs
#define AXIS_JOY1_X          (0)
#define AXIS_JOY1_Y          (1)
#define AXIS_JOY1_Z          (2)
#define AXIS_JOY1_R          (3)
#define AXIS_JOY1_U          (4)
#define AXIS_JOY1_V          (5)

#define AXIS_JOY2_X          (JK_JOYSTICK_AXIS_STRIDE + 0) // 6
#define AXIS_JOY2_Y          (JK_JOYSTICK_AXIS_STRIDE + 1) // 7
#define AXIS_JOY2_Z          (JK_JOYSTICK_AXIS_STRIDE + 2) // 8
#define AXIS_JOY2_R          (JK_JOYSTICK_AXIS_STRIDE + 3) // 9
#define AXIS_JOY2_U          (JK_JOYSTICK_AXIS_STRIDE + 4) // a 10
#define AXIS_JOY2_V          (JK_JOYSTICK_AXIS_STRIDE + 5) // b 11

#define AXIS_MOUSE_X         ((JK_JOYSTICK_AXIS_STRIDE * 2) + 0) // c 12
#define AXIS_MOUSE_Y         ((JK_JOYSTICK_AXIS_STRIDE * 2) + 1) // d 13
#define AXIS_MOUSE_Z         ((JK_JOYSTICK_AXIS_STRIDE * 2) + 2) // e 14

typedef struct jkGuiMouseSubEntry
{
    int field_0;
    int bitflag;
    float field_8;
} jkGuiMouseSubEntry;

typedef struct jkGuiMouseEntry
{
    int dxKeyNum;
    const char *displayStrKey;
    int inputFuncIdx;
    int flags;
    jkGuiMouseSubEntry *pSubEnt;
    int bindIdx;
    int mouseEntryIdx;
} jkGuiMouseEntry;

typedef struct jkGuiKeyboardEntry
{
    int inputFuncIdx;
    int axisIdx;
    int dxKeyNum;
    int field_C;
    int field_10;
    int field_14;
} jkGuiKeyboardEntry;

typedef struct jkSaberInfo
{
    char BM[0x20];
    char sideMat[0x20];
    char tipMat[0x20];
} jkSaberInfo;

typedef struct jkMultiModelInfo
{
    char modelFpath[0x20];
    char sndFpath[0x20];
} jkMultiModelInfo;

typedef struct sithDplayPlayer
{
    wchar_t waName[32];
    int field_40;
    int field_44;
    int field_48;
    int field_4C;
    int field_50;
    int field_54;
    int field_58;
    int field_5C;
    int field_60;
    int16_t field_64;
    int16_t field_66;
    int field_68;
    int field_6C;
    int field_70;
    int field_74;
    int field_78;
    int field_7C;
    int field_80;
    int field_84;
    int field_88;
    int field_8C;
    int dpId;
} sithDplayPlayer;

typedef wchar_t* LPWSTR;

typedef struct DPNAME
{
  DWORD dwSize;
  DWORD dwFlags;
  union
  {
    LPWSTR lpszShortName;
    LPSTR lpszShortNameA;
  };
  union
  {
    LPWSTR lpszLongName;
    LPSTR lpszLongNameA;
  };
} DPNAME;

typedef uint32_t DPID;
typedef uint32_t *LPDPID;
typedef const DPNAME *LPCDPNAME;

#define DPSYS_ADDPLAYER               0x0003  // DPMSG_ADDPLAYER
#define DPSYS_DELETEPLAYER            0x0005  // DPMSG_DELETEPLAYER
#define DPSYS_ADDPLAYERTOGROUP        0x0007  // DPMSG_GROUPADD
#define DPSYS_INVITE                  0x000e  // DPMSG_INVITE, Net only.
#define DPSYS_DELETEGROUP             0x0020  // DPMSG_DELETEPLAYER
#define DPSYS_DELETEPLAYERFROMGRP     0x0021  // DPMSG_GROUPDELETE
#define DPSYS_SESSIONLOST             0x0031
#define DPSYS_CONNECT                 0x484b  // DPMSG_GENERIC

#define DPID_SYSMSG         0
#define DPID_ALLPLAYERS     0
#define DPID_SERVERPLAYER   1
#define DPID_UNKNOWN        0xFFFFFFFF

#ifndef __cplusplus
typedef wchar_t char16_t;
#endif

typedef struct jkGuiControlInfoHeader
{
    uint32_t version;
    wchar_t wstr[64];
} jkGuiControlInfoHeader;

typedef struct jkGuiControlInfo
{
    jkGuiControlInfoHeader header;
    char fpath[128];
} jkGuiControlInfo;

#ifdef SDL2_RENDER
#define JOYSTICK_MAX_STRS (6)
#else
#define JOYSTICK_MAX_STRS (3)
#endif

typedef struct jkGuiJoystickStrings
{
    wchar_t aStrings[JOYSTICK_MAX_STRS][128];
} jkGuiJoystickStrings;

typedef struct jkGuiJoystickEntry
{
  int dikNum;
  const char *displayStrKey;
  int keybits;
  int inputFunc;
  uint32_t flags;
  stdControlKeyInfoEntry *pControlEntry;
  int dxKeyNum;
  union {
    int binaryAxisValInt;
    float binaryAxisVal;
  };
} jkGuiJoystickEntry;

#ifdef GHIDRA_IMPORT
#include "Win95/stdGob.h"
#include "Engine/rdKeyframe.h"
#include "Engine/sithAdjoin.h"
#include "Engine/rdCanvas.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithAnimClass.h"
#include "General/stdHashTable.h"
#include "General/stdStrTable.h"
#include "General/stdFont.h"
#include "General/stdFileUtil.h"
#include "General/stdPcx.h"
#include "Cog/sithCog.h"
#include "Cog/sithCogScript.h"
#include "Dss/sithMulti.h"

#include "Cog/sithCog.h"
#include "Cog/sithCogExec.h"
#include "Cog/jkCog.h"
#include "Cog/sithCogFunction.h"
#include "Cog/sithCogFunctionThing.h"
#include "Cog/sithCogFunctionPlayer.h"
#include "Cog/sithCogFunctionAI.h"
#include "Cog/sithCogFunctionSurface.h"
#include "Cog/sithCogFunctionSector.h"
#include "Cog/sithCogFunctionSound.h"
#include "General/stdBitmap.h"
#include "General/stdMath.h"
#include "General/stdJSON.h"
#include "Primitives/rdVector.h"
#include "General/stdMemory.h"
#include "General/stdColor.h"
#include "General/stdConffile.h"
#include "General/stdFont.h"
#include "General/stdFnames.h"
#include "General/stdFileUtil.h"
#include "General/stdHashTable.h"
#include "General/stdString.h"
#include "General/stdStrTable.h"
#include "General/sithStrTable.h"
#include "General/stdPcx.h"
#include "General/Darray.h"
#include "General/stdPalEffects.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIMain.h"
#include "Gui/jkGUIGeneral.h"
#include "Gui/jkGUIForce.h"
#include "Gui/jkGUIEsc.h"
#include "Gui/jkGUIDecision.h"
#include "Gui/jkGUISaveLoad.h"
#include "Gui/jkGUISingleplayer.h"
#include "Gui/jkGUISingleTally.h"
#include "Gui/jkGUIControlOptions.h"
#include "Gui/jkGUIObjectives.h"
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIGameplay.h"
#include "Gui/jkGUIDisplay.h"
#include "Gui/jkGUISound.h"
#include "Gui/jkGUIKeyboard.h"
#include "Gui/jkGUIMouse.h"
#include "Gui/jkGUIJoystick.h"
#include "Gui/jkGUITitle.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUIMultiplayer.h"
#include "Gui/jkGUIBuildMulti.h"
#include "Gui/jkGUIMultiTally.h"
#include "Engine/rdroid.h"
#include "Engine/rdActive.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdLight.h"
#include "Engine/rdMaterial.h"
#include "Raster/rdCache.h"
#include "Engine/rdColormap.h"
#include "Engine/rdClip.h"
#include "Engine/rdCanvas.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdThing.h"
#include "Engine/sithCamera.h"
#include "Devices/sithControl.h"
#include "Gameplay/sithTime.h"
#include "Main/sithMain.h"
#include "Main/sithCommand.h"
#include "World/sithModel.h"
#include "Engine/sithParticle.h"
#include "Engine/sithPhysics.h"
#include "Engine/sithPuppet.h"
#include "Dss/sithGamesave.h"
#include "World/sithSprite.h"
#include "World/sithSurface.h"
#include "World/sithTemplate.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithKeyFrame.h"
#include "Gameplay/sithOverlayMap.h"
#include "World/sithMaterial.h"
#include "Engine/sithRender.h"
#include "Engine/sithRenderSky.h"
#include "Devices/sithSound.h"
#include "Devices/sithSoundMixer.h"
#include "World/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdPolyLine.h"
#include "Primitives/rdParticle.h"
#include "Primitives/rdSprite.h"
#include "Primitives/rdMatrix.h"
#include "Raster/rdFace.h"
#include "Primitives/rdMath.h"
#include "Primitives/rdPrimit2.h"
#include "Primitives/rdPrimit3.h"
#include "Raster/rdRaster.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithWeapon.h"
#include "World/sithExplosion.h"
#include "World/sithItem.h"
#include "World/sithWorld.h"
#include "Gameplay/sithInventory.h"
#include "World/jkPlayer.h"
#include "Gameplay/jkSaber.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "World/sithMap.h"
#include "Engine/sithIntersect.h"
#include "Gameplay/sithPlayerActions.h"
#include "World/sithTrackThing.h"
#include "Devices/sithConsole.h"
#include "Win95/DirectX.h"
#include "Win95/stdComm.h"
#include "Win95/std.h"
#include "Win95/stdGob.h"
#include "Win95/stdMci.h"
#include "Win95/stdGdi.h"
#include "Platform/stdControl.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdConsole.h"
#include "Win95/stdSound.h"
#include "Win95/Window.h"
#include "Win95/Windows.h"
#include "Platform/wuRegistry.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "AI/sithAICmd.h"
#include "AI/sithAIAwareness.h"
#include "Main/jkAI.h"
#include "Main/jkCredits.h"
#include "Main/jkCutscene.h"
#include "Main/jkDev.h"
#include "Main/jkMain.h"
#include "Main/jkSmack.h"
#include "Main/jkGame.h"
#include "Main/jkGob.h"
#include "Main/jkRes.h"
#include "Main/jkStrings.h"
#include "Main/jkControl.h"
#include "Main/jkEpisode.h"
#include "Main/jkHud.h"
#include "Main/jkHudInv.h"
#include "Main/Main.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "Dss/jkDSS.h"
#include "Devices/sithComm.h"
#include "stdPlatform.h"
#endif

#ifdef __cplusplus
}
#endif

#endif // TYPES_H
