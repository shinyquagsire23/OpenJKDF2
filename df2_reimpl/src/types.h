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
typedef int stdFile_t;
#else
typedef void* stdFile_t;
#endif

typedef struct IDirectSoundBuffer IDirectSoundBuffer;
typedef IDirectSoundBuffer* LPDIRECTSOUNDBUFFER;

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;

typedef struct sithAIClass sithAIClass;
typedef struct sithCog sithCog;
typedef struct sithCogMsg sithCogMsg;
typedef struct sithSector sithSector;
typedef struct sithSound sithSound;
typedef struct sithSurface sithSurface;
typedef struct sithThing sithThing;
typedef struct sithWorld sithWorld;

typedef struct stdStrTable stdStrTable;
typedef struct stdConffileArg stdConffileArg;
typedef struct stdHashTable stdHashTable;
typedef struct stdVBuffer stdVBuffer;
typedef struct stdGob stdGob;
typedef struct stdGobFile stdGobFile;

typedef struct rdColormap rdColormap;
typedef struct rdSprite rdSprite;
typedef struct rdEdge rdEdge;
typedef struct rdMaterial rdMaterial;
typedef struct rdParticle rdParticle;
typedef struct rdClipFrustum rdClipFrustum;
typedef struct rdVertexIdxInfo rdVertexIdxInfo;
typedef struct rdProcEntry rdProcEntry;
typedef struct sithUnk3SearchEntry sithUnk3SearchEntry;
typedef struct sithPlayingSound sithPlayingSound;
typedef struct sithSoundClass sithSoundClass;
typedef struct sithAI sithAI;
typedef struct sithAICommand sithAICommand;
typedef struct sithActor sithActor;
typedef struct sithSurfaceInfo sithSurfaceInfo;

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

#define WM_LBUTTONDOWN 0
#define WM_LBUTTONUP 1
#define WM_MOUSEMOVE 2
#define WM_KEYFIRST 3
#define WM_KEYUP 4
#define WM_CHAR 5
#define WM_PAINT 6
#define WM_SETCURSOR 7
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
