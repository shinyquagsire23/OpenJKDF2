#ifndef TYPES_H
#define TYPES_H

#ifdef TARGET_TWL
//#include <nds.h>
#define flextov16(n) ((v16)((int32_t)n.to_raw() >> (FIXED_POINT_DECIMAL_BITS-12)))
#define flextof32(n) ((int32_t)((int32_t)n.to_raw() >> (FIXED_POINT_DECIMAL_BITS-12)))
#define f32toflex(n) (numeric::fixed<FIXED_POINT_WHOLE_BITS, FIXED_POINT_DECIMAL_BITS>::from_base(n<<(FIXED_POINT_DECIMAL_BITS-12)))
#endif

#ifdef EXPERIMENTAL_FIXED_POINT
#define flexdirect(n) (numeric::fixed<FIXED_POINT_WHOLE_BITS, FIXED_POINT_DECIMAL_BITS>::from_base(n))
#endif

#ifdef __cplusplus
#ifdef EXPERIMENTAL_FIXED_POINT
#include "fixed.h"
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MACOS
#define GL_SILENCE_DEPRECATION
#define AL_SILENCE_DEPRECATION
#endif

#if (defined(LINUX) || defined(TARGET_TWL)) && !defined(PLAT_MISSING_WIN32)
#define PLAT_MISSING_WIN32
#endif

#if defined(LINUX) || defined(TARGET_TWL)
#define FS_POSIX
#endif

#if defined(SDL2_RENDER)
#define QUAKE_CONSOLE
#endif

// Ghidra tutorial:
// File > Parse C Source...
//
// Select VisualStudio12_32.prf
// Click second top-right button "Save profile to new name"
// Name it JK, JKM, DW, etc
//
// Hit + button
// Add this file as a header
//
// Add the following to the parse options:
// -DGHIDRA_IMPORT
//
// For JKM:
// -DJKM_TYPES
//
// For DroidWorks:
// -DDW_TYPES
//
// Parse to Program and Save
// In Data Type Manager, right click the EXE and Apply Function Data Types

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
#define JKM_PARAMS
#define JKM_AI
#define JKM_SABER
#define JKM_DSS
#define JKM_CAMERA
#endif

#ifdef DW_TYPES
#define DW_LASERS
#endif

#include "types_win_enums.h"
#include "types_enums.h"
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

#ifdef QOL_IMPROVEMENTS
    #define SITH_NUM_EVENTS (6)
#else // !QOL_IMPROVEMENTS
    #ifdef JKM_TYPES
        #define SITH_NUM_EVENTS (6)
    #else // !JKM_TYPES
        #define SITH_NUM_EVENTS (5)
    #endif // JKM_TYPES
#endif // QOL_IMPROVEMENTS


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

#if defined(PLAT_MISSING_WIN32)
#define __stdcall
#define __cdecl
typedef int32_t HKEY;
typedef char* LPCSTR;
typedef wchar_t* LPCWSTR;
typedef uint32_t DWORD;
typedef uint32_t* LPDWORD;
typedef uint32_t LSTATUS;
typedef uint8_t BYTE;
typedef uint8_t* LPBYTE;
typedef int32_t REGSAM;
typedef HKEY* PHKEY;
typedef char* LPSTR;
typedef void* LPSECURITY_ATTRIBUTES;
typedef int32_t HRESULT;
typedef void** LPVOID;
typedef uint32_t HINSTANCE;
typedef void* LPUNKNOWN;
typedef int32_t HDC;
typedef int BOOL;
typedef uint32_t UINT;
typedef void* LPPALETTEENTRY;
typedef int* HGDIOBJ;
typedef int32_t HFONT;
typedef int32_t COLORREF;
typedef int32_t HBITMAP;
typedef void BITMAPINFO;
typedef int32_t HANDLE;
typedef int32_t HPALETTE;
typedef void PALETTEENTRY;
typedef int32_t LOGPALETTE;
typedef void RGBQUAD;
typedef void* LPCVOID;
typedef uint32_t SIZE_T;
typedef int32_t HWND;
typedef uint16_t WORD;
typedef int16_t SHORT;
typedef int32_t LONG;
typedef wchar_t WCHAR;
typedef int32_t PAINTSTRUCT;

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
typedef int32_t IUnknown;
typedef uint16_t WPARAM;
typedef uint32_t LRESULT;
typedef int32_t HCURSOR;
typedef int32_t LPARAM;
typedef int32_t WNDPROC;

typedef int32_t CONSOLE_CURSOR_INFO;

typedef struct COORD
{
    int32_t x;
    int32_t y;
} COORD;

typedef struct RECT
{
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
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

#ifdef __cplusplus
}
#endif

//typedef int64_t cog_int_t;
//typedef double cog_flex_t;

// For serialization, must stay float for save compat
typedef float flex32_t;
typedef double flex64_t;

// For intermediate calculations, physics, rendering
#ifdef EXPERIMENTAL_FIXED_POINT
// Fixed point experiment
typedef numeric::fixed<FIXED_POINT_WHOLE_BITS, FIXED_POINT_DECIMAL_BITS> flex_t;
typedef numeric::fixed<FIXED_POINT_WHOLE_BITS, FIXED_POINT_DECIMAL_BITS> flex_d_t;
#else
typedef flex_t_type flex_t;
typedef flex_d_t_type flex_d_t;
#endif

// For COG compatibility
typedef int32_t cog_int_t;
typedef flex32_t cog_flex_t;

#ifdef __cplusplus
extern "C" {
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
typedef struct stdFontCharset stdFontCharset;
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

#if !defined(SDL2_RENDER) && defined(WIN32)
typedef IDirectSoundBuffer stdSound_buffer_t;
typedef IDirectSound3DBuffer stdSound_3dBuffer_t;
#else // STDSOUND_OPENAL

#ifdef STDSOUND_OPENAL
typedef stdALBuffer stdSound_buffer_t;
typedef stdALBuffer stdSound_3dBuffer_t;
#endif

#ifdef STDSOUND_NULL
typedef stdNullSoundBuffer stdSound_buffer_t;
typedef stdNullSoundBuffer stdSound_3dBuffer_t;
#endif 

#endif // STDSOUND_OPENAL

typedef rdModel3* (*model3Loader_t)(const char *, int);
typedef int (*model3Unloader_t)(rdModel3*);
typedef rdKeyframe* (*keyframeLoader_t)(const char*);
typedef int (*keyframeUnloader_t)(rdKeyframe*);
typedef void (*sithRender_weapRendFunc_t)(sithThing*);
typedef int (*sithMultiHandler_t)();
typedef int (*stdPalEffectSetPaletteFunc_t)(uint8_t*);
typedef int (*sithAICommandFunc_t)(sithActor *actor, sithAIClassEntry *a8, sithActorInstinct *a3, int32_t b, intptr_t a4);
typedef int (*sithControlEnumFunc_t)(int32_t inputFuncIdx, const char *pInputFuncStr, uint32_t a3, int32_t dxKeyNum, uint32_t a5, int32_t a6, stdControlKeyInfoEntry* pControlEntry, Darray* pDarr);
typedef int (*sithCollisionHitHandler_t)(sithThing *, sithSurface *, sithCollisionSearchEntry *);
typedef void (*rdPuppetTrackCallback_t)(sithThing*, int32_t, uint32_t);

extern int32_t openjkdf2_bSkipWorkingDirData;
extern int32_t openjkdf2_bIsFirstLaunch;
extern int32_t openjkdf2_bIsRunningFromExistingInstall;
extern int32_t openjkdf2_bOrigWasRunningFromExistingInstall;
extern int32_t openjkdf2_bOrigWasDF2;
extern int32_t openjkdf2_restartMode;
extern int32_t openjkdf2_bIsLowMemoryPlatform;
extern int32_t openjkdf2_bIsExtraLowMemoryPlatform;
extern char openjkdf2_aRestartPath[256];
extern int32_t Main_bMotsCompat;
extern int32_t Main_bDwCompat;
extern char* openjkdf2_pExecutablePath;

// All the typedefs
typedef struct rdVector2i
{
    int32_t x;
    int32_t y;
} rdVector2i;

typedef struct rdVector3i
{
    int32_t x;
    int32_t y;
    int32_t z;
} rdVector3i;

typedef struct rdVector2
{
    flex_t x;
    flex_t y;
} rdVector2;

typedef struct rdVector3
{
    flex_t x;
    flex_t y;
    flex_t z;
} rdVector3;

typedef struct rdVector4
{
    flex_t x;
    flex_t y;
    flex_t z;
    flex_t w;
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
    int32_t type;
    uint32_t active;
    rdVector3 direction;
    flex_t intensity;
    uint32_t color;
    
#ifdef JKM_LIGHTING
    flex_t angleX;
    flex_t cosAngleX;
    flex_t angleY;
    flex_t cosAngleY;
    flex_t lux;
#else
    uint32_t dword20;
    uint32_t dword24;
#endif
    flex_t falloffMin;
    flex_t falloffMax;
} rdLight;


typedef struct sithCameraRenderInfo
{
    uint32_t field_0;
    flex_t field_4;
    flex_t field_8;
    rdColormap* colormap;
} sithCameraRenderInfo;

typedef struct rdCamera
{
    int32_t projectType;
    rdCanvas* canvas;
    rdMatrix34 view_matrix;
    flex_t fov;
    flex_t fov_y;
    flex_t screenAspectRatio;
    flex_t orthoScale;
    rdClipFrustum *pClipFrustum;
    void (*fnProject)(rdVector3 *, rdVector3 *);
    void (*fnProjectLst)(rdVector3 *, rdVector3 *, unsigned int);
    flex_t ambientLight;
    int32_t numLights;
    rdLight* lights[64];
    rdVector3 lightPositions[64];
    flex_t attenuationMin;
    flex_t attenuationMax;
} rdCamera;

typedef struct rdCanvas
{
    uint32_t bIdk;
    stdVBuffer* vbuffer;
    flex_t half_screen_width;
    flex_t half_screen_height;
    stdVBuffer* d3d_vbuf;
    uint32_t field_14;
    int32_t xStart;
    int32_t yStart;
    int32_t widthMinusOne;
    int32_t heightMinusOne;
} rdCanvas;

typedef struct rdMarkers
{
    flex_t marker_float[8];
    int32_t marker_int[8];
} rdMarkers;

typedef struct rdAnimEntry
{
    flex_t frameNum;
    uint32_t flags;
    rdVector3 pos;
    rdVector3 orientation;
    rdVector3 vel;
    rdVector3 angVel;
} rdAnimEntry;

typedef struct rdJoint
{
    char mesh_name[32];
    uint32_t nodeIdx;
    uint32_t numAnimEntries;
    rdAnimEntry* paAnimEntries;
} rdJoint;

typedef struct rdKeyframe
{
    char name[32];
    uint32_t id;
    uint32_t flags;
    uint32_t numJoints;
    uint32_t type;
    flex_t fps;
    uint32_t numFrames;
    uint32_t numJoints2;
    rdJoint* paJoints;
    uint32_t numMarkers;
    rdMarkers markers;
} rdKeyframe;

typedef struct rdClipFrustum
{
  int bClipFar;
  flex_t zNear;
  flex_t zFar;
  flex_t orthoLeft;
  flex_t orthoTop;
  flex_t orthoRight;
  flex_t orthoBottom;
  flex_t farTop;
  flex_t bottom;
  flex_t farLeft;
  flex_t right;
  flex_t nearTop;
  flex_t nearLeft;
} rdClipFrustum;


typedef struct rdProcEntry
{
    uint32_t extraData;
    int32_t type;
    rdGeoMode_t geometryMode;
    rdLightMode_t lightingMode;
    rdTexMode_t textureMode;
    uint32_t anonymous_4;
    uint32_t anonymous_5;
    uint32_t numVertices;
    rdVector3* vertices;
    rdVector2* vertexUVs;
    flex_t* vertexIntensities;
#ifdef JKM_LIGHTING
    flex_t* paRedIntensities;
    flex_t* paGreenIntensities;
    flex_t* paBlueIntensities;
#endif
    rdMaterial* material;
    uint32_t wallCel;
    flex_t ambientLight;
    flex_t light_level_static;
    flex_t extralight;
    rdColormap* colormap;
    uint32_t light_flags;
    int32_t x_min;
    uint32_t x_max;
    int32_t y_min;
    uint32_t y_max;
    flex_t z_min;
    flex_t z_max;
    int32_t y_min_related;
    int32_t y_max_related;
    uint32_t vertexColorMode;
} rdProcEntry;

typedef struct v11_struct
{
  int32_t mipmap_related;
  int32_t field_4;
  rdMaterial *material;
} v11_struct;

typedef struct rdTri
{
  int32_t v1;
  int32_t v2;
  int32_t v3;
  int32_t flags;
  rdDDrawSurface *texture; // DirectDrawSurface*
} rdTri;

typedef struct rdUITri
{
  int32_t v1;
  int32_t v2;
  int32_t v3;
  int32_t flags;
  uint32_t texture; // DirectDrawSurface*
} rdUITri;

typedef struct rdLine
{
    int32_t v1;
    int32_t v2;
    int32_t flags;
} rdLine;

typedef float D3DVALUE;

#pragma pack(push, 4)
typedef struct D3DVERTEX_orig
{
  union ALIGNED_(4)
  {
    D3DVALUE x;
    D3DVALUE dvX;
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
    D3DVALUE dvX;
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
  D3DVALUE lightLevel;
  #pragma pack(pop)
} D3DVERTEX_ext;
#pragma pack(pop)


#pragma pack(push, 4)
typedef struct D3DVERTEX_twl
{
  union ALIGNED_(4)
  {
    flex_t x;
    flex_t dvX;
  };
  #pragma pack(push, 4)
  union
  {
    flex_t y;
    flex_t dvY;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    flex_t z;
    flex_t dvZ;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    flex_t nx;
    flex_t dvNX;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    flex_t ny;
    flex_t dvNY;
    uint32_t color;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    flex_t nz;
    flex_t dvNZ;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    flex_t tu;
    flex_t dvTU;
  };
  #pragma pack(pop)
  #pragma pack(push, 4)
  union
  {
    flex_t tv;
    flex_t dvTV;
  };
  #pragma pack(pop)
} D3DVERTEX_twl;
#pragma pack(pop)

// TODO: Differentiate by renderer, not SDL2
#ifdef SDL2_RENDER
typedef D3DVERTEX_ext D3DVERTEX;
#elif defined(TARGET_TWL)
typedef D3DVERTEX_twl D3DVERTEX;
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

typedef struct jkgm_cache_entry_t jkgm_cache_entry_t;

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

    uint32_t textureSize;
    uint32_t frameNum;
    rdDDrawSurface* pPrevCachedTexture;
    rdDDrawSurface* pNextCachedTexture;
    
    //uint32_t texture_area;
    //uint32_t gpu_accel_maybe;
    //rdDDrawSurface* tex_prev;
    //rdDDrawSurface* tex_next;
#ifdef SDL2_RENDER
    uint32_t emissive_texture_id;
    uint32_t displacement_texture_id;
    flex_t emissive_factor[3];
    flex_t albedo_factor[4];
    flex_t displacement_factor;
    void* emissive_data;
    void* albedo_data;
    void* displacement_data;
    void* pDataDepthConverted;
    int32_t skip_jkgm;
    jkgm_cache_entry_t* cache_entry;
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


typedef struct stdFontEntry
{
  int32_t field_0;
  int32_t field_4;
} stdFontEntry;

typedef struct stdFontCharset
{
  stdFontCharset *previous;
  uint16_t charFirst;
  uint16_t charLast;
  stdFontEntry *pEntries;
  stdFontEntry entries;
} stdFontCharset;

typedef struct stdFont
{
  char name[32];
  int32_t marginY;
  int32_t marginX;
  int16_t field_28;
  int16_t monospaceW;
  stdBitmap *bitmap;
  stdFontCharset charsetHead;
} stdFont;

typedef struct stdFontHeader
{
  int32_t magic;
  int32_t version;
  int32_t marginY;
  int32_t marginX;
  int32_t field_10;
  int32_t numCharsets;
  int32_t field_18;
  int32_t field_1C;
  int32_t field_20;
  int32_t field_24;
} stdFontHeader;

typedef struct stdFontExtHeader
{
  uint16_t characterFirst;
  uint16_t characterLast;
} stdFontExtHeader;


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
    flex32_t tint[3];
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
#ifdef SDL2_RENDER
    int32_t has_jkgm_override;
#endif
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
#if defined(SDL2_RENDER) || defined(RDMATERIAL_LRU_LOAD_UNLOAD)
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
#ifdef RDMATERIAL_LRU_LOAD_UNLOAD
    BOOL bDataLoaded;
#endif
} rdMaterial;

struct sithPuppet
{
    int32_t field_0;
    int32_t field_4;
    int32_t majorMode;
    int32_t currentAnimation;
    sithAnimclassEntry* playingAnim;
    int32_t otherTrack;
    int32_t field_18;
    int32_t currentTrack;
    int32_t animStartedMs;
};

typedef struct sithAnimclassEntry
{
    rdKeyframe* keyframe;
    uint32_t flags;
    uint32_t lowPri;
    uint32_t highPri;
} sithAnimclassEntry;

typedef struct sithAnimclassMode
{
    sithAnimclassEntry keyframe[42];
    uint32_t field_2A0;
    uint32_t field_2A4;
    uint32_t field_2A8;
    uint32_t field_2AC;
#ifdef JKM_TYPES
    uint32_t pad[8];
#endif
} sithAnimclassMode;

typedef struct sithAnimclass
{
    char name[32];
    sithAnimclassMode modes[6];
    int32_t bodypart_to_joint[10];
} sithAnimclass;

typedef struct sithAdjoin
{
    uint32_t flags;
    sithSector* sector;
    sithSurface* surface;
    sithAdjoin *mirror;
    sithAdjoin *next;
    uint32_t field_14;
    flex_t dist;
    rdVector3 field_1C;
} sithAdjoin;

#pragma pack(push, 4)
typedef struct sithCamera
{
    uint32_t cameraPerspective;
    uint32_t dword4;
    flex_t fov;
    flex_t aspectRatio;
    sithThing* primaryFocus;
    sithThing* secondaryFocus;
    sithSector* sector;
    rdVector3 collisionOffset;
    rdVector3 unused1;
    rdMatrix34 viewMat;
    rdVector3 vec3_1;
    rdVector3 viewPYR;
    rdCamera rdCam;
#ifdef JKM_CAMERA
    int32_t bZoomed;
    flex_t zoomScale;
    flex_t invZoomScale;
    flex_t zoomFov;
    flex_t zoomSpeed;
#ifdef QOL_IMPROVEMENTS
    flex_t zoomScaleOrig;
#endif
#endif
} sithCamera;
#pragma pack(pop)

typedef struct sithEventInfo sithEventInfo; 
typedef struct sithEvent sithEvent;

typedef int (*sithEventHandler_t)(int32_t, sithEventInfo*);

typedef struct sithEventInfo
{
    int32_t cogIdx;
    int32_t timerIdx;
    flex_t field_10;
    flex_t field_14;
} sithEventInfo;

typedef struct sithEvent
{
    uint32_t endMs;
    int32_t taskNum;
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
    int32_t flags;
    int32_t idx;
    flex_t vol_2;
    flex_t anonymous_5;
    flex_t maxPosition;
    flex_t anonymous_7;
    flex_t volumeVelocity;
    flex_t volume;
    flex_t pitch;
    flex_t pitchVel;
    flex_t nextPitch;
    flex_t distance;
    rdVector3 posRelative;
    sithThing* thing;
    rdVector3 pos;
    int32_t refid;
} sithPlayingSound;

typedef struct sithSound
{
    char sound_fname[32];
    int32_t id;
    int32_t isLoaded;
    uint32_t bufferBytes;
    uint32_t sampleRateHz;
    int32_t bitsPerSample;
    int32_t bStereo; // stdSound_buffer_t*
    uint32_t sound_len;
    int32_t seekOffset;
    int32_t field_40;
    int32_t infoLoaded;
    stdSound_buffer_t* dsoundBuffer2; // stdSound_buffer_t*
} sithSound;

typedef int (*sithControl_handler_t)(sithThing*, flex_t);

typedef void (*sithSaveHandler_t)();

typedef struct sithGamesave_Header
{
    int32_t version;
    char episodeName[128];
    char jklName[128];
    flex32_t playerHealth;
    flex32_t playerMaxHealth;
    flex32_t binAmts[200];
    wchar_t saveName[256];
} sithGamesave_Header;

typedef struct sithMapViewConfig
{
    int32_t numArr;
    flex_t *unkArr;
    int32_t *paColors;
    int32_t playerColor;
    int32_t playerLineColor;
    int32_t actorColor;
    int32_t actorLineColor;
    int32_t itemColor;
    int32_t weaponColor;
    int32_t otherColor;
    int32_t bRotateOverlayMap;
    int32_t aTeamColors[5];
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
    flex_t* paDynamicLight;
    flex_t* intensities;
#ifdef JKM_LIGHTING
    flex_t* paRedIntensities;
    flex_t* paGreenIntensities;
    flex_t* paBlueIntensities;
#endif
} rdVertexIdxInfo;

typedef struct rdMeshinfo
{
    uint32_t numVertices;
    int* vertexPosIdx;
    int* vertexUVIdx;
    rdVector3* verticesProjected;
    rdVector2* vertexUVs;
    flex_t* paDynamicLight;
    flex_t* intensities;
#ifdef JKM_LIGHTING
    flex_t* paRedIntensities;
    flex_t* paGreenIntensities;
    flex_t* paBlueIntensities;
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
    flex_t extraLight;
    rdVector3 normal;
} rdFace;

typedef struct sithSurfaceInfo
{
    rdFace face;
    flex_t* intensities;
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
  rdVector2 scrollVector;
  rdVector3 field_24;
  uint32_t field_30;
  uint32_t field_34;
  uint32_t wallCel;
  flex_t field_3C;
  flex_t field_40;
  flex_t field_44;
  flex_t field_48;
};

typedef struct sithSurface
{
    uint32_t index;
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
    int32_t timeMsExpiration;
    int32_t field_104;
    int32_t drawWidth;
    int32_t field_10C;
    int32_t bDrawEntry;
} jkDevLogEnt;

#ifdef PLAT_MISSING_WIN32
typedef uint32_t MCIDEVICEID;
#endif


typedef struct stdDeviceParams
{
  int32_t field_0;
  int32_t field_4;
  int32_t field_8;
  int32_t field_C;
  int32_t field_10;
} stdDeviceParams;

typedef struct video_device
{
  int32_t device_active;
  int32_t hasGUID;
  int32_t has3DAccel;
  int32_t hasNoGuid;
  int32_t windowedMaybe;
  int32_t dwVidMemTotal;
  int32_t dwVidMemFree;
} video_device;

typedef struct stdVideoMode
{
  int32_t field_0;
  flex_t widthMaybe;
  stdVBufferTexFmt format;
} stdVideoMode;

typedef struct stdVideoDevice
{
  char driverDesc[128];
  char driverName[128];
  video_device video_device[14];
  GUID guid;
  int32_t max_modes;
  stdVideoMode *stdVideoMode;
  uint32_t gap2A0;
  int32_t field_2A4;
} stdVideoDevice;

typedef struct render_8bpp
{
  int32_t bpp;
  int32_t rBpp;
  int32_t width;
  int32_t height;
  int32_t rShift;
  int32_t gShift;
  int32_t bShift;
  int32_t palBytes;
} render_8bpp;

typedef struct render_rgb
{
  int32_t bpp;
  int32_t rBpp;
  int32_t gBpp;
  int32_t bBpp;
  int32_t rShift;
  int32_t gShift;
  int32_t bShift;
  int32_t rBytes;
  int32_t gBytes;
  int32_t bBytes;
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
  int32_t xMin;
  int32_t yMin;
  flex_t xMax;
  flex_t yMax;
} jkViewSize;

typedef struct videoModeStruct
{
  int32_t modeIdx;
  int32_t descIdx;
  int32_t Video_8605C8;
  int32_t field_C;
  int32_t field_10;
  int32_t field_14;
  int32_t field_18;
  int32_t field_1C;
  int32_t field_20;
  int32_t field_24;
  int32_t field_28;
  HKEY b3DAccel;
  uint32_t viewSizeIdx;
  jkViewSize aViewSizes[11];
  int32_t Video_8606A4;
  int32_t Video_8606A8;
#ifndef JKM_TYPES
  int32_t geoMode;
  int32_t lightMode;
#else
  int32_t lightMode;
  int32_t geoMode;
#endif
  int32_t texMode;
  HKEY Video_8606B8;
  HKEY Video_8606BC;
#ifdef JKM_TYPES
  int32_t Video_motsNew1;
#endif
  int32_t Video_8606C0;
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
    int32_t selfCog;
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
    cog_flex_t params[4];
    cog_flex_t returnEx;
    sithCogCallstack callstack[4];
    uint32_t calldepth;
    sithCogSymboltable* pSymbolTable;
    sithCogStackvar stack[SITHCOGVM_MAX_STACKSIZE];
    uint32_t stackPos;
    char cogscript_fpath[32];
#ifdef JKM_TYPES
    uint32_t unk1;
    int32_t numHeapVars;
    sithCogStackvar* heap;
#endif
    char field_4BC[32*128];
#ifndef JKM_TYPES
    sithCogStackvar* heap;
    int32_t numHeapVars;
#endif
} sithCog;

// end sithCogVm

typedef struct sithCogSectorLink
{
    sithSector* sector;
    sithCog* cog;
    int32_t linkid;
    int32_t mask;
} sithCogSectorLink;

typedef struct sithCogThingLink
{
    sithThing* thing;
    int32_t signature;
    sithCog* cog;
    int32_t linkid;
    int32_t mask;
} sithCogThingLink;

typedef struct sithCogSurfaceLink
{
    sithSurface* surface;
    sithCog* cog;
    int32_t linkid;
    int32_t mask;
} sithCogSurfaceLink;

// jkEpisode
typedef int32_t jkEpisodeTypeFlags_t;

typedef struct jkEpisode
{
    char name[32];
    wchar_t unistr[32];
    int32_t field_60;
    int32_t field_64;
    int32_t field_68;
    int32_t field_6C;
    int32_t field_70;
    int32_t field_74;
    int32_t field_78;
    int32_t field_7C;
    int32_t field_80;
    int32_t field_84;
    int32_t field_88;
    int32_t field_8C;
    int32_t field_90;
    int32_t field_94;
    int32_t field_98;
    int32_t field_9C;
    jkEpisodeTypeFlags_t type;
} jkEpisode;

typedef struct jkEpisodeEntry
{
    int32_t lineNum;
    int32_t cdNum;
    int32_t level;
    int32_t type;
    char fileName[32];
    int32_t lightpow;
    int32_t darkpow;
    int32_t gotoA;
    int32_t gotoB;
} jkEpisodeEntry;

typedef struct jkEpisodeLoad
{
    jkEpisodeTypeFlags_t type;
    int32_t numSeq;
    int32_t currentEpisodeEntryIdx;
    jkEpisodeEntry* paEntries;
} jkEpisodeLoad;
//end jkEpisode

// jkRes
typedef struct HostServicesBasic
{
    flex_t some_float;
    int (*messagePrint)(const char *, ...);
    int (*statusPrint)(const char *, ...);
    int (*warningPrint)(const char *, ...);
    int (*errorPrint)(const char *, ...);
    int (*debugPrint)(const char *, ...);
    void (*assert)(const char *, const char *, int);
    int32_t unk_0;
    void *(*alloc)(uint32_t);
    void (*free)(void *);
    void *(*realloc)(void *, uint32_t);
    uint32_t (*getTimerTick)();
    stdFile_t (*fileOpen)(const char *, const char *);
    int (*fileClose)(stdFile_t);
    size_t (*fileRead)(stdFile_t, void *, size_t);
    const char *(*fileGets)(stdFile_t, char *, size_t);
    size_t (*fileWrite)(stdFile_t, void *, size_t);
    int (*fileEof)(stdFile_t);
    int (*ftell)(stdFile_t);
    int (*fseek)(stdFile_t, int, int);
    int (*fileSize)(stdFile_t);
    int (*filePrintf)(stdFile_t, const char*, ...);
    const wchar_t* (*fileGetws)(stdFile_t, wchar_t *, size_t);
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
    void *(*alloc)(uint32_t);
    void (*free)(void *);
    void *(*realloc)(void *, uint32_t);
    uint32_t (*getTimerTick)();
    stdFile_t (*fileOpen)(const char *, const char *);
    int (*fileClose)(stdFile_t);
    size_t (*fileRead)(stdFile_t, void *, size_t);
    const char *(*fileGets)(stdFile_t, char *, size_t);
    size_t (*fileWrite)(stdFile_t, void *, size_t);
    int (*fileEof)(stdFile_t);
    int (*ftell)(stdFile_t);
    int (*fseek)(stdFile_t, int, int);
    int (*fileSize)(stdFile_t);
    int (*filePrintf)(stdFile_t, const char*, ...);
    const wchar_t* (*fileGetws)(stdFile_t, wchar_t *, size_t);
    void* (*allocHandle)(size_t);
    void (*freeHandle)(void*);
    void* (*reallocHandle)(void*, size_t);
    uint32_t (*lockHandle)(uint32_t);
    void (*unlockHandle)(uint32_t);
} HostServices;

typedef struct jkResGobDirectory
{
  char name[128];
  int32_t numGobs;
  stdGob *gobs[64];
} jkResGobDirectory;

typedef struct jkRes
{
    jkResGobDirectory aGobDirectories[5];
} jkRes;

typedef struct jkResFile
{
  int32_t bOpened;
  char fpath[128];
  int32_t useLowLevel;
  stdFile_t fsHandle;
  stdGobFile *gobHandle;
} jkResFile;

// end jkRes


typedef struct sithCogTrigger
{
    uint32_t trigId;
    uint32_t trigPc;
    uint32_t field_8;
} sithCogTrigger;

typedef struct cogSymbol
{
    int32_t type;
    cog_int_t val;
    cogSymbolFunc_t func;
} cogSymbol;

typedef struct sithCogSymbol
{
  int32_t symbol_id;
  sithCogStackvar val;
#if 0
  int32_t symbol_type;
  union
  {
    char *symbol_name;
    cogSymbolFunc_t func;
    cog_flex_t as_float;
    cog_flex_t as_flex;
    cog_int_t as_int;
    void* as_data;
    sithAIClass* as_aiclass;
    rdVector3 as_vec3;
    intptr_t as_intptrs[3];
  };
#endif
  int32_t field_14;
  char* field_18;
} sithCogSymbol;

typedef struct sithCogSymboltable
{
    sithCogSymbol* buckets;
    stdHashTable* hashtable;
    uint32_t entry_cnt;
    uint32_t max_entries;
    uint32_t bucket_idx;
    uint32_t unk_14;
} sithCogSymboltable;

typedef struct sithCogReference
{
    int32_t type;
    int32_t flags;
    int32_t linkid;
    int32_t mask;
    int32_t hash;
    char* desc;
    char value[32];
} sithCogReference;

typedef struct sithCogScript
{
    sithCogFlags_t flags;
    char cog_fpath[32];
    int32_t* script_program;
    uint32_t codeSize;
    sithCogSymboltable *pSymbolTable;
    uint32_t num_triggers;
    sithCogTrigger triggers[32];
    sithCogReference aIdk[128];
    uint32_t numIdk;
} sithCogScript;

typedef struct sithAICommand
{
    char name[32];
    sithAICommandFunc_t func;
    int32_t param1;
    int32_t param2;
    int32_t param3;
} sithAICommand;

typedef struct sithAIClassEntry
{
  int32_t param1;
  int32_t param2;
  int32_t param3;
  flex_t argsAsFloat[16];
  int32_t argsAsInt[16];
  sithAICommandFunc_t func;
} sithAIClassEntry;

typedef struct sithAIClass
{
  int32_t index;
  int32_t field_4;
  flex_t alignment;
  flex_t rank;
  flex_t maxStep;
  flex_t sightDist;
  flex_t hearDist;
  flex_t fov;
  flex_t wakeupDist;
  flex_t accuracy;
  int32_t numEntries;
  sithAIClassEntry entries[16];
  char fpath[32];
} sithAIClass;

#ifdef JKM_LIGHTING
typedef struct sithArchLightMesh
{
    flex_t* aMono;
    flex_t* aRed;
    flex_t* aGreen;
    flex_t* aBlue;
    int32_t numVertices;
} sithArchLightMesh;

typedef struct sithArchLight
{
    int32_t numMeshes;
    sithArchLightMesh* aMeshes;
} sithArchLight;
#endif

typedef void (__cdecl *sithWorldProgressCallback_t)(flex_t);

typedef struct sDwLaser tDwLaser;

typedef struct sithWorld
{
    uint32_t level_type_maybe;
    char map_jkl_fname[32];
    char episodeName[32];
    int32_t numColormaps;
    rdColormap* colormaps;
    int32_t numSectors;
    sithSector* sectors;
    int32_t numMaterialsLoaded;
    int32_t numMaterials;
    rdMaterial* materials;
    rdVector2* materials2;
    uint32_t numModelsLoaded;
    uint32_t numModels;
    rdModel3* models;
    int32_t numSpritesLoaded;
    int32_t numSprites;
    rdSprite* sprites;
    int32_t numParticlesLoaded;
    int32_t numParticles;
    rdParticle* particles;
    int32_t numVertices;
    rdVector3* vertices;
    rdVector3* verticesTransformed;
    int32_t* alloc_unk98;
    flex_t* verticesDynamicLight;
    int32_t* alloc_unk9c;
    int32_t numVertexUVs;
    rdVector2* vertexUVs;
    int32_t numSurfaces;
    sithSurface* surfaces;
    int32_t numAdjoinsLoaded;
    int32_t numAdjoins;
    sithAdjoin* adjoins;
    int32_t numThingsLoaded;
    int32_t numThings;
    sithThing* things;
    int32_t numTemplatesLoaded;
    int32_t numTemplates;
    sithThing* templates;
    flex_t worldGravity;
    uint32_t field_D8;
    flex_t ceilingSky;
    flex_t horizontalDistance;
    flex_t horizontalPixelsPerRev;
    rdVector2 horizontalSkyOffs;
    rdVector2 ceilingSkyOffs;
    rdVector4 mipmapDistance;
    rdVector4 lodDistance;
    flex_t perspectiveDistance;
    flex_t gouradDistance;
    sithThing* cameraFocus;
    sithThing* playerThing;
    uint32_t field_128;
    int32_t numSoundsLoaded;
    int32_t numSounds;
    sithSound* sounds;
    int32_t numSoundClassesLoaded;
    int32_t numSoundClasses;
    sithSoundClass* soundclasses;
    int32_t numCogScriptsLoaded;
    int32_t numCogScripts;
    sithCogScript* cogScripts;
    int32_t numCogsLoaded;
    int32_t numCogs;
    sithCog* cogs;
    int32_t numAIClassesLoaded;
    int32_t numAIClasses;
    sithAIClass* aiclasses;
    int32_t numKeyframesLoaded;
    int32_t numKeyframes;
    rdKeyframe* keyframes;
    int32_t numAnimClassesLoaded;
    int32_t numAnimClasses;
    sithAnimclass* animclasses;
#ifdef JKM_LIGHTING
    int32_t numArchLights;
    //int sizeArchLights;
    sithArchLight* aArchlights;
#endif
#ifdef DW_LASERS
    sDwLaser* paLasers;
    sDwLaser* pLastLaser;
#endif
} sithWorld;

typedef struct sDwLaser
{
    uint32_t field_0;
    uint32_t field_4;
    uint32_t pad[0xF];
    uint32_t pad2[0x10];
    uint32_t pad3[0x10];
    uint32_t pad4[0x8];
} tDwLaser;

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
    flex_t ammoMin;
    flex_t ammoMax;
    sithCog* cog;
#ifndef DW_TYPES
    uint32_t field_90;
    uint32_t field_94;
#endif
    stdBitmap* hudBitmap;
} sithItemDescriptor;

typedef struct sithItemInfo
{
    flex_t ammoAmt;
    int32_t field_4;
    int32_t state;
    flex_t activatedTimeSecs;
    flex_t activationDelaySecs;
    flex_t binWait;
} sithItemInfo;

typedef struct sithKeybind {
    int32_t enabled;
    int32_t binding;
    int32_t idk;
} sithKeybind;

typedef struct sithMap
{
  int32_t numArr;
  flex_t* unkArr;
  int32_t* anonymous_1;
  int32_t playerColor;
  int32_t actorColor;
  int32_t itemColor;
  int32_t weaponColor;
  int32_t otherColor;
  int32_t teamColors[5];
} sithMap;

typedef struct rdPolyLine 
{
    char fname[32];
    flex_t length;
    flex_t baseRadius;
    flex_t tipRadius;
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
    int32_t type;
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
    int32_t status;
    int32_t field_4;
    int32_t lowPri;
    int32_t highPri;
    flex_t speed;
    flex_t noise;
    flex_t playSpeed;
    flex_t fadeSpeed;
    uint32_t nodes[64];
    flex_t field_120;
    flex_t field_124;
    rdKeyframe *keyframe;
    rdPuppetTrackCallback_t callback;
    int32_t field_130;
} rdPuppetTrack;

typedef struct rdPuppet
{
    uint32_t paused;
    rdThing *rdthing;
    rdPuppetTrack tracks[4];
} rdPuppet;

typedef struct sithPlayerInfo
{
#ifndef DW_TYPES
    wchar_t player_name[32];
    wchar_t multi_name[32];
#endif
    uint32_t flags;
    uint32_t net_id;

#ifdef DW_TYPES
    sithItemInfo iteminfo[32];
    int32_t pad[0x6C];
#else
    sithItemInfo iteminfo[200];
#endif
    int32_t curItem;
    int32_t curWeapon;
    int32_t curPower;
#ifndef DW_TYPES
    int32_t field_1354;
#endif
    sithThing* playerThing;
    rdMatrix34 spawnPosOrient;
    sithSector* pSpawnSector;
#ifndef DW_TYPES
    uint32_t respawnMask;
#endif
    uint32_t palEffectsIdx1;
    uint32_t palEffectsIdx2;
    uint32_t teamNum;
    int32_t numKills;
    int32_t numKilled;
    int32_t numSuicides;
    int32_t score;
    int32_t lastUpdateMs;
} sithPlayerInfo;

typedef struct jkSaberCollide
{
    int32_t field_1A4;
    flex_t damage;
    flex_t bladeLength;
    flex_t stunDelay;
    uint32_t field_1B4;
    uint32_t numDamagedThings;
    sithThing* damagedThings[6];
    uint32_t numDamagedSurfaces;
    sithSurface* damagedSurfaces[6];
} jkSaberCollide;

typedef struct jkPlayerInfo
{
    uint32_t field_0;
    rdThing rd_thing;
    rdThing povModel;
    flex_t length;
    uint32_t field_98;
    rdPolyLine polyline;
    rdThing polylineThing;
    jkSaberCollide saberCollideInfo;
    uint32_t lastSparkSpawnMs;
#ifdef JKM_SABER
    uint32_t jkmUnk1;
    rdMatrix34 jkmSaberUnk1;
    rdMatrix34 jkmSaberUnk2;
#endif // JKM_SABER
    sithThing* wall_sparks;
    sithThing* blood_sparks;
    sithThing* saber_sparks;
    sithThing* actorThing;
#ifdef JKM_DSS
    uint32_t thing_id;
#endif // JKM_TYPES
    uint32_t maxTwinkles;
    uint32_t twinkleSpawnRate;
    uint32_t bRenderTwinkleParticle;
    uint32_t nextTwinkleRandMs;
    uint32_t nextTwinkleSpawnMs;
    uint32_t numTwinkles;
    uint32_t bHasSuperWeapon;
    int32_t bHasSuperShields;
    uint32_t bHasForceSurge;
#ifdef JKM_DSS
    int32_t jkmUnk4;
    uint32_t jkmUnk5;
    flex_t jkmUnk6;
    int32_t personality;
#endif // JKM_TYPES
} jkPlayerInfo;

typedef struct jkPlayerMpcInfo
{
  wchar_t name[32];
  char model[32];
  char soundClass[32];
  uint8_t gap80[32];
#ifdef JKM_PARAMS
  int32_t unk1;
#endif
  char sideMat[32];
  char tipMat[32];
  int32_t jediRank;
#ifdef JKM_PARAMS
  int32_t personality;
  sithCog* pCutsceneCog;
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
    flex_t distance;
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
    flex_t ambientLight;
    flex_t extraLight;
    rdColormap* colormap;
    rdVector3 tint;
    uint32_t numVertices;
    int32_t* verticeIdxs;
    uint32_t numSurfaces;
    sithSurface* surfaces;
    sithAdjoin* adjoins;
    sithThing* thingsList;
    uint32_t flags;
    rdVector3 center;
    rdVector3 thrust;
    sithSound* sectorSound;
    flex_t sectorSoundVol;
    rdVector3 collidebox_onecorner;
    rdVector3 collidebox_othercorner;
    rdVector3 boundingbox_onecorner;
    rdVector3 boundingbox_othercorner;
    flex_t radius;
    uint32_t renderTick;
    uint32_t clipVisited;
    rdClipFrustum* clipFrustum;
} sithSector;

typedef struct sithSectorEntry
{
    sithSector *sector;
    sithThing *thing;
    rdVector3 pos;
    int32_t field_14;
    flex_t field_18;
} sithSectorEntry;

typedef struct sithSectorAlloc
{
    int32_t field_0;
    flex_t field_4[3];
    rdVector3 field_10[3];
    rdVector3 field_34[3];
    sithThing* field_58[3];
} sithSectorAlloc;

// sithThing start

typedef struct sithActorInstinct
{
    int32_t field_0;
    int32_t nextUpdate;
    flex_t param0;
    flex_t param1;
    flex_t param2;
    flex_t param3;
} sithActorInstinct;

typedef struct sithActor
{
    sithThing *thing;
    sithAIClass *pAIClass;
    int32_t flags;
    sithActorInstinct instincts[16];
    uint32_t numAIClassEntries;
    int32_t nextUpdate;
#ifdef JKM_AI
    sithThing* pInterest;
#endif
    rdVector3 lookVector;
    rdVector3 movePos;
    rdVector3 toMovePos;
    flex_t distToMovePos;
    flex_t moveSpeed;
    sithThing* pFleeThing;
    rdVector3 field_1C4;
    sithThing* pDistractor;
    rdVector3 field_1D4;
    int32_t field_1E0;
    rdVector3 attackError;
    flex_t attackDistance;
    int32_t field_1F4;
    rdVector3 field_1F8;
    int32_t field_204;
    rdVector3 blindAimError;
    sithThing *pMoveThing;
    rdVector3 movepos;
    int32_t field_224;
    rdVector3 field_228;
    flex_t currentDistanceFromTarget;
    int32_t field_238;
    rdVector3 field_23C;
    int32_t field_248;
    rdVector3 position;
    rdVector3 lookOrientation;
    flex_t field_264;
    int32_t field_268;
    int32_t field_26C;
    int32_t mood0;
    int32_t mood1;
    int32_t mood2;
    int32_t field_27C;
    int32_t field_280;
    int32_t field_284;
    int32_t field_288;
    int32_t field_28C;
    rdVector3 *paFrames;
    int32_t loadedFrames;
    int32_t sizeFrames;
} sithActor;

typedef struct sithAIAlign
{
    int32_t bValid;
    int32_t field_4;
    flex_t field_8;
} sithAIAlign;

typedef struct sithThingParticleParams
{
    uint32_t typeFlags;
    uint32_t count;
    rdMaterial* material;
    flex_t elementSize;
    flex_t growthSpeed;
    flex_t minSize;
    flex_t range;
    flex_t pitchRange;
    flex_t yawRange;
    flex_t rate;
    flex_t field_28;
    flex_t field_2C;
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
    flex_t range;
    flex_t force;
    uint32_t blastTime;
    flex_t maxLight;
    uint32_t field_18;
    flex_t damage;
    uint32_t damageClass;
    int32_t flashR;
    int32_t flashG;
    int32_t flashB;
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
    flex_t value;
} sithBackpackItem;

typedef struct sithThingItemParams
{
    uint32_t typeflags;
    rdVector3 position;
    sithSector* sector;
    flex_t respawn;
#ifdef JKM_PARAMS
    flex_t respawnFactor;
#endif
    uint32_t respawnTime;
    int16_t numBins;
    int16_t field_1E;
    sithBackpackItem contents[12];
    uint32_t field_80;
} sithThingItemParams;

typedef struct sithThingWeaponParams
{
    sithWeaponFlags_t typeflags; // 00
    uint32_t damageClass; // 04
    flex_t unk8; // 08
    flex_t damage; // 0C
    sithThing* explodeTemplate; // 10
    sithThing* fleshHitTemplate; // 14
    uint32_t numDeflectionBounces; // 18
    flex_t rate; // 1C
    flex_t mindDamage; // 20
    sithThing* trailThing; // 24
    flex_t elementSize; // 28
    flex_t trailCylRadius; // 2C
    flex_t trainRandAngle; // 30
#ifdef JKM_PARAMS
    sithThing* pTargetThing; // 34
    flex_t field_38; // 38
#endif
    uint32_t field_3C; // 3C
    flex_t range; // 40
    flex_t force; // 3C
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
#ifndef JKM_PARAMS
    uint32_t field_88;
    uint32_t field_8C;
#endif
} sithThingWeaponParams;

typedef struct sithThingActorParams
{
    uint32_t typeflags;
    flex_t health;
    flex_t maxHealth;
    uint32_t msUnderwater;
    flex_t jumpSpeed;
    flex_t extraSpeed;
    flex_t maxThrust;
    flex_t maxRotThrust;
    sithThing* templateWeapon;
    sithThing* templateWeapon2;
    sithThing* templateExplode;
    rdVector3 eyePYR;
    rdVector3 eyeOffset;
    flex_t minHeadPitch;
    flex_t maxHeadPitch;
    rdVector3 fireOffset;
    rdVector3 lightOffset;
    flex_t lightIntensity;
    rdVector3 saberBladePos;
    flex_t timeLeftLengthChange;
    uint32_t field_1A8;
    uint32_t field_1AC;
    flex_t chance;
    flex_t fov;
    flex_t error;
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
    flex_t mass;
    flex_t height;
    flex_t airDrag;
    flex_t surfaceDrag;
    flex_t staticDrag;
    flex_t maxRotVel;
    flex_t maxVel;
    flex_t orientSpeed;
    flex_t buoyancy;
    rdVector3 addedVelocity;
    rdVector3 velocityMaybe;
    flex_t physicsRolloverFrames;
    flex_t field_74;
    flex_t field_78;
} sithThingPhysParams;

typedef struct sithThingFrame
{
    rdVector3 pos;
    rdVector3 rot;
} sithThingFrame;

typedef struct sithThingTrackParams
{
    int32_t sizeFrames;
    int32_t loadedFrames;
    sithThingFrame *aFrames;
    uint32_t flags;
    rdVector3 vel;
    flex_t field_1C;
    flex_t lerpSpeed;
    rdMatrix34 moveFrameOrientation;
    flex_t field_54;
    rdVector3 field_58;
    rdVector3 moveFrameDeltaAngles;
    rdVector3 orientation;
} sithThingTrackParams;

typedef struct sithThing
{
    uint32_t thingflags;
    uint32_t thingIdx;
    uint32_t thing_id;
#ifdef JKM_PARAMS
    uint32_t unk;
#endif // JKM_TYPES
    uint32_t type;
    uint32_t moveType;
    uint32_t controlType;
    int32_t lifeLeftMs;
    uint32_t timer;
    uint32_t pulse_end_ms;
    uint32_t pulse_ms;
    uint32_t collide;
    flex_t moveSize;
    flex_t collideSize;
#ifdef JKM_PARAMS
    flex_t treeSize;
#endif // JKM_TYPES

    // TODO split these into a struct
    uint32_t attach_flags;
    rdVector3 field_38;
    sithSurfaceInfo* attachedSufaceInfo;
    flex_t field_48;
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
    flex_t light;
    flex_t lightMin;
    int32_t lastRenderedTickIdx;
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
    flex_t field_24C;
    uint32_t field_250;
    int32_t curframe;
    uint32_t field_258;
    int32_t goalframe;
    uint32_t field_260;
    flex_t waggle;
    rdVector3 field_268;
    sithAIClass* pAIClass;
    sithActor* actor;
    char template_name[32];
    sithCog* class_cog;
    sithCog* capture_cog;
    jkPlayerInfo* playerInfo;
    uint32_t jkFlags;
    flex_t userdata;
#ifdef JKM_TYPES
    int32_t idk1;
#endif

#ifdef JKM_LIGHTING
    int32_t archlightIdx;
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
  int32_t dword10;
  int32_t bInitialized;
} Darray;

typedef void (*jkGuiDrawFunc_t)(jkGuiElement*, jkGuiMenu*, stdVBuffer*, BOOL);
typedef int (*jkGuiEventHandlerFunc_t)(jkGuiElement*, jkGuiMenu*, int32_t, int32_t);
typedef int (*jkGuiClickHandlerFunc_t)(jkGuiElement*, jkGuiMenu*, int32_t mouseX, int32_t mouseY, BOOL);

typedef struct jkGuiElementHandlers
{
  jkGuiEventHandlerFunc_t fnEventHandler;
  jkGuiDrawFunc_t draw;
  jkGuiClickHandlerFunc_t fnClickHandler;
} jkGuiElementHandlers;

typedef struct jkGuiTexInfo
{
  int32_t textHeight;
  int32_t numTextEntries;
  int32_t maxTextEntries;
  int32_t textScrollY;
  int32_t anonymous_18;
  rdRect rect;
} jkGuiTexInfo;

typedef struct jkGuiElement
{
    int32_t type;
    int32_t hoverId;
    int32_t textType;

// Added: Allow soft-resetting of these fields easily
#ifdef QOL_IMPROVEMENTS
    union
    {
        const void* compilerShutUp;
        const char* origStr;
        jkGuiStringEntry *orig_unistr;
        const wchar_t* orig_wstr;
        int32_t origExtraInt;
    };
#else
    union
    {
        const void* compilerShutUp;
        const char* str;
        jkGuiStringEntry *unistr;
        const wchar_t* wstr;
        int32_t extraInt;
        int32_t origExtraInt;
    };
#endif

    union
    {
        int32_t selectedTextEntry;
        int32_t boxChecked;
        intptr_t otherDataPtr;
    };
    rdRect rect;
    BOOL bIsVisible;
    BOOL enableHover;

// Added: Allow soft-resetting of these fields easily
#ifdef QOL_IMPROVEMENTS
    union
    {
        const void* compilerShutUp2;
        const char* origHintText;
        wchar_t* orig_wHintText;
    };
#else
    union
    {
        const void* compilerShutUp2;
        const char* hintText;
        wchar_t* wHintText;
    };
#endif
    jkGuiDrawFunc_t drawFuncOverride;
    jkGuiClickHandlerFunc_t clickHandlerFunc;
    union
    {
         int32_t* uiBitmaps;
         int32_t oldForcePoints;
    };
    jkGuiTexInfo texInfo;
    int32_t clickShortcutScancode;

// Added: Allow soft-resetting of these fields easily
#ifdef QOL_IMPROVEMENTS
    union
    {
      const char* str;
      jkGuiStringEntry *unistr;
      const wchar_t* wstr;
      int32_t extraInt;
    };
    union
    {
        const char* hintText;
        const wchar_t* wHintText;
    };

    union
    {
      const char* strAlloced;
      jkGuiStringEntry *unistrAlloced;
      const wchar_t* wstrAlloced;
      int32_t extraIntAlloced;
    };
    union
    {
        const char* hintTextAlloced;
        const wchar_t* wHintTextAlloced;
    };
#endif
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
  jkGuiElement *paElements;
  int32_t clickableIdxIdk;
  int32_t textBoxCursorColor;
  int32_t fillColor;
  int32_t checkboxBitmapIdx;
  stdVBuffer *texture;
  uint8_t* palette;
  stdBitmap **ui_structs;
  stdFont** fonts;
  intptr_t paddings;
  void (__cdecl *idkFunc)(jkGuiMenu *);
  char *soundHover;
  char *soundClick;
  jkGuiElement *focusedElement;
  jkGuiElement *lastMouseDownClickable;
  jkGuiElement *lastMouseOverClickable;
  int32_t lastClicked;
  jkGuiElement* pReturnKeyShortcutElement;
  jkGuiElement* pEscapeKeyShortcutElement;
} jkGuiMenu;

typedef struct stdPalEffect
{
    rdVector3i filter;
    rdVector3 tint;
    rdVector3i add;
    flex_t fade;
} stdPalEffect;

typedef struct stdPalEffectsState
{
  int32_t bEnabled;
  int32_t field_4;
  int32_t field_8;
  int32_t field_C;
  int32_t field_10;
  stdPalEffect effect;
  int32_t bUseFilter;
  int32_t bUseTint;
  int32_t bUseAdd;
  int32_t bUseFade;
} stdPalEffectsState;

typedef struct stdPalEffectRequest
{
  int32_t isValid;
  int32_t idx;
  stdPalEffect effect;
} stdPalEffectRequest;

typedef struct stdConffileArg
{
    char* key;
    char* value;
} stdConffileArg;

typedef struct stdConffileEntry
{
    int32_t numArgs;
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
    int32_t child_loop_depth;
    int32_t parent_loop_depth;
    sith_cog_parser_node *parent;
    sith_cog_parser_node *child;
    int32_t opcode;
    int32_t value;
    cog_flex_t vector[3];
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

typedef struct jkHudMotsBitmap
{
    stdBitmap **pBitmap;
    char *path8bpp;
    char *path16bpp;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t unk4;
    uint32_t unk5;
} jkHudMotsBitmap;

typedef struct jkHudMotsFont
{
    stdFont **pFont;
    char *path8bpp;
    char *path16bpp;
} jkHudMotsFont;

typedef struct jkHudTeamScore
{
    int32_t field_0;
    int32_t score;
    int32_t field_8;
    int32_t field_C;
} jkHudTeamScore;

typedef struct jkHudPlayerScore
{
    wchar_t playerName[32];
    wchar_t modelName[32];
    int32_t score;
    int32_t teamNum;
} jkHudPlayerScore;

typedef struct rdScreenPoint
{
    uint32_t x;
    uint32_t y;
    flex_t z;
} rdScreenPoint;

typedef struct jkHudInvInfo
{
  uint32_t field_0;
  int32_t field_4;
  int32_t field_8[2];
  int32_t field_10[2];
  int32_t field_18;
  int32_t field_1C;
  int32_t rend_timeout_5secs;
  int32_t field_24;
  int32_t field_28;
  rdRect drawRect;
  int32_t field_3C;
} jkHudInvInfo;

typedef struct jkHudInvScroll
{
    uint32_t blitX;
    int32_t scroll;
    int32_t maxItemRend;
    int32_t field_C;
    int32_t field_10;
    int32_t rendIdx;
} jkHudInvScroll;

typedef void* DPLCONNECTION;

typedef struct sith_dplay_connection
{
  wchar_t name[128];
  GUID guid;
  DPLCONNECTION *connection;
  int32_t connectionSize;
} sith_dplay_connection;

#pragma pack(push, 4)
typedef struct jkMultiEntry
{
    GUID_idk guidInstance;
    int32_t maxPlayers;
    int32_t numPlayers;
    wchar_t serverName[32];
    char episodeGobName[32];
    char mapJklFname[32];
    wchar_t wPassword[32];
    int32_t sessionFlags;
    int32_t checksumSeed;
    int32_t field_E0;
    int32_t multiModeFlags;
    int32_t tickRateMs;
    int32_t maxRank;
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
    int32_t field_0;
    wchar_t serverName[32];
    char episodeGobName[32];
    char mapJklFname[128];
    int32_t maxPlayers;
    wchar_t wPassword[32];
    int32_t sessionFlags;
    int32_t multiModeFlags;
    int32_t maxRank;
    int32_t timeLimit;
    int32_t scoreLimit;
    int32_t tickRateMs;
} jkMultiEntry3;

typedef struct jkMultiEntry4
{
    char episodeGobName[32];
    char mapJklFname[32];
    int32_t field_40;
    int32_t field_44;
    int32_t field_48;
    int32_t field_4C;
    int32_t field_50;
    int32_t field_54;
    int32_t field_58;
    int32_t field_5C;
    int32_t field_60;
    int32_t field_64;
    int32_t field_68;
    int32_t field_6C;
    int32_t field_70;
    int32_t field_74;
    int32_t field_78;
    int32_t field_7C;
    int32_t field_80;
    int32_t field_84;
    int32_t field_88;
    int32_t field_8C;
    int32_t field_90;
    int32_t field_94;
    int32_t field_98;
    int32_t field_9C;
    wchar_t sessionName[32];
    int32_t tickRateMs;
} jkMultiEntry4;

typedef struct stdControlKeyInfoEntry
{
    int32_t dxKeyNum;
    uint32_t flags;
    flex_t binaryAxisVal;
} stdControlKeyInfoEntry;

typedef struct stdControlKeyInfo
{
    uint32_t numEntries;
    stdControlKeyInfoEntry aEntries[8];
} stdControlKeyInfo;

typedef struct stdControlJoystickEntry
{
    int32_t flags;
    int32_t uMinVal;
    int32_t uMaxVal;
    int32_t dwXoffs;
    int32_t dwYoffs;
    flex_t fRangeConversion;
} stdControlJoystickEntry;

typedef struct stdControlStickEntry
{
    int32_t dwXpos;
    int32_t dwYpos;
    int32_t dwZpos;
    int32_t dwRpos;
    int32_t dwUpos;
    int32_t dwVpos;
} stdControlStickEntry;

typedef struct stdControlDikStrToNum
{
    int32_t val;
    const char *pStr;
} stdControlDikStrToNum;

typedef struct jkGuiMouseSubEntry
{
    int32_t field_0;
    int32_t bitflag;
    flex_t field_8;
} jkGuiMouseSubEntry;

typedef struct jkGuiMouseEntry
{
    int32_t dxKeyNum;
    const char *displayStrKey;
    int32_t inputFuncIdx;
    int32_t flags;
    jkGuiMouseSubEntry *pSubEnt;
    int32_t bindIdx;
    int32_t mouseEntryIdx;
} jkGuiMouseEntry;

typedef struct jkGuiKeyboardEntry
{
    int32_t inputFuncIdx;
    int32_t axisIdx;
    int32_t dxKeyNum;
    int32_t field_C;
    int32_t field_10;
    int32_t field_14;
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
    int32_t field_40;
    int32_t field_44;
    int32_t field_48;
    int32_t field_4C;
    int32_t field_50;
    int32_t field_54;
    int32_t field_58;
    int32_t field_5C;
    int32_t field_60;
    int16_t field_64;
    int16_t field_66;
    int32_t field_68;
    int32_t field_6C;
    int32_t field_70;
    int32_t field_74;
    int32_t field_78;
    int32_t field_7C;
    int32_t field_80;
    int32_t field_84;
    int32_t field_88;
    int32_t field_8C;
    int32_t dpId;
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

typedef struct jkGuiJoystickStrings
{
    wchar_t aStrings[JOYSTICK_MAX_STRS][128];
} jkGuiJoystickStrings;

typedef struct jkGuiJoystickEntry
{
  int32_t dikNum;
  const char *displayStrKey;
  int32_t keybits;
  int32_t inputFunc;
  uint32_t flags;
  stdControlKeyInfoEntry *pControlEntry;
  int32_t dxKeyNum;
  union {
    int32_t binaryAxisValInt;
    flex_t binaryAxisVal;
  };
} jkGuiJoystickEntry;

typedef uint32_t (*sithWorld_ChecksumHandler_t)(uint32_t);

typedef struct jkBubbleInfo
{
    sithThing* pThing;
    flex_t radiusSquared;
    uint32_t type;
} jkBubbleInfo;

typedef struct sSithCvar
{
    const char* pName;
    const char* pNameLower;
    void* pLinkPtr;
    int32_t type;
    int32_t flags;
    union
    {
        intptr_t val;
        char* pStrVal;
        int32_t intVal;
        int32_t boolVal;
        flex_t flexVal;
    };
    union
    {
        intptr_t defaultVal;
        char* pDefaultStrVal;
        int32_t defaultIntVal;
        int32_t defaultBoolVal;
        flex_t defaultFlexVal;
    };
} tSithCvar;

typedef void (*sithCvarEnumerationFn_t)(tSithCvar*);

#ifdef GHIDRA_IMPORT
#include "Win95/stdGob.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdCanvas.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithAnimClass.h"
#include "General/stdHashTable.h"
#include "General/stdStrTable.h"
#include "General/stdFont.h"
#include "General/stdFileUtil.h"
#include "General/stdPcx.h"
#include "Cog/sithCog.h"
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
#include "General/stdBitmapRle.h"
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

#include "version.h"

#ifdef __cplusplus
}
#endif

#endif // TYPES_H
