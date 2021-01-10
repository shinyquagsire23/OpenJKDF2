#ifndef _STD3D_H
#define _STD3D_H

#define std3D_Startup_ADDR (0x00429310)
#define std3D_Shutdown_ADDR (0x00429390)
#define std3D_FindClosestDevice_ADDR (0x004293B0)
#define std3D_PurgeTextureCache_ADDR (0x00429750)
#define std3D_GetRenderList_ADDR (0x00429860)
#define std3D_SetRenderList_ADDR (0x00429870)
#define std3D_SetFogColor_ADDR (0x00429880)
#define std3D_SetFogDistances_ADDR (0x004298A0)
#define std3D_GetValidDimensions_ADDR (0x004298C0)
#define std3D_StartScene_ADDR (0x004298F0)
#define std3D_EndScene_ADDR (0x00429900)
#define std3D_ResetRenderList_ADDR (0x00429910)
#define std3D_AddRenderListVertices_ADDR (0x00429970)
#define std3D_RenderListVerticesFinish_ADDR (0x004299D0)
#define std3D_AddRenderListTris_ADDR (0x00429A20)
#define std3D_DrawRenderList_ADDR (0x00429BD0)
#define std3D_AddRenderListTrisAttributes_ADDR (0x00429C80)
#define std3D_SetCurrentPalette_ADDR (0x00429EF0)
#define std3D_GetValidDimension_ADDR (0x00429FA0)
#define std3D_AddToTextureCache_ADDR (0x0042A040)
#define std3D_UnloadAllTextures_ADDR (0x0042A890)
#define std3D_AppendTextureToList_ADDR (0x0042A910)
#define std3D_RemoveTextureFromList_ADDR (0x0042A980)
#define std3D_42AA20_ADDR (0x0042AA20)
#define std3D_UpdateFrameCount_ADDR (0x0042AA90)
#define std3D_ClearZBuffer_ADDR (0x0042AB90)
#define std3D_42AC40_ADDR (0x0042AC40)
#define std3D_FindClosestTextureFormat_ADDR (0x0042ACD0)
#define std3D_DrawOverlay_ADDR (0x0042ADB0)
#define std3D_InitializeViewport_ADDR (0x0042B360)
#define std3D_CreateExecuteBuffer_ADDR (0x0042B450)
#define std3D_CreateViewport_ADDR (0x0042B810)
#define std3D_CreateZBuffer_ADDR (0x0042B920)
#define std3D_EnumerateCallback_ADDR (0x0042BA60)
#define std3D_EnumerateTexturesCallback_ADDR (0x0042BC80)
#define std3D_D3DBitdepthToRdBitdepth_ADDR (0x0042BF50)
#define std3D_RdBitdepthToD3DBitdepth_ADDR (0x0042BF90)
#define std3D_42BFE0_ADDR (0x0042BFE0)
#define std3D_42C030_ADDR (0x0042C030)

#define d3d_maxVertices (*(uint32_t*)0x0055C7F0)
#define d3d_device_ptr (*(d3d_device**)0x0055C7DC)

typedef float D3DVALUE;

#pragma pack(push, 4)
typedef struct D3DVERTEX
{
  union __declspec(align(4))
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
} D3DVERTEX;
#pragma pack(pop)

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

typedef struct __declspec(align(16)) d3d_device
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
  __declspec(align(16)) D3DDeviceDesc device_desc;
  DWORD d3d_this;
} d3d_device;

typedef struct rdTri rdTri;

static int (*std3D_ClearZBuffer)() = (void*)std3D_ClearZBuffer_ADDR;
static int (*std3D_StartScene)() = (void*)std3D_StartScene_ADDR;
static int (*std3D_EndScene)() = (void*)std3D_EndScene_ADDR;
static void (*std3D_ResetRenderList)() = (void*)std3D_ResetRenderList_ADDR;
static void (*std3D_DrawRenderList)() = (void*)std3D_DrawRenderList_ADDR;
static int (*std3D_RenderListVerticesFinish)() = (void*)std3D_RenderListVerticesFinish_ADDR;
static int (*std3D_AddRenderListVertices)(void *vertex_array, int count) = (void*)std3D_AddRenderListVertices_ADDR;
static void (*std3D_AddRenderListTris)(rdTri *tris, unsigned int num_tris) = (void*)std3D_AddRenderListTris_ADDR;
static signed int (__cdecl *std3D_SetCurrentPalette)(rdColor24 *a1, int a2) = (void*)std3D_SetCurrentPalette_ADDR;

static unsigned int* (*std3D_GetValidDimension)(unsigned int a1, unsigned int a2, unsigned int *a3, unsigned int *a4) = (void*)std3D_GetValidDimension_ADDR;

#endif // _STD3D_H
