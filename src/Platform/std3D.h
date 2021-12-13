#ifndef _STD3D_H
#define _STD3D_H

#include "types.h"
#include "globals.h"

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

// Added
int std3D_HasAlpha();
int std3D_HasModulateAlpha();
int std3D_HasAlphaFlatStippled();

#ifdef SDL2_RENDER
int std3D_Startup();
void std3D_Shutdown();
int std3D_StartScene();
int std3D_EndScene();
void std3D_ResetRenderList();
int std3D_RenderListVerticesFinish();
void std3D_DrawRenderList();
int std3D_SetCurrentPalette(rdColor24 *a1, int a2);
void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int *outW, unsigned int *outH);
int std3D_DrawOverlay();
void std3D_UnloadAllTextures();
void std3D_AddRenderListTris(rdTri *tris, unsigned int num_tris);
void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines);
int std3D_AddRenderListVertices(D3DVERTEX *vertex_array, int count);
void std3D_UpdateFrameCount(rdDDrawSurface *surface);
void std3D_PurgeTextureCache();
void std3D_Shutdown();
int std3D_ClearZBuffer();
int std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_16bit_maybe, int no_alpha);
void std3D_DrawMenu();
void std3D_FreeResources();
#else
static int (*std3D_Startup)() = (void*)std3D_Startup_ADDR;
static void (*std3D_Shutdown)() = (void*)std3D_Shutdown_ADDR;
static int (*std3D_StartScene)() = (void*)std3D_StartScene_ADDR;
static int (*std3D_EndScene)() = (void*)std3D_EndScene_ADDR;
static void (*std3D_ResetRenderList)() = (void*)std3D_ResetRenderList_ADDR;
static int (*std3D_RenderListVerticesFinish)() = (void*)std3D_RenderListVerticesFinish_ADDR;
static void (*std3D_DrawRenderList)() = (void*)std3D_DrawRenderList_ADDR;
static int (*std3D_SetCurrentPalette)(rdColor24 *a1, int a2) = (void*)std3D_SetCurrentPalette_ADDR;
static unsigned int* (*std3D_GetValidDimension)(unsigned int a1, unsigned int a2, unsigned int *a3, unsigned int *a4) = (void*)std3D_GetValidDimension_ADDR;;
static int (*std3D_DrawOverlay)() = (void*)std3D_DrawOverlay_ADDR;
static void (*std3D_UnloadAllTextures)() = (void*)std3D_UnloadAllTextures_ADDR;
static void (*std3D_AddRenderListTris)(rdTri *tris, unsigned int num_tris) = (void*)std3D_AddRenderListTris_ADDR;
static int (*std3D_AddRenderListVertices)(D3DVERTEX *vertex_array, int count) = (void*)std3D_AddRenderListVertices_ADDR;
static int (*std3D_ClearZBuffer)() = (void*)std3D_ClearZBuffer_ADDR;
static int (*std3D_AddToTextureCache)(stdVBuffer *a1, rdDDrawSurface *tex_2, int is_16bit_maybe, int no_alpha) = (void*)std3D_AddToTextureCache_ADDR;
static void (*std3D_UpdateFrameCount)(rdDDrawSurface *surface) = (void*)std3D_UpdateFrameCount_ADDR;
static void (*std3D_PurgeTextureCache)() = (void*)std3D_PurgeTextureCache_ADDR;
#endif

#endif // _STD3D_H
