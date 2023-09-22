#include "Platform/std3D.h"

int std3D_bReinitHudElements = 0;

int std3D_Startup()
{
    return 0;
}
void std3D_Shutdown() {}
int std3D_StartScene()
{
    return 0;
}
int std3D_EndScene()
{
    return 0;
}
void std3D_ResetRenderList() {}
int std3D_RenderListVerticesFinish()
{
    return 0;
}
void std3D_DrawRenderList() {}
int std3D_SetCurrentPalette(rdColor24 *a1, int a2)
{
    return 0;
}
void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int *outW, unsigned int *outH) {}
int std3D_DrawOverlay()
{
    return 0;
}
void std3D_UnloadAllTextures() {}
void std3D_AddRenderListTris(rdTri *tris, unsigned int num_tris) {}
void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines) {}
int std3D_AddRenderListVertices(D3DVERTEX *vertex_array, int count)
{
    return 0;
}
void std3D_UpdateFrameCount(rdDDrawSurface *surface) {}
void std3D_PurgeTextureCache() {}
int std3D_ClearZBuffer()
{
    return 0;
}
int std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha)
{
    return 0;
}
void std3D_DrawMenu() {}
void std3D_DrawSceneFbo() {}
void std3D_FreeResources() {}
void std3D_InitializeViewport(rdRect *viewRect) {}
int std3D_GetValidDimensions(int a1, int a2, int a3, int a4)
{
    return 0;
}
int std3D_FindClosestDevice(uint32_t index, int a2)
{
    return 0;
}
int std3D_SetRenderList(intptr_t a1)
{
    return 0;
}
intptr_t std3D_GetRenderList()
{
    return 0;
}
int std3D_CreateExecuteBuffer()
{
    return 0;
}

int std3D_HasAlpha() { return 0; }
int std3D_HasAlphaFlatStippled() { return 0; }
int std3D_HasModulateAlpha() { return 0; }



void std3D_PurgeUIEntry(int i, int idx) {}
void std3D_PurgeTextureEntry(int i) {}
void std3D_PurgeBitmapRefs(stdBitmap *pBitmap) {}
void std3D_PurgeSurfaceRefs(rdDDrawSurface *texture) {}
void std3D_UpdateSettings() {}
void std3D_Screenshot(const char* pFpath) {}

void std3D_ResetUIRenderList() {}
int std3D_AddBitmapToTextureCache(stdBitmap *texture, int mipIdx, int is_alpha_tex, int no_alpha) {}
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, float dstX, float dstY, rdRect* srcRect, float scaleX, float scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, float dstX, float dstY, rdRect* srcRect, float scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
int std3D_IsReady() {}