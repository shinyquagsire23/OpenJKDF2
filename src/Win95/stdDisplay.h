#ifndef _STDDISPLAY_H
#define _STDDISPLAY_H

#include "Engine/rdMaterial.h"
#include "Primitives/rdRect.h"
#include "types.h"
#include "globals.h"
#include "Win95/Video.h"
#include "Win95/stdVBuffer.h"

#define stdDisplay_Startup_ADDR (0x0421FC0)
#define stdDisplay_RestoreDisplayMode_ADDR (0x04220B0)
#define stdDisplay_Open_ADDR (0x04220E0)
#define stdDisplay_Close_ADDR (0x04224D0)
#define stdDisplay_SetMode_ADDR (0x04226A0)
#define stdDisplay_422A50_ADDR (0x0422A50)
#define stdDisplay_ClearMode_ADDR (0x0422C30)
#define stdDisplay_DrawAndFlipGdi_ADDR (0x0422E80)
#define stdDisplay_SetCooperativeLevel_ADDR (0x0422F90)
#define stdDisplay_DDrawGdiSurfaceFlip_ADDR (0x0422FC0)
#define stdDisplay_ddraw_surface_flip2_ADDR (0x0423050)
#define stdDisplay_ddraw_waitforvblank_ADDR (0x04230A0)
#define stdDisplay_VBufferNew_ADDR (0x04230C0)
#define stdDisplay_VBufferFree_ADDR (0x04232F0)
#define stdDisplay_423360_ADDR (0x0423360)
#define stdDisplay_VBufferLock_ADDR (0x04233C0)
#define stdDisplay_VBufferUnlock_ADDR (0x0423450)
#define stdDisplay_VBufferFill_ADDR (0x04234E0)
#define stdDisplay_ClearRect_ADDR (0x0423740)
#define stdDisplay_VBufferCopy_ADDR (0x04237B0)
#define stdDisplay_VBufferSetColorKey_ADDR (0x0423830)
#define stdDisplay_VBufferConvertColorFormat_ADDR (0x0423880)
#define stdDisplay_sub_423B80_ADDR (0x0423B80)
#define stdDisplay_SetMasterPalette_ADDR (0x0423BB0)
#define stdDisplay_GammaCorrect_ADDR (0x0423CB0)
#define stdDisplay_GammaCorrect2_ADDR (0x0423D10)
#define stdDisplay_SetGammaTable_ADDR (0x0423E10)
#define stdDisplay_GammaCorrect3_ADDR (0x0423E30)
#define stdDisplay_GammaCorrect4_ADDR (0x0423F80)
#define stdDisplay_GetPalette_ADDR (0x0423FF0)
#define stdDisplay_SetPalette_ADDR (0x0424000)
#define stdDisplay_TextOut_ADDR (0x04240F0)
#define stdDisplay_FindClosestDevice_ADDR (0x04242B0)
#define stdDisplay_FindClosestMode_ADDR (0x0424340)
#define stdDisplay_GetModeInfo_ADDR (0x04243F0)
#define stdDisplay_sub_424440_ADDR (0x0424440)
#define stdDisplay_SortVideoModes_ADDR (0x04246E0)

void stdDisplay_SetGammaTable(int len, uint32_t *table);
uint8_t* stdDisplay_GetPalette();

static void (*stdDisplay_DrawAndFlipGdi)() = (void*)stdDisplay_DrawAndFlipGdi_ADDR;
static void (*stdDisplay_SetCooperativeLevel)() = (void*)stdDisplay_SetCooperativeLevel_ADDR;
static void (*stdDisplay_422A50)() = (void*)stdDisplay_422A50_ADDR;
static void (*stdDisplay_ClearMode)() = (void*)stdDisplay_ClearMode_ADDR;
//static char* (*stdDisplay_GetPalette)() = (void*)stdDisplay_GetPalette_ADDR;

#ifndef SDL2_RENDER
static int (*stdDisplay_Startup)() = (void*)stdDisplay_Startup_ADDR;
static int (*stdDisplay_VBufferFill)(stdVBuffer *a2, int fillColor, rdRect *a4) = (void*)stdDisplay_VBufferFill_ADDR;
static int (*stdDisplay_VBufferCopy)(stdVBuffer *vbuf, stdVBuffer *vbuf2, unsigned int blit_x, int blit_y, rdRect *rect, int alpha_maybe) = (void*)stdDisplay_VBufferCopy_ADDR;
static int (*stdDisplay_SetMasterPalette)(uint8_t* pal) = (void*)stdDisplay_SetMasterPalette_ADDR;
static int (*stdDisplay_DDrawGdiSurfaceFlip)() = (void*)stdDisplay_DDrawGdiSurfaceFlip_ADDR;
static int (*stdDisplay_ClearRect)(stdVBuffer *buf, int fillColor, rdRect *rect) = (void*)stdDisplay_ClearRect_ADDR;
static int (*stdDisplay_SetMode)(unsigned int modeIdx, const void *palette, int paged) = (void*)stdDisplay_SetMode_ADDR;
static int (*stdDisplay_FindClosestMode)(render_pair *a1, struct stdVideoMode *render_surface, unsigned int max_modes) = (void*)stdDisplay_FindClosestMode_ADDR;
static int (*stdDisplay_FindClosestDevice)(stdDeviceParams *a1) = (void*)stdDisplay_FindClosestDevice_ADDR;
static void (*stdDisplay_Close)() = (void*)stdDisplay_Close_ADDR;
static int (*stdDisplay_Open)(unsigned int index) = (void*)stdDisplay_Open_ADDR;
static stdVBuffer* (__cdecl *stdDisplay_VBufferNew)(stdVBufferTexFmt *a1, int create_ddraw_surface, int gpu_mem, void* palette) = (void*)stdDisplay_VBufferNew_ADDR;
static int (__cdecl *stdDisplay_VBufferLock)(stdVBuffer *a1) = (void*)stdDisplay_VBufferLock_ADDR;
static void (__cdecl *stdDisplay_VBufferUnlock)(stdVBuffer *a1) = (void*)stdDisplay_VBufferUnlock_ADDR;
static int (__cdecl *stdDisplay_VBufferSetColorKey)(stdVBuffer *a1, int color) = (void*)stdDisplay_VBufferSetColorKey_ADDR;
static void (__cdecl *stdDisplay_VBufferFree)(stdVBuffer *a1) = (void*)stdDisplay_VBufferFree_ADDR;
static void (*stdDisplay_ddraw_waitforvblank)(void) = (void*)stdDisplay_ddraw_waitforvblank_ADDR;
static void (*stdDisplay_ddraw_surface_flip2)() = (void*)stdDisplay_ddraw_surface_flip2_ADDR;
static void (*stdDisplay_RestoreDisplayMode)() = (void*)stdDisplay_RestoreDisplayMode_ADDR;
static stdVBuffer* (*stdDisplay_VBufferConvertColorFormat)(void* a, stdVBuffer* b) = (void*)stdDisplay_VBufferConvertColorFormat_ADDR;
static int (*stdDisplay_GammaCorrect3)(int a1) = (void*)stdDisplay_GammaCorrect3_ADDR;
#else
extern uint32_t Video_menuTexId;
extern rdColor24 stdDisplay_masterPalette[256];

int stdDisplay_Startup();
int stdDisplay_VBufferFill(stdVBuffer *a2, int fillColor, rdRect *a4);
int stdDisplay_VBufferCopy(stdVBuffer *vbuf, stdVBuffer *vbuf2, unsigned int blit_x, int blit_y, rdRect *rect, int alpha_maybe);
int stdDisplay_SetMasterPalette(uint8_t* pal);
int stdDisplay_DDrawGdiSurfaceFlip();
int stdDisplay_ddraw_waitforvblank();
int stdDisplay_ClearRect(stdVBuffer *buf, int fillColor, rdRect *rect);
int stdDisplay_SetMode(unsigned int modeIdx, const void *palette, int paged);
int stdDisplay_FindClosestMode(render_pair *a1, struct stdVideoMode *render_surface, unsigned int max_modes);
int stdDisplay_FindClosestDevice(void* a);
int stdDisplay_Open(int a);
void stdDisplay_Close();
stdVBuffer* stdDisplay_VBufferNew(stdVBufferTexFmt *a1, int create_ddraw_surface, int gpu_mem, void* palette);
int stdDisplay_VBufferLock(stdVBuffer *a1);
void stdDisplay_VBufferUnlock(stdVBuffer *a1);
int stdDisplay_VBufferSetColorKey(stdVBuffer *vbuf, int color);
void stdDisplay_VBufferFree(stdVBuffer *vbuf);
void stdDisplay_ddraw_surface_flip2();
void stdDisplay_RestoreDisplayMode();
stdVBuffer* stdDisplay_VBufferConvertColorFormat(void* a, stdVBuffer* b);
int stdDisplay_GammaCorrect3(int a1);
#endif

#endif // _STDDISPLAY_H
