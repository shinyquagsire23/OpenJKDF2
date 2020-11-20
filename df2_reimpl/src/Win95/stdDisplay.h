#ifndef _STDDISPLAY_H
#define _STDDISPLAY_H

#include "Engine/rdMaterial.h"
#include "Primitives/rdRect.h"
#include "types.h"

#define stdDisplay_ddraw_waitforvblank_ADDR (0x004230A0)
#define stdDisplay_free_texture_ADDR (0x4232F0)
#define stdDisplay_VBufferNew_ADDR (0x004230C0)
#define stdDisplay_VBufferSetColorKey_ADDR (0x00423830)
#define stdDisplay_VBufferLock_ADDR (0x004233C0)
#define stdDisplay_VBufferUnlock_ADDR (0x00423450)
#define stdDisplay_VBufferCopy_ADDR (0x4237B0)
#define stdDisplay_SetMasterPalette_ADDR (0x423BB0)
#define stdDisplay_streamidk_ADDR (0x423740)
#define stdDisplay_DrawAndFlipGdi_ADDR (0x422E80)
#define stdDisplay_SetCooperativeLevel_ADDR (0x422F90)
#define stdDisplay_ddraw_surface_flip_ADDR (0x00422FC0)

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
  texture_format format;
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

static void (*stdDisplay_ddraw_waitforvblank)(void) = (void*)stdDisplay_ddraw_waitforvblank_ADDR;
static void (__cdecl *stdDisplay_free_texture)(stdVBuffer *a1) = (void*)stdDisplay_free_texture_ADDR;

static stdVBuffer* (__cdecl *stdDisplay_VBufferNew)(texture_format *a1, int create_ddraw_surface, int gpu_mem, int is_paletted) = (void*)stdDisplay_VBufferNew_ADDR;
static int (__cdecl *stdDisplay_VBufferSetColorKey)(stdVBuffer *a1, int color) = (void*)stdDisplay_VBufferSetColorKey_ADDR;
static int (__cdecl *stdDisplay_VBufferLock)(stdVBuffer *a1) = (void*)stdDisplay_VBufferLock_ADDR;
static void (__cdecl *stdDisplay_VBufferUnlock)(stdVBuffer *a1) = (void*)stdDisplay_VBufferUnlock_ADDR;
static int (*stdDisplay_VBufferCopy)(stdVBuffer *vbuf, stdVBuffer *vbuf2, unsigned int blit_x, int blit_y, rdRect *rect, int alpha_maybe) = (void*)stdDisplay_VBufferCopy_ADDR;
static int (*stdDisplay_SetMasterPalette)(uint8_t* pal) = (void*)stdDisplay_SetMasterPalette_ADDR;
static int (*stdDisplay_streamidk)(stdVBuffer *buf, int fillColor, rdRect *rect) = (void*)stdDisplay_streamidk_ADDR;
static void (*stdDisplay_DrawAndFlipGdi)() = (void*)stdDisplay_DrawAndFlipGdi_ADDR;
static void (*stdDisplay_SetCooperativeLevel)() = (void*)stdDisplay_SetCooperativeLevel_ADDR;
static int (*stdDisplay_ddraw_surface_flip)() = (void*)stdDisplay_ddraw_surface_flip_ADDR;

#define stdDisplay_pCurDevice (*(stdVideoDevice**)0x0055B3E8)
#define stdDisplay_pCurVideoMode (*(stdVideoMode **)0x0055B3F0)

#endif // _STDDISPLAY_H
