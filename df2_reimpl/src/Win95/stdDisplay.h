#ifndef _STDDISPLAY_H
#define _STDDISPLAY_H

#include "Engine/rdMaterial.h"

#define stdDisplay_ddraw_waitforvblank_ADDR (0x004230A0)
#define stdDisplay_free_texture_ADDR (0x4232F0)
#define stdDisplay_VBufferNew_ADDR (0x004230C0)
#define stdDisplay_VBufferSetColorKey_ADDR (0x00423830)
#define stdDisplay_VBufferLock_ADDR (0x004233C0)
#define stdDisplay_VBufferUnlock_ADDR (0x00423450)


static void (*stdDisplay_ddraw_waitforvblank)(void) = stdDisplay_ddraw_waitforvblank_ADDR;
static void (__cdecl *stdDisplay_free_texture)(stdVBuffer *a1) = stdDisplay_free_texture_ADDR;

static stdVBuffer* (__cdecl *stdDisplay_VBufferNew)(texture_format *a1, int create_ddraw_surface, int gpu_mem, int is_paletted) = stdDisplay_VBufferNew_ADDR;
static int (__cdecl *stdDisplay_VBufferSetColorKey)(stdVBuffer *a1, int color) = stdDisplay_VBufferSetColorKey_ADDR;
static void (__cdecl *stdDisplay_VBufferLock)(stdVBuffer *a1) = stdDisplay_VBufferLock_ADDR;
static void (__cdecl *stdDisplay_VBufferUnlock)(stdVBuffer *a1) = stdDisplay_VBufferUnlock_ADDR;

#endif // _STDDISPLAY_H
