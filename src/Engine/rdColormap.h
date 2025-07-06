#ifndef _RDCOLORMAP_H
#define _RDCOLORMAP_H

#include "Engine/rdMaterial.h"
#include "types.h"
#include "globals.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rdColormap_SetCurrent_ADDR (0x00442510)
#define rdColormap_SetIdentity_ADDR (0x00442560)
#define rdColormap_Load_ADDR (0x004425A0)
#define rdColormap_LoadEntry_ADDR (0x00442660)
#define rdColormap_Free_ADDR (0x00442930)
#define rdColormap_FreeEntry_ADDR (0x004429C0)
#define rdColormap_Write_ADDR (0x00442A50)
#define rdColormap_BuildMono_ADDR (0x00442B80)
#define rdColormap_BuildRGB16_ADDR (0x00442D10)
#define rdColormap_BuildRGBToPalette16_ADDR (0x00442F90)
#define rdColormap_BuildAlpha_ADDR (0x00443060)
#define rdColormap_BuildGrayRamp_ADDR (0x00443190)

int rdColormap_SetCurrent(rdColormap *colormap);
int rdColormap_SetIdentity(rdColormap *colormap);
rdColormap* rdColormap_Load(char *colormap_fname);
int rdColormap_LoadEntry(char *colormap_fname, rdColormap *colormap);
void rdColormap_Free(rdColormap *colormap);
void rdColormap_FreeEntry(rdColormap *colormap);
int rdColormap_Write(char *outpath, rdColormap *colormap);

int rdColormap_BuildRGB16(uint16_t *paColors16, rdColor24 *paColors24, uint8_t a4, uint8_t a5, uint8_t a6, rdTexformat *format);
int rdColormap_BuildGrayRamp(rdColormap* pColormap);

//static int (*rdColormap_BuildGrayRamp)(rdColormap *colormap) = (void*)rdColormap_BuildGrayRamp_ADDR;
//static int (*rdColormap_BuildRGB16)(uint16_t *a2, rdColor24 *a3, uint8_t a4, uint8_t a5, uint8_t a6, rdTexformat *format) = (void*)rdColormap_BuildRGB16_ADDR;
//static int (__cdecl *rdColormap_LoadEntry)(char *colormap_fname, rdColormap *colormap) = (void*)rdColormap_LoadEntry_ADDR;

#ifdef __cplusplus
}
#endif

#endif // _RDCOLORMAP_H
