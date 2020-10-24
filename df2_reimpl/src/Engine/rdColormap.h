#ifndef _RDCOLORMAP_H
#define _RDCOLORMAP_H

#include "Primitives/rdVector.h"
#include "Engine/rdMaterial.h"
#include "types.h"

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

#define rdColormap_pCurMap (*(rdColormap**)0x0073A3C8)
#define rdColormap_pIdentityMap (*(rdColormap**)0x0073A3CC)

int rdColormap_SetCurrent(rdColormap *colormap);
int rdColormap_SetIdentity(rdColormap *colormap);
rdColormap* rdColormap_Load(char *colormap_fname);
void rdColormap_Free(rdColormap *colormap);
void rdColormap_FreeEntry(rdColormap *colormap);
int rdColormap_Write(char *outpath, rdColormap *colormap);

static int (__cdecl *rdColormap_LoadEntry)(char *colormap_fname, rdColormap *colormap) = rdColormap_LoadEntry_ADDR;

#endif // _RDCOLORMAP_H
