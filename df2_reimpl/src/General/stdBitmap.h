#ifndef _STDBITMAP_H
#define _STDBITMAP_H

#include "types.h"
#include "Engine/rdMaterial.h"

typedef struct stdBitmap
{
    int field_0;
    int field_4;
    int field_8;
    int field_C;
    int field_10;
    int field_14;
    int field_18;
    uint8_t field_1C;
    uint8_t field_1D;
    uint8_t field_1E;
    uint8_t field_1F;
    int field_20;
    int palFmt;
    rdTexformat format;
    void *palette;
    int numMips;
    int field_68;
    int xPos;
    int yPos;
    uint32_t colorkey;
    stdVBuffer **mipSurfaces;
} stdBitmap;

typedef struct bitmapHeader
{
    uint32_t magic;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t palFmt;
    uint32_t numMips;
    uint32_t xPos;
    uint32_t yPos;
    uint32_t colorkey;
    rdTexformat format;
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
} bitmapHeader;

#define stdBitmap_Load_ADDR (0x0042CAA0)
#define stdBitmap_LoadFromFile_ADDR (0x0042CB80)
#define stdBitmap_LoadEntry_ADDR (0x0042CCA0)
#define stdBitmap_LoadEntryFromFile_ADDR (0x0042CD30)
#define stdBitmap_Free_ADDR (0x0042D040)
#define stdBitmap_FreeEntry_ADDR (0x0042D100)
#define stdBitmap_AppendToFile_ADDR (0x0042D180)
#define stdBitmap_Write_ADDR (0x0042D400)
#define stdBitmap_ConvertColorFormat_ADDR (0x0042D4B0)
#define stdBitmap_Convert24to16bpp_ADDR (0x0042D580)
#define stdBitmap_VBufferToBitmap_ADDR (0x0042D730)
#define stdBitmap_New_ADDR (0x0042D810)
#define stdBitmap_NewEntry_ADDR (0x0042D920)
#define stdBitmap_MemUsage_ADDR (0x0042D9D0)

stdBitmap* stdBitmap_Load(char *fpath, int bCreateDDrawSurface, int gpuMem);
stdBitmap* stdBitmap_LoadFromFile(intptr_t fd, int bCreateDDrawSurface, int a3);
int stdBitmap_LoadEntry(char *fpath, stdBitmap *out, int bCreateDDrawSurface, int gpuMem);
int stdBitmap_LoadEntryFromFile(intptr_t fp, stdBitmap *out, int bCreateDDrawSurface, int gpuMem);
void stdBitmap_ConvertColorFormat(rdTexformat *formatTo, stdBitmap *bitmap);

//static rdTexformat* (*stdBitmap_ConvertColorFormat)(rdTexformat *formatTo, stdBitmap *bitmap) = (void*)stdBitmap_ConvertColorFormat_ADDR;

//static stdBitmap* (*stdBitmap_Load)(char *fpath, int create_ddraw_surface, int a3) = (void*)stdBitmap_Load_ADDR;
static void (*stdBitmap_Free)(stdBitmap *bitmap) = (void*)stdBitmap_Free_ADDR;
//static stdBitmap* (*stdBitmap_LoadFromFile)(int a1, int a2, int a3) = (void*)stdBitmap_LoadFromFile_ADDR;
//static int (*stdBitmap_LoadEntryFromFile)(intptr_t fp, stdBitmap *a2, int bCreateDDrawSurface, int gpuMem) = (void*)stdBitmap_LoadEntryFromFile_ADDR;

#endif // _STDBITMAP_H
