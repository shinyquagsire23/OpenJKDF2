#ifndef _STDBITMAP_H
#define _STDBITMAP_H

typedef struct stdVBuffer stdVBuffer;

typedef struct stdBitmap
{
    int field_0;
    int field_4;
    int field_8;
    int field_C;
    int field_10;
    int field_14;
    int field_18;
    int field_1C;
    int field_20;
    int palFmt;
    int field_28;
    int bitDepth;
    int field_30;
    int field_34;
    int field_38;
    int field_3C;
    int field_40;
    int field_44;
    int field_48;
    int field_4C;
    int field_50;
    int field_54;
    int field_58;
    int field_5C;
    void *palette;
    int numMips;
    int field_68;
    int field_6C;
    int field_70;
    void* colorkey;
    stdVBuffer **mipSurfaces;
} stdBitmap;

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

static stdBitmap* (*stdBitmap_Load)(char *fpath, int create_ddraw_surface, int a3) = (void*)stdBitmap_Load_ADDR;
static void (*stdBitmap_Free)(stdBitmap *bitmap) = (void*)stdBitmap_Free_ADDR;

#endif // _STDBITMAP_H
