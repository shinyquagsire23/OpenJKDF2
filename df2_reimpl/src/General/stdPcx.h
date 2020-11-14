#ifndef _STDPCX_H
#define _STDPCX_H

#include <stdint.h>

#define stdPcx_Load_ADDR (0x0042D9F0)
#define stdPcx_Write_ADDR (0x0042DC50)

typedef struct stdBitmap stdBitmap;

typedef struct stdPcx_Header
{
    uint8_t magic;
    uint8_t version;
    uint8_t isRle;
    uint8_t bitDepth;
    uint16_t xMin;
    uint16_t yMin;
    uint16_t xMax;
    uint16_t yMax;
    uint16_t xDpi;
    uint16_t yDpi;
    uint8_t egaPalette[48];
    uint8_t reserved_40;
    uint8_t colorDims;
    uint16_t stride;
    uint16_t paletteMode;
    uint16_t width;
    uint16_t height;
    uint8_t reserved_4A[54];
} stdPcx_Header;

stdBitmap* stdPcx_Load(char *fpath, int create_ddraw_surface, int gpu_mem);
int stdPcx_Write(char *fpath, stdBitmap *bitmap);

#endif // _STDPCX_H
