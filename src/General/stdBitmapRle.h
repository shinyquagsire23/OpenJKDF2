#ifndef _STDBITMAPRLE_H
#define _STDBITMAPRLE_H

#include "types.h"
#include "Engine/rdMaterial.h"

#pragma pack(push, 1)
typedef struct rleBitmapHeader
{
    uint16_t magic;
    uint32_t total_size;
    uint32_t field_6;
    uint32_t data_start;
} rleBitmapHeader;

typedef struct rleBitmapHeaderExt
{
    uint32_t ext_length;
    uint32_t width;
    uint32_t height;
    uint16_t field_C;
    uint16_t bpp;

    uint32_t format;
    uint32_t data_length;
    uint32_t field_18;
    uint32_t field_1C;

    uint32_t field_20;
    uint32_t field_24;
} rleBitmapHeaderExt;

typedef struct stdRleBitmap
{
    void* vtable;
    uint16_t width;
    uint16_t height;
    uint32_t bIdk;
    void* data;
} stdRleBitmap;

typedef struct stdRleBitmap2
{
    void* vtable;
    uint16_t width;
    uint16_t height;
    uint32_t field_8;
    uint32_t field_C;
    void* data;
    uint32_t field_14;
} stdRleBitmap2;

typedef struct bitmapExtent
{
    int16_t x;
    int16_t y;
    int16_t width;
    int16_t height;
} bitmapExtent;
#pragma pack(pop)

#endif // _STDBITMAPRLE_H