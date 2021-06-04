#include "stdBitmap.h"

#include "stdPlatform.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"
#include "jk.h"

stdBitmap* stdBitmap_Load(char *fpath, int bCreateDDrawSurface, int gpuMem)
{
    stdBitmap *outAlloc; // esi
    stdBitmap *result; // eax
    intptr_t fp; // edi
    signed int v6; // ebx
    const char *v7; // eax

    outAlloc = (stdBitmap *)std_pHS->alloc(sizeof(stdBitmap));
    if ( outAlloc )
    {
        fp = std_pHS->fileOpen(fpath, "rb");
        if ( fp )
        {
            v7 = stdFileFromPath(fpath);
            _strncpy((char *)outAlloc, v7, 0x1Fu);
            outAlloc->field_1F = 0;
            v6 = stdBitmap_LoadEntryFromFile(fp, outAlloc, bCreateDDrawSurface, gpuMem);
            std_pHS->fileClose(fp);
        }
        else
        {
            stdPrintf((int)std_pHS->errorPrint, ".\\General\\stdBitmap.c", 147, "Error: Invalid load filename '%s'.\n", fpath);
            v6 = 0;
        }
        if ( v6 )
        {
            result = outAlloc;
        }
        else
        {
            std_pHS->free(outAlloc);
            result = 0;
        }
    }
    else
    {
        stdPrintf((int)std_pHS->errorPrint, ".\\General\\stdBitmap.c", 68, "Error: Unable to allocate memory for bitmap '%s'\n", fpath);
        result = 0;
    }
    return result;
}

stdBitmap* stdBitmap_LoadFromFile(intptr_t fd, int bCreateDDrawSurface, int a3)
{
    stdBitmap *outAlloc; // esi
    stdBitmap *result; // eax
    unsigned int i; // edi

    outAlloc = (stdBitmap *)std_pHS->alloc(sizeof(stdBitmap));
    if ( outAlloc )
    {
        if ( stdBitmap_LoadEntryFromFile(fd, outAlloc, bCreateDDrawSurface, a3) )
        {
            result = outAlloc;
        }
        else
        {
            if ( outAlloc->mipSurfaces )
            {
                for ( i = 0; i < outAlloc->numMips; ++i )
                {
                    if ( outAlloc->mipSurfaces[i] )
                        stdDisplay_VBufferFree(outAlloc->mipSurfaces[i]);
                }
                std_pHS->free(outAlloc->mipSurfaces);
            }
            if ( outAlloc->palette )
                std_pHS->free(outAlloc->palette);
            stdPrintf(std_pHS->debugPrint, ".\\General\\stdBitmap.c", 359, "Bitmap elements successfully freed.\n", 0, 0, 0, 0);
            std_pHS->free(outAlloc);
            stdPrintf(std_pHS->debugPrint, ".\\General\\stdBitmap.c", 322, "Bitmap successfully freed.\n", 0, 0, 0, 0);
            result = 0;
        }
    }
    else
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 103, "Error: Unable to allocate memory for bitmap.\n", 0, 0, 0, 0);
        result = 0;
    }
    return result;
}

int stdBitmap_LoadEntry(char *fpath, stdBitmap *out, int bCreateDDrawSurface, int gpuMem)
{
    intptr_t fd; // esi
    const char *v6; // eax
    signed int v7; // edi

    fd = std_pHS->fileOpen(fpath, "rb");
    if ( fd )
    {
        v6 = stdFileFromPath(fpath);
        _strncpy((char *)out, v6, 0x1Fu);
        out->field_1F = 0;
        v7 = stdBitmap_LoadEntryFromFile(fd, out, bCreateDDrawSurface, gpuMem);
        std_pHS->fileClose(fd);
        return v7;
    }
    else
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 147, "Error: Invalid load filename '%s'.\n", fpath);
        return 0;
    }
}

int stdBitmap_LoadEntryFromFile(intptr_t fp, stdBitmap *out, int bCreateDDrawSurface, int gpuMem)
{
    stdBitmap *v5; // ebx
    int palFmt; // ebp
    int numMips_; // edx
    unsigned int vbufAllocSize; // esi
    stdVBuffer **vbufAlloc; // edi
    int v10; // ecx
    int v11; // edx
    int v12; // eax
    stdVBuffer *surface; // esi
    char *lockAlloc; // ebp
    size_t v15; // edi
    unsigned int i; // ebx
    void *palette_map; // eax
    int v18; // [esp+10h] [ebp-DCh]
    int mipCount; // [esp+10h] [ebp-DCh]
    int numMips; // [esp+14h] [ebp-D8h]
    unsigned int v21[2]; // [esp+18h] [ebp-D4h] BYREF
    bitmapHeader bmp_header; // [esp+20h] [ebp-CCh] BYREF
    stdVBufferTexFmt vbufTexFmt; // [esp+A0h] [ebp-4Ch] BYREF

    std_pHS->fileRead(fp, &bmp_header, 128);
    if ( _memcmp((const char *)&bmp_header, "BM  ", 4u) )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 213, "Error: Bad signature in header of bitmap file.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( bmp_header.field_4 != 70 )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 220, "Error: Bad version %d for bitmap file\n", bmp_header.field_4);
        return 0;
    }
    v5 = out;
    palFmt = bmp_header.palFmt;
    v18 = bmp_header.field_8;
    numMips_ = bmp_header.numMips;
    _memset(out, 0, sizeof(stdBitmap));
    vbufAllocSize = 4 * numMips_;
    numMips = numMips_;
    vbufAlloc = (stdVBuffer **)std_pHS->alloc(4 * numMips_);
    out->mipSurfaces = vbufAlloc;
    if ( vbufAlloc )
    {
        _memset(vbufAlloc, 0, vbufAllocSize);
        out->field_20 = v18;
        _memcpy(&out->format, &bmp_header.format, sizeof(out->format));
        out->palFmt = palFmt;
        out->numMips = numMips;
        out->palette = 0;
    }
    else
    {
        stdPrintf(std_pHS->messagePrint, ".\\General\\stdBitmap.c", 843, "Ran out of memory trying allocate bitmap.\n", 0, 0, 0, 0);
    }
    v10 = bmp_header.colorkey;
    v11 = bmp_header.xPos;
    out->yPos = bmp_header.yPos;
    out->colorkey = v10;
    _memset(&vbufTexFmt, 0, sizeof(vbufTexFmt));
    mipCount = 0;
    v12 = out->numMips;
    out->xPos = v11;
    if ( v12 )
    {
        do
        {
            std_pHS->fileRead(fp, v21, 8);
            vbufTexFmt.height = v21[1];
            vbufTexFmt.width = v21[0];

            _memcpy(&vbufTexFmt.format, &out->format, sizeof(vbufTexFmt.format));

            surface = stdDisplay_VBufferNew(&vbufTexFmt, bCreateDDrawSurface, gpuMem, 0);
            if ( !surface )
                goto LABEL_17;

            v5->mipSurfaces[mipCount] = surface;
            stdDisplay_VBufferLock(surface);
            lockAlloc = surface->surface_lock_alloc;
            
            v15 = surface->format.width * ((unsigned int)surface->format.format.bpp >> 3);
            for ( i = 0; i < vbufTexFmt.height; ++i )
            {
                std_pHS->fileRead(fp, lockAlloc, v15);
                lockAlloc += surface->format.width_in_bytes;
            }
            stdDisplay_VBufferUnlock(surface);
            if ( (out->palFmt & 1) != 0 )
                stdDisplay_VBufferSetColorKey(surface, out->colorkey);
            v5 = out;
        }
        while ( (unsigned int)++mipCount < out->numMips );
    }
    if ( (v5->palFmt & 2) != 0 )
    {
        palette_map = std_pHS->alloc(0x300);
        v5->palette = palette_map;
        if ( !palette_map )
        {
LABEL_17:
            stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 297, "Error: Out of memory trying to load bitmap.\n", 0, 0, 0, 0);
            return 0;
        }
        std_pHS->fileRead(fp, palette_map, 0x300);
    }
    return 1;
}
