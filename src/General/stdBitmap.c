#include "stdBitmap.h"

#include "stdPlatform.h"
#include "General/stdColor.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"
#include "Platform/std3D.h"
#include "jk.h"

stdBitmap* stdBitmap_Load(char *fpath, int bCreateDDrawSurface, int gpuMem)
{
    stdBitmap *outAlloc; // esi
    stdBitmap *result; // eax
    intptr_t fp; // edi
    signed int v6; // ebx
    const char *v7; // eax

    outAlloc = (stdBitmap *)std_pHS->alloc(sizeof(stdBitmap));
    if (!outAlloc)
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 68, "Error: Unable to allocate memory for bitmap '%s'\n", fpath);
        return NULL;
    }


    fp = std_pHS->fileOpen(fpath, "rb");
    if ( fp )
    {
        v7 = stdFileFromPath(fpath);
        _strncpy((char *)outAlloc->fpath, v7, 0x1Fu);
        outAlloc->fpath[31] = 0;
        v6 = stdBitmap_LoadEntryFromFile(fp, outAlloc, bCreateDDrawSurface, gpuMem);
        std_pHS->fileClose(fp);
    }
    else
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 147, "Error: Invalid load filename '%s'.\n", fpath);
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
    
    return result;
}

// MOTS added
stdBitmap* stdBitmap_Load2(char *fpath, int bCreateDDrawSurface, int gpuMem)
{
    return stdBitmap_Load(fpath, bCreateDDrawSurface, gpuMem);
}

stdBitmap* stdBitmap_LoadFromFile(stdFile_t fd, int bCreateDDrawSurface, int gpuMem)
{
    stdBitmap* outAlloc = (stdBitmap*)std_pHS->alloc(sizeof(stdBitmap));
    if (!outAlloc)
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 103, "Error: Unable to allocate memory for bitmap.\n", 0, 0, 0, 0);
        return NULL;
    }

    if (stdBitmap_LoadEntryFromFile(fd, outAlloc, bCreateDDrawSurface, gpuMem))
    {
        return outAlloc;
    }
    else
    {
        stdBitmap_Free(outAlloc);
        return 0;
    }
}

int stdBitmap_LoadEntry(char *fpath, stdBitmap *out, int bCreateDDrawSurface, int gpuMem)
{
    stdFile_t fd; // esi
    const char *v6; // eax
    signed int v7; // edi

    fd = std_pHS->fileOpen(fpath, "rb");
    if ( fd )
    {
        v6 = stdFileFromPath(fpath);
        _strncpy((char *)out->fpath, v6, 0x1Fu);
        out->fpath[31] = 0;
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
    int palFmt; // ebp
    int numMips_; // edx
    unsigned int vbufAllocSize; // esi
    stdVBuffer **vbufAlloc; // edi
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

    std_pHS->fileRead(fp, &bmp_header, sizeof(bitmapHeader));
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
    palFmt = bmp_header.palFmt;
    v18 = bmp_header.field_8;
    numMips_ = bmp_header.numMips;
    _memset(out, 0, sizeof(stdBitmap));
    vbufAllocSize = 4 * numMips_;
    numMips = numMips_;
    vbufAlloc = (stdVBuffer **)std_pHS->alloc(sizeof(stdVBuffer*) * numMips_);
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
    out->colorkey = bmp_header.colorkey;
    out->xPos = bmp_header.xPos;
    out->yPos = bmp_header.yPos;
    _memset(&vbufTexFmt, 0, sizeof(vbufTexFmt));
    for (mipCount = 0; mipCount < out->numMips; mipCount++)
    {
        std_pHS->fileRead(fp, v21, 8);
        vbufTexFmt.height = v21[1];
        vbufTexFmt.width = v21[0];

        _memcpy(&vbufTexFmt.format, &out->format, sizeof(vbufTexFmt.format));

        surface = stdDisplay_VBufferNew(&vbufTexFmt, bCreateDDrawSurface, gpuMem, 0);
        if ( !surface )
            goto LABEL_17;

        out->mipSurfaces[mipCount] = surface;
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
    }

    if ( (out->palFmt & 2) != 0 )
    {
        palette_map = std_pHS->alloc(0x300);
        out->palette = palette_map;
        if ( !palette_map )
        {
LABEL_17:
            stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 297, "Error: Out of memory trying to load bitmap.\n", 0, 0, 0, 0);
            return 0;
        }
        std_pHS->fileRead(fp, palette_map, 0x300);
    }

#ifdef SDL2_RENDER
    out->aTextureIds = (uint32_t*)std_pHS->alloc(out->numMips * sizeof(uint32_t));
    out->abLoadedToGPU = (int*)std_pHS->alloc(out->numMips * sizeof(int));
    out->paDataDepthConverted = (void**)std_pHS->alloc(out->numMips * sizeof(void*));

    memset(out->aTextureIds, 0, (out->numMips * sizeof(uint32_t)));
    memset(out->abLoadedToGPU, 0, (out->numMips * sizeof(int)));
    memset(out->paDataDepthConverted, 0, (out->numMips * sizeof(void*)));
    for (int i = 0; i < out->numMips; i++)
    {
        std3D_AddBitmapToTextureCache(out, i, !(out->palFmt & 1), 0);
    }
#endif

    return 1;
}

void stdBitmap_ConvertColorFormat(rdTexformat *formatTo, stdBitmap *bitmap)
{
    rdTexformat *formatFrom_; // eax
    int v4; // esi
    stdVBuffer *v5; // eax
    rdTexformat *formatFrom; // [esp+18h] [ebp+8h]

    formatFrom_ = &bitmap->format;
    formatFrom = &bitmap->format;
    if ( _memcmp(formatTo, formatFrom, sizeof(rdTexformat)) && (formatFrom_->is16bit || formatTo->is16bit) )
    {
        v4 = 0;
        if ( bitmap->numMips > 0 )
        {
            do
            {
                v5 = stdDisplay_VBufferConvertColorFormat(formatTo, bitmap->mipSurfaces[v4]);
                bitmap->mipSurfaces[v4] = v5;
                if ( !v5 )
                    ((void (__cdecl *)(const char *, const char *, int))std_pHS->assert)(
                        "Unable to allocate a new frame when converting image from 24 to 16bpp.",
                        ".\\General\\stdBitmap.c",
                        570);
                if ( (bitmap->palFmt & 1) != 0 )
                    stdDisplay_VBufferSetColorKey(bitmap->mipSurfaces[v4], bitmap->mipSurfaces[v4]->transparent_color);
                ++v4;
            }
            while ( v4 < bitmap->numMips );
            formatFrom_ = formatFrom;
        }
        if ( (bitmap->palFmt & 1) != 0 )
        {
            bitmap->colorkey = stdColor_ColorConvertOnePixel(formatTo, bitmap->colorkey, formatFrom_);
            formatFrom_ = formatFrom;
        }
        _memcpy(formatFrom_, formatTo, sizeof(rdTexformat));
    }
}

void stdBitmap_Free(stdBitmap *pBitmap)
{
    unsigned int i; // esi
    
    // Added: nullptr check
    if (!pBitmap) return;

#ifdef SDL2_RENDER
    std3D_PurgeBitmapRefs(pBitmap);
    std_pHS->free(pBitmap->aTextureIds);
    pBitmap->aTextureIds = NULL;
    std_pHS->free(pBitmap->abLoadedToGPU);
    pBitmap->abLoadedToGPU = NULL;
    std_pHS->free(pBitmap->paDataDepthConverted);
    pBitmap->paDataDepthConverted = NULL;
#endif

    if ( pBitmap->mipSurfaces )
    {
        for ( i = 0; i < pBitmap->numMips; ++i )
        {
            if ( pBitmap->mipSurfaces[i] )
                stdDisplay_VBufferFree(pBitmap->mipSurfaces[i]);
        }
        std_pHS->free(pBitmap->mipSurfaces);
    }
    if ( pBitmap->palette )
        std_pHS->free(pBitmap->palette);
    stdPrintf(std_pHS->debugPrint, ".\\General\\stdBitmap.c", 359, "Bitmap elements successfully freed.\n", 0, 0, 0, 0);
    std_pHS->free(pBitmap);
    stdPrintf(std_pHS->debugPrint, ".\\General\\stdBitmap.c", 322, "Bitmap successfully freed.\n", 0, 0, 0, 0);
}
