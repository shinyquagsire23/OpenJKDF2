#include "stdBitmap.h"

#include "stdPlatform.h"
#include "General/stdColor.h"
#include "General/stdString.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"
#include "Platform/std3D.h"
#include "jk.h"

// Added: Partial loading
stdBitmap* stdBitmap_LoadCommon(char *fpath, int bCreateDDrawSurface, int gpuMem, int bPartial)
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

    v6 = stdBitmap_LoadEntry(fpath, outAlloc, bCreateDDrawSurface, gpuMem, bPartial);
    
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

// Added: Partial loading
stdBitmap* stdBitmap_Load(char *fpath, int bCreateDDrawSurface, int gpuMem)
{
    return stdBitmap_LoadCommon(fpath, bCreateDDrawSurface, gpuMem, 0);
}

// Added: Partial loading
stdBitmap* stdBitmap_LoadPartial(char *fpath, int bCreateDDrawSurface, int gpuMem)
{
#ifdef STDBITMAP_PARTIAL_LOAD
    return stdBitmap_LoadCommon(fpath, bCreateDDrawSurface, gpuMem, 1);
#else
    return stdBitmap_LoadCommon(fpath, bCreateDDrawSurface, gpuMem, 0);
#endif
}

int stdBitmap_EnsureData(stdBitmap *pBitmap) {
#ifdef STDBITMAP_PARTIAL_LOAD
    char tmp[128];
    if (!pBitmap) return 0;

    if (pBitmap->bLoaded) {
        return 1;
    }
    stdString_SafeStrCopy(tmp, pBitmap->fpath_full, 128);
    stdBitmap_FreeEntry(pBitmap);
    stdPlatform_Printf("stdBitmap: Ensuring data for: `%s`\n", tmp);
    return stdBitmap_LoadEntry(tmp, pBitmap, 1, 0, 0); // TODO
#endif
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

    if (stdBitmap_LoadEntryFromFile(fd, outAlloc, bCreateDDrawSurface, gpuMem, 0))
    {
        return outAlloc;
    }
    else
    {
        stdBitmap_Free(outAlloc);
        return 0;
    }
}

int stdBitmap_LoadEntry(char *fpath, stdBitmap *out, int bCreateDDrawSurface, int gpuMem, int bPartial)
{
    stdFile_t fd; // esi
    signed int v7; // edi

#ifdef STDBITMAP_PARTIAL_LOAD
    stdString_SafeStrCopy(out->fpath_full, fpath, 128);
#endif

    fd = std_pHS->fileOpen(fpath, "rb");
    if ( fd )
    {
#ifndef OPTIMIZE_AWAY_UNUSED_FIELDS
        stdString_SafeStrCopy(out->fpath, stdFileFromPath(fpath), 32);
#endif
        v7 = stdBitmap_LoadEntryFromFile(fd, out, bCreateDDrawSurface, gpuMem, bPartial);
        std_pHS->fileClose(fd);
        return v7;
    }
    else
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 147, "Error: Invalid load filename '%s'.\n", fpath);
        return 0;
    }
}

int stdBitmap_LoadEntryFromFile(intptr_t fp, stdBitmap *out, int bCreateDDrawSurface, int gpuMem, int bPartial)
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

#ifndef STDBITMAP_PARTIAL_LOAD
    bPartial = 0;
#endif

    // Added: This used to wipe out fpath
    // Added: Moved this up
    _memset(&out->field_20, 0, sizeof(stdBitmap)-offsetof(stdBitmap, field_20));

    std_pHS->fileRead(fp, &bmp_header, sizeof(bitmapHeader));
    if ( _memcmp((const char *)&bmp_header, "BM  ", 4u) )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 213, "Error: Bad signature in header of bitmap file (%x).\n", *(uint32_t*)&bmp_header);
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

    vbufAllocSize = sizeof(stdVBuffer*) * numMips_;
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
        // Added: Don't crash
        return 0;
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

        if (bPartial) {
            out->mipSurfaces[mipCount] = NULL;
            std_pHS->fseek(fp, vbufTexFmt.width*vbufTexFmt.height*((unsigned int)vbufTexFmt.format.bpp >> 3), SEEK_CUR);
            continue;
        }

        surface = stdDisplay_VBufferNew(&vbufTexFmt, bCreateDDrawSurface, gpuMem, 0);
        if ( !surface ) {
            goto LABEL_17;
        }

        out->mipSurfaces[mipCount] = surface;
        stdDisplay_VBufferLock(surface);
        lockAlloc = (char*)surface->surface_lock_alloc;
        
        v15 = surface->format.width * ((unsigned int)surface->format.format.bpp >> 3);
#ifdef TARGET_RETRO_HOMEBREW
        // Added: bounce rows through a temp buffer; fileRead byte-writes internally
        // and the vbuffer may be word-addressable-only (DC VRAM / NDS slot-2).
        char* pRowTmp = (char*)std_pHS->alloc(v15);
        for ( i = 0; i < vbufTexFmt.height; ++i )
        {
            if (pRowTmp) {
                std_pHS->fileRead(fp, pRowTmp, v15);
                stdPlatform_Memcpy32(lockAlloc, pRowTmp, v15);
            } else {
                std_pHS->fileRead(fp, lockAlloc, v15);
            }
            lockAlloc += surface->format.width_in_bytes;
        }
        if (pRowTmp) {
            std_pHS->free(pRowTmp);
        }
#else
        for ( i = 0; i < vbufTexFmt.height; ++i )
        {
            std_pHS->fileRead(fp, lockAlloc, v15);
            lockAlloc += surface->format.width_in_bytes;
        }
#endif
        stdDisplay_VBufferUnlock(surface);
        if ( (out->palFmt & 1) != 0 ) {
            stdDisplay_VBufferSetColorKey(surface, out->colorkey);
        }
        // TODO: Eviction caching for stdBitmap, rdMaterial
#ifdef TARGET_TWL
        if (openjkdf2_bIsExtraLowMemoryPlatform && vbufTexFmt.width == 640 && vbufTexFmt.height == 480){
            std_pHS->free(surface->surface_lock_alloc);
            surface->surface_lock_alloc = NULL;
        }
#endif
    }

    if ( (out->palFmt & 2) != 0  && !bPartial)
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

#ifdef STDBITMAP_PARTIAL_LOAD
    if (!bPartial) {
        out->bLoaded = 1;
    }
#endif

    return 1;
}

void stdBitmap_ConvertColorFormat(rdTexFormat *formatTo, stdBitmap *bitmap)
{
    rdTexFormat *formatFrom_; // eax
    int v4; // esi
    stdVBuffer *v5; // eax
    rdTexFormat *formatFrom; // [esp+18h] [ebp+8h]

    formatFrom_ = &bitmap->format;
    formatFrom = &bitmap->format;
    if ( _memcmp(formatTo, formatFrom, sizeof(rdTexFormat)) && (formatFrom_->is16bit || formatTo->is16bit) )
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
        _memcpy(formatFrom_, formatTo, sizeof(rdTexFormat));
    }
}

void stdBitmap_FreeEntry(stdBitmap *pBitmap)
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
            if ( pBitmap->mipSurfaces[i] ) {
                stdDisplay_VBufferFree(pBitmap->mipSurfaces[i]);
            }
            pBitmap->mipSurfaces[i] = NULL; // Added
        }
        std_pHS->free(pBitmap->mipSurfaces);
    }
    pBitmap->mipSurfaces = NULL; // Added
    if (pBitmap->palette) {
        std_pHS->free(pBitmap->palette);
    }
    pBitmap->palette = NULL; // Added

#ifdef STDBITMAP_PARTIAL_LOAD
    pBitmap->bLoaded = 0;
#endif
    //stdPrintf(std_pHS->debugPrint, ".\\General\\stdBitmap.c", 359, "Bitmap elements successfully freed.\n", 0, 0, 0, 0);
}

void stdBitmap_Free(stdBitmap *pBitmap)
{
    stdBitmap_FreeEntry(pBitmap);
    std_pHS->free(pBitmap);
    //stdPrintf(std_pHS->debugPrint, ".\\General\\stdBitmap.c", 322, "Bitmap successfully freed.\n", 0, 0, 0, 0);
}

// Added
int stdBitmap_UnloadData(stdBitmap* pBitmap) {
#ifdef STDBITMAP_PARTIAL_LOAD
    if (!pBitmap || !pBitmap->bLoaded) return 0;

    stdPlatform_Printf("stdBitmap: Unloading data for `%s`\n", pBitmap->fpath_full);
    stdBitmap_FreeEntry(pBitmap);
    pBitmap->bLoaded = 0;
#endif
    return 1;
}

int stdBitmap_AppendToFile(stdFile_t fhand, stdBitmap *pBitmap)
{
    bitmapHeader header;
    int written;

    _memset(&header, 0, sizeof(header));
    _strncpy((char*)&header.magic, "BM  ", 4);
    header.field_4 = 0x46;
    header.field_8 = pBitmap->field_20;
    header.palFmt = pBitmap->palFmt;
    header.numMips = pBitmap->numMips;
    header.xPos = pBitmap->xPos;
    header.yPos = pBitmap->yPos;
    header.colorkey = pBitmap->colorkey;
    _memcpy(&header.format, &pBitmap->format, sizeof(rdTexFormat));

    written = std_pHS->fileWrite(fhand, &header, sizeof(bitmapHeader));
    if ( written != sizeof(bitmapHeader) )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 0x1AC,
                  "Error: Unable to write %d bytes to file.", sizeof(bitmapHeader));
        return 0;
    }

    for (uint32_t i = 0; i < (uint32_t)pBitmap->numMips; i++)
    {
        stdVBuffer *vbuf = pBitmap->mipSurfaces[i];
        int dims[2];
        dims[0] = vbuf->format.width;
        dims[1] = vbuf->format.height;
        written = std_pHS->fileWrite(fhand, dims, 8);
        if ( written != 8 )
        {
            stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 0x1C3,
                      "Error: Unable to write %d bytes to file.", 8);
            return 0;
        }

        stdDisplay_VBufferLock(vbuf);
        uint32_t rowBytes = (vbuf->format.format.bpp >> 3) * dims[0];
        uint8_t *pixels = (uint8_t *)vbuf->surface_lock_alloc;
        for (uint32_t row = 0; row < (uint32_t)dims[1]; row++)
        {
            written = std_pHS->fileWrite(fhand, pixels, rowBytes);
            if ( written != (int)rowBytes )
            {
                stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 0x1D4,
                          "Error: Unable to write %d bytes to file.", rowBytes);
                return 0;
            }
            pixels += vbuf->format.width_in_bytes;
        }
        stdDisplay_VBufferUnlock(vbuf);
    }

    if ( (pBitmap->palFmt & 2) && pBitmap->palette )
    {
        written = std_pHS->fileWrite(fhand, pBitmap->palette, 0x300);
        if ( written != 0x300 )
        {
            stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 0x1E5,
                      "Error: Unable to write %d bytes to file.", 0x300);
            return 0;
        }
    }
    return 1;
}

int stdBitmap_Write(const char *fpath, stdBitmap *pBitmap)
{
    stdFile_t fhand = std_pHS->fileOpen(fpath, "wb");
    if ( !fhand )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 0x206,
                  "Error: Invalid write filename: '%s'.", fpath);
        return 0;
    }
    if ( !stdBitmap_AppendToFile(fhand, pBitmap) )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBitmap.c", 0x20D,
                  "Error writing to file '%s'.", fpath);
        std_pHS->fileClose(fhand);
        return 0;
    }
    std_pHS->fileClose(fhand);
    return 1;
}

void stdBitmap_MemUsage(stdBitmap *pBitmap, int mipIdx, stdVBuffer *vbuf)
{
    pBitmap->mipSurfaces[mipIdx] = vbuf;
}

stdBitmap* stdBitmap_New(uint32_t numMips, int palFmt, int field_20, int field_68, rdTexFormat *pFormat)
{
    stdBitmap *bitmap = (stdBitmap *)std_pHS->alloc(sizeof(stdBitmap));
    if ( !bitmap )
    {
        stdPrintf(std_pHS->statusPrint, ".\\General\\stdBitmap.c", 0x316,
                  "Ran out of memory trying allocating bitmap.");
        return NULL;
    }
    _memset(bitmap, 0, sizeof(stdBitmap));

    stdVBuffer **surfaces = (stdVBuffer **)std_pHS->alloc(numMips * sizeof(stdVBuffer *));
    bitmap->mipSurfaces = surfaces;
    if ( !surfaces )
    {
        stdPrintf(std_pHS->statusPrint, ".\\General\\stdBitmap.c", 0x34B,
                  "Ran out of memory trying allocating bitmap.");
        std_pHS->free(bitmap);
        return NULL;
    }
    _memset(surfaces, 0, numMips * sizeof(stdVBuffer *));

    bitmap->field_68 = field_68;
    bitmap->field_20 = field_20;
    _memcpy(&bitmap->format, pFormat, sizeof(rdTexFormat));
    bitmap->numMips = numMips;
    bitmap->palFmt = palFmt;
    return bitmap;
}

int stdBitmap_NewEntry(stdBitmap *bitmap, uint32_t numMips, int palFmt, int field_20, int field_68, rdTexFormat *pFormat)
{
    _memset(bitmap, 0, sizeof(stdBitmap));

    stdVBuffer **surfaces = (stdVBuffer **)std_pHS->alloc(numMips * sizeof(stdVBuffer *));
    bitmap->mipSurfaces = surfaces;
    if ( !surfaces )
    {
        stdPrintf(std_pHS->statusPrint, ".\\General\\stdBitmap.c", 0x34B,
                  "Ran out of memory trying allocating bitmap.");
        return 0;
    }
    _memset(surfaces, 0, numMips * sizeof(stdVBuffer *));

    bitmap->field_68 = field_68;
    bitmap->numMips = numMips;
    _memcpy(&bitmap->format, pFormat, sizeof(rdTexFormat));
    bitmap->field_20 = field_20;
    bitmap->palFmt = palFmt;
    return 1;
}
