#include "stdPcx.h"

#include "Engine/rdMaterial.h"
#include "General/stdBitmap.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"

stdBitmap* stdPcx_Load(char *fpath, int create_ddraw_surface, int gpu_mem)
{
    stdBitmap *bitmap;
    stdVBuffer **mipSurfaces;
    stdVBuffer *vbuf;
    stdVBuffer *mipSurface;
    char *lockAlloc;
    void *paletteAlloc;
    stdVBufferTexFmt format;
    stdPcx_Header pcxHeader;

    int fhand = std_pHS->fileOpen(fpath, "rb");
    if ( !fhand )
        return 0;

    bitmap = (stdBitmap *)std_pHS->alloc(sizeof(stdBitmap));
    if ( !bitmap )
        goto fail; // TODO will this nullptr deref?

    _memset(bitmap, 0, sizeof(stdBitmap));
    std_pHS->fileRead(fhand, &pcxHeader, sizeof(stdPcx_Header));
    if ( pcxHeader.magic != 10 )
        goto fail;

    bitmap->field_20 = 0;
    bitmap->palFmt = 2;
    bitmap->numMips = 1;
    bitmap->field_68 = 0;
    bitmap->format.is16bit = 0;
    bitmap->format.bpp = pcxHeader.bitDepth;

    bitmap->mipSurfaces = (stdVBuffer **)std_pHS->alloc(sizeof(stdVBuffer *) * 1);
    if ( !bitmap->mipSurfaces )
        goto fail;
    _memset(&format, 0, sizeof(format));
    format.format.is16bit = 0;
    format.format.bpp = (uint8_t)pcxHeader.bitDepth;
    format.height = pcxHeader.yMax + 1;
    format.width = pcxHeader.stride / (signed int)((unsigned int)pcxHeader.bitDepth >> 3);

    vbuf = stdDisplay_VBufferNew(&format, create_ddraw_surface, gpu_mem, 0);
    bitmap->mipSurfaces[0] = vbuf;
    if ( !vbuf )
        goto fail;

    vbuf->format.width = pcxHeader.xMax + 1;

    stdDisplay_VBufferLock(vbuf);

    mipSurface = bitmap->mipSurfaces[0];
    lockAlloc = (uint8_t*)mipSurface->surface_lock_alloc;
    for (int i = 0; i < mipSurface->format.texture_size_in_bytes; i++ )
    {
        uint8_t v11 = stdFGetc(fhand);
        if ( (v11 & 0xC0) == -64 )
        {
            uint8_t v13 = stdFGetc(fhand);
            uint32_t v16 = (v11 & 0x3F);
            uint32_t v15 = (v11 & 0x3F) - 1;
            if (v11 & 0x3F)
            {
                uint32_t v17 = (v13 | (v13 << 8) | (v13 << 16) | (v13 << 24));
                _memset32(lockAlloc, v17, v16 >> 2);
                _memset(&lockAlloc[v16 & ~3], v17, v16 & 3);
                lockAlloc += v16;
            }
        }
        else
        {
            *lockAlloc++ = v11;
        }
    }
    stdDisplay_VBufferUnlock(*bitmap->mipSurfaces);
    paletteAlloc = std_pHS->alloc(0x300u);
    bitmap->palette = paletteAlloc;
    if ( paletteAlloc )
    {
        stdFGetc(fhand);
        std_pHS->fileRead(fhand, (void *)bitmap->palette, 0x300);
        std_pHS->fileClose(fhand);
    }
    else
    {
        goto fail;
    }
    return bitmap;
    
fail:
    std_pHS->fileClose(fhand);
    stdBitmap_Free(bitmap);
    return NULL;
}

int stdPcx_Write(char *fpath, stdBitmap *bitmap)
{
    stdVBuffer *mipSurface;
    uint8_t* lockAlloc;
    stdPcx_Header pcxHeader;

    pcxHeader.magic = 10;
    pcxHeader.version = 5;
    pcxHeader.isRle = 1;
    pcxHeader.bitDepth = 8;
    pcxHeader.xMin = 0;
    pcxHeader.yMin = 0;
    pcxHeader.xMax = ((uint16_t)bitmap->mipSurfaces[0]->format.width) - 1;
    pcxHeader.yMax = ((uint16_t)bitmap->mipSurfaces[0]->format.height) - 1;
    pcxHeader.xDpi = bitmap->mipSurfaces[0]->format.width;
    pcxHeader.yDpi = bitmap->mipSurfaces[0]->format.height;
    pcxHeader.reserved_40 = 0;
    pcxHeader.colorDims = 1;
    pcxHeader.stride = bitmap->mipSurfaces[0]->format.width;
    pcxHeader.paletteMode = 0;
    _memset(pcxHeader.egaPalette, 0, sizeof(pcxHeader.egaPalette));
    _memset(&pcxHeader.width, 0, 0x38u);
    *(uint16_t*)&pcxHeader.reserved_4A[52] = 0;
    
    int fhand = std_pHS->fileOpen(fpath, "wb");
    if ( !fhand )
        return 0;

    std_pHS->fileWrite(fhand, &pcxHeader, sizeof(stdPcx_Header));
    mipSurface = *bitmap->mipSurfaces;
    lockAlloc = (uint8_t*)mipSurface->surface_lock_alloc;
    for (int i = 0; i < mipSurface->format.height; i++)
    {
        for (int j = 0; j < mipSurface->format.width; j )
        {
            uint8_t* v14 = &lockAlloc[(mipSurface->format.width * i) + j];
            uint8_t v13 = *v14;
            int v15 = 1;
            while ( v13 == v14[v15] )
            {
                    if ( j + v15 >= mipSurface->format.width )
                        break;
                    if ( v15 >= 0x3Fu )
                        break;
            }

            if ( v15 > 1u || v13 > 0xBFu )
                stdFPutc(v15 | 0xC0, fhand);
            stdFPutc(*v14, fhand);
            j += v15;
        }
    }

    stdFPutc(0xC, fhand);
    std_pHS->fileWrite(fhand, bitmap->palette, 0x300);
    std_pHS->fileClose(fhand);
    return 1;
}
