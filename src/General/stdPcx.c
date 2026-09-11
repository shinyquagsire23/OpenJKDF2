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
    tVBuffer **mipSurfaces;
    tVBuffer *vbuf;
    tVBuffer *mipSurface;
    char *lockAlloc;
    void *paletteAlloc;
    tRasterInfo format;
    stdPcx_Header pcxHeader;

    stdFile_t hGobFile = std_g_pHS->fileOpen(fpath, "rb");
    if ( !hGobFile )
        return 0;

    bitmap = (stdBitmap *)STD_ALLOC(sizeof(stdBitmap));
    if ( !bitmap )
        goto fail; // TODO will this nullptr deref?

    _memset(bitmap, 0, sizeof(stdBitmap));
    std_g_pHS->fileRead(hGobFile, &pcxHeader, sizeof(stdPcx_Header));
    if ( pcxHeader.magic != 10 )
        goto fail;

    bitmap->field_20 = 0;
    bitmap->palFmt = 2;
    bitmap->numMips = 1;
    bitmap->field_68 = 0;
    bitmap->format.is16bit = 0;
    bitmap->format.bpp = pcxHeader.bitDepth;

    bitmap->mipSurfaces = (tVBuffer **)STD_ALLOC(sizeof(tVBuffer *) * 1);
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
    lockAlloc = (char*)mipSurface->surface_lock_alloc;
    for (int i = 0; i < mipSurface->format.size; i++ )
    {
        uint8_t v11 = stdFGetc(hGobFile);
        if ((v11 & 0xC0) == 0xC0)
        {
            uint8_t v13 = stdFGetc(hGobFile);
            uint32_t v16 = (v11 & 0x3F);
            uint32_t v15 = (v11 & 0x3F) - 1;
            if (v11 & 0x3F)
            {
                // Added: word-safe fill, also handles the unaligned run start
                stdPlatform_Memset32(lockAlloc, v13, v16);
                lockAlloc += v16;
            }
        }
        else
        {
            // Added: word-safe store (vbuffers may be word-addressable-only)
            stdPlatform_WriteByte16(lockAlloc, v11);
            lockAlloc++;
        }
    }
    stdDisplay_VBufferUnlock(*bitmap->mipSurfaces);
    paletteAlloc = STD_ALLOC(0x300u);
    bitmap->palette = paletteAlloc;
    if ( paletteAlloc )
    {
        stdFGetc(hGobFile);
        std_g_pHS->fileRead(hGobFile, (void *)bitmap->palette, 0x300);
        std_g_pHS->fileClose(hGobFile);
    }
    else
    {
        goto fail;
    }
    return bitmap;
    
fail:
    std_g_pHS->fileClose(hGobFile);
    stdBitmap_Free(bitmap);
    return NULL;
}

int stdPcx_Write(char *fpath, stdBitmap *bitmap)
{
    tVBuffer *mipSurface;
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
    
    stdFile_t hGobFile = std_g_pHS->fileOpen(fpath, "wb");
    if ( !hGobFile )
        return 0;

    std_g_pHS->fileWrite(hGobFile, &pcxHeader, sizeof(stdPcx_Header));
    mipSurface = *bitmap->mipSurfaces;
    lockAlloc = (uint8_t*)mipSurface->surface_lock_alloc;
    for (int i = 0; i < mipSurface->format.height; i++)
    {
        for (int j = 0; j < mipSurface->format.width; j++ )
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
                stdFPutc(v15 | 0xC0, hGobFile);
            stdFPutc(*v14, hGobFile);
            j += v15;
        }
    }

    stdFPutc(0xC, hGobFile);
    std_g_pHS->fileWrite(hGobFile, bitmap->palette, 0x300);
    std_g_pHS->fileClose(hGobFile);
    return 1;
}
