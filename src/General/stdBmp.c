#include "stdBmp.h"

#include "General/stdBitmap.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"
#include "stdPlatform.h"
#include "jk.h"

stdBitmap* stdBmp_Load(const char *fpath, int create_ddraw_surface, int gpu_mem)
{
    stdBitmap *bitmap;

    bitmap = (stdBitmap *)std_pHS->alloc(sizeof(stdBitmap));
    if ( !bitmap )
        return NULL;
    if ( !stdBmp_LoadEntryFromFile(fpath, bitmap, create_ddraw_surface, gpu_mem) )
    {
        std_pHS->free(bitmap);
        return NULL;
    }
    return bitmap;
}

int stdBmp_LoadEntryFromFile(const char *fpath, stdBitmap *bitmap, int create_ddraw_surface, int gpu_mem)
{
    stdBmp_Header bmpHeader;
    stdBmp_InfoHeader infoHeader;
    void *paletteData = NULL;
    stdVBufferTexFmt format;
    const char *fname;

    int fhand = std_pHS->fileOpen(fpath, "rb");
    if ( !fhand )
        return 0;

    int headerRead = std_pHS->fileRead(fhand, &bmpHeader, sizeof(stdBmp_Header));
    int infoRead = std_pHS->fileRead(fhand, &infoHeader, sizeof(stdBmp_InfoHeader));
    if ( headerRead + infoRead != sizeof(stdBmp_Header) + sizeof(stdBmp_InfoHeader) )
    {
        std_pHS->fileClose(fhand);
        return 0;
    }

    if ( bmpHeader.magic != 0x4D42 ) // 'BM'
    {
        std_pHS->fileClose(fhand);
        return 0;
    }

    if ( infoHeader.headerSize != 0x28 )
    {
        std_pHS->fileClose(fhand);
        return 0;
    }

    // Read palette for indexed color modes
    if ( infoHeader.bpp < 8 )
    {
        int paletteSize = (1 << infoHeader.bpp) * 4;
        paletteData = std_pHS->alloc(paletteSize + sizeof(stdVBufferTexFmt));
        int palRead = std_pHS->fileRead(fhand, paletteData, paletteSize);
        if ( palRead != paletteSize )
        {
            std_pHS->assert("Unable to read the palette. Your BMP file may be corrupt.", ".\\General\\stdBmp.c", 0x122);
        }
    }

    // Clear bitmap struct
    _memset(bitmap, 0, sizeof(stdBitmap));

    // Copy filename
    fname = stdFileFromPath((char*)fpath);
#ifndef OPTIMIZE_AWAY_UNUSED_FIELDS
    _strncpy(bitmap->fpath, fname, 31);
    bitmap->fpath[31] = 0;
#endif

    bitmap->palette = paletteData;
    bitmap->numMips = 1;
    bitmap->field_68 = 0;

    switch ( infoHeader.bpp )
    {
        case 8:
            bitmap->palFmt = 2;
            bitmap->format.bpp = 8;
            bitmap->format.is16bit = 0;
            break;
        case 16:
            std_pHS->assert("16 bit per pixel BMP not yet supported!", ".\\General\\stdBmp.c", 0x13E);
            break;
        case 24:
            bitmap->format.is16bit = 1;
            bitmap->format.bpp = 24;
            bitmap->format.r_bits = 8;
            bitmap->format.g_bits = 8;
            bitmap->format.b_bits = 8;
            bitmap->format.r_shift = 0;
            bitmap->format.g_shift = 8;
            bitmap->format.b_shift = 16;
            bitmap->format.r_bitdiff = 0;
            bitmap->format.g_bitdiff = 0;
            bitmap->format.b_bitdiff = 0;
            bitmap->format.unk_40 = 0;
            bitmap->format.unk_44 = 0;
            bitmap->format.unk_48 = 0;
            break;
        case 32:
            std_pHS->assert("32bit per pixel BMP not yet supported.", ".\\General\\stdBmp.c", 0x142);
            break;
        default:
            std_pHS->assert("This BMP file uses a bit depth which is not supported.", ".\\General\\stdBmp.c", 0x14E);
            break;
    }

    // Allocate mip surface pointers
    bitmap->mipSurfaces = (stdVBuffer **)std_pHS->alloc(bitmap->numMips * sizeof(stdVBuffer *));
    if ( !bitmap->mipSurfaces )
    {
        std_pHS->assert("Unable to allocate memory.", ".\\General\\stdBmp.c", 0x153);
    }

    // Create VBuffer
    _memset(&format, 0, sizeof(format));
    _memcpy(&format.format, &bitmap->format, sizeof(rdTexFormat));
    format.width = infoHeader.width;
    format.height = infoHeader.height < 0 ? -infoHeader.height : infoHeader.height;

    bitmap->mipSurfaces[0] = stdDisplay_VBufferNew(&format, create_ddraw_surface, gpu_mem, paletteData);
    if ( !bitmap->mipSurfaces[0] )
    {
        std_pHS->assert("Unable to allocate memory.", ".\\General\\stdBmp.c", 0x15D);
    }

    // Lock and read pixel data
    if ( !stdDisplay_VBufferLock(bitmap->mipSurfaces[0]) )
    {
        std_pHS->assert("Unable to lock VBuffer memory.", ".\\General\\stdBmp.c", 0x169);
    }

    stdVBuffer *vbuf = bitmap->mipSurfaces[0];
    int height = vbuf->format.height;
    uint8_t *pixels = (uint8_t *)vbuf->surface_lock_alloc;
    int stride = vbuf->format.width_in_bytes;

    // Read rows
#ifdef TARGET_RETRO_HOMEBREW
    // Added: bounce rows through a temp buffer; fileRead byte-writes internally
    // and the vbuffer may be word-addressable-only (DC VRAM / NDS slot-2).
    uint8_t* pRowTmp = (uint8_t*)std_pHS->alloc(stride);
#endif
    for (int row = 0; row < height; row++)
    {
#ifdef TARGET_RETRO_HOMEBREW
        int bytesRead;
        if (pRowTmp) {
            bytesRead = std_pHS->fileRead(fhand, pRowTmp, vbuf->format.width_in_bytes);
            stdPlatform_Memcpy32(pixels, pRowTmp, vbuf->format.width_in_bytes);
        } else {
            bytesRead = std_pHS->fileRead(fhand, pixels, vbuf->format.width_in_bytes);
        }
#else
        int bytesRead = std_pHS->fileRead(fhand, pixels, vbuf->format.width_in_bytes);
#endif
        if ( bytesRead != (int)vbuf->format.width_in_bytes )
        {
            std_pHS->assert("Unable to read all the data from file.", ".\\General\\stdBmp.c", 0x17E);
        }
        // Skip padding to 4-byte alignment
        std_pHS->fseek(fhand, ((stride + 3) & ~3) - stride, 1);
        pixels += stride;
    }

    // Flip rows vertically if height is positive (bottom-up BMP)
    if ( infoHeader.height > 0 )
    {
        int halfHeight = height / 2;
        uint8_t *topRow = (uint8_t *)vbuf->surface_lock_alloc;
        for (int i = 0; i < halfHeight; i++)
        {
            uint8_t *botRow = (uint8_t *)vbuf->surface_lock_alloc + (height - 1 - i) * stride;
#ifdef TARGET_RETRO_HOMEBREW
            // Added: word-safe row swap (byte reads OK, writes via temp + Memcpy32)
            if (pRowTmp) {
                _memcpy(pRowTmp, topRow, stride);
                stdPlatform_Memcpy32(topRow, botRow, stride);
                stdPlatform_Memcpy32(botRow, pRowTmp, stride);
            } else
#endif
            for (int j = 0; j < stride; j++)
            {
                uint8_t tmp = topRow[j];
                topRow[j] = botRow[j];
                botRow[j] = tmp;
            }
            topRow += stride;
        }
    }
#ifdef TARGET_RETRO_HOMEBREW
    if (pRowTmp)
        std_pHS->free(pRowTmp);
#endif

    stdDisplay_VBufferUnlock(vbuf);
    std_pHS->fileClose(fhand);
    return 1;
}

int stdBmp_Write(const char *fpath, stdBitmap *bitmap)
{
    stdBmp_Header bmpHeader;
    stdBmp_InfoHeader infoHeader;

    stdVBuffer *vbuf = bitmap->mipSurfaces[0];
    uint32_t paletteSize;

    if ( vbuf->format.format.is16bit == 0 )
    {
        paletteSize = (1 << vbuf->format.format.bpp) * 4;
    }
    else
    {
        if ( vbuf->format.format.bpp != 24 )
        {
            std_pHS->assert("Only 24bpp supported", ".\\General\\stdBmp.c", 0x1C8);
        }
        paletteSize = 0;
    }

    uint32_t rowBytes = (vbuf->format.width * vbuf->format.format.bpp) >> 3;

    // Fill headers
    _memset(&infoHeader, 0, sizeof(infoHeader));
    infoHeader.headerSize = 0x28;
    infoHeader.width = vbuf->format.width;
    infoHeader.height = vbuf->format.height;
    infoHeader.planes = 1;
    infoHeader.bpp = vbuf->format.format.bpp;
    infoHeader.compression = 0;
    infoHeader.imageSize = rowBytes;
    infoHeader.xPpm = 0xB12;
    infoHeader.yPpm = 0xB12;

    bmpHeader.magic = 0x4D42;
    bmpHeader.reserved1 = 0;
    bmpHeader.reserved2 = 0;
    bmpHeader.dataOffset = paletteSize + sizeof(stdBmp_Header) + sizeof(stdBmp_InfoHeader);
    bmpHeader.fileSize = rowBytes + bmpHeader.dataOffset;

    int fhand = std_pHS->fileOpen(fpath, "wb");
    if ( !fhand )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBmp.c", 0x1FB,
                  "Unable to open file '%s' for writing.", fpath);
        return 0;
    }

    // Write BMP header
    int written = std_pHS->fileWrite(fhand, &bmpHeader, sizeof(stdBmp_Header));
    if ( written != sizeof(stdBmp_Header) )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBmp.c", 0x204,
                  "Error attempting to write %d bytes to '%s'.", sizeof(stdBmp_Header), fpath);
        std_pHS->fileClose(fhand);
        return 0;
    }

    // Write info header
    written = std_pHS->fileWrite(fhand, &infoHeader, sizeof(stdBmp_InfoHeader));
    if ( written != sizeof(stdBmp_InfoHeader) )
    {
        stdPrintf(std_pHS->errorPrint, ".\\General\\stdBmp.c", 0x20E,
                  "Error attempting to write %d bytes to '%s'.", sizeof(stdBmp_InfoHeader), fpath);
        std_pHS->fileClose(fhand);
        return 0;
    }

    // Write palette if present
    if ( paletteSize > 0 )
    {
        written = std_pHS->fileWrite(fhand, bitmap->palette, paletteSize);
        if ( (uint32_t)written != paletteSize )
        {
            stdPrintf(std_pHS->errorPrint, ".\\General\\stdBmp.c", 0x21C,
                      "Error attempting to write %d bytes to '%s'.", paletteSize, fpath);
            std_pHS->fileClose(fhand);
            return 0;
        }
    }

    // Write pixel rows bottom-up
    int height = vbuf->format.height;
    uint32_t rowStride = (vbuf->format.width * vbuf->format.format.bpp) >> 3;
    while ( --height >= 0 )
    {
        written = std_pHS->fileWrite(fhand, (uint8_t *)vbuf->surface_lock_alloc + height * vbuf->format.width_in_bytes, rowStride);
        if ( (uint32_t)written != rowStride )
        {
            stdPrintf(std_pHS->errorPrint, ".\\General\\stdBmp.c", 0x22D,
                      "Error attempting to write %d bytes to '%s'.", rowStride, fpath);
            std_pHS->fileClose(fhand);
            return 0;
        }
    }

    std_pHS->fileClose(fhand);
    return 1;
}
