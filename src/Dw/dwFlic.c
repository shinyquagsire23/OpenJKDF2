// dwFlic — DroidWorks Autodesk FLC/FLI animation decoder (see dwFlic.h).
//
// Ghidra (DroidWorks.exe) 0x413cd0-0x414c1x. Faithful translation of the
// binary's decoder, including its quirks:
//  - dwFlic_Open always returns 0 (open failures are undetectable) and
//    leaves pFile dangling after closing an unknown-type file.
//  - The COLOR_64 6->8-bit scale loop is off by one: it shifts the byte
//    BEFORE each run and leaves the run's last byte unscaled (see below).
//  - BLACK does not clear the target; it only skips the (empty) payload.
//  - All run/coordinate arithmetic is 16-bit (8-bit for run counters),
//    mirroring the original's word registers; clip math can go negative on
//    malformed files exactly like the original.
// The chunk handlers are static: in the binary they are only ever called by
// dwFlic_DecodeFrame's dispatch. In the binary the dispatcher pushes
// (pFlic, pTarget, pOverlay) for every pixel chunk; handlers that ignore the
// tail arguments (LC/BLACK/COPY) are declared here with only the parameters
// they read.
//
// This module has no static state (everything lives in the caller-owned
// dwFlic context), so there is no dwFlic_Startup reset hook.

#include "Dw/dwFlic.h"

#include <stddef.h>

extern HostServices* dwMain_pHS; // the DW host-services pointer (binary: dwHS @0x6b6258)

// The on-disk header/frame/chunk regions are read straight into the struct;
// pin the load-bearing offsets (all naturally aligned, no packing needed).
_Static_assert(offsetof(dwFlic, oframe1) == 0x50, "dwFlic header layout");
_Static_assert(offsetof(dwFlic, frameSize) == 0x80, "dwFlic frame header layout");
_Static_assert(offsetof(dwFlic, numSubChunks) == 0x86, "dwFlic frame header layout");
_Static_assert(offsetof(dwFlic, chunkType) == 0x94, "dwFlic chunk header layout");

// @0x413f80 — COLOR_256 chunk (type 4): FLC 8-bit palette packets, written
// straight into paPalette (= pThis->palette; the caller pushes the result to
// the display palette itself).
static void dwFlic_ChunkColor256(dwFlic* pThis, uint8_t* paPalette)
{
    int16_t nPackets;
    int16_t idx;
    uint8_t nSkip;
    uint8_t nCountByte;
    uint16_t nCount;

    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nPackets, 2);
    idx = 0;
    while (nPackets != 0)
    {
        nPackets--;
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nSkip, 1);
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nCountByte, 1);
        nCount = nCountByte;
        if (nCountByte == 0)
            nCount = 0x100;
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, paPalette + (int16_t)(idx + nSkip) * 3,
                             (int16_t)(nCount * 3));
        idx = (int16_t)(idx + nSkip + nCount);
    }
}

// @0x414060 — COLOR_64 chunk (type 11): FLI 6-bit VGA palette packets,
// scaled <<2 to 8-bit in place after each run is read.
static void dwFlic_ChunkColor64(dwFlic* pThis, uint8_t* paPalette)
{
    int16_t nPackets;
    int16_t idx;
    uint8_t nSkip;
    uint8_t nCountByte;
    uint16_t nCount;

    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nPackets, 2);
    idx = 0;
    while (nPackets != 0)
    {
        uint8_t* pDst;
        int16_t nBytes;

        nPackets--;
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nSkip, 1);
        idx = (int16_t)(idx + nSkip);
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nCountByte, 1);
        nCount = nCountByte;
        if (nCountByte == 0)
            nCount = 0x100;
        pDst = paPalette + idx * 3;
        nBytes = (int16_t)(nCount * 3);
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, pDst, nBytes);
        // Note: faithful off-by-one from the binary: the scale loop runs over
        // [pDst-1, pDst+nBytes-2] instead of [pDst, pDst+nBytes-1] — the last
        // byte of each run keeps its 6-bit value and the byte before the run
        // is shifted instead (for idx==0 that is the top byte of curFrame,
        // which is always 0 in practice, same as in the original layout).
        if (nBytes != 0)
        {
            uint8_t* pB = pDst + nBytes - 1;
            int32_t n = nBytes;
            do
            {
                pB--;
                *pB = (uint8_t)(*pB << 2);
            } while (--n != 0);
        }
        idx = (int16_t)(idx + nCount);
    }
}

// @0x414160 — DELTA_FLC chunk (type 7, "SS2"): word-oriented row deltas.
// pOverlay != NULL enables transparent compositing (0 bytes take the overlay
// pixel at the same position).
static void dwFlic_ChunkDeltaSS2(dwFlic* pThis, dwFlicBits* pTarget, dwFlicBits* pOverlay)
{
    int16_t h;
    int16_t w;
    uint8_t* pRow;
    uint8_t* pOvlRow;
    uint16_t nLines;
    uint16_t y;

    h = (int16_t)pThis->height;
    if (pTarget->height < h)
        h = pTarget->height;
    w = (int16_t)pThis->width;
    if (pTarget->width < w)
        w = pTarget->width;

    pRow = pTarget->pPixels;
    pOvlRow = NULL;
    if (pOverlay != NULL)
        pOvlRow = pOverlay->pPixels;

    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nLines, 2);
    y = 0;
    if (nLines == 0)
        return;

    for (;;)
    {
        uint16_t lastByte = 0xFFFF;  // set by 10xx control words (odd-width tail pixel)
        uint16_t nPackets = 0xFFFF;
        uint8_t* p;
        uint8_t* pOvl;
        uint16_t x;

        if ((int16_t)y >= h)
            return;

        // Control words: line skips / last-byte until a packet count arrives.
        do
        {
            uint16_t word;

            if ((int16_t)y >= h)
                return;
            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &word, 2);
            switch (word >> 14)
            {
            case 0: // packet count for this line
                nPackets = word;
                break;
            case 1: // undefined opcode -> bail out
                return;
            case 2: // low byte = last pixel of an odd-width line
                lastByte = word & 0xFF;
                break;
            case 3: // negative line skip
            {
                uint16_t nSkipLines = (uint16_t)(0 - word);
                y += nSkipLines;
                pRow += pTarget->rowStride * nSkipLines;
                if (pOverlay != NULL)
                    pOvlRow += pOverlay->rowStride * nSkipLines;
                break;
            }
            }
        } while ((int16_t)nPackets < 0);

        if ((int16_t)y >= h)
            return;

        x = 0;
        p = pRow;
        pOvl = pOvlRow;
        while (nPackets != 0)
        {
            uint8_t nSkip;
            int8_t nCount;
            uint8_t* pOvlRun;

            nPackets--;
            if ((int16_t)x >= w)
                break;
            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nSkip, 1);
            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nCount, 1);
            p += nSkip;
            pOvl += nSkip;
            x += nSkip;
            pOvlRun = pOvl;

            if (nCount < 0)
            {
                // Replicate a 2-byte pattern -nCount times.
                uint8_t aPattern[2];
                int8_t nRun = (int8_t)-nCount;
                int16_t nBytes;
                int32_t nOver;

                dwMain_pHS->fileRead((stdFile_t)pThis->pFile, aPattern, 2);
                nBytes = (int16_t)((int16_t)nRun * 2);
                nOver = (int32_t)(int16_t)x - (int32_t)w + (int32_t)nBytes;

                if (pOverlay == NULL || (aPattern[0] != 0 && aPattern[1] != 0))
                {
                    // Opaque pattern (or no overlay): plain fill.
                    uint8_t c = (uint8_t)nRun;
                    pOvl += nBytes;
                    if (nOver <= 0)
                    {
                        while (c != 0)
                        {
                            c--;
                            p[0] = aPattern[0];
                            p[1] = aPattern[1];
                            p += 2;
                        }
                        x = (uint16_t)(x + nBytes);
                    }
                    else
                    {
                        // Clipped: bounds-checked pair writes.
                        while (c != 0)
                        {
                            c--;
                            x++;
                            if ((int16_t)x >= w)
                                break;
                            *p++ = aPattern[0];
                            x++;
                            if ((int16_t)x >= w)
                                break;
                            *p++ = aPattern[1];
                        }
                    }
                }
                else if (aPattern[0] == 0 && aPattern[1] == 0)
                {
                    // Fully transparent pattern: copy from the overlay.
                    int16_t nCopy = nBytes;

                    x = (uint16_t)(x + nBytes);
                    if (nOver > 0)
                        nCopy = (int16_t)(nCopy - (int16_t)nOver);
                    if (nCopy != 0)
                    {
                        int32_t n = (int32_t)(int16_t)(nCopy - 1) + 1;
                        do
                        {
                            *p++ = *pOvl++;
                        } while (--n != 0);
                    }
                }
                else if (aPattern[0] == 0)
                {
                    // Even byte transparent, odd byte opaque.
                    uint8_t c = (uint8_t)nRun;
                    while (c != 0)
                    {
                        c--;
                        x++;
                        if ((int16_t)x >= w)
                            break;
                        *p++ = *pOvl++;
                        x++;
                        if ((int16_t)x >= w)
                            break;
                        *p++ = aPattern[1];
                        pOvl++;
                    }
                }
                else
                {
                    // Even byte opaque, odd byte transparent.
                    uint8_t c = (uint8_t)nRun;
                    while (c != 0)
                    {
                        c--;
                        x++;
                        if ((int16_t)x >= w)
                            break;
                        *p++ = aPattern[0];
                        pOvl++;
                        x++;
                        if ((int16_t)x >= w)
                            break;
                        *p++ = *pOvl++;
                    }
                }
            }
            else
            {
                // Literal run of nCount words (2*nCount bytes) from the file.
                int16_t nBytes = (int16_t)((int16_t)nCount * 2);
                int32_t nOver = (int32_t)(int16_t)x - (int32_t)w + (int32_t)nBytes;
                int16_t nRead = nBytes;

                x = (uint16_t)(x + nBytes);
                if (nOver <= 0)
                {
                    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, nBytes);
                }
                else
                {
                    nRead = (int16_t)(nBytes - (int16_t)nOver);
                    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, nRead);
                    dwMain_pHS->fseek((stdFile_t)pThis->pFile, nOver, 1);
                }
                if (pOverlay == NULL)
                {
                    p += nRead;
                }
                else if (nRead != 0)
                {
                    int32_t n = (int32_t)(int16_t)(nRead - 1) + 1;
                    do
                    {
                        if (*p == 0)
                            *p = *pOvlRun;
                        p++;
                        pOvlRun++;
                    } while (--n != 0);
                }
                pOvl = pOvlRun;
            }
        }

        // Odd-width tail pixel from a 10xx control word (0 = transparent).
        if (lastByte == 0 && pOverlay != NULL)
        {
            if ((int16_t)x < w)
                *p = *pOvl;
        }
        else if ((int16_t)lastByte >= 0 && (int16_t)x < w)
        {
            *p = (uint8_t)lastByte;
        }

        y++;
        pRow += pTarget->rowStride;
        if (pOverlay != NULL)
            pOvlRow += pOverlay->rowStride;
        if (--nLines == 0)
            return;
    }
}

// @0x414640 — DELTA_FLI chunk (type 12, "LC"): byte-oriented row deltas.
// Clips against the TARGET dimensions only (unlike SS2/BRUN, which clip
// against min(flic, target)); no overlay compositing in the binary (the
// dispatcher pushes pOverlay but this handler never reads it).
static void dwFlic_ChunkDeltaLC(dwFlic* pThis, dwFlicBits* pTarget)
{
    uint16_t rowIdx;
    int16_t nRows;
    uint8_t* p;

    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &rowIdx, 2);
    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nRows, 2);
    p = pTarget->pPixels + rowIdx * pTarget->rowStride;
    while (nRows != 0)
    {
        uint8_t nPackets;
        uint8_t* pRowStart = p;
        uint16_t x = 0;

        nRows--;
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nPackets, 1);
        while (nPackets != 0)
        {
            uint8_t nSkip;
            int8_t nCount;
            uint8_t b;

            nPackets--;
            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nSkip, 1);
            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nCount, 1);
            p += nSkip;
            x += nSkip;
            if (nCount < 0)
            {
                // Replicate -nCount copies of one byte.
                dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &b, 1);
                if ((int32_t)rowIdx < (int32_t)pTarget->height)
                {
                    int8_t c = nCount;
                    if ((int32_t)pTarget->width < (int32_t)x - (int32_t)nCount)
                    {
                        // Clipped: write while the (1-based) column fits.
                        while (c != 0)
                        {
                            x++;
                            if ((int32_t)x > (int32_t)pTarget->width)
                                break;
                            *p++ = b;
                            c++;
                        }
                    }
                    else
                    {
                        x = (uint16_t)(x - (uint16_t)(int16_t)nCount);
                        while (c != 0)
                        {
                            *p++ = b;
                            c++;
                        }
                    }
                }
                // Off-screen rows: the value byte is consumed, nothing written.
            }
            else
            {
                // Literal run of nCount bytes from the file.
                if ((int32_t)rowIdx < (int32_t)pTarget->height)
                {
                    if ((int32_t)pTarget->width < (int32_t)x + (int32_t)nCount)
                    {
                        // Clipped: consume every byte, write only in bounds.
                        int8_t c = nCount;
                        while (c != 0)
                        {
                            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &b, 1);
                            x++;
                            if ((int32_t)x <= (int32_t)pTarget->width)
                            {
                                *p = b;
                                p++;
                            }
                            c--;
                        }
                    }
                    else
                    {
                        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, nCount);
                        p += nCount;
                        x = (uint16_t)(x + (uint16_t)(int16_t)nCount);
                    }
                }
                else
                {
                    dwMain_pHS->fseek((stdFile_t)pThis->pFile, nCount, 1);
                }
            }
        }
        p = pRowStart + pTarget->rowStride;
        rowIdx++;
    }
}

// @0x414900 — BLACK chunk (type 13). Note: DW does NOT clear the target
// here; it just skips the chunk payload (a real BLACK chunk has none, so
// this seeks 0 bytes — the frame is left unchanged).
static void dwFlic_ChunkBlack(dwFlic* pThis)
{
    dwMain_pHS->fseek((stdFile_t)pThis->pFile, pThis->chunkSize - 6, 1);
}

// @0x414930 — BYTE_RUN chunk (type 15): per-row RLE full frame.
// pOverlay != NULL enables transparent compositing (0-valued pixels take the
// overlay pixel at the same position).
static void dwFlic_ChunkBrun(dwFlic* pThis, dwFlicBits* pTarget, dwFlicBits* pOverlay)
{
    int16_t h;
    int16_t w;
    uint8_t* pOvlRow;
    uint8_t* p;
    int32_t nRows;

    h = (int16_t)pThis->height;
    if (pTarget->height < h)
        h = pTarget->height;
    w = (int16_t)pThis->width;
    if (pTarget->width < w)
        w = pTarget->width;

    pOvlRow = NULL;
    if (pOverlay != NULL)
        pOvlRow = pOverlay->pPixels;
    p = pTarget->pPixels;
    if (h <= 0)
        return;

    nRows = h;
    do
    {
        uint8_t* pOvl = pOvlRow;
        uint8_t* pRowStart = p;
        int16_t x = 0;

        // Skip the obsolete per-row packet-count byte (FLC ignores it).
        dwMain_pHS->fseek((stdFile_t)pThis->pFile, 1, 1);
        if (w > 0)
        {
            do
            {
                int8_t nCount;

                dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &nCount, 1);
                if (nCount < 0)
                {
                    // Literal run of -nCount bytes from the file.
                    int32_t nOver;

                    nCount = (int8_t)-nCount;
                    x = (int16_t)(x + nCount);
                    // Note: literal runs clip against the TARGET width while
                    // replicate runs clip against min(flic, target) — as in
                    // the binary.
                    nOver = (int32_t)x - (int32_t)pTarget->width;
                    if (nOver <= 0)
                    {
                        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, nCount);
                    }
                    else
                    {
                        nCount = (int8_t)(nCount - (int8_t)nOver);
                        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, nCount);
                        dwMain_pHS->fseek((stdFile_t)pThis->pFile, nOver, 1);
                    }
                    if (pOverlay == NULL)
                    {
                        p += nCount;
                    }
                    else
                    {
                        // Composite: 0 pixels take the overlay.
                        uint8_t c = (uint8_t)nCount;
                        while (c != 0)
                        {
                            c--;
                            if (*p == 0)
                                *p = *pOvl;
                            p++;
                            pOvl++;
                        }
                    }
                }
                else
                {
                    // Replicate nCount copies of one byte.
                    uint8_t b;
                    int32_t nOver;

                    x = (int16_t)(x + nCount);
                    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &b, 1);
                    nOver = (int32_t)x - (int32_t)w;
                    if (nOver > 0)
                        nCount = (int8_t)(nCount - (int8_t)nOver);
                    if (pOverlay == NULL || b != 0)
                    {
                        uint8_t c = (uint8_t)nCount;
                        pOvl += nCount;
                        while (c != 0)
                        {
                            c--;
                            *p++ = b;
                        }
                    }
                    else
                    {
                        // Transparent fill: copy from the overlay instead.
                        uint8_t c = (uint8_t)nCount;
                        while (c != 0)
                        {
                            c--;
                            *p = *pOvl;
                            p++;
                            pOvl++;
                        }
                    }
                }
            } while (x < w);
        }
        p = pRowStart + pTarget->rowStride;
        if (pOverlay != NULL)
            pOvlRow += pOverlay->rowStride;
    } while (--nRows != 0);
}

// @0x414b80 — LITERAL chunk (type 16): raw uncompressed frame, one
// flic-width row of bytes per line, clipped/skipped against the target.
static void dwFlic_ChunkCopy(dwFlic* pThis, dwFlicBits* pTarget)
{
    int16_t y = 0;
    uint8_t* p = pTarget->pPixels;

    if ((int16_t)pThis->height <= 0)
        return;
    do
    {
        if (y < pTarget->height)
        {
            if (pTarget->width < (int16_t)pThis->width)
            {
                dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, pTarget->width);
                dwMain_pHS->fseek((stdFile_t)pThis->pFile,
                                  (int32_t)(int16_t)pThis->width - (int32_t)pTarget->width, 1);
            }
            else
            {
                dwMain_pHS->fileRead((stdFile_t)pThis->pFile, p, (int16_t)pThis->width);
            }
        }
        else
        {
            dwMain_pHS->fseek((stdFile_t)pThis->pFile, (int16_t)pThis->width, 1);
        }
        p += pTarget->rowStride;
        y++;
    } while (y < (int16_t)pThis->height);
}

// @0x413cd0
int dwFlic_Open(dwFlic* pThis, const char* pFilename)
{
    pThis->pFile = (void*)dwMain_pHS->fileOpen(pFilename, "rb");
    if (pThis->pFile != NULL)
    {
        dwMain_pHS->fileRead((stdFile_t)pThis->pFile, pThis, 0x80);
        pThis->curFrame = 0;
        if (pThis->type == 0xAF12) // FLC: frames start at oframe1
        {
            dwMain_pHS->fseek((stdFile_t)pThis->pFile, (int32_t)pThis->oframe1, 0);
            return 0;
        }
        if (pThis->type == 0xAF11) // FLI: fixed 320x200, frames follow the header
        {
            pThis->width = 320;
            pThis->height = 200;
            return 0;
        }
        // Unknown type: close, but (as original) pFile stays dangling and
        // 0 is still returned.
        dwMain_pHS->fileClose((stdFile_t)pThis->pFile);
    }
    return 0;
}

// @0x413d70
void dwFlic_Close(dwFlic* pThis)
{
    if (pThis->pFile != NULL)
    {
        dwMain_pHS->fileClose((stdFile_t)pThis->pFile);
    }
}

// @0x413d90
int dwFlic_DecodeFrame(dwFlic* pThis, dwFlicBits* pTarget, dwFlicBits* pOverlay)
{
    uint32_t frameRemain;
    int32_t framePos;

    if (pThis->curFrame >= (int32_t)(int16_t)pThis->numFrames)
        return 0xFFFF;
    pThis->curFrame++;

    dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &pThis->frameSize, 0x10);
    frameRemain = pThis->frameSize - 0x10;
    framePos = dwMain_pHS->ftell((stdFile_t)pThis->pFile);
    if (pThis->frameType != 0xF1FA)
        return 1; // note: file position is NOT restored here (as original)

    if (pThis->numSubChunks != 0)
    {
        int32_t nChunks = (int32_t)(int16_t)(pThis->numSubChunks - 1) + 1;
        do
        {
            uint32_t chunkRemain;
            int32_t chunkPos;

            dwMain_pHS->fileRead((stdFile_t)pThis->pFile, &pThis->chunkSize, 6);
            chunkRemain = pThis->chunkSize - 6;
            chunkPos = dwMain_pHS->ftell((stdFile_t)pThis->pFile);
            switch ((int16_t)pThis->chunkType)
            {
            case 4: // COLOR_256 — applied even with no target
                dwFlic_ChunkColor256(pThis, pThis->palette);
                break;
            case 7: // DELTA_FLC (SS2)
                if (pTarget != NULL)
                    dwFlic_ChunkDeltaSS2(pThis, pTarget, pOverlay);
                break;
            case 11: // COLOR_64 — applied even with no target
                dwFlic_ChunkColor64(pThis, pThis->palette);
                break;
            case 12: // DELTA_FLI (LC)
                if (pTarget != NULL)
                    dwFlic_ChunkDeltaLC(pThis, pTarget);
                break;
            case 13: // BLACK
                if (pTarget != NULL)
                    dwFlic_ChunkBlack(pThis);
                break;
            case 15: // BYTE_RUN
                if (pTarget != NULL)
                    dwFlic_ChunkBrun(pThis, pTarget, pOverlay);
                break;
            case 16: // LITERAL
                if (pTarget != NULL)
                    dwFlic_ChunkCopy(pThis, pTarget);
                break;
            }
            // Land exactly on the next sub-chunk regardless of what the
            // handler consumed.
            dwMain_pHS->fseek((stdFile_t)pThis->pFile, chunkPos + (int32_t)chunkRemain, 0);
        } while (--nChunks != 0);
    }

    // Land exactly on the next frame header.
    dwMain_pHS->fseek((stdFile_t)pThis->pFile, framePos + (int32_t)frameRemain, 0);
    return 0;
}
