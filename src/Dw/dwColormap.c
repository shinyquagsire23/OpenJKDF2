// dwColormap — DroidWorks global current-colormap manager: loads a .cmp via
// rdColormap, keeps the single active colormap + the palette indices closest
// to black/white/green, and pushes the palette to the display (8bpp master
// palette + gamma, or a rebuilt 8->16bpp lookup table when the display runs
// 16bpp).
//
// Ghidra (DroidWorks.exe) 0x4430c0-0x4434fx:
//   dwColormap_SetDisplayPalette@0x4430c0, dwColormap_Load@0x4430e0,
//   dwColormap_Apply@0x4432d0.

#include "Dw/dwColormap.h"

#include "Dw/dwRect.h"
#include "Dw/dwString.h" // dwString_Equals (extern "C" free function; dwString itself stays opaque to C)
#include "Engine/rdColormap.h"
#include "General/stdColor.h"
#include "Win95/stdDisplay.h"
#include "stdPlatform.h"

// TODO(dw-decomp): provided by dwDisplay (P2). AddDirtyRect/Present are real
// dwDisplay unit functions; dwDisplay_pBackVBuf is our handle for the
// DW-stdDisplay-internal back-buffer tVBuffer (binary: unnamed @0x6b5a40)
// that the dwDisplay translation will own.
void dwDisplay_AddDirtyRect(dwRect* pRect);
void dwDisplay_Present();
extern tVBuffer* dwDisplay_pBackVBuf;

rdColormap* dwColormap_pCurrent = NULL;     // binary: 0x541c60
void* dwColormap_pDisplayPalette = NULL;    // binary: 0x541d1c
int dwColormap_transparentIdx = 0;          // binary: 0x541c48
int dwColormap_whiteIdx = 0;                // binary: 0x541d14
int dwColormap_greenIdx = 0;                // binary: 0x541d10
uint16_t dwColormap_aPalette16[256];        // binary: stdDisplay .bss 0x6afde0 (see dwColormap.h)

// Note: no binary counterpart — statics reset for the soft-reset loop only.
// Deliberately does not free dwColormap_pCurrent: shutdown-order vs. the
// render heap is the caller's problem, matching other *_Startup resets.
void dwColormap_Startup()
{
    dwColormap_pCurrent = NULL;
    dwColormap_pDisplayPalette = NULL;
    dwColormap_transparentIdx = 0;
    dwColormap_whiteIdx = 0;
    dwColormap_greenIdx = 0;
    _memset(dwColormap_aPalette16, 0, sizeof(dwColormap_aPalette16));
}

// Note: replicates the DW-era stdColor helper @0x5021c0 (no OpenJKDF2 twin:
// stdColor_ColorConvertOneRow converts pixel rows, not 24-bit palette
// entries). Builds the 256-entry 16bpp palette lookup table.
static void dwColormap_BuildPalette16(rdColor24* paColors, uint16_t* paOut, rdTexFormat* pFmt)
{
    for (int i = 0; i < 256; i++)
    {
        paOut[i] = (uint16_t)(((uint16_t)(paColors[i].g >> pFmt->g_bitdiff) << pFmt->g_shift)
                            | ((uint16_t)(paColors[i].r >> pFmt->r_bitdiff) << pFmt->r_shift)
                            | ((uint16_t)(paColors[i].b >> pFmt->b_bitdiff) << pFmt->b_shift));
    }
}

// Pushes the master palette to the hardware with the given gamma parameter
// and remembers it for dedup.
// Note: the binary calls a DW-stdDisplay routine (@0x4fe490) that
// gamma-corrects the master palette by pPalette and sets the hardware
// palette — the exact role of JK.EXE/OpenJKDF2 stdDisplay_GammaCorrect3, so
// the opaque parameter is forwarded as its gamma index.
void dwColormap_SetDisplayPalette(void* pPalette)
{
    if (dwColormap_pDisplayPalette != pPalette)
    {
        dwColormap_pDisplayPalette = pPalette;
        stdDisplay_GammaCorrect3((int)(intptr_t)pPalette);
    }
}

int dwColormap_Load(char* pName)
{
    if (dwColormap_pCurrent)
    {
        if (dwString_Equals(pName, dwColormap_pCurrent->colormap_fname))
        {
            dwColormap_Apply();
            return dwColormap_pCurrent != NULL;
        }
    }

    rdColormap* pColormap = rdColormap_Load(pName);
    if (pColormap)
    {
        if (dwColormap_pCurrent)
            rdColormap_Free(dwColormap_pCurrent);
        dwColormap_pCurrent = pColormap;

        stdPlatform_Printf("Color map %s\n", pName); // Note: binary logs via HostServices debug print

        // Entry 0 is forced to black, and the closest-color scans run over
        // entries 1..254 (0xfe entries) with the result biased +1.
        dwColormap_pCurrent->colors[0].b = 0;
        dwColormap_pCurrent->colors[0].g = 0;
        dwColormap_pCurrent->colors[0].r = 0;

        // Note: the binary stores only the low byte here (readers mask with
        // 0xff); whiteIdx/greenIdx get full int stores.
        dwColormap_transparentIdx = (uint8_t)(stdColor_FindClosest(&dwColormap_pCurrent->colors[1], 0xfe, 0.0, 0.0, 0.0) + 1);
        dwColormap_whiteIdx = stdColor_FindClosest(&dwColormap_pCurrent->colors[1], 0xfe, 255.0, 255.0, 255.0) + 1;
        dwColormap_greenIdx = stdColor_FindClosest(&dwColormap_pCurrent->colors[1], 0xfe, 0.0, 255.0, 0.0) + 1;

        // If the display is fully up and the palette actually changed, blank
        // the back buffer to the transparent color and present, so the next
        // frame isn't shown through the stale palette.
        // Note: the binary tests its three DirectDraw object pointers
        // (DAT_006478e0/e4/e8); mapped onto the open+mode-set flags.
        if (stdDisplay_bOpen && stdDisplay_bModeSet)
        {
            // Byte-compare the current master palette against the new colors,
            // entries 1..254 (0x2fa bytes; entry 0 skipped on both sides).
            uint8_t* pOld = (uint8_t*)stdDisplay_masterPalette + 3;
            uint8_t* pNew = (uint8_t*)&dwColormap_pCurrent->colors[1];
            int bSame = 1;
            for (int i = 0; i < 0x2fa; i++)
            {
                if (pOld[i] != pNew[i])
                {
                    bSame = 0;
                    break;
                }
            }

            // Note: NULL guards added — the binary's back buffer /
            // current-video-mode statics always exist once the display is
            // open; ours arrive with the dwDisplay unit.
            if (!bSame && dwDisplay_pBackVBuf && stdDisplay_pCurVideoMode)
            {
                stdDisplay_VBufferFill(dwDisplay_pBackVBuf, dwColormap_transparentIdx & 0xff, NULL);

                dwRect rect;
                rect.left = 0;
                rect.top = 0;
                rect.right = (int16_t)stdDisplay_pCurVideoMode->format.width;
                rect.bottom = (int16_t)stdDisplay_pCurVideoMode->format.height;
                dwDisplay_AddDirtyRect(&rect);
                dwDisplay_Present();
            }
        }

        rdColormap_SetCurrent(dwColormap_pCurrent);

        // Note: binary gates on its current-display-device pointer
        // (DAT_006478f0 = DW stdDisplay_pCurDevice).
        if (stdDisplay_pCurDevice)
        {
            stdDisplay_SetMasterPalette((uint8_t*)dwColormap_pCurrent->colors);
            if (!stdDisplay_pCurVideoMode)
                return dwColormap_pCurrent != NULL; // binary: goto past the 16bpp block
            stdDisplay_GammaCorrect3((int)(intptr_t)dwColormap_pDisplayPalette);
        }
    }

    // Rebuild the 16bpp palette table when the display runs 16bpp (also
    // reached with the previous colormap when the load above failed).
    if (stdDisplay_pCurVideoMode && stdDisplay_pCurVideoMode->format.format.bpp == 0x10
        && dwColormap_pCurrent)
    {
        dwColormap_BuildPalette16(dwColormap_pCurrent->colors, dwColormap_aPalette16,
                                  &stdDisplay_pCurVideoMode->format.format);
    }

    return dwColormap_pCurrent != NULL;
}

// Re-activates dwColormap_pCurrent on the rasterizer + display (called when
// the requested map is already loaded, and by dwGuiInGame).
void dwColormap_Apply()
{
    if (!dwColormap_pCurrent)
        return;

    rdColormap_SetCurrent(dwColormap_pCurrent);
    stdDisplay_SetMasterPalette((uint8_t*)dwColormap_pCurrent->colors);
    stdDisplay_GammaCorrect3((int)(intptr_t)dwColormap_pDisplayPalette);

    if (stdDisplay_pCurVideoMode && stdDisplay_pCurVideoMode->format.format.bpp == 0x10
        && dwColormap_pCurrent)
    {
        dwColormap_BuildPalette16(dwColormap_pCurrent->colors, dwColormap_aPalette16,
                                  &stdDisplay_pCurVideoMode->format.format);
    }
}
