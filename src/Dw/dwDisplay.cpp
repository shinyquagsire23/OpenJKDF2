// dwDisplay — DroidWorks display/backbuffer manager: display bring-up, the
// dirty-rect repaint list, the wrapped screen image, and frame present.
//
// Decompiled from DroidWorks.exe, unit range 0x443920-0x4442ff (the
// dwRect_Overlaps/Clip/Union tail @0x444180-0x4442ff already lives in
// dwRect.c).
//
// ORIGINAL BRING-UP (0x4439c0): build a display environment
// (stdBuildDisplayEnvironment), pick a device (stdDisplay_FindClosestDevice),
// scan every device/mode for hardware-3D capability, start stdDisplay, hook
// the gamma table + palette-effects palette pusher, open the device, load the
// colormap, then either the HW path (640x480x16 + std3D init + render option
// 0x100) or the SW path (640x480x8 + a 16bpp scratch VBuffer). SetMode wraps
// the back buffer in a dwImageVBuf (dwDisplay_pScreenImage) that the whole DW
// GUI draws through.
//
// OPENJKDF2 ADAPTATION (per DW/DECOMP_PROGRESS.md "DirectSound / Win32"
// decision): the SDL3-era stdDisplay owns the real window/GPU pipeline
// (Window_InitWindow/Video_Startup run before dwMain_Startup), so this unit
// must NOT bring up a second pipeline. The DW dual-path STRUCTURE is kept but
// routed through the repo stdDisplay:
//   - no display-environment enumeration (dwDisplay_pEnv stays NULL) and no
//     DirectDraw caps scan (dwDisplay_bHardware3D forced 0);
//   - TODO(dw-decomp): LOUD — the HARDWARE-3D path (std3D_* init @0x443bd0,
//     render option |0x100, 640x480x16) is STUBBED; only the software 8bpp
//     path is brought up (P2 decision: SW path first).
//   - buffer mapping: DW back/working buffer @0x6b5a40 -> &Video_otherBuf;
//     DW front/primary buffer @0x6b17c0 -> &Video_menuBuffer, pushed to the
//     window with stdDisplay_DDrawGdiSurfaceFlip() after each present (the
//     binary's fullscreen present WAS the copy to the visible primary).
//     Under -droidworks the jk GUI never runs, so both engine buffers are
//     free for DW's use.
//
// Dirty-rect list: circular list of dwDirtyRect with a rect-less sentinel.
// The binary allocated the sentinel in a CRT static ctor (@0x443910, with an
// atexit'd FreeDirtyList); here dwDisplay_Startup() does it. Nodes use
// malloc/free like dwList (binary: operator new / HostServices FreeHandle).
//
// Compiled as C++ (dwDisplay_SetMode has an MSVC EH frame and constructs a
// dwImageVBuf with operator new); the API keeps C linkage via dwDisplay.h.

#include "Dw/dwDisplay.h"

#include "Dw/dwCursor.h"
#include "Dw/dwColormap.h"
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h"

#include <stdlib.h>

#include "jk.h"
#include "stdPlatform.h"
#include "Engine/rdColormap.h"
#include "General/stdPalEffects.h"
// These engine headers have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/stdDisplay.h"
#include "Engine/rdroid.h"
#include "Engine/sithRender.h"
}

// Module globals (all reset in dwDisplay_Startup; soft-reset rule).
void* dwDisplay_pEnv = NULL;               // binary: 0x541d24
int dwDisplay_deviceIdx = 0;               // binary: 0x541c4c
char dwDisplay_bHardware3D = 0;            // binary: 0x541d28
uint32_t dwDisplay_hw3DDevice = 0;         // binary: 0x541c58
uint32_t dwDisplay_hw3DMode = 0;           // binary: 0x541c5c
dwImageVBuf* dwDisplay_pScreenImage = NULL;// binary: 0x541c3c
tVBuffer* dwDisplay_pSwBuffer = NULL;      // binary: 0x541c20
dwDirtyRect* dwDisplay_pDirtyList = NULL;  // binary: 0x541c54
tVBuffer* dwDisplay_pBackVBuf = NULL;      // binary: the unnamed tVBuffer @0x6b5a40
tVBuffer* dwDisplay_pFrontVBuf = NULL;     // binary: the unnamed tVBuffer @0x6b17c0

// DW's 10-entry display gamma table (binary: DAT_00529fb8; verified
// byte-identical to the engine's own table in src/Win95/Video.c).
static flex_d_t dwDisplay_aGammaTable[10] = {
    1.0,
    0.9090909090909091,
    0.8333333333333334,
    0.7142857142857143,
    0.625,
    0.5555555555555556,
    0.5263157894736842,
    0.5,
    0.47619047619047616,
    0.4347826086956522,
};

// Note: no binary counterpart — the binary built the dirty list in a CRT
// static ctor (@0x443910: call InitDirtyList, atexit FreeDirtyList). Resets
// every module global for the soft-reset loop, freeing a previous run's list.
void dwDisplay_Startup()
{
    if (dwDisplay_pDirtyList)
        dwDisplay_FreeDirtyList();
    dwDisplay_pDirtyList = NULL;

    dwDisplay_pEnv = NULL;
    dwDisplay_deviceIdx = 0;
    dwDisplay_bHardware3D = 0;
    dwDisplay_hw3DDevice = 0;
    dwDisplay_hw3DMode = 0;
    dwDisplay_pScreenImage = NULL;
    dwDisplay_pSwBuffer = NULL;
    dwDisplay_pBackVBuf = NULL;
    dwDisplay_pFrontVBuf = NULL;

    dwDisplay_InitDirtyList();
}

// @443920
void dwDisplay_InitDirtyList()
{
    dwDisplay_pDirtyList = NULL;
    dwDisplay_pDirtyList = (dwDirtyRect*)malloc(sizeof(dwDirtyRect));
    // Note: the original did not null-check the allocation either, and left
    // the sentinel's rect fields uninitialized.
    dwDisplay_pDirtyList->pNext = dwDisplay_pDirtyList;
    dwDisplay_pDirtyList->pPrev = dwDisplay_pDirtyList;
}

// @443960
void dwDisplay_FreeDirtyList()
{
    dwDirtyRect* pSent = dwDisplay_pDirtyList;
    dwDirtyRect* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwDirtyRect* pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        pNode->pNext = NULL;
        pNode->pPrev = NULL;
        free(pNode);
        pNode = pNext;
    }
    free(pSent);
    // Note: like the binary, dwDisplay_pDirtyList is left dangling; callers
    // (dwDisplay_Startup) re-run InitDirtyList before any further use.
}

// @4439c0
int dwDisplay_Open(char* pColormapName)
{
    stdDeviceParams params;

    // Binary: dwDisplay_pEnv = stdBuildDisplayEnvironment(), then a caps scan
    // over every device/mode for a hardware-3D-capable 16bpp mode (preferring
    // GUID'd 3D devices, falling back to any 3D mode), setting
    // dwDisplay_bHardware3D/hw3DDevice/hw3DMode.
    // Note: the SDL3 stdDisplay has no display-environment enumeration
    // (stdBuildDisplayEnvironment is JK.EXE-only) — the environment stays
    // NULL and the scan is skipped.
    dwDisplay_pEnv = NULL;
    params.field_0 = 1;
    params.field_4 = 1;
    params.field_8 = 1;
    params.field_C = 1;
    params.field_10 = 1;
    dwDisplay_deviceIdx = stdDisplay_FindClosestDevice(&params);

    // TODO(dw-decomp): LOUD — hardware-3D detection stubbed off; only the
    // software 8bpp path below is brought up (see the file-top note).
    dwDisplay_bHardware3D = 0;
    dwDisplay_hw3DDevice = 0;
    dwDisplay_hw3DMode = 0;

    if (stdDisplay_Startup())
    {
        // Binary: DW-stdDisplay SetGammaTable(10, DAT_00529fb8) + registers
        // its gamma-corrected master-palette pusher (@0x4fe3b0) with
        // stdPalEffects. Note: repo twin per Video_Startup — the palette
        // pusher maps to stdDisplay_SetMasterPalette.
        stdDisplay_SetGammaTable(10, dwDisplay_aGammaTable);
        stdPalEffects_Open((stdPalEffectSetPaletteFunc_t)stdDisplay_SetMasterPalette);

        dwDisplay_bHardware3D = 0;

        // Binary: if a mode is already set on the SAME device, bail out with
        // cursors only (return 0); if set on another device, clear it first.
        // Note: keyed on our own dwDisplay_pScreenImage instead of the
        // DW-stdDisplay statics, so a soft reset (statics cleared) re-runs
        // the full path even though the engine display stays up.
        if (stdDisplay_bModeSet && dwDisplay_pScreenImage)
        {
            dwDisplay_CreateCursorSprites();
            return 0;
        }

        stdDisplay_Open(dwDisplay_deviceIdx);
        dwColormap_Load(pColormapName);

        if (dwDisplay_bHardware3D)
        {
            // TODO(dw-decomp): LOUD — HARDWARE-3D PATH STUBBED. Binary:
            //   dwDisplay_SetMode(640, 480, 16);
            //   std3D_FUN_00505110(); std3D_FUN_005051b0(dwDisplay_hw3DMode, 1);
            //   if (!*DAT_00648e04) std3D_SetRenderList(std3D_FUN_00505510() & 0xfffffe4d);
            //   std3D_FUN_00505530(1, 1, 0x100, 0x100);
            //   rdOpen(1); rdSetRenderOptions(rdGetRenterOptions() | 0x100);
            // Unreachable while dwDisplay_bHardware3D is forced 0 above.
            dwDisplay_SetMode(640, 480, 16);
            rdOpen(1);
            rdSetRenderOptions(rdGetRenterOptions() | 0x100);
            dwDisplay_CreateCursorSprites();
            return 1;
        }

        // Software path: 640x480x8.
        dwDisplay_SetMode(640, 480, 8);
        rdOpen(0); // binary: rd_FUN_0047ea60(0) == rdOpen(0); no-op if the engine already opened rd
        rdSetRenderOptions(rdGetRenterOptions() & ~0x100);

        // Screen-sized system-memory scratch buffer in the current mode's
        // format with bpp forced to 16 (binary quirk: the SW path still
        // allocates a 16bpp buffer).
        if (stdDisplay_pCurVideoMode) // Note: guard added; always non-NULL in the binary here
        {
            tRasterInfo fmt;
            _memcpy(&fmt, &stdDisplay_pCurVideoMode->format, sizeof(fmt));
            fmt.format.bpp = 0x10;
            dwDisplay_pSwBuffer = stdDisplay_VBufferNew(&fmt, 0, 0, NULL);
        }
        dwDisplay_CreateCursorSprites();
        return 1;
    }

    dwDisplay_CreateCursorSprites();
    return 0;
}

// @443cb0
void dwDisplay_CreateCursorSprites()
{
    // Running 16bpp: reload the workshop colormap so dwColormap rebuilds its
    // 8->16bpp palette table for the cursor sprite blits.
    if (stdDisplay_pCurVideoMode && stdDisplay_pCurVideoMode->format.format.bpp == 0x10)
        dwColormap_Load((char*)"workshop2.cmp");

    // Note: guard added — the binary copied the front buffer's format
    // unconditionally (its tVBuffer globals always existed); ours only exist
    // once dwDisplay_SetMode ran.
    if (!dwDisplay_pFrontVBuf)
        return;

    tRasterInfo fmt;
    _memcpy(&fmt, &dwDisplay_pFrontVBuf->format, sizeof(fmt));
    fmt.width = 0x20;
    fmt.height = 0x20;

    rdColor24* pPal = NULL;
    if (fmt.format.bpp == 8 && dwColormap_pCurrent)
        pPal = dwColormap_pCurrent->colors;

    dwCursor_pSprite = stdDisplay_VBufferNew(&fmt, 0, 0, pPal);
    if (dwCursor_pSprite)
    {
        if (dwCursor_pSprite->lockSurfRefCount != 0)
            stdDisplay_VBufferUnlock(dwCursor_pSprite);
        stdDisplay_VBufferSetColorKey(dwCursor_pSprite, 0);
    }

    dwCursor_pSaveUnder = stdDisplay_VBufferNew(&fmt, 0, 0, pPal);
    if (dwCursor_pSaveUnder && dwCursor_pSaveUnder->lockSurfRefCount != 0)
        stdDisplay_VBufferUnlock(dwCursor_pSaveUnder);

    dwCursor_SetCursor(1);
}

// @443d80
void dwDisplay_Shutdown()
{
    // Binary: stdFreeDisplayEnvironment(dwDisplay_pEnv).
    // Note: no environment is ever allocated in the SDL3 adaptation.
    dwDisplay_pEnv = NULL;

    if (dwColormap_pCurrent)
        rdColormap_Free(dwColormap_pCurrent); // binary: rdColormap_FUN_0047e230
    dwColormap_pCurrent = NULL;

    if (dwDisplay_pScreenImage)
        delete dwDisplay_pScreenImage; // binary: vtbl +0x00 scalar-deleting dtor(1)
    dwDisplay_pScreenImage = NULL;

    if (dwDisplay_pSwBuffer)
    {
        stdDisplay_VBufferFree(dwDisplay_pSwBuffer);
        dwDisplay_pSwBuffer = NULL;
    }

    dwDisplay_FreeCursors();

    sithRender_Open(); // faithful: the binary re-opens the sith render defaults on display teardown

    // Binary: released its frame surfaces + display mode + restored the
    // desktop mode (stdDisplay_FUN_004fdb40 / _FUN_004fd950 /
    // stdDisplay_RestoreDisplayMode). Note: the engine owns the SDL3
    // display, so only the (no-op) RestoreDisplayMode is kept; the DW-side
    // buffer pointers are simply dropped.
    dwDisplay_pBackVBuf = NULL;
    dwDisplay_pFrontVBuf = NULL;
    stdDisplay_RestoreDisplayMode();
}

// @443e00
void dwDisplay_FreeCursors()
{
    if (dwCursor_pSprite)
    {
        stdDisplay_VBufferFree(dwCursor_pSprite);
        dwCursor_pSprite = NULL;
    }
    if (dwCursor_pSaveUnder)
    {
        stdDisplay_VBufferFree(dwCursor_pSaveUnder);
        dwCursor_pSaveUnder = NULL;
    }
    for (int i = 0; i < DWCURSOR_NUM_CURSORS; i++)
    {
        if (dwCursor_aCursors[i].pImage)
            delete dwCursor_aCursors[i].pImage; // binary: vtbl +0x00 scalar-deleting dtor(1)
        dwCursor_aCursors[i].pImage = NULL;
    }
}

// @443e60
int dwDisplay_SetMode(int width, int height, int bpp)
{
    render_pair mode;

    _memset(&mode, 0, sizeof(mode)); // Note: added — the binary left the unset fields as stack garbage
    // Field placement mirrors the binary exactly (Ghidra render_pair offsets
    // +0x20 / +0x1c / +0x08 / +0x0c).
    mode.render_rgb.bpp = (bpp != 8) ? bpp : 8;
    mode.render_8bpp.palBytes = (bpp != 8);
    mode.render_8bpp.width = width & 0xffff;
    mode.render_8bpp.height = height & 0xffff;

    int modeIdx = stdDisplay_FindClosestMode(&mode, Video_renderSurface, stdDisplay_numVideoModes);
    // Binary palette arg: rdColormap_pCurMap->colors (DAT_005542b8 + 0x30).
    int bOk = stdDisplay_SetMode(modeIdx,
                                 rdColormap_pCurMap ? (const void*)rdColormap_pCurMap->colors : NULL,
                                 1);
    if (bOk)
    {
        // Binary: Window_sub_507170(windowed, modeW, modeH) resized the OS
        // window to the mode. Note: the repo window layer owns sizing/scaling.

        // Establish the DW buffer mapping (see file-top note).
        dwDisplay_pBackVBuf = &Video_otherBuf;
        dwDisplay_pFrontVBuf = &Video_menuBuffer;

        stdDisplay_VBufferFill(dwDisplay_pBackVBuf, 0, NULL); // binary: DW-stdDisplay fill @0x4fe010
        stdDisplay_DDrawGdiSurfaceFlip();                     // binary: DW-stdDisplay flip @0x4fdc60

        if (dwDisplay_pScreenImage)
            delete dwDisplay_pScreenImage; // binary: vtbl +0x00 scalar-deleting dtor(1)
        // Note: the binary null-checked operator new's result; C++ new throws
        // instead, matching the original's practical behavior (it never ran
        // the NULL branch).
        dwDisplay_pScreenImage = new dwImageVBuf(dwDisplay_pBackVBuf);
    }
    return bOk != 0;
}

// @444140 — links a fresh node carrying *pRect after pAfter.
// (File-local in effect: the binary's only caller is dwDisplay_AddDirtyRect.)
static dwDirtyRect* dwDisplay_InsertDirtyNode(dwDirtyRect* pAfter, dwRect* pRect)
{
    dwDirtyRect* pNew = (dwDirtyRect*)malloc(sizeof(dwDirtyRect));
    // Note: the binary "null-checked" a biased pointer (&node->left), which
    // never fails — kept unchecked like the dwList allocations.
    pNew->left = pRect->left;
    pNew->top = pRect->top;
    pNew->right = pRect->right;
    pNew->bottom = pRect->bottom;

    pNew->pNext = pAfter->pNext;
    pNew->pPrev = pAfter;
    pAfter->pNext = pNew;
    pNew->pNext->pPrev = pNew;
    return pNew;
}

// @443fa0
void dwDisplay_AddDirtyRect(dwRect* pRect)
{
    // Note: guard added — the binary's list exists from CRT static-init;
    // ours only after dwDisplay_Startup (dwColormap can call in before the
    // P7 boot flow wires that up).
    if (!dwDisplay_pDirtyList)
        return;

    dwDirtyRect* pNode = dwDisplay_pDirtyList->pNext;
    if (pNode == dwDisplay_pDirtyList)
    {
        dwDisplay_InsertDirtyNode(dwDisplay_pDirtyList->pPrev, pRect);
        return;
    }

    for (; pNode != dwDisplay_pDirtyList; pNode = pNode->pNext)
    {
        if (dwRect_Overlaps(pRect, (dwRect*)&pNode->left))
        {
            // Coalesce: grow the existing node to cover the new rect.
            // (Touching rects count as overlapping — see dwRect_Overlaps.)
            dwRect_Union((dwRect*)&pNode->left, pRect);
            break;
        }
    }

    if (pNode == dwDisplay_pDirtyList)
    {
        // No overlap anywhere: append a copy at the tail (the binary inlines
        // a duplicate of InsertDirtyNode here).
        dwDirtyRect* pTail = dwDisplay_pDirtyList->pPrev;
        dwDirtyRect* pNew = (dwDirtyRect*)malloc(sizeof(dwDirtyRect));
        pNew->left = pRect->left;
        pNew->top = pRect->top;
        pNew->right = pRect->right;
        pNew->bottom = pRect->bottom;

        pNew->pPrev = pTail;
        pNew->pNext = pTail->pNext;
        pTail->pNext = pNew;
        pNew->pNext->pPrev = pNew;
    }
}

// @444050
void dwDisplay_Present(void)
{
    rdRect rect;

    // Note: NULL guard added — the binary's screen image always existed once
    // a mode was set; ours arrives with dwDisplay_SetMode. pScreenImage
    // non-NULL implies pBackVBuf/pFrontVBuf are set (same SetMode).
    if (!dwDisplay_pScreenImage)
        return;
    if (dwDisplay_pScreenImage->lockState != 0)
        return;

    // Binary: in windowed GDI mode (device video_device[0] flag == 0) this
    // was just the whole-surface BitBlt (DW-stdDisplay flip @0x4fdc60) with
    // the OS cursor on top; the fullscreen path below drew the software
    // cursor and copied back -> front/primary. Note: the SDL3 adaptation
    // always takes the DW fullscreen-style software-cursor path, then flips
    // the front (menu) buffer to the window.
    dwCursor_bPrevValid = dwCursor_Draw(&rect);
    if (dwCursor_bPrevValid)
    {
        dwCursor_prevRect.x = rect.x;
        dwCursor_prevRect.y = rect.y;
        dwCursor_prevRect.width = rect.width;
        dwCursor_prevRect.height = rect.height;
    }

    stdDisplay_VBufferCopy(dwDisplay_pFrontVBuf, dwDisplay_pBackVBuf, 0, 0, NULL, 0);

    if (dwCursor_bPrevValid)
        dwCursor_RestoreUnder(&rect);

    stdDisplay_DDrawGdiSurfaceFlip(); // Note: added — pushes the front buffer to the window

    // Empty the dirty list (every present clears the accumulated rects).
    dwDirtyRect* pSent = dwDisplay_pDirtyList;
    if (pSent) // Note: guard added (see dwDisplay_AddDirtyRect)
    {
        dwDirtyRect* pNode = pSent->pNext;
        while (pNode != pSent)
        {
            dwDirtyRect* pNext = pNode->pNext;
            pNode->pPrev->pNext = pNode->pNext;
            pNode->pNext->pPrev = pNode->pPrev;
            pNode->pNext = NULL;
            pNode->pPrev = NULL;
            free(pNode);
            pNode = pNext;
        }
    }
}
