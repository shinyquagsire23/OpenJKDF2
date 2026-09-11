#ifndef _DWDISPLAY_H
#define _DWDISPLAY_H

// dwDisplay — DroidWorks display/backbuffer manager: display bring-up, the
// dirty-rect repaint list, the wrapped screen image, and frame present.
//
// Ghidra (DroidWorks.exe) 0x443920-0x4442ff:
//   dwDisplay_InitDirtyList@0x443920      dwDisplay_FreeDirtyList@0x443960
//   dwDisplay_Open@0x4439c0               dwDisplay_CreateCursorSprites@0x443cb0
//   dwDisplay_Shutdown@0x443d80           dwDisplay_FreeCursors@0x443e00
//   dwDisplay_SetMode@0x443e60            dwDisplay_AddDirtyRect@0x443fa0
//   dwDisplay_Present@0x444050            dwDisplay_InsertDirtyNode@0x444140
//   (the dwRect_Overlaps/Clip/Union helpers @0x4441xx live in dwRect.c)
//
// Buffer model (binary -> OpenJKDF2 mapping, see dwDisplay.cpp):
//   back/working buffer (unnamed @0x6b5a40, the whole DW GUI draws here)
//       -> dwDisplay_pBackVBuf  = &Video_otherBuf
//   front/primary buffer (unnamed @0x6b17c0, what the player sees)
//       -> dwDisplay_pFrontVBuf = &Video_menuBuffer (pushed to the window via
//          stdDisplay_DDrawGdiSurfaceFlip after each present)
//
// Compiled as C++ (dwDisplay_SetMode carries an MSVC EH frame and constructs
// a dwImageVBuf with operator new); the whole API keeps C linkage via these
// guards.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dwImageVBuf dwImageVBuf; // C++ class (Dw/dwImageVBuf.h); opaque in the C view

// Dirty-rect list node (binary /DW struct dwDirtyRect, size 0x10). The list
// is circular with a rect-less sentinel (dwDisplay_pDirtyList); the four
// shorts at +0x08 have the same LTRB layout as dwRect.
typedef struct dwDirtyRect dwDirtyRect;
struct dwDirtyRect
{
    dwDirtyRect* pNext; // 0x00
    dwDirtyRect* pPrev; // 0x04
    int16_t left;       // 0x08
    int16_t top;        // 0x0a
    int16_t right;      // 0x0c
    int16_t bottom;     // 0x0e
};

// Display environment/device selection (binary: stdBuildDisplayEnvironment
// result + FindClosestDevice index + the hardware-3D caps scan results).
extern void* dwDisplay_pEnv;          // binary: 0x541d24 (always NULL here — see dwDisplay_Open)
extern int dwDisplay_deviceIdx;       // binary: 0x541c4c
extern char dwDisplay_bHardware3D;    // binary: 0x541d28 (forced 0 — HW path stubbed)
extern uint32_t dwDisplay_hw3DDevice; // binary: 0x541c58
extern uint32_t dwDisplay_hw3DMode;   // binary: 0x541c5c

// The screen wrapped as a dwImage (rebuilt by dwDisplay_SetMode; wraps the
// BACK buffer — everything the DW GUI blits through it lands offscreen until
// dwDisplay_Present).
extern dwImageVBuf* dwDisplay_pScreenImage; // binary: 0x541c3c

// Screen-sized 16bpp system-memory scratch buffer created on the software
// path (binary: 0x541c20; the mode format with bpp forced to 16).
extern tVBuffer* dwDisplay_pSwBuffer;

// Sentinel of the circular dirty-rect list (binary: 0x541c54; consumed by
// dwGuiScreen_RenderActive/SegUpdate to decide what to repaint).
extern dwDirtyRect* dwDisplay_pDirtyList;

// Back/front buffers (see the buffer model above). NULL until
// dwDisplay_SetMode succeeds.
extern tVBuffer* dwDisplay_pBackVBuf;
extern tVBuffer* dwDisplay_pFrontVBuf;

// Note: no binary counterpart — resets the module globals for OpenJKDF2's
// soft-reset loop and (re)creates the dirty list, which the binary built in a
// CRT static ctor (@0x443910) and freed atexit.
void dwDisplay_Startup();

// Allocates the dirty list's sentinel node.
void dwDisplay_InitDirtyList();

// Frees every node INCLUDING the sentinel (dwDisplay_pDirtyList is left
// non-NULL/dangling by the binary; call dwDisplay_InitDirtyList to reuse).
void dwDisplay_FreeDirtyList();

// Full display bring-up: device selection, gamma/palette-effects hookup,
// stdDisplay open, colormap load, mode set (software 640x480x8 path; the
// hardware-3D 640x480x16 path is stubbed), cursor sprite creation.
// Returns 1 on success, 0 on failure OR when the display was already up.
int dwDisplay_Open(char* pColormapName);

// (Re)creates the 32x32 cursor sprite + save-under VBuffers in the current
// mode's format (reloading workshop2.cmp first when running 16bpp) and
// selects the arrow cursor.
void dwDisplay_CreateCursorSprites();

// Frees the DW-owned display objects (screen image, scratch buffer, cursor
// sprites/images) and re-opens the sith render defaults. Does NOT tear down
// the engine's display (see the Note in dwDisplay.cpp).
void dwDisplay_Shutdown();

// Frees the cursor sprite/save-under VBuffers and every loaded cursor image.
void dwDisplay_FreeCursors();

// Picks the closest video mode to width x height x bpp and sets it, clears
// the back buffer, presents once, and rewraps the back buffer in a fresh
// dwDisplay_pScreenImage. Returns nonzero on success.
// (The binary call sites push a 4th always-1 argument that the function
// never reads; it is omitted here.)
int dwDisplay_SetMode(int width, int height, int bpp);

// Unions pRect into the first overlapping node of the dirty list (touching
// rects count as overlapping — see dwRect_Overlaps), else appends a new node
// at the tail.
void dwDisplay_AddDirtyRect(dwRect* pRect);

// Draws the software cursor, copies the back buffer to the front, restores
// the cursor save-under, and empties the dirty list.
void dwDisplay_Present(void);

#ifdef __cplusplus
}
#endif

#endif // _DWDISPLAY_H
