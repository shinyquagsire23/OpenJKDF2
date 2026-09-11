#ifndef _DWCURSOR_H
#define _DWCURSOR_H

// dwCursor — DroidWorks software mouse cursor with save-under
// double-buffering (draws a 32x32 sprite into the dwDisplay back buffer,
// remembering the pixels underneath so the working buffer stays clean).
//
// Ghidra (DroidWorks.exe) 0x443340-0x44391x:
//   dwCursor_TableInit@0x443350 (CRT static-ctor body; thunk @0x443340)
//   dwCursor_Redraw@0x443500
//   dwCursor_Draw@0x4435f0
//   dwCursor_RestoreUnder@0x443720
//   dwCursor_SetCursor@0x443780
//   dwCursor_Precache@0x4438d0
//
// The cursor sprite/save-under tVBuffers are ALLOCATED AND FREED BY dwDisplay
// (dwDisplay_CreateCursorSprites / dwDisplay_FreeCursors); this module only
// owns the table, position and previous-rect state.
//
// Compiled as C++ (dwCursor_SetCursor carries an MSVC EH frame around a stack
// dwImageVBuf); the whole API keeps C linkage via these guards.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dwImage dwImage; // C++ class (Dw/dwImage.h); opaque in the C view

// One cursor-shape slot (binary: 12-byte entries in dwCursor_aCursors).
// hotX/hotY = hotspot offset subtracted from the mouse position when drawing.
typedef struct dwCursorEntry
{
    const char* pFilename; // 0x00: .rle image name (NULL for slot 0 = hidden)
    dwImage* pImage;       // 0x04: lazily loaded via dwImage_LoadFile
    int16_t hotX;          // 0x08
    int16_t hotY;          // 0x0a
} dwCursorEntry;

// Table slots (see dwCursor_TableInit): 0 = none/hidden, 1 = arrow, 2 = hand,
// 3 = help, 4 = wait, 5..13 = the nine paint-tool cursors.
#define DWCURSOR_NUM_CURSORS (14)

extern dwCursorEntry dwCursor_aCursors[DWCURSOR_NUM_CURSORS];
extern int dwCursor_curIdx;        // current table index (0 = no cursor)
extern dwPoint dwCursor_pos;       // binary: 0x541bf8 — shared cursor position
                                   // (dwWidget/dwSegment write it directly)
extern int16_t dwCursor_drawX;     // last draw position (pos - hotspot), pre-clip
extern int16_t dwCursor_drawY;
extern rdRect dwCursor_prevRect;   // front-buffer rect of the previously shown cursor
extern int dwCursor_bPrevValid;    // nonzero when dwCursor_prevRect is valid
extern tVBuffer* dwCursor_pSprite;    // 32x32 cursor sprite (owned by dwDisplay)
extern tVBuffer* dwCursor_pSaveUnder; // 32x32 save-under buffer (owned by dwDisplay)

// Note: no binary counterpart — resets the module globals for OpenJKDF2's
// soft-reset loop and runs dwCursor_TableInit (which the binary ran as a CRT
// static ctor). Does NOT free loaded images or the sprite VBuffers — run
// dwDisplay_FreeCursors first when resetting a live display.
void dwCursor_Startup();

// Fills dwCursor_aCursors (binary: C++ static ctor via the CRT table).
void dwCursor_TableInit();

// Per-frame incremental cursor update: draws the cursor into the back buffer,
// copies the affected rect (and the previous cursor rect) to the front
// buffer, then restores the save-under so the back buffer stays clean.
void dwCursor_Redraw();

// Draws the cursor sprite into the dwDisplay back buffer at
// dwCursor_pos - hotspot, saving the covered pixels into dwCursor_pSaveUnder
// first. Writes the affected back-buffer rect to pOutRect. Returns nonzero
// when something was drawn.
int dwCursor_Draw(rdRect* pOutRect);

// Copies the save-under pixels back into the back buffer at pRect.
void dwCursor_RestoreUnder(rdRect* pRect);

// Selects cursor shape idx: lazily loads its image, renders it into
// dwCursor_pSprite, and toggles the OS cursor (hidden whenever the software
// cursor is active or idx is 0).
void dwCursor_SetCursor(int idx);

// Lazily loads cursor idx's image without selecting it.
void dwCursor_Precache(int idx);

#ifdef __cplusplus
}
#endif

#endif // _DWCURSOR_H
