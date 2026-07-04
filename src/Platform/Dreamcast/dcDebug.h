// dcDebug: Dreamcast on-screen debug overlay helpers.
//
// A controller plugged into the 4th maple port (port D) turns on an on-screen
// debug overlay -- the jkHud FPS counter plus a memory-pressure readout. Keeping
// it behind the 4th-port pad means it's trivial to toggle on real hardware
// without a debug build. Dreamcast port only.
#ifndef DC_DEBUG_H
#define DC_DEBUG_H

#ifdef TARGET_DREAMCAST

#include <stddef.h>

// 1 if a controller is connected to the 4th maple port (port D). This is the
// toggle for the debug overlay.
int dcDebug_PadInPort4(void);

// Fill pOut with memory-pressure overlay line `idx`. Returns 1 if a line exists
// at that index, 0 once past the end.
int dcDebug_GetOverlayLine(int idx, char* pOut, size_t outSz);

#endif // TARGET_DREAMCAST
#endif // DC_DEBUG_H
