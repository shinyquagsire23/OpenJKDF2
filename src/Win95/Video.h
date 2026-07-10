#ifndef _WIN95_VIDEO_H
#define _WIN95_VIDEO_H

#include "types.h"
#include "globals.h"

#define Video_Startup_ADDR (0x004018C0)
#define Video_Shutdown_ADDR (0x00401910)
#define Video_SetVideoDesc_ADDR (0x00401940)
#define Video_SwitchToGDI_ADDR (0x00401C10)
#define Video_camera_related_ADDR (0x00401CD0)

int Video_Startup();
void Video_Shutdown();
void Video_SwitchToGDI();
int Video_camera_related();
int Video_SetVideoDesc(const void *color_buf);

#ifdef SDL2_RENDER
extern rdCanvas* Video_pCanvasOverlayMap;
extern tVBuffer* Video_pOverlayMapBuffer;
extern tVBuffer Video_overlayMapBuffer;
extern uint32_t Video_overlayTexId;
#endif

#ifdef RDRASTER_SOFTWARE_RENDERER
// Dedicated full-resolution color buffer the software renderer draws the world into (sized to
// Video_menuBuffer, i.e. aspect*960 x 960). Kept SEPARATE from Video_menuBuffer so the world can be
// presented full-screen while the HUD/menu stays the 640x480-logical overlay composited on top
// (std3D_DrawMenu samples only a 640x480 sub-rect of the menu buffer). NULL until first ensured.
extern tVBuffer* Video_pSwWorldBuffer;
// Set by the jkGame_Update software bracket on frames that actually render the world; consumed by
// std3D's full-screen present so stale world frames aren't shown during menus/cutscenes.
extern int Video_swWorldPresentPending;
// Lazily (re)allocate Video_pSwWorldBuffer to match Video_menuBuffer's current dimensions (tracks
// window resize). Returns the buffer, or NULL if the menu buffer isn't ready yet.
tVBuffer* Video_swEnsureWorldBuffer(void);
// Composite the 2D overlays (HUD + overlay map) into the software world buffer so the frame is a
// single software image. Called after the HUD is drawn, before std3D_DrawMenu presents. No-op unless
// the software renderer rendered the world this frame.
void Video_swCompositeOverlaysIntoWorld(void);
#endif

//static void (*Video_camera_related)() = (void*)Video_camera_related_ADDR;

//static void (*Video_Shutdown)() = (void*)Video_Shutdown_ADDR;
//static void (*Video_SwitchToGDI)() = (void*)Video_SwitchToGDI_ADDR;
//static int (*Video_Startup)() = (void*)Video_Startup_ADDR;

#endif // _WIN95_VIDEO_H
