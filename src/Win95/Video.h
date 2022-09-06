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

#ifdef SDL2_RENDER
extern rdCanvas* Video_pCanvasOverlayMap;
extern stdVBuffer* Video_pOverlayMapBuffer;
extern stdVBuffer Video_overlayMapBuffer;
extern uint32_t Video_overlayTexId;
#endif

static void (*Video_camera_related)() = (void*)Video_camera_related_ADDR;

//static void (*Video_Shutdown)() = (void*)Video_Shutdown_ADDR;
//static void (*Video_SwitchToGDI)() = (void*)Video_SwitchToGDI_ADDR;
//static int (*Video_Startup)() = (void*)Video_Startup_ADDR;

#endif // _WIN95_VIDEO_H
