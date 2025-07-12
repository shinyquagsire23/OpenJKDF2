#ifndef _SITHOVERLAYMAP_H
#define _SITHOVERLAYMAP_H

#include "types.h"
#include "globals.h"

#define sithOverlayMap_Startup_ADDR (0x004D9180)
#define sithOverlayMap_Shutdown_ADDR (0x004D91B0)
#define sithOverlayMap_ToggleMapDrawn_ADDR (0x004D91D0)
#define sithOverlayMap_FuncIncrease_ADDR (0x004D91F0)
#define sithOverlayMap_FuncDecrease_ADDR (0x004D9260)
#define sithOverlayMap_Render1_ADDR (0x004D92C0)
#define sithOverlayMap_Render2_ADDR (0x004D9500)
#define sithOverlayMap_Render3_ADDR (0x004D9560)
#define sithOverlayMap_Render4_ADDR (0x004D9C40)

int sithOverlayMap_Startup(const sithMapViewConfig *config);
int sithOverlayMap_Shutdown();
void sithOverlayMap_ToggleMapDrawn();
void sithOverlayMap_FuncIncrease();
void sithOverlayMap_FuncDecrease();

MATH_FUNC int sithOverlayMap_Render1(rdCanvas *canvas);
MATH_FUNC void sithOverlayMap_Render2(sithSector *sector);
MATH_FUNC int sithOverlayMap_Render3(sithSector *pSector);
MATH_FUNC int sithOverlayMap_Render4(sithSurface *a1, int a2, int a3);

//static int (*sithOverlayMap_Render1)(rdCanvas* canvas) = (void*)sithOverlayMap_Render1_ADDR;
//static int (*sithOverlayMap_ToggleMapDrawn)() = (void*)sithOverlayMap_ToggleMapDrawn_ADDR;
//static void (*sithOverlayMap_FuncIncrease)() = (void*)sithOverlayMap_FuncIncrease_ADDR;
//static void (*sithOverlayMap_FuncDecrease)() = (void*)sithOverlayMap_FuncDecrease_ADDR;

#endif // _SITHOVERLAYMAP_H
