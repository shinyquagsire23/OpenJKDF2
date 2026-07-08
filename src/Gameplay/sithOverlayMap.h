#ifndef _SITHOVERLAYMAP_H
#define _SITHOVERLAYMAP_H

#include "types.h"
#include "globals.h"

#define sithOverlayMap_Startup_ADDR (0x004D9180)
#define sithOverlayMap_Close_ADDR (0x004D91B0)
#define sithOverlayMap_ToggleMap_ADDR (0x004D91D0)
#define sithOverlayMap_ZoomIn_ADDR (0x004D91F0)
#define sithOverlayMap_ZoomOut_ADDR (0x004D9260)
#define sithOverlayMap_Draw_ADDR (0x004D92C0)
#define sithOverlayMap_DrawSectors_ADDR (0x004D9500)
#define sithOverlayMap_DrawSector_ADDR (0x004D9560)
#define sithOverlayMap_CanDrawSurfaceEdge_ADDR (0x004D9C40)

int sithOverlayMap_Startup(const SithOverlayMapConfig *config);
int sithOverlayMap_Close();
void sithOverlayMap_ToggleMap();
void sithOverlayMap_ZoomIn();
void sithOverlayMap_ZoomOut();

MATH_FUNC int sithOverlayMap_Draw(rdCanvas *pCanvas);
MATH_FUNC void sithOverlayMap_DrawSectors(SithSector *sector);
MATH_FUNC int sithOverlayMap_DrawSector(SithSector *pSector);
MATH_FUNC int sithOverlayMap_CanDrawSurfaceEdge(SithSurface *a1, int a2, int a3);

//static int (*sithOverlayMap_Draw)(rdCanvas* pCanvas) = (void*)sithOverlayMap_Draw_ADDR;
//static int (*sithOverlayMap_ToggleMap)() = (void*)sithOverlayMap_ToggleMap_ADDR;
//static void (*sithOverlayMap_ZoomIn)() = (void*)sithOverlayMap_ZoomIn_ADDR;
//static void (*sithOverlayMap_ZoomOut)() = (void*)sithOverlayMap_ZoomOut_ADDR;

#endif // _SITHOVERLAYMAP_H
