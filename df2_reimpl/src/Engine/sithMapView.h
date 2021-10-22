#ifndef _SITHMAPVIEW_H
#define _SITHMAPVIEW_H

#include "types.h"
#include "globals.h"

#define sithMapView_Initialize_ADDR (0x004D9180)
#define sithMapView_Shutdown_ADDR (0x004D91B0)
#define sithMapView_ToggleMapDrawn_ADDR (0x004D91D0)
#define sithMapView_FuncIncrease_ADDR (0x004D91F0)
#define sithMapView_FuncDecrease_ADDR (0x004D9260)
#define sithMapView_Render1_ADDR (0x004D92C0)
#define sithMapView_Render2_ADDR (0x004D9500)
#define sithMapView_Render3_ADDR (0x004D9560)
#define sithMapView_Render4_ADDR (0x004D9C40)

int sithMapView_Initialize(const void *a1);
int sithMapView_Shutdown();
void sithMapView_ToggleMapDrawn();
void sithMapView_FuncIncrease();
void sithMapView_FuncDecrease();

int sithMapView_Render4(sithSurface *a1, int a2, int a3);

//static int (*sithMapView_ToggleMapDrawn)() = (void*)sithMapView_ToggleMapDrawn_ADDR;
//static void (*sithMapView_FuncIncrease)() = (void*)sithMapView_FuncIncrease_ADDR;
//static void (*sithMapView_FuncDecrease)() = (void*)sithMapView_FuncDecrease_ADDR;

#endif // _SITHMAPVIEW_H
