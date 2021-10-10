#ifndef _SITHMAPVIEW_H
#define _SITHMAPVIEW_H

#include "types.h"

#define sithMapView_Initialize_ADDR (0x004D9180)
#define sithMapView_Shutdown_ADDR (0x004D91B0)
#define sithMapView_ToggleMapDrawn_ADDR (0x004D91D0)
#define sithMapView_FuncIncrease_ADDR (0x004D91F0)
#define sithMapView_FuncDecrease_ADDR (0x004D9260)
#define sithMapView_Render1_ADDR (0x004D92C0)
#define sithMapView_Render2_ADDR (0x004D9500)
#define sithMapView_Render3_ADDR (0x004D9560)
#define sithMapView_Render4_ADDR (0x004D9C40)

#define sithMapView_flMapSize (*(float*)0x0054A5E0)

#define sithMapView_matrix (*(rdMatrix34*)0x00835840)
#define sithMapView_pPlayer (*(sithThing**)0x00835870)
#define sithMapView_pCanvas (*(rdCanvas**)0x00835874)
#define sithMapView_x1 (*(int*)0x00835878)
#define sithMapView_y1 (*(int*)0x0083587C)
#define sithMapView_inst (*(sithMapView*)0x00835880)
#define sithMapView_bShowMap (*(int*)0x008358C4)
#define sithMapView_bInitted (*(int*)0x008358C8)

typedef struct sithMapView
{
    int numArr;
    float *unkArr;
    int *anonymous_2;
    int anonymous_3;
    int anonymous_4;
    int anonymous_5;
    int anonymous_6;
    int anonymous_7;
    int anonymous_8;
    int anonymous_9;
    int anonymous_10;
    int anonymous_11;
    char anonymous_12[16];
    sithWorld *world;
} sithMapView;

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
