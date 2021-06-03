#ifndef _WIN95_VIDEO_H
#define _WIN95_VIDEO_H

#include "types.h"

#define Video_Startup_ADDR (0x004018C0)
#define Video_Shutdown_ADDR (0x00401910)
#define Video_SetVideoDesc_ADDR (0x00401940)
#define Video_SwitchToGDI_ADDR (0x00401C10)
#define Video_camera_related_ADDR (0x00401CD0)

#define Video_fillColor (*(int*)0x00552898)
#define Video_modeStruct (*(videoModeStruct*)0x008605C0)
#define Video_otherBuf (*(stdVBuffer*)0x00866CA0)
#define Video_dword_866D78 (*(int*)0x00866D78)
#define Video_curMode (*(int*)0x00866D7C)
#define Video_renderSurface ((stdVideoMode*)0x00866D80)
#define Video_menuBuffer (*(stdVBuffer*)0x0086AC00)
#define Video_pOtherBuf (*(stdVBuffer**)0x00552888)
#define Video_pMenuBuffer (*(stdVBuffer**)0x0055288C)
#define Video_bInitted (*(int*)0x005528B4)
#define Video_flt_55289C (*(float*)0x0055289C)
#define Video_dword_5528A0 (*(int*)0x005528A0)
#define Video_dword_5528A4 (*(int*)0x005528A4)
#define Video_dword_5528A8 (*(int*)0x005528A8)
#define Video_lastTimeMsec (*(int*)0x005528AC)
#define Video_dword_5528B0 (*(int*)0x005528B0)
#define Video_pVbufIdk (*(stdVBuffer**)0x00552890)
#define Video_pCanvas (*(rdCanvas**)0x00552894)

typedef struct jkViewSize
{
  int xMin;
  int yMin;
  float xMax;
  float yMax;
} jkViewSize;

typedef struct videoModeStruct
{
  int modeIdx;
  int descIdx;
  int Video_8605C8;
  int field_C;
  int field_10;
  int field_14;
  int field_18;
  int field_1C;
  int field_20;
  int field_24;
  int field_28;
  HKEY b3DAccel;
  uint32_t viewSizeIdx;
  jkViewSize aViewSizes[11];
  int Video_8606A4;
  int Video_8606A8;
  int geoMode;
  int lightMode;
  int texMode;
  HKEY Video_8606B8;
  HKEY Video_8606BC;
  int Video_8606C0;
} videoModeStruct;

int Video_Startup();

static void (*Video_SwitchToGDI)() = (void*)Video_SwitchToGDI_ADDR;
//static int (*Video_Startup)() = (void*)Video_Startup_ADDR;

#endif // _WIN95_VIDEO_H
