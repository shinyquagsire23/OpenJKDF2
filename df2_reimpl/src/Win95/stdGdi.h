#ifndef _STDGDI_H
#define _STDGDI_H

#include "types.h"

#define stdGdi_Create8bppPaletted_ADDR (0x004368D0)
#define stdGdi_CreateRGB_ADDR (0x00436980)
#define stdGdi_Create16bppPaletted_ADDR (0x00436A10)
#define stdGdi_SetPalette_ADDR (0x00436A80)
#define stdGdi_SetPalette2_ADDR (0x00436B70)
#define stdGdi_GetSystemInfo_ADDR (0x00436C70)
#define stdGdi_SetHwnd_ADDR (0x00436D10)
#define stdGdi_GetHwnd_ADDR (0x00436D20)
#define stdGdi_SetHInstance_ADDR (0x00436D30)
#define stdGdi_GetHInstance_ADDR (0x00436D40)

static HWND (*stdGdi_GetHwnd)() = (void*)stdGdi_GetHwnd_ADDR;
static HINSTANCE (*stdGdi_GetHInstance)() = (void*)stdGdi_GetHInstance_ADDR;

#endif // _STDGDI_H
