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

HBITMAP stdGdi_Create8bppPaletted(HDC hdc, int a2, int a3, void **ppvBits, uint8_t *a5);
HBITMAP stdGdi_CreateRGB(HDC hdc, LONG width, int height, void **ppvBits);
HBITMAP stdGdi_Create16bppPaletted(HDC hdc, int width, int height, void **ppvBits);
UINT stdGdi_SetPalette(HDC hdc, BYTE *a2);
UINT stdGdi_SetPalette2(HDC hdc, uint8_t* a2, UINT iStartIndex, UINT cEntries);
void stdGdi_GetSystemInfo(int *a1, int *a2, int a3, int a4);
void stdGdi_SetHwnd(HWND a1);
HWND stdGdi_GetHwnd();
void stdGdi_SetHInstance(HINSTANCE a1);
HINSTANCE stdGdi_GetHInstance();

#endif // _STDGDI_H
