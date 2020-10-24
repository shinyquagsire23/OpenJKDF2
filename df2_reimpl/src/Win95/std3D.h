#ifndef _STD3D_H
#define _STD3D_H

#define std3D_SetCurrentPalette_ADDR (0x429EF0)

signed int (__cdecl *std3D_SetCurrentPalette)(rdColor24 *a1, int a2) = std3D_SetCurrentPalette_ADDR;

#endif // _STD3D_H
