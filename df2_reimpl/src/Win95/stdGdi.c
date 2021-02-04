#include "stdGdi.h"

#include "jk.h"

typedef struct BITMAPINFO_stack
{
    union
    {
        BITMAPINFO bmi;
        
        // aaaaaaaaaaaaaaaaaaaaaaa
        struct aaaaaaaaaaaaaa
        {
            uint8_t hdr[0x28];
            RGBQUAD prgbq[256]; // aaaaaaaaaaaaaaaaa
        }
    }
} BITMAPINFO_stack;

typedef struct LOGPALETTE_stack
{
    LOGPALETTE plpal;
    PALETTEENTRY ppe[256];
    
} LOGPALETTE_stack;

static HWND stdGdi_hwnd;
static HINSTANCE stdGdi_HInstance;

HBITMAP stdGdi_Create8bppPaletted(HDC hdc, int a2, int a3, void **ppvBits, uint8_t *a5)
{
    BITMAPINFO_stack bmi_;

    bmi_.bmi.bmiHeader.biWidth = a2;
    bmi_.bmi.bmiHeader.biHeight = -a3;
    bmi_.bmi.bmiHeader.biSize = 40;
    bmi_.bmi.bmiHeader.biPlanes = 1;
    bmi_.bmi.bmiHeader.biBitCount = 8;
    bmi_.bmi.bmiHeader.biCompression = 0;
    bmi_.bmi.bmiHeader.biSizeImage = 0;
    bmi_.bmi.bmiHeader.biXPelsPerMeter = 0;
    bmi_.bmi.bmiHeader.biYPelsPerMeter = 0;
    bmi_.bmi.bmiHeader.biClrUsed = 0;
    bmi_.bmi.bmiHeader.biClrImportant = 0;

    for (int i = 0; i < 256; i++)
    {
        bmi_.bmi.bmiColors[i].rgbRed = a5[i*3 + 0];
        bmi_.bmi.bmiColors[i].rgbGreen = a5[i*3 + 1];
        bmi_.bmi.bmiColors[i].rgbBlue = a5[i*3 + 2];
        bmi_.bmi.bmiColors[i].rgbReserved = 0;
        //jk_printf("%u\n", i);
    }

    return jk_CreateDIBSection(hdc, &bmi_.bmi, 0, ppvBits, 0, 0);
}

HBITMAP stdGdi_CreateRGB(HDC hdc, LONG width, int height, void **ppvBits)
{
    RGBQUAD *v4; // ecx
    int i; // eax
    BITMAPINFO_stack bmi_;

    bmi_.bmi.bmiHeader.biWidth = width;
    bmi_.bmi.bmiHeader.biHeight = -height;
    bmi_.bmi.bmiHeader.biSize = 40;
    bmi_.bmi.bmiHeader.biPlanes = 1;
    bmi_.bmi.bmiHeader.biBitCount = 8;
    bmi_.bmi.bmiHeader.biCompression = 0;
    bmi_.bmi.bmiHeader.biSizeImage = 0;
    bmi_.bmi.bmiHeader.biXPelsPerMeter = 0;
    bmi_.bmi.bmiHeader.biYPelsPerMeter = 0;
    bmi_.bmi.bmiHeader.biClrUsed = 0;
    bmi_.bmi.bmiHeader.biClrImportant = 0;
    v4 = bmi_.bmi.bmiColors;
    for ( i = 0; i < 256; ++i )
    {
        *(WORD *)&v4->rgbBlue = i;
        v4 = (RGBQUAD *)((char *)v4 + 2);
    }
    return jk_CreateDIBSection(hdc, &bmi_.bmi, 1u, ppvBits, 0, 0);
}

HBITMAP stdGdi_Create16bppPaletted(HDC hdc, int width, int height, void **ppvBits)
{
    BITMAPINFO bmi; // [esp+0h] [ebp-2Ch] BYREF

    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biSize = 40;
    bmi.bmiHeader.biCompression = 0;
    bmi.bmiHeader.biSizeImage = 0;
    bmi.bmiHeader.biXPelsPerMeter = 0;
    bmi.bmiHeader.biYPelsPerMeter = 0;
    bmi.bmiHeader.biClrUsed = 0;
    bmi.bmiHeader.biClrImportant = 0;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 16;
    return jk_CreateDIBSection(hdc, &bmi, 0, ppvBits, 0, 0);
}

UINT stdGdi_SetPalette(HDC hdc, BYTE *a2)
{
    return stdGdi_SetPalette2(hdc, a2, 0, 256);
}

UINT stdGdi_SetPalette2(HDC hdc, uint8_t* a2, UINT iStartIndex, UINT cEntries)
{
    UINT result; // eax
    HPALETTE v19; // eax
    HPALETTE v22; // ebp
    
    LOGPALETTE_stack plpal_;
    LOGPALETTE* plpal = (LOGPALETTE*)&plpal;
    RGBQUAD prgbq[256]; // [esp+418h] [ebp-400h] BYREF

    for (int i = 0; i < cEntries; i++)
    {
        prgbq[i].rgbRed = a2[i*3 + 0];
        prgbq[i].rgbGreen = a2[i*3 + 1];
        prgbq[i].rgbBlue = a2[i*3 + 2];
        prgbq[i].rgbReserved = 0;
    }

    result = jk_SetDIBColorTable(hdc, 0, 0x100u, &prgbq);
    if ( result )
    {
        plpal->palVersion = 768;
        plpal->palNumEntries = 256;
        for (int i = 0; i < cEntries; i++)
        {
            plpal_.ppe[i].peRed = a2[i*3 + 0];
            plpal_.ppe[i].peGreen = a2[i*3 + 1];
            plpal_.ppe[i].peBlue = a2[i*3 + 2];
            plpal_.ppe[i].peFlags = 1;
        }
        v19 = jk_CreatePalette(plpal);
        v22 = jk_SelectPalette(hdc, v19, 1);
        jk_AnimatePalette(v19, iStartIndex, cEntries, plpal_.ppe);
        jk_RealizePalette(hdc);
        jk_SelectPalette(hdc, v22, 0);
        jk_DeleteObject(v19);
        result = 1;
    }
    return result;
}

void stdGdi_GetSystemInfo(int *a1, int *a2, int a3, int a4)
{
    int v5; // ebp
    int v6; // esi
    int v7; // edi
    int v8; // eax
    int v9; // ebp
    int v10; // eax

    v5 = a3;
    v6 = 0;
    v7 = 0;
    if ( (0x800000 & a3) != 0 )
    {
        if ( (a3 & 0x40000) != 0 )
        {
            v7 = 2 * jk_GetSystemMetrics(32);
            v8 = jk_GetSystemMetrics(33);
        }
        else
        {
            v7 = 2 * jk_GetSystemMetrics(5);
            v8 = jk_GetSystemMetrics(6);
        }
        v6 = 2 * v8;
    }
    if ( (a3 & 0xC00000) != 0 )
    {
        v9 = jk_GetSystemMetrics(6);
        v10 = jk_GetSystemMetrics(4) - v9;
        v5 = a3;
        v6 += v10;
    }
    if ( a4 )
        v6 += jk_GetSystemMetrics(15);
    if ( (v5 & 0x200000) != 0 )
        v7 += jk_GetSystemMetrics(2);
    if ( (v5 & 0x100000) != 0 )
        v6 += jk_GetSystemMetrics(21);
    *a1 += v7;
    *a2 += v6;
}

void stdGdi_SetHwnd(HWND a1)
{
    stdGdi_hwnd = a1;
}

HWND stdGdi_GetHwnd()
{
    return stdGdi_hwnd;
}

void stdGdi_SetHInstance(HINSTANCE a1)
{
    stdGdi_HInstance = a1;
}

HINSTANCE stdGdi_GetHInstance()
{
    return stdGdi_HInstance;
}
