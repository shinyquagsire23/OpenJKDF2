#include "gdi32.h"

#include "vm.h"
#include "kernel32.h"
#include "main.h"

uint32_t Gdi32::GetStockObject(uint32_t a)
{
    return 0;
}

uint32_t Gdi32::GetDeviceCaps(uint32_t device, uint32_t index)
{
    printf("Get caps for %x, index %i\n", device, index);
    switch (index)
    {
        case BITSPIXEL:
            return 16;
        default:
            return 0;
    }
}

uint32_t Gdi32::CreateDIBSection(uint32_t hdc, struct BITMAPINFO* pbmi, uint32_t usage, uint32_t* ppvBits, uint32_t hSection, uint32_t offset)
{
    printf("STUB: CreateDibSection hdc %x, pbmi %x, usage %x, hsection %x, offset %x, %dx%d\n", hdc, real_ptr_to_vm_ptr(pbmi), usage, hSection, offset, pbmi->bmiHeader.biWidth, pbmi->bmiHeader.biHeight);
    *ppvBits = kernel32->VirtualAlloc(0, abs(pbmi->bmiHeader.biWidth)*abs(pbmi->bmiHeader.biHeight), 0, 0);
    
    SDL_Surface *surface = SDL_CreateRGBSurface(0, abs(pbmi->bmiHeader.biWidth), abs(pbmi->bmiHeader.biHeight), 8, 0,0,0,0);
    
    SDL_SetWindowSize(displayWindow, abs(pbmi->bmiHeader.biWidth), abs(pbmi->bmiHeader.biHeight));
    
    dc_surface[hdc] = surface;
    dc_fbufs[hdc] = (uint8_t*)vm_ptr_to_real_ptr(*ppvBits);
    gdi_render = true;
    
    return hBitmapCnt++;
}

uint32_t Gdi32::CreateCompatibleDC(uint32_t hdc)
{
    printf("Stub: CreateCompatibleDC(0x%x), ret %x\n", hdc, hdcCnt);
    return hdcCnt++;
}

uint32_t Gdi32::SelectObject(uint32_t hdc, uint32_t h)
{
    printf("Stub: SelectObject(0x%x, 0x%x)\n", hdc, h);
    
    selectedHdcSrc = hdc;
    return 0;
}

uint32_t Gdi32::GdiFlush()
{
    //SDL_UpdateWindowSurface(displayWindow);
    //SDL_RenderPresent(displayRenderer);

    return 1;
}

uint32_t Gdi32::BitBlt(uint32_t hdc, int x, int y, int cx, int cy, uint32_t hdcSrc, int x1, int y1, struct color rop)
{
    if (!dc_fbufs[hdc]) return 1;

    //printf("STUB: BitBlt hdc %x, x %i, y %i, cx %i, cy %i, hdcSrc %x, x1 %i, y1 %i, rop %x\n", hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
    
    if (gdi_render)
    {    
        memcpy(dc_surface[hdc]->pixels, dc_fbufs[hdc], dc_surface[hdc]->w*dc_surface[hdc]->h);
        SDL_SetPaletteColors(dc_surface[hdc]->format->palette, dc_palettes[hdcSrc], 0, 256);
        
        SDL_Texture* texture = SDL_CreateTextureFromSurface(displayRenderer, dc_surface[hdc]);
        SDL_RenderClear(displayRenderer);
        SDL_RenderCopy(displayRenderer, texture, NULL, NULL);
        //SDL_UpdateWindowSurface(displayWindow);
        SDL_RenderPresent(displayRenderer);
        SDL_DestroyTexture(texture);
    }

    return 1;
}

uint32_t Gdi32::CreateFontA(int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName)
{
    printf("STUB: Create font %s\n", pszFaceName);
    return 0xebab;
}

uint32_t Gdi32::SetDIBColorTable(uint32_t hdc, uint32_t iStart, uint32_t cEntries, struct color* prgbq)
{
    printf("STUB: SetDIBColorTable %x %x %x, colors...\n", hdc, iStart, cEntries);
    
    for (int i = 0; i < cEntries; i++)
    {
        dc_palettes[hdc][i].r = prgbq[iStart + i].r;
        dc_palettes[hdc][i].g = prgbq[iStart + i].g;
        dc_palettes[hdc][i].b = prgbq[iStart + i].b;
        dc_palettes[hdc][i].a = 0xFF;
    }

    return 1;
}

uint32_t Gdi32::CreatePalette(void *plpal)
{
    return 0xebac;
}

uint32_t Gdi32::SelectPalette(uint32_t hdc, uint32_t hPal, bool bForceBkgd)
{
    return 0xebad;
}

uint32_t Gdi32::AnimatePalette(uint32_t hdc, uint32_t iStart, uint32_t cEntries, uint32_t** ppe)
{
    
    return 1;
}

uint32_t Gdi32::RealizePalette(uint32_t hdc)
{
    return 100;
}

uint32_t Gdi32::DeleteObject(uint32_t no)
{
    printf("STUB: DeleteObject(0x%x)\n", no);
    return 1;
}

uint32_t Gdi32::DeleteDC(uint32_t hdc)
{
    printf("STUB: DeleteDC(0x%x)\n", hdc);
    return 1;
}

uint32_t Gdi32::GetSystemPaletteEntries(uint32_t hdc, uint32_t iStart, uint32_t cEntries, struct color* pPalEntries)
{
    printf("STUB: Gdi32::GetSystemPaletteEntries hdc %x start %x cnt %x\n", hdc, iStart, cEntries);
    
    return cEntries;
}

/*uint32_t Gdi32::(uint32_t )
{
}*/
