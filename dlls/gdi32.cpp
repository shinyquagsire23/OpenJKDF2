#include "gdi32.h"

#include "uc_utils.h"
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

uint32_t Gdi32::CreateDIBSection(uint32_t hdc, void* pbmi, uint32_t usage, uint32_t* ppvBits, uint32_t hSection, uint32_t offset)
{
    printf("STUB: CreateDibSection hdc %x, pbmi %x, usage %x, hsection %x, offset %x\n", hdc, real_ptr_to_uc_ptr(pbmi), usage, hSection, offset);
    *ppvBits = kernel32->VirtualAlloc(0, 0x80000, 0, 0);
    
    fbuf = (uint8_t*)uc_ptr_to_real_ptr(*ppvBits);
    
    return 7;
}

uint32_t Gdi32::CreateCompatibleDC(uint32_t hdc)
{
    return 0;
}

uint32_t Gdi32::SelectObject(uint32_t hdc, uint32_t h)
{
    return 0;
}

uint32_t Gdi32::GdiFlush()
{
    SDL_UpdateWindowSurface(displayWindow);
    SDL_RenderPresent(displayRenderer);

    return 1;
}

uint32_t Gdi32::BitBlt(uint32_t hdc, int x, int y, int cx, int cy, uint32_t hdcSrc, int x1, int y1, uint32_t rop)
{
    printf("STUB: BitBlt %x %i %i %i %i %x %i %i %x\n", hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
    
    uint8_t r, g, b, a;
    b = rop & 0xFF;
    g = (rop & 0xFF00) >> 8;
    r = (rop & 0xFF0000) >> 16;
    a = 0xff;
    
    SDL_SetRenderDrawColor(displayRenderer, r, g, b, a);
    SDL_Rect rectGame = {0, 0, 640, 480};
    SDL_RenderFillRect(displayRenderer, &rectGame);
    
    for (int i = 0; i < 640*480; i++)
    {
        uint8_t index = fbuf[i];
        
        uint32_t val = palette[index];
        b = val & 0xFF;
        g = (val & 0xFF00) >> 8;
        r = (val & 0xFF0000) >> 16;
        a = 0xff;
        
        SDL_SetRenderDrawColor(displayRenderer, r, g, b, a);
        SDL_RenderDrawPoint(displayRenderer, i % 640, i / 640);
    }

    return 1;
}

uint32_t Gdi32::CreateFontA(int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName)
{
    printf("STUB: Create font %s\n", pszFaceName);
    return 0xebab;
}

uint32_t Gdi32::SetDIBColorTable(uint32_t hdc, uint32_t iStart, uint32_t cEntries, uint32_t* prgbq)
{
    printf("STUB: SetDIBColorTable %x %x %x, colors...\n", hdc, iStart, cEntries);
    for (int i = 0; i < cEntries; i++)
    {
        printf("%08x\n", prgbq[iStart + i]);
        palette[i] = prgbq[iStart + i];
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
    return 1;
}

uint32_t Gdi32::DeleteDC(uint32_t hdc)
{
    return 1;
}

/*uint32_t Gdi32::(uint32_t )
{
}*/
