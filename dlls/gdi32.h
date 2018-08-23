#ifndef GDI32_H
#define GDI32_H

#include <QObject>
#include <unicorn/unicorn.h>
#include <SDL2/SDL.h>

#define BITSPIXEL 12

struct color
{
    uint8_t b;
    uint8_t g;
    uint8_t r;
    uint8_t a;
};

#pragma pack(push, 1)
struct BITMAPINFOHEADER
{
    uint32_t biSize;
    int32_t biWidth;
    int32_t biHeight;
    uint16_t biPlanes;
    uint16_t biBitCount;
    uint32_t biCompression;
    uint32_t biSizeImage;
    uint32_t biXPelsPerMeter;
    uint32_t biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
};

struct BITMAPINFO
{
    struct BITMAPINFOHEADER bmiHeader;
    uint32_t bmiColors;
};

#pragma pack(pop)

class Gdi32 : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint8_t*> dc_fbufs;
    std::map<uint32_t, SDL_Color[256]> dc_palettes;
    std::map<uint32_t, SDL_Surface*> dc_surface;
    uint32_t hdcCnt;
    uint32_t hBitmapCnt;
    
    
    uint32_t xres;
    uint32_t yres;

public:

    uint32_t selectedHdcSrc;
    bool gdi_render;

    Q_INVOKABLE Gdi32() : hdcCnt(1), hBitmapCnt(1), gdi_render(true) {}
    
    Q_INVOKABLE uint32_t GetStockObject(uint32_t a);
    Q_INVOKABLE uint32_t GetDeviceCaps(uint32_t device, uint32_t index);
    Q_INVOKABLE uint32_t CreateDIBSection(uint32_t hdc, struct BITMAPINFO* pbmi, uint32_t usage, uint32_t* ppvBits, uint32_t hSection, uint32_t offset);
    Q_INVOKABLE uint32_t CreateCompatibleDC(uint32_t hdc);
    Q_INVOKABLE uint32_t SelectObject(uint32_t hdc, uint32_t h);
    Q_INVOKABLE uint32_t GdiFlush();
    Q_INVOKABLE uint32_t BitBlt(uint32_t hdc, int x, int y, int cx, int cy, uint32_t hdcSrc, int x1, int y1, struct color rop);
    Q_INVOKABLE uint32_t CreateFontA(int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t    cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName);
    Q_INVOKABLE uint32_t SetDIBColorTable(uint32_t hdc, uint32_t iStart, uint32_t cEntries, struct color* prgbq);
    Q_INVOKABLE uint32_t CreatePalette(void *plpal);
    Q_INVOKABLE uint32_t SelectPalette(uint32_t hdc, uint32_t hPal, bool bForceBkgd);
    Q_INVOKABLE uint32_t AnimatePalette(uint32_t hdc, uint32_t iStart, uint32_t cEntries, uint32_t** ppe);
    Q_INVOKABLE uint32_t RealizePalette(uint32_t hdc);
    Q_INVOKABLE uint32_t DeleteObject(uint32_t no);
    Q_INVOKABLE uint32_t DeleteDC(uint32_t hdc);
    Q_INVOKABLE uint32_t GetSystemPaletteEntries(uint32_t hdc, uint32_t iStart, uint32_t cEntries, struct color* pPalEntries);

//    Q_INVOKABLE uint32_t ();
};

extern Gdi32 *gdi32;

#endif // GDI32_H
