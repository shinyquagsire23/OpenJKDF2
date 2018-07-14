#ifndef GDI32_H
#define GDI32_H

#include <QObject>
#include <unicorn/unicorn.h>

#define BITSPIXEL 12

class Gdi32 : public QObject
{
Q_OBJECT

private:
    uint8_t* fbuf;
    uint32_t palette[256];

public:

    Q_INVOKABLE Gdi32() {}
    
    Q_INVOKABLE uint32_t GetStockObject(uint32_t a);
    Q_INVOKABLE uint32_t GetDeviceCaps(uint32_t device, uint32_t index);
    Q_INVOKABLE uint32_t CreateDIBSection(uint32_t hdc, void* pbmi, uint32_t usage, uint32_t* ppvBits, uint32_t hSection, uint32_t offset);
    Q_INVOKABLE uint32_t CreateCompatibleDC(uint32_t hdc);
    Q_INVOKABLE uint32_t SelectObject(uint32_t hdc, uint32_t h);
    Q_INVOKABLE uint32_t GdiFlush();
    Q_INVOKABLE uint32_t BitBlt(uint32_t hdc, int x, int y, int cx, int cy, uint32_t hdcSrc, int x1, int y1, uint32_t rop);
    Q_INVOKABLE uint32_t CreateFontA(int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t    cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName);
    Q_INVOKABLE uint32_t SetDIBColorTable(uint32_t hdc, uint32_t iStart, uint32_t cEntries, uint32_t* prgbq);
    Q_INVOKABLE uint32_t CreatePalette(void *plpal);
    Q_INVOKABLE uint32_t SelectPalette(uint32_t hdc, uint32_t hPal, bool bForceBkgd);
    Q_INVOKABLE uint32_t AnimatePalette(uint32_t hdc, uint32_t iStart, uint32_t cEntries, uint32_t** ppe);
    Q_INVOKABLE uint32_t RealizePalette(uint32_t hdc);
    Q_INVOKABLE uint32_t DeleteObject(uint32_t no);
    Q_INVOKABLE uint32_t DeleteDC(uint32_t hdc);

//    Q_INVOKABLE uint32_t ();
};

extern Gdi32 *gdi32;

#endif // GDI32_H
