#ifndef GDI32_H
#define GDI32_H

#include <QObject>
#include <unicorn/unicorn.h>
#include <SDL2/SDL.h>
#include <GL/glew.h>

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

typedef struct BITMAPINFO
{
    struct BITMAPINFOHEADER bmiHeader;
    uint32_t bmiColors;
} BITMAPINFO;

typedef struct DCSurfaceInfo
{
    uint32_t w;
    uint32_t h;
} DCSurfaceInfo;

#pragma pack(pop)

class Gdi32 : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint8_t*> dc_fbufs;
    std::map<uint32_t, SDL_Color[256]> dc_palettes;
    std::map<uint32_t, GLuint> dc_surfacetex;
    std::map<uint32_t, GLuint> dc_surfacepal;
    std::map<uint32_t, void*> dc_surfacebuf;
    std::map<uint32_t, DCSurfaceInfo> dc_surface;
    uint32_t hdcCnt;
    uint32_t hBitmapCnt;
    uint32_t defaultHdcPal;
    
    
    uint32_t xres;
    uint32_t yres;

public:

    SDL_Color* getDefaultPal()
    {
        return dc_palettes[defaultHdcPal];
    }

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
    
    Q_INVOKABLE uint32_t GetLayout(uint32_t hWnd)
    {
        printf("STUB: GDI32.dll::GetLayout(%x)\n", hWnd);
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetLayout(uint32_t hWnd, uint32_t a)
    {
        printf("STUB: GDI32.dll::SetLayout(%x, %x)\n", hWnd, a);
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t CreateCompatibleBitmap(uint32_t hWnd, int w, int h)
    {
        printf("STUB: GDI32.dll::CreateCompatibleBitmap(%x, %u, %u)\n", hWnd, w, h);
        
        return 0xbbab;
    }
    
    Q_INVOKABLE uint32_t GetObjectA(uint32_t handle, int c, void* pv)
    {
        printf("STUB: GDI32.dll::GetObjectA(%x, %u, ...)\n", handle, c);
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t SetSystemPaletteUse(uint32_t hdc, uint32_t use)
    {
        printf("STUB: GDI32.dll::SetSystemPaletteUse(%x, %x)\n", hdc, use);
        
        return 1; //SYSPAL_STATIC
    }
    
    Q_INVOKABLE uint32_t StretchDIBits(
      uint32_t         hdc,
      int              xDest,
      int              yDest,
      int              DestWidth,
      int              DestHeight,
      int              xSrc,
      int              ySrc,
      int              SrcWidth,
      int              SrcHeight,
      void*       lpBits,
      BITMAPINFO *lpbmi,
      uint32_t         iUsage,
      uint32_t         rop
    )
    {
        printf("STUB: GDI32.dll::StretchDIBits(%x, %x, %x, %x, %x, %x, %x, %x, %x, ..., ..., %x, %x)\n", hdc, xDest, yDest, DestWidth, DestHeight, xSrc, ySrc, SrcWidth, SrcHeight, iUsage, rop);
        return DestWidth;
    }
    
    Q_INVOKABLE uint32_t ResizePalette(uint32_t hPal, uint32_t n)
    {
        printf("STUB: GDI32.dll::ResizePalette(%x, %x)\n", hPal, n);
        return 1;
    }
    
    Q_INVOKABLE uint32_t SetPaletteEntries(uint32_t hPal, uint32_t iStart, uint32_t cEntries, struct color* pPalEntries)
    {
        printf("STUB: GDI32.dll::SetPaletteEntries(%x, %x, %x, ...)\n", hPal, iStart, cEntries);
        
        return cEntries;
    }
    
    Q_INVOKABLE uint32_t GetPaletteEntries(uint32_t hPal, uint32_t iStart, uint32_t cEntries, struct color* pPalEntries)
    {
        printf("STUB: GDI32.dll::GetPaletteEntries(%x, %x, %x, ...)\n", hPal, iStart, cEntries);
        
        return cEntries;
    }
    
    Q_INVOKABLE uint32_t CreateHalftonePalette(uint32_t hdc)
    {
        printf("STUB: GDI32.dll::CreateHalftonePalette(%x)\n", hdc);
        return 0xAABBCC8;
    }

//    Q_INVOKABLE uint32_t ();
};

extern Gdi32 *gdi32;

#endif // GDI32_H
