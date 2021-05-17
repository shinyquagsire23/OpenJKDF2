
#ifndef IDIRECTDRAW4_H
#define IDIRECTDRAW4_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"
#include "dlls/gdi32.h"
#include "renderer.h"

#define DDPF_ALPHAPIXELS     0x1
#define DDPF_PALETTEINDEXED8 0x20
#define DDPF_RGB             0x40

#define DDCAPS_3D                  0x00000001

#define DDSCAPS_BACKBUFFER         0x00000004
#define DDSCAPS_COMPLEX            0x00000008
#define DDSCAPS_PALETTE            0x00000100
#define DDSCAPS_PRIMARYSURFACE     0x00000200
#define DDSCAPS_PRIMARYSURFACELEFT 0x00000400
#define DDSCAPS_SYSTEMMEMORY       0x00000800
#define DDSCAPS_TEXTURE            0x00001000
#define DDSCAPS_3DDEVICE           0x00002000
#define DDSCAPS_VIDEOMEMORY        0x00004000
#define DDSCAPS_ZBUFFER            0x00020000
#define DDSCAPS_MIPMAP             0x00400000

#define DDSD_CAPS           0x00000001
#define DDSD_HEIGHT         0x00000002
#define DDSD_WIDTH          0x00000004
#define DDSD_PITCH          0x00000008
#define DDSD_PIXELFORMAT    0x00001000
#define DDSD_MIPMAPCOUNT    0x00020000
#define DDSD_LINEARSIZE     0x00080000
#define DDSD_DEPTH          0x00800000

struct ddraw_color
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
};

struct DDCOLORKEY
{
    uint32_t thing1;
    uint32_t thing2;
};

struct DDPIXELFORMAT
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwFourCC;
    uint32_t dwRGBBitCount;
    uint32_t dwRBitMask;
    uint32_t dwGBitMask;
    uint32_t dwBBitMask;
    uint32_t dwRGBAlphaBitMask;
};

struct DDSURFACEDESC
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwHeight;
    uint32_t dwWidth;
    uint32_t lPitch; //10
    uint32_t dwBackBufferCount;
    uint32_t dwMipMapCount;
    uint32_t dwAlphaBitDepth;
    uint32_t dwReserved; //20
    uint32_t lpSurface;
    struct DDCOLORKEY ddckCKDestOverlay; //28
    struct DDCOLORKEY ddckCKDestBltl; //30
    struct DDCOLORKEY ddckCKSrcOverlay; //38
    struct DDCOLORKEY ddckCKSrcBlt; //40
    struct DDPIXELFORMAT ddpfPixelFormat; //48
    uint32_t ddsCaps;
};

//x $ebp+0x4c

struct DDCAPS
{
  uint32_t dwSize;
  uint32_t dwCaps;
  uint32_t dwCaps2;
  uint32_t dwCKeyCaps;
  uint32_t dwFXCaps;
  uint32_t dwFXAlphaCaps;
  uint32_t dwPalCaps;
  uint32_t dwSVCaps;
  uint32_t dwAlphaBltConstBitDepths;
  uint32_t dwAlphaBltPixelBitDepths;
  uint32_t dwAlphaBltSurfaceBitDepths;
  uint32_t dwAlphaOverlayConstBitDepths;
  uint32_t dwAlphaOverlayPixelBitDepths;
  uint32_t dwAlphaOverlaySurfaceBitDepths;
  uint32_t dwZBufferBitDepths;
  uint32_t dwVidMemTotal;
  uint32_t dwVidMemFree;
  uint32_t dwMaxVisibleOverlays;
  uint32_t dwCurrVisibleOverlays;
  uint32_t dwNumFourCCCodes;
  uint32_t dwAlignBoundarySrc;
  uint32_t dwAlignSizeSrc;
  uint32_t dwAlignBoundaryDest;
  uint32_t dwAlignSizeDest;
  uint32_t dwAlignStrideAlign;
  uint32_t dwRops[8];
  uint32_t ddsCaps;
  uint32_t dwMinOverlayStretch;
  uint32_t dwMaxOverlayStretch;
  uint32_t dwMinLiveVideoStretch;
  uint32_t dwMaxLiveVideoStretch;
  uint32_t dwMinHwCodecStretch;
  uint32_t dwMaxHwCodecStretch;
  uint32_t dwReserved1;
  uint32_t dwReserved2;
  uint32_t dwReserved3;
  uint32_t dwSVBCaps;
  uint32_t dwSVBCKeyCaps;
  uint32_t dwSVBFXCaps;
  uint32_t dwSVBRops[8];
  uint32_t dwVSBCaps;
  uint32_t dwVSBCKeyCaps;
  uint32_t dwVSBFXCaps;
  uint32_t dwVSBRops[8];
  uint32_t dwSSBCaps;
  uint32_t dwSSBCKeyCaps;
  uint32_t dwSSBFXCaps;
  uint32_t dwSSBRops[8];
  uint32_t dwReserved4;
  uint32_t dwReserved5;
  uint32_t dwReserved6;
};

struct ddsurface_ext
{
    uint32_t lpVtbl;
    uint32_t unk;
    DDSURFACEDESC desc;
    vm_ptr<struct d3dtex_ext*> tex;
    DDSURFACEDESC locked_desc;
    uint32_t alloc;
    uint32_t palette;
    uint32_t handle;
    void* surfacebuf;
    GLuint surfacetex, surfacepaltex;
};

struct d3dtex_ext
{
    uint32_t lpVtbl;
    uint32_t padding[0x200/4];
    vm_ptr<struct ddsurface_ext*> parent_surface;
    uint32_t handle;
};

class IDirectDraw4 : public QObject
{
Q_OBJECT

public:

    std::map<uint32_t, SDL_Color[256]> palettes;
    struct ddsurface_ext* primary_surface;
    
    uint32_t displayModeWidth;
    uint32_t displayModeHeight;
    uint32_t displayModeBpp;

    Q_INVOKABLE IDirectDraw4() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectDraw4::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectDraw methods ***/
    Q_INVOKABLE void Compact(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::Compact\n");
    }
    
    Q_INVOKABLE void CreateClipper(void* this_ptr, uint32_t a, uint32_t b, uint32_t lpUnkOuter)
    {
        printf("STUB: IDirectDraw4::CreateClipper\n");
    }
    
    Q_INVOKABLE uint32_t CreatePalette(void* this_ptr, uint32_t a, struct ddraw_color* lpPaletteEntry, uint32_t* lpDDPalette, uint32_t lpUnkOuter)
    {
        printf("STUB: IDirectDraw4::CreatePalette(%u)\n", a);
        
        *lpDDPalette = CreateInterfaceInstance("IDirectDrawPalette", 200);
        uint32_t key = *(uint32_t*)(vm_ptr_to_real_ptr(*lpDDPalette));

        for(int i = 0; i < 256; i++)
        {
            palettes[key][i].r = lpPaletteEntry[i].r;
            palettes[key][i].g = lpPaletteEntry[i].g;
            palettes[key][i].b = lpPaletteEntry[i].b;
            palettes[key][i].a = 0xFF;
        }
        
        // 0 is transparent
        palettes[key][0].a = 0;
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t CreateSurface(void* this_ptr, DDSURFACEDESC* desc, uint32_t* lpDDSurface, void* lpUnkOuter)
    {
        printf("STUB: IDirectDraw4::CreateSurface\n");
        
        *lpDDSurface = CreateInterfaceInstance("IDirectDrawSurface3", 200); //4
        
        struct ddsurface_ext* ext = (struct ddsurface_ext*)vm_ptr_to_real_ptr(*lpDDSurface);

        if (!desc->ddpfPixelFormat.dwRGBBitCount)
        {
            desc->ddpfPixelFormat.dwRGBBitCount = displayModeBpp;
            //TODO fill the rest of the bitmask info?
        }

        desc->lPitch = desc->dwWidth * (desc->ddpfPixelFormat.dwRGBBitCount / 8);
        
        ext->desc = *desc;
        ext->palette = -1;
        ext->handle = 0;

        printf("IDirectDraw4::CreateSurface: texinfo, %ux%u pitch %u ddsCaps %x dwFlags %x bpp %x R,G,B,ABitMask %x %x %x %x\n", desc->dwWidth, desc->dwHeight, desc->lPitch, desc->ddsCaps, desc->ddpfPixelFormat.dwFlags, desc->ddpfPixelFormat.dwRGBBitCount, desc->ddpfPixelFormat.dwRBitMask, desc->ddpfPixelFormat.dwGBitMask, desc->ddpfPixelFormat.dwBBitMask, desc->ddpfPixelFormat.dwRGBAlphaBitMask);
        
        if (desc->ddsCaps & DDSCAPS_PRIMARYSURFACE)
        {
            printf("IDirectDraw4::CreateSurface: This is a primary surface!\n");
            primary_surface = ext;
        }
        
        ext->tex = {CreateInterfaceInstance("IDirect3DTexture", 200)}; //TODO memleaks, use this
        ext->tex->parent_surface = {*lpDDSurface};

        if (!(desc->ddsCaps & DDSCAPS_TEXTURE))
        {
            ext->unk = ext->tex.raw_vm_ptr;
        }
        
        
        // TODO duplicated in IDirectDraw4.h
        GLuint image_texture, pal_texture;
        glGenTextures(1, &image_texture);
        glGenTextures(1, &pal_texture);
        void* image_data = malloc(desc->dwWidth*desc->dwHeight*sizeof(uint32_t));
        
        glBindTexture(GL_TEXTURE_1D, pal_texture);
        glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        
        memset(image_data, 0xFF, 256);
        glTexImage1D(GL_TEXTURE_1D, 0, GL_RGBA8, 256, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
        

        glBindTexture(GL_TEXTURE_2D, image_texture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RED, desc->dwWidth, desc->dwHeight, 0, GL_RED, GL_UNSIGNED_BYTE, image_data);
        
        ext->surfacebuf = image_data;
        ext->surfacetex = image_texture;
        ext->surfacepaltex = pal_texture;
        
        return 0;
    }
    
    Q_INVOKABLE void DuplicateSurface(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDraw4::DuplicateSurface\n");
    }
    
    Q_INVOKABLE uint32_t EnumDisplayModes(void* this_ptr, uint32_t a, void* surfacedesc, void* c, uint32_t callback)
    {
        printf("STUB: IDirectDraw4::EnumDisplayModes\n");
        
        // a 640x480 8bpp display is mandatory for JK
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwSize = sizeof(desc);
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640*sizeof(uint8_t);
            desc->ddpfPixelFormat.dwSize = sizeof(desc->ddpfPixelFormat);
            desc->ddpfPixelFormat.dwRGBBitCount = 8;
            desc->ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_PALETTEINDEXED8;

            vm_call_func(callback, desc.raw_vm_ptr, 0);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 1280;
            desc->dwHeight = 1024;
            desc->lPitch = 1280*sizeof(uint8_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_PALETTEINDEXED8;

            vm_call_func(callback, desc.raw_vm_ptr, 0);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 1600;
            desc->dwHeight = 900;
            desc->lPitch = 1600*sizeof(uint8_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_PALETTEINDEXED8;

            vm_call_func(callback, desc.raw_vm_ptr, 0);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 1920;
            desc->dwHeight = 1080;
            desc->lPitch = 1920*sizeof(uint8_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_PALETTEINDEXED8;

            vm_call_func(callback, desc.raw_vm_ptr, 0);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
#if 0        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640;
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 32;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0x00FF0000;
            desc->ddpfPixelFormat.dwGBitMask = 0x0000FF00;
            desc->ddpfPixelFormat.dwBBitMask = 0x000000FF;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
#endif
#if 0
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640;
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0xF800;
            desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
            desc->ddpfPixelFormat.dwBBitMask = 0x001F;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
#endif
#if 0
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640;
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0xF800;
            desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
            desc->ddpfPixelFormat.dwBBitMask = 0x001F;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
#endif

        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640*sizeof(uint16_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0xF800;
            desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
            desc->ddpfPixelFormat.dwBBitMask = 0x001F;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }

        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 1280;
            desc->dwHeight = 1024;
            desc->lPitch = 1280*sizeof(uint16_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0xF800;
            desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
            desc->ddpfPixelFormat.dwBBitMask = 0x001F;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 1600;
            desc->dwHeight = 900;
            desc->lPitch = 1600*sizeof(uint16_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0xF800;
            desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
            desc->ddpfPixelFormat.dwBBitMask = 0x001F;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }

        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 1920;
            desc->dwHeight = 1080;
            desc->lPitch = 1920*sizeof(uint16_t);
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0;
            desc->ddpfPixelFormat.dwRBitMask = 0xF800;
            desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
            desc->ddpfPixelFormat.dwBBitMask = 0x001F;
            
            vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
            
            kernel32->VirtualFree(desc.raw_vm_ptr, 0, 0);
        }
        return 0;
    }
    
    Q_INVOKABLE void EnumSurfaces(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectDraw4::EnumSurfaces\n");
    }
    
    Q_INVOKABLE void FlipToGDISurface(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::FlipToGDISurface\n");
    }
    
    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, struct DDCAPS* caps1, struct DDCAPS* caps2)
    {
        printf("STUB: IDirectDraw4::GetCaps\n");
        
        caps1->dwCaps |= DDCAPS_3D;
        caps2->dwCaps |= 1;
        caps1->dwVidMemTotal = 0x10000000;
        caps1->dwVidMemFree = 0x10000000;
        caps2->dwVidMemTotal = 0x10000000;
        caps2->dwVidMemFree = 0x10000000;
        
        return 0;
    }
    
    Q_INVOKABLE void GetDisplayMode(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDraw4::GetDisplayMode\n");
    }
    
    Q_INVOKABLE void GetFourCCCodes(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDraw4::GetFourCCCodes\n");
    }
    
    Q_INVOKABLE void GetGDISurface(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDraw4::GetGDISurface\n");
    }
    
    Q_INVOKABLE void GetMonitorFrequency(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDraw4::GetMonitorFrequency\n");
    }
    
    Q_INVOKABLE void GetScanLine(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDraw4::GetScanLine\n");
    }
    
    Q_INVOKABLE void GetVerticalBlankStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDraw4::GetVerticalBlankStatus\n");
    }
    
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDraw4::Initialize\n");
    }
    
    Q_INVOKABLE void RestoreDisplayMode(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::\n");
    }
    
    Q_INVOKABLE uint32_t SetCooperativeLevel(void* this_ptr, uint32_t hWnd, uint32_t level)
    {
        printf("STUB: IDirectDraw4::SetCooperativeLevel, hWnd %x level %u\n", hWnd, level);
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t SetDisplayMode(void* this_ptr, uint32_t dwWidth, uint32_t dwHeight, uint32_t dwBpp /*, uint32_t dwRefreshrate, uint32_t dwFlags*/)
    {
        printf("STUB: IDirectDraw4::SetDisplayMode %ux%u, %ubpp\n", dwWidth, dwHeight, dwBpp);
        
        displayModeWidth = dwWidth;
        displayModeHeight = dwHeight;
        displayModeBpp = dwBpp;
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t WaitForVerticalBlank(void* this_ptr, uint32_t a, uint32_t b)
    {
        //printf("STUB: IDirectDraw4::WaitForVerticalBlank\n");
        
        renderer_waitforvblank();
        
        return 0;
    }

    /*** IDirectDraw2 methods ***/
    Q_INVOKABLE uint32_t GetAvailableVidMem(void* this_ptr, uint32_t caps, uint32_t* total, uint32_t* free)
    {
        printf("STUB: IDirectDraw4::GetAvailableVidMem\n");
        
        *total = 0x8000000;
        *free = 0x8000000;
        
        return 0;
    }

    /*** IDirectDraw4 methods ***/
    Q_INVOKABLE void GetSurfaceFromDC(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDraw4::GetSurfaceFromDC\n");
    }
    
    Q_INVOKABLE void RestoreAllSurfaces(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::RestoreAllSurfaces\n");
    }
    
    Q_INVOKABLE void TestCooperativeLevel(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::TestCooperativeLevel\n");
    }
    
    Q_INVOKABLE void GetDeviceIdentifier(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDraw4::GetDeviceIdentifier\n");
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirectDraw4* idirectdraw4;

#endif // IDIRECTDRAW4_H
