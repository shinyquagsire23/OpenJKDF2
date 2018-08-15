
#ifndef IDIRECTDRAW4_H
#define IDIRECTDRAW4_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

#define DDPF_PALETTEINDEXED8 0x20
#define DDPF_RGB 0x40

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
    uint32_t lPitch;
    uint32_t dwBackBufferCount;
    uint32_t dwMipMapCount;
    uint32_t dwAlphaBitDepth;
    uint32_t dwReserved;
    uint32_t lpSurface;
    struct DDCOLORKEY ddckCKDestOverlay;
    struct DDCOLORKEY ddckCKDestBltl;
    struct DDCOLORKEY ddckCKSrcOverlay;
    struct DDCOLORKEY ddckCKSrcBlt;
    struct DDPIXELFORMAT ddpfPixelFormat;
    uint32_t ddsCaps;
};

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

class IDirectDraw4 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectDraw4() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectDraw4::QueryInterface %s\n", iid_str.c_str());
        
        if (iid_str == "3bba0080-2421-11cf-a31a-00aa00b93356")
        {
            *lpInterface = CreateInterfaceInstance("IDirect3D3", 200);
            return 0;
        }
        else if (iid_str == "0194c220-a303-11d0-9c4f-00a0c905425e")
        {
            *lpInterface = CreateInterfaceInstance("IDirectPlayLobby3", 16);
            return 0;
        }
        
        return 1;
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::Release\n");
    }
    
    /*** IDirectDraw methods ***/
    Q_INVOKABLE void Compact(void* this_ptr)
    {
        printf("STUB: IDirectDraw4::Compact\n");
    }
    
    Q_INVOKABLE void CreateClipper(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectDraw4::CreateClipper\n");
    }
    
    Q_INVOKABLE uint32_t CreatePalette(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectDraw4::CreatePalette\n");
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t CreateSurface(void* this_ptr, DDSURFACEDESC* desc, uint32_t* lpDDSurface, void* lpUnkOuter)
    {
        printf("STUB: IDirectDraw4::CreateSurface\n");
        
        *lpDDSurface = CreateInterfaceInstance("IDirectDrawSurface3", 200);
        
        return 0;
    }
    
    Q_INVOKABLE void DuplicateSurface(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDraw4::DuplicateSurface\n");
    }
    
    Q_INVOKABLE uint32_t EnumDisplayModes(void* this_ptr, uint32_t a, void* surfacedesc, void* c, uint32_t callback)
    {
        printf("STUB: IDirectDraw4::EnumDisplayModes\n");
        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640;
            desc->ddpfPixelFormat.dwFlags |= DDPF_PALETTEINDEXED8;
            
            uint32_t ret = vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
        }
        
        {
            vm_ptr<struct DDSURFACEDESC*> desc = {kernel32->VirtualAlloc(0, 0x1000, 0, 0)};
            memset(desc.translated(), 0, sizeof(struct DDSURFACEDESC));
            desc->dwWidth = 640;
            desc->dwHeight = 480;
            desc->lPitch = 640;
            desc->ddpfPixelFormat.dwFlags |= DDPF_RGB;
            
            desc->ddpfPixelFormat.dwRGBBitCount = 16;
            desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0x000000FF;
            desc->ddpfPixelFormat.dwRBitMask = 0x0000FF;
            desc->ddpfPixelFormat.dwGBitMask = 0x00FF0000;
            desc->ddpfPixelFormat.dwBBitMask = 0xFF000000;
            
            uint32_t ret = vm_call_func(callback, desc.raw_vm_ptr, 0xabcdef);
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
        
        caps1->dwCaps |= 1;
        caps2->dwCaps |= 1;
        
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
    
    Q_INVOKABLE uint32_t SetDisplayMode(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDraw4::SetDisplayMode\n");
        
        return 0;
    }
    
    Q_INVOKABLE void WaitForVerticalBlank(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDraw4::WaitForVerticalBlank\n");
    }

    /*** IDirectDraw2 methods ***/
    Q_INVOKABLE void GetAvailableVidMem(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectDraw4::GetAvailableVidMem\n");
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
