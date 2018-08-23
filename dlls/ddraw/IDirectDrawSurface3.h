
#ifndef IDIRECTDRAWSURFACE3_H
#define IDIRECTDRAWSURFACE3_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/gdi32.h"
#include "dlls/winutils.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include <map>

#include "main.h"

struct info
{
    uint32_t alloc;
    struct DDSURFACEDESC desc;
    uint32_t palette;
};

class IDirectDrawSurface3 : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, struct info> locked_objs;

public:

    Q_INVOKABLE IDirectDrawSurface3() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectDrawSurface3::QueryInterface %s\n", iid_str.c_str());

        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::Release %x %x\n", real_ptr_to_vm_ptr(this_ptr), *(uint32_t*)this_ptr);
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectDrawSurface methods ***/
    Q_INVOKABLE uint32_t AddAttachedSurface(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::AddAttachedSurface\n");
        
        return 0;
    }

    Q_INVOKABLE void AddOverlayDirtyRect(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::AddOverlayDirtyRect\n");
    }

    Q_INVOKABLE uint32_t Blt(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::Blt %x %x %x %x %x\n", a, b, c, d, e);
        
        return 0;
    }

    Q_INVOKABLE void BltBatch(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectDrawSurface3::BltBatch\n");
    }

    Q_INVOKABLE void BltFast(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::BltFast\n");
    }

    Q_INVOKABLE void DeleteAttachedSurface(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::DeleteAttachedSurface\n");
    }

    Q_INVOKABLE void EnumAttachedSurfaces(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::EnumAttachedSurfaces\n");
    }

    Q_INVOKABLE void EnumOverlayZOrders(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectDrawSurface3::EnumOverlayZOrders\n");
    }

    Q_INVOKABLE void Flip(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::Flip\n");
    }

    Q_INVOKABLE uint32_t GetAttachedSurface(void* this_ptr, uint32_t caps, uint32_t* lpdirectdrawsurface)
    {
        printf("STUB: IDirectDrawSurface3::GetAttachedSurface\n");
        
        *lpdirectdrawsurface = CreateInterfaceInstance("IDirectDrawSurface3", 200);
        
        return 0;
    }

    Q_INVOKABLE void GetBltStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetBltStatus\n");
    }

    Q_INVOKABLE void GetCaps(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetCaps\n");
    }

    Q_INVOKABLE void GetClipper(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetClipper\n");
    }

    Q_INVOKABLE void GetColorKey(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetColorKey\n");
    }

    Q_INVOKABLE void GetDC(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetDC\n");
    }

    Q_INVOKABLE uint32_t GetFlipStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetFlipStatus\n");
        
        return 0;
    }

    Q_INVOKABLE void GetOverlayPosition(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetOverlayPosition\n");
    }

    Q_INVOKABLE uint32_t GetPalette(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetPalette\n");
        return 0;
    }

    Q_INVOKABLE uint32_t GetPixelFormat(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetPixelFormat\n");
        return 0;
    }

    Q_INVOKABLE uint32_t GetSurfaceDesc(void* this_ptr, uint32_t* a)
    {
        printf("STUB: IDirectDrawSurface3::GetSurfaceDesc\n");
        
        *a = 0x123456;
        
        return 0;
    }

    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::Initialize\n");
        return 0;
    }

    Q_INVOKABLE uint32_t IsLost(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::IsLost\n");
        return 0;
    }

    Q_INVOKABLE uint32_t Lock(void* this_ptr, uint32_t rect, struct DDSURFACEDESC* surfacedesc, uint32_t flags, uint32_t d)
    {
        printf("STUB: IDirectDrawSurface3::Lock\n");
        
        surfacedesc->lpSurface = kernel32->VirtualAlloc(0, surfacedesc->dwWidth*surfacedesc->dwHeight*4, 0, 0); //TODO
        memset(vm_ptr_to_real_ptr(surfacedesc->lpSurface), 0xFF, surfacedesc->dwWidth*surfacedesc->dwHeight*4);
        
        //surfacedesc->lPitch = 640;
        
        locked_objs[real_ptr_to_vm_ptr(this_ptr)].alloc = surfacedesc->lpSurface;
        locked_objs[real_ptr_to_vm_ptr(this_ptr)].desc = *surfacedesc;
        
        printf("%ux%u %x\n", surfacedesc->dwWidth, surfacedesc->dwHeight, surfacedesc->lPitch);
        
        return 0;
    }

    Q_INVOKABLE uint32_t ReleaseDC(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::ReleaseDC\n");
        return 0;
    }

    Q_INVOKABLE uint32_t Restore(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::Restore\n");
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetClipper(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::SetClipper\n");
        return 0;
    }

    Q_INVOKABLE uint32_t SetColorKey(void* this_ptr, uint32_t a, uint32_t* b)
    {
        printf("STUB: IDirectDrawSurface3::SetColorKey(%u)\n", a);
        
        /*for (int i = 0; i < 256; i++)
        {
            printf("%x\n", b[i]);
        }*/
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetOverlayPosition(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetOverlayPosition\n");
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetPalette(void* this_ptr, uint32_t* a)
    {
        printf("STUB: IDirectDrawSurface3::SetPalette %x\n", *a);
        
        locked_objs[real_ptr_to_vm_ptr(this_ptr)].palette = *a;
        
        /*uint32_t* pal = vm_ptr_to_real_ptr(*a);
        
        for (int i = 0; i < 256; i++)
        {
            printf("%x\n", pal[i]);
        }*/

        return 0;
    }

    Q_INVOKABLE uint32_t Unlock(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::Unlock %x\n", locked_objs[real_ptr_to_vm_ptr(this_ptr)].desc.ddsCaps);
        
        /*for (int i = 0; i < 640*480; i++)
        {
            printf("%x\n", *(uint8_t*)vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)]+i));
        }*/
        
        // 840 for overlay, 0x218 for main
        
        auto obj = &locked_objs[real_ptr_to_vm_ptr(this_ptr)];
        
        static int test = 0;
        //test += 640;
        
        if (obj->desc.ddsCaps & DDSCAPS_PRIMARYSURFACE || obj->desc.ddsCaps & DDSCAPS_BACKBUFFER)
        {
            uint32_t w, h;
            gdi32->gdi_render = false;
            
            w = obj->desc.dwWidth;
            h = obj->desc.dwHeight;
            SDL_SetWindowSize(displayWindow, w, h);
            
            SDL_Surface *surface = SDL_CreateRGBSurface(0, w, h, 8, 0,0,0,0);
            memcpy(surface->pixels, vm_ptr_to_real_ptr(obj->alloc) + test, w*h);
            SDL_SetPaletteColors(surface->format->palette, idirectdraw4->palettes[obj->palette], 0, 256);
            
            SDL_Texture* texture = SDL_CreateTextureFromSurface(displayRenderer, surface);
            SDL_RenderClear(displayRenderer);
            SDL_RenderCopy(displayRenderer, texture, NULL, NULL);
            SDL_RenderPresent(displayRenderer);
            SDL_DestroyTexture(texture);
            SDL_FreeSurface(surface);
        }
        
        kernel32->VirtualFree(obj->alloc, 0, 0); //TODO
        obj->alloc = 0;
        
        return 0;
    }

    Q_INVOKABLE void UpdateOverlay(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlay\n");
    }

    Q_INVOKABLE void UpdateOverlayDisplay(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlayDisplay\n");
    }

    Q_INVOKABLE void UpdateOverlayZOrder(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlayZOrder\n");
    }


    /*** IDirectDrawSurface2 methods ***/
    Q_INVOKABLE void GetDDInterface(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetDDInterface\n");
    }

    Q_INVOKABLE void PageLock(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::PageLock\n");
    }

    Q_INVOKABLE void PageUnlock(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::PageUnlock\n");
    }


    /*** IDirectDrawSurface3 methods ***/
    Q_INVOKABLE void SetSurfaceDesc(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetSurfaceDesc\n");
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirectDrawSurface3* idirectdrawsurface3;

#endif // IDIRECTDRAWSURFACE3_H
