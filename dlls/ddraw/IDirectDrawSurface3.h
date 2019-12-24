
#ifndef IDIRECTDRAWSURFACE3_H
#define IDIRECTDRAWSURFACE3_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/gdi32.h"
#include "dlls/winutils.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include "dlls/ddraw/IDirect3DDevice.h"
#include <map>

#include "main.h"

struct RECT
{
    uint32_t left;
    uint32_t top;
    uint32_t right;
    uint32_t bottom;
};

struct DDBLTFX
{
    uint32_t dwSize;
    uint32_t dwDDFX;
    uint32_t dwROP;
    uint32_t dwDDROP;
    uint32_t dwRotationAngle;
    uint32_t dwZBufferOpCode;
    uint32_t dwZBufferLow;
    uint32_t dwZBufferHigh;
    uint32_t dwZBufferBaseDest;
    uint32_t dwZDestConstBitDepth;
};

class IDirectDrawSurface3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectDrawSurface3() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(struct ddsurface_ext* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectDrawSurface3::QueryInterface %s\n", iid_str.c_str());
        
        if (iid_str == "2cdcd9e0-25a0-11cf-a31a-00aa00b93356" && this_ptr->tex.translated() != nullptr) //D3D tex
        {
            *lpInterface = this_ptr->tex.raw_vm_ptr;
            return 0;
        }

        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(struct ddsurface_ext* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::AddRef\n");
    }

    Q_INVOKABLE void Release(struct ddsurface_ext* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::Release %x %x\n", real_ptr_to_vm_ptr(this_ptr), *(uint32_t*)this_ptr);
        
        if (this_ptr->alloc)
        {
            kernel32->VirtualFree(this_ptr->alloc, 0, 0);
            this_ptr->alloc = 0;
        }
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectDrawSurface methods ***/
    Q_INVOKABLE uint32_t AddAttachedSurface(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::AddAttachedSurface\n");
        
        return 0;
    }

    Q_INVOKABLE void AddOverlayDirtyRect(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::AddOverlayDirtyRect\n");
    }

    Q_INVOKABLE uint32_t Blt(struct ddsurface_ext* this_ptr, struct RECT* lpDestRect, struct ddsurface_ext* lpDDSrcSurface, struct RECT* lpSrcRect, uint32_t dwFlags, struct DDBLTFX* lpDDBltFx)
    {
        printf("STUB: IDirectDrawSurface3::Blt %p %p %x %x %x\n", lpDestRect, lpDDSrcSurface, lpSrcRect, dwFlags, lpDDBltFx);
#if 1
        uint32_t dstl = 0, dstr = 0, dstt = 0, dstb = 0;
        uint32_t srcl = 0, srcr = 0, srct = 0, srcb = 0;
        if (lpDestRect)
        {
            dstl = lpDestRect->left;
            dstr = lpDestRect->right;
            dstt = lpDestRect->top;
            dstb = lpDestRect->bottom;
            printf("To: %ux%u, %u %u %u %u\n", this_ptr->desc.dwWidth, this_ptr->desc.dwHeight, dstl, dstr, dstt, dstb);
            if (this_ptr->desc.ddsCaps & DDSCAPS_PRIMARYSURFACE)
                printf("Blitting to the primary surface!\n");
        }
        
        if (lpDDSrcSurface)
        {
            srcl = lpSrcRect->left;
            srcr =  lpSrcRect->right;
            srct = lpSrcRect->top;
            srcb = lpSrcRect->bottom;
            printf("From: %ux%u, %u %u %u %u\n", lpDDSrcSurface->desc.dwWidth, lpDDSrcSurface->desc.dwHeight, srcl, srcr, srct, srcb);
            
            if (!lpDDSrcSurface->alloc && this_ptr->alloc)
            {
                int bytes_per_pixel_dst = this_ptr->desc.ddpfPixelFormat.dwRGBBitCount / 8;
                uint32_t dst_pitch = this_ptr->desc.lPitch;

                if (!this_ptr->desc.ddpfPixelFormat.dwRGBBitCount)
                    bytes_per_pixel_dst = sizeof(uint8_t);

                //TODO: figure out this blitting stuff idk
                uint8_t* dst = (uint8_t*)vm_ptr_to_real_ptr(this_ptr->alloc);
                
                int copy_w = srcr-srcl;
                int copy_h = srcb-srct;
                
                for (int x = 0; x < copy_w; x++)
                {
                    for (int y = 0; y < copy_h; y++)
                    {
                        //TODO bpp
                        for (int i = 0; i < bytes_per_pixel_dst; i++)
                        {
                            uint8_t srcByte = bytes_per_pixel_dst == 1 ? 0 : 0xFF;
                            uint8_t dstByte = dst[(dstt+y)*dst_pitch + (dstl+x)*bytes_per_pixel_dst + i];
                            dst[(dstt+y)*dst_pitch + (dstl+x)*bytes_per_pixel_dst + i] = srcByte;
                        }
                    }
                }
            }
            else if (lpDDSrcSurface->alloc && this_ptr->alloc)
            {
                int bytes_per_pixel_src = lpDDSrcSurface->desc.ddpfPixelFormat.dwRGBBitCount / 8;
                int bytes_per_pixel_dst = this_ptr->desc.ddpfPixelFormat.dwRGBBitCount / 8;
                uint32_t src_pitch = lpDDSrcSurface->desc.lPitch;
                uint32_t dst_pitch = this_ptr->desc.lPitch;
                
                printf("asdf %x %x\n", bytes_per_pixel_src, bytes_per_pixel_dst);

                if (!lpDDSrcSurface->desc.ddpfPixelFormat.dwRGBBitCount)
                    bytes_per_pixel_src = sizeof(uint8_t);
                if (!this_ptr->desc.ddpfPixelFormat.dwRGBBitCount)
                    bytes_per_pixel_dst = sizeof(uint8_t);

                //TODO: figure out this blitting stuff idk
                uint8_t* src = (uint8_t*)vm_ptr_to_real_ptr(lpDDSrcSurface->alloc);
                uint8_t* dst = (uint8_t*)vm_ptr_to_real_ptr(this_ptr->alloc);
                
                int copy_w = srcr-srcl;
                int copy_h = srcb-srct;
                
                for (int x = 0; x < copy_w; x++)
                {
                    for (int y = 0; y < copy_h; y++)
                    {
                        for (int i = 0; i < bytes_per_pixel_dst; i++)
                        {
                            uint8_t srcByte = src[(srct+y)*src_pitch + (srcl+x)*bytes_per_pixel_src + i];
                            uint8_t dstByte = dst[(dstt+y)*dst_pitch + (dstl+x)*bytes_per_pixel_dst + i];
                            //if (srcByte != 0xFF)
                            //    printf("src %x dst %x\n", srcByte, dstByte);
                            dst[(dstt+y)*dst_pitch + (dstl+x)*bytes_per_pixel_dst + i] = srcByte;
                        }
                    }
                }
            }
        }
        
        printf("size %x DDFX %x DDROP %x others...%x %x %x %x %x %x %x\n", lpDDBltFx->dwSize, lpDDBltFx->dwDDFX, lpDDBltFx->dwROP, lpDDBltFx->dwDDROP, lpDDBltFx->dwRotationAngle, lpDDBltFx->dwZBufferOpCode, lpDDBltFx->dwZBufferLow, lpDDBltFx->dwZBufferHigh, lpDDBltFx->dwZBufferBaseDest, lpDDBltFx->dwZDestConstBitDepth);
        #endif
        
        return 0;
    }

    Q_INVOKABLE void BltBatch(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectDrawSurface3::BltBatch\n");
    }

    Q_INVOKABLE void BltFast(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::BltFast\n");
    }

    Q_INVOKABLE void DeleteAttachedSurface(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::DeleteAttachedSurface\n");
    }

    Q_INVOKABLE void EnumAttachedSurfaces(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::EnumAttachedSurfaces\n");
    }

    Q_INVOKABLE void EnumOverlayZOrders(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectDrawSurface3::EnumOverlayZOrders\n");
    }

    Q_INVOKABLE uint32_t Flip(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        //printf("STUB: IDirectDrawSurface3::Flip %x %x\n", a, b);
        
        return 0;
    }

    Q_INVOKABLE uint32_t GetAttachedSurface(struct ddsurface_ext* this_ptr, uint32_t caps, uint32_t* lpdirectdrawsurface)
    {
        printf("STUB: IDirectDrawSurface3::GetAttachedSurface\n");
        
        *lpdirectdrawsurface = real_ptr_to_vm_ptr(this_ptr);
        
        return 0;
    }

    Q_INVOKABLE uint32_t GetBltStatus(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetBltStatus\n");
        
        return 0;
    }

    Q_INVOKABLE void GetCaps(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetCaps\n");
    }

    Q_INVOKABLE void GetClipper(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetClipper\n");
    }

    Q_INVOKABLE void GetColorKey(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetColorKey\n");
    }

    Q_INVOKABLE void GetDC(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetDC\n");
    }

    Q_INVOKABLE uint32_t GetFlipStatus(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetFlipStatus\n");
        
        return 0;
    }

    Q_INVOKABLE void GetOverlayPosition(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetOverlayPosition\n");
    }

    Q_INVOKABLE uint32_t GetPalette(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetPalette\n");
        return 0;
    }

    Q_INVOKABLE uint32_t GetPixelFormat(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetPixelFormat\n");
        return 0;
    }

    Q_INVOKABLE uint32_t GetSurfaceDesc(struct ddsurface_ext* this_ptr, vm_ptr<struct DDSURFACEDESC*> desc_out)
    {
        printf("STUB: IDirectDrawSurface3::GetSurfaceDesc\n");
        
        **desc_out = this_ptr->desc;
        
        return 0;
    }

    Q_INVOKABLE uint32_t Initialize(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::Initialize\n");
        return 0;
    }

    Q_INVOKABLE uint32_t IsLost(struct ddsurface_ext* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::IsLost\n");
        return 0;
    }

    Q_INVOKABLE uint32_t Lock(struct ddsurface_ext* this_ptr, uint32_t rect, struct DDSURFACEDESC* surfacedesc, uint32_t flags, uint32_t d)
    {
        //printf("STUB: IDirectDrawSurface3::Lock %x %x\n", rect, flags);
        
        int w,h;
        
        memcpy(surfacedesc, &this_ptr->desc, sizeof(struct DDSURFACEDESC));
        
        w = 512 > surfacedesc->dwWidth ? 512 : surfacedesc->dwWidth;
        h = 512 > surfacedesc->dwHeight ? 512 : surfacedesc->dwHeight;
        
        int bpp = surfacedesc->ddpfPixelFormat.dwRGBBitCount;
        if (!bpp)
            bpp = 8;

        surfacedesc->lPitch = surfacedesc->dwWidth * (bpp/8);
        surfacedesc->lpSurface = kernel32->VirtualAlloc(0, surfacedesc->lPitch*h, 0, 0);
        if (bpp == 8)
            memset(vm_ptr_to_real_ptr(surfacedesc->lpSurface), 0, surfacedesc->lPitch*h);
        else
        {
            if (surfacedesc->ddpfPixelFormat.dwRBitMask == 0x7C00)
            {
                uint16_t transparent = 0x3C0F;
                uint16_t* pixels = (uint16_t*)vm_ptr_to_real_ptr(surfacedesc->lpSurface);
                for (int i = 0; i < surfacedesc->dwWidth*surfacedesc->dwHeight; i++)
                {
                    pixels[i] = transparent;
                }
            }
            else if (surfacedesc->ddpfPixelFormat.dwRBitMask == 0xF00)
            {
                uint16_t transparent = 0xF0F;
                uint16_t* pixels = (uint16_t*)vm_ptr_to_real_ptr(surfacedesc->lpSurface);
                for (int i = 0; i < surfacedesc->dwWidth*surfacedesc->dwHeight; i++)
                {
                    pixels[i] = transparent;
                }
            }
            else
            {
                uint16_t transparent = 0xF81F;
                uint16_t* pixels = (uint16_t*)vm_ptr_to_real_ptr(surfacedesc->lpSurface);
                for (int i = 0; i < surfacedesc->dwWidth*surfacedesc->dwHeight; i++)
                {
                    pixels[i] = transparent;
                }
            }
        }

        if (this_ptr->alloc)
        {
            memcpy(vm_ptr_to_real_ptr(surfacedesc->lpSurface), vm_ptr_to_real_ptr(this_ptr->alloc), surfacedesc->lPitch*h);
            kernel32->VirtualFree(this_ptr->alloc, 0, 0);
        }
        this_ptr->alloc = surfacedesc->lpSurface;
        this_ptr->locked_desc = *surfacedesc;
        
        printf("IDirectDrawSurface3::Lock: %ux%u pitch %x\n", surfacedesc->dwWidth, surfacedesc->dwHeight, surfacedesc->lPitch);
        
        return 0;
    }

    Q_INVOKABLE uint32_t ReleaseDC(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::ReleaseDC\n");
        return 0;
    }

    Q_INVOKABLE uint32_t Restore(struct ddsurface_ext* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::Restore\n");
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetClipper(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::SetClipper\n");
        return 0;
    }

    Q_INVOKABLE uint32_t SetColorKey(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t* b)
    {
        printf("STUB: IDirectDrawSurface3::SetColorKey(%u, %x, %x, %x)\n", a, b[0], b[1], b[2]);
        
        /*for (int i = 0; i < 256; i++)
        {
            printf("%x\n", b[i]);
        }*/
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetOverlayPosition(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetOverlayPosition\n");
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetPalette(struct ddsurface_ext* this_ptr, uint32_t* a)
    {
        printf("STUB: IDirectDrawSurface3::SetPalette %x\n", *a);
        
        this_ptr->palette = *a;
        
        /*uint32_t* pal = vm_ptr_to_real_ptr(*a);
        
        for (int i = 0; i < 256; i++)
        {
            printf("%x\n", pal[i]);
        }*/

        return 0;
    }

    Q_INVOKABLE uint32_t Unlock(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::Unlock %x\n", this_ptr->locked_desc.ddsCaps);
        
        /*for (int i = 0; i < 640*480; i++)
        {
            printf("%x\n", *(uint8_t*)vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)]+i));
        }*/
        
        // 840 for overlay, 0x218 for main
        
        static int test = 0;
        //test += 640;

#if 0
        if (this_ptr->locked_desc.ddsCaps & DDSCAPS_PRIMARYSURFACE)
        {
            printf("Render this!\n");
            uint32_t w, h;
            gdi32->gdi_render = false;
            
            w = this_ptr->locked_desc.dwWidth;
            h = this_ptr->locked_desc.dwHeight;
            SDL_SetWindowSize(displayWindow, w, h);
            
            SDL_Surface *surface = SDL_CreateRGBSurface(0, w, h, 8, 0,0,0,0);
            memcpy(surface->pixels, vm_ptr_to_real_ptr(this_ptr->alloc) + test, w*h);
            
            /*uint32_t key = this_ptr->palette;
            for(int i = 0; i < 256; i++)
            {
                idirectdraw4->palettes[key][i].r = i;
                idirectdraw4->palettes[key][i].g = i;
                idirectdraw4->palettes[key][i].b = i;
                idirectdraw4->palettes[key][i].a = 0xFF;
            }*/
            
            SDL_SetPaletteColors(surface->format->palette, idirectdraw4->palettes[this_ptr->palette], 0, 256);
            
            SDL_Texture* texture = SDL_CreateTextureFromSurface(displayRenderer, surface);
            SDL_RenderClear(displayRenderer);
            SDL_RenderCopy(displayRenderer, texture, NULL, NULL);
            SDL_RenderPresent(displayRenderer);
            SDL_DestroyTexture(texture);
            SDL_FreeSurface(surface);
        }
#endif

        /*if (this_ptr->locked_desc.dwWidth > 128 && this_ptr->locked_desc.dwWidth <= 256)
        {
            uint16_t* tex_data = (uint16_t*)vm_ptr_to_real_ptr(this_ptr->alloc);
            memset(tex_data, 0xFF, this_ptr->locked_desc.dwWidth*this_ptr->locked_desc.dwHeight*2);
        }*/

#if 0
        uint16_t* tex_data = (uint16_t*)vm_ptr_to_real_ptr(this_ptr->alloc);
        
        static int id = 0;
        char tmp[256];
        
        printf("%u %ux%u, %x\n", id, this_ptr->locked_desc.dwWidth, this_ptr->locked_desc.dwHeight, this_ptr->alloc);
        
        if (this_ptr->alloc && this_ptr->locked_desc.dwWidth && this_ptr->locked_desc.dwHeight <= 32)
        {
            snprintf(tmp, 256, "texdump/%u_%ux%u.bin",  id++, this_ptr->locked_desc.dwWidth, this_ptr->locked_desc.dwHeight);
            FILE* test = fopen(tmp, "wb");
            fwrite(tex_data, this_ptr->locked_desc.dwWidth*this_ptr->locked_desc.dwHeight*2, 1, test);
            fclose(test);
        }
#endif
        //printf("\n");
// This is definitely a draw cue, but we need rendering on its own thread
#if 0
        if (this_ptr->desc.ddsCaps & DDSCAPS_PRIMARYSURFACE)
        {
            idirect3dexecutebuffer->view.dwWidth = 640;
            idirect3dexecutebuffer->view.dwHeight = 480;
            idirect3ddevice->BeginScene(NULL);
            idirect3ddevice->EndScene(NULL);
        }
#endif
        return 0;
    }

    Q_INVOKABLE void UpdateOverlay(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlay\n");
    }

    Q_INVOKABLE void UpdateOverlayDisplay(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlayDisplay\n");
    }

    Q_INVOKABLE void UpdateOverlayZOrder(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlayZOrder\n");
    }


    /*** IDirectDrawSurface2 methods ***/
    Q_INVOKABLE void GetDDInterface(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetDDInterface\n");
    }

    Q_INVOKABLE void PageLock(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::PageLock\n");
    }

    Q_INVOKABLE void PageUnlock(struct ddsurface_ext* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::PageUnlock\n");
    }


    /*** IDirectDrawSurface3 methods ***/
    Q_INVOKABLE void SetSurfaceDesc(struct ddsurface_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetSurfaceDesc\n");
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirectDrawSurface3* idirectdrawsurface3;

#endif // IDIRECTDRAWSURFACE3_H
