#include "stdDisplay.h"

#include "stdPlatform.h"
#include "jk.h"
#include "Win95/Video.h"
#include "Win95/Window.h"

void stdDisplay_SetGammaTable(int len, uint32_t *table)
{
    stdDisplay_gammaTableLen = len;
    stdDisplay_paGammaTable = table;
}

uint8_t* stdDisplay_GetPalette()
{
    return (uint8_t*)stdDisplay_gammaPalette;
}

#ifndef SDL2_RENDER

#else

#ifdef WIN32
#define GL_R8 GL_RED
#endif

#ifdef ARCH_WASM
#include <SDL2/SDL.h>
#else
#include <SDL.h>
#endif

#ifdef MACOS
#include "OpenGL/gl.h"
#else
#include <GL/gl.h>
#endif
#include <assert.h>

uint32_t Video_menuTexId = 0;
rdColor24 stdDisplay_masterPalette[256];
int Video_bModeSet = 0;

int stdDisplay_Startup()
{
    stdDisplay_bStartup = 1;
    return 1;
}

int stdDisplay_FindClosestDevice(void* a)
{
    Video_dword_866D78 = 0;
    return 0;
}

int stdDisplay_Open(int a)
{
    stdDisplay_pCurDevice = &stdDisplay_aDevices[0];
    stdDisplay_bOpen = 1;
    return 1;
}

void stdDisplay_Close()
{
    stdDisplay_bOpen = 0;
}

int stdDisplay_FindClosestMode(render_pair *a1, struct stdVideoMode *render_surface, unsigned int max_modes)
{
    Video_curMode = 0;
    stdDisplay_bPaged = 1;
    stdDisplay_bModeSet = 1;
    return 0;
}

int stdDisplay_SetMode(unsigned int modeIdx, const void *palette, int paged)
{
    uint32_t newW = Window_xSize;
    uint32_t newH = Window_ySize;

    //if (jkGame_isDDraw)
    {
        newW = (uint32_t)((float)Window_xSize * ((480.0*2.0)/Window_ySize));
        newH = 480*2;
    }

    if (newW > Window_xSize)
    {
        newW = Window_xSize;
        newH = Window_ySize;
    }

    if (newW < 640)
        newW = 640;
    if (newH < 480)
        newH = 480;

    stdDisplay_pCurVideoMode = &Video_renderSurface[modeIdx];
    
    stdDisplay_pCurVideoMode->format.format.bpp = 8;
    stdDisplay_pCurVideoMode->format.width_in_pixels = newW;
    stdDisplay_pCurVideoMode->format.width = newW;
    stdDisplay_pCurVideoMode->format.height = newH;
    
    _memcpy(&Video_otherBuf.format, &stdDisplay_pCurVideoMode->format, sizeof(Video_otherBuf.format));
    _memcpy(&Video_menuBuffer.format, &stdDisplay_pCurVideoMode->format, sizeof(Video_menuBuffer.format));
    
    if (Video_bModeSet)
    {
        glDeleteTextures(1, &Video_menuTexId);
        if (Video_otherBuf.sdlSurface)
            SDL_FreeSurface(Video_otherBuf.sdlSurface);
        if (Video_menuBuffer.sdlSurface)
            SDL_FreeSurface(Video_menuBuffer.sdlSurface);
        
        Video_otherBuf.sdlSurface = 0;
        Video_menuBuffer.sdlSurface = 0;
    }
    
    SDL_Surface* otherSurface = SDL_CreateRGBSurface(0, newW, newH, 8,
                                        0,
                                        0,
                                        0,
                                        0);
    SDL_Surface* menuSurface = SDL_CreateRGBSurface(0, newW, newH, 8,
                                        0,
                                        0,
                                        0,
                                        0);
    
    if (palette)
    {
        memcpy(stdDisplay_gammaPalette, palette, 0x300);
        const rdColor24* pal24 = palette;
        SDL_Color* tmp = malloc(sizeof(SDL_Color) * 256);
        for (int i = 0; i < 256; i++)
        {
            tmp[i].r = pal24[i].r;
            tmp[i].g = pal24[i].g;
            tmp[i].b = pal24[i].b;
            tmp[i].a = 0xFF;
        }
        
        SDL_SetPaletteColors(otherSurface->format->palette, tmp, 0, 256);
        SDL_SetPaletteColors(menuSurface->format->palette, tmp, 0, 256);
        free(tmp);
    }
    
    //SDL_SetSurfacePalette(otherSurface, palette);
    //SDL_SetSurfacePalette(menuSurface, palette);
    
    Video_otherBuf.sdlSurface = otherSurface;
    Video_menuBuffer.sdlSurface = menuSurface;
    
    Video_menuBuffer.format.width_in_bytes = menuSurface->pitch;
    Video_otherBuf.format.width_in_bytes = otherSurface->pitch;
    
    Video_menuBuffer.format.width_in_pixels = menuSurface->pitch;
    Video_otherBuf.format.width_in_pixels = otherSurface->pitch;
    Video_menuBuffer.format.width = newW;
    Video_otherBuf.format.width = newW;
    Video_menuBuffer.format.height = newH;
    Video_otherBuf.format.height = newH;
    
    Video_menuBuffer.format.format.bpp = 8;
    Video_otherBuf.format.format.bpp = 8;
    
    glGenTextures(1, &Video_menuTexId);
    glBindTexture(GL_TEXTURE_2D, Video_menuTexId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, newW, newH, 0, GL_RED, GL_UNSIGNED_BYTE, Video_menuBuffer.sdlSurface->pixels);
    
    Video_bModeSet = 1;
    
    return 1;
}

int stdDisplay_ClearRect(stdVBuffer *buf, int fillColor, rdRect *rect)
{
    return stdDisplay_VBufferFill(buf, fillColor, rect);
}



int stdDisplay_DDrawGdiSurfaceFlip()
{
    Window_SdlUpdate();
    return 1;
}

int stdDisplay_ddraw_waitforvblank()
{
    Window_SdlVblank();
    return 1;
}

int stdDisplay_SetMasterPalette(uint8_t* pal)
{
    rdColor24* pal24 = (rdColor24*)pal;
    
    memcpy(stdDisplay_masterPalette, pal24, sizeof(stdDisplay_masterPalette));
    
    SDL_Color* tmp = malloc(sizeof(SDL_Color) * 256);
    for (int i = 0; i < 256; i++)
    {
        tmp[i].r = pal24[i].r;
        tmp[i].g = pal24[i].g;
        tmp[i].b = pal24[i].b;
        tmp[i].a = 0xFF;
    }
    
    free(tmp);
    return 1;
}

stdVBuffer* stdDisplay_VBufferNew(stdVBufferTexFmt *fmt, int create_ddraw_surface, int gpu_mem, void* palette)
{
    stdVBuffer* out = std_pHS->alloc(sizeof(stdVBuffer));
    
    _memset(out, 0, sizeof(*out));
    
    _memcpy(&out->format, fmt, sizeof(out->format));
    
    // force 0 reads
    //out->format.width = 0;
    //out->format.width_in_bytes = 0;
    //out->surface_lock_alloc = std_pHS->alloc(texture_size_in_bytes);
    
    uint32_t rbitmask = ((1 << fmt->format.r_bits) - 1) << fmt->format.r_shift;
    uint32_t gbitmask = ((1 << fmt->format.g_bits) - 1) << fmt->format.g_shift;
    uint32_t bbitmask = ((1 << fmt->format.b_bits) - 1) << fmt->format.b_shift;
    uint32_t abitmask = 0;//((1 << fmt->format.a_bits) - 1) << fmt->format.a_shift;
    if (fmt->format.bpp == 8)
    {
        rbitmask = 0;
        gbitmask = 0;
        bbitmask = 0;
        abitmask = 0;
    }

    SDL_Surface* surface = SDL_CreateRGBSurface(0, fmt->width, fmt->height, fmt->format.bpp, rbitmask, gbitmask, bbitmask, abitmask);
    
    if (surface)
    {
        static int num = 0;
        //printf("Allocated VBuffer %u, w %u h %u bpp %u %x %x %x\n", num++, fmt->width, fmt->height, fmt->format.bpp, rbitmask, gbitmask, bbitmask);
        out->format.width_in_bytes = surface->pitch;
        out->format.width_in_pixels = fmt->width;
        out->format.texture_size_in_bytes = surface->pitch * fmt->height;
    }
    else
    {
        //printf("asdf\n");
        printf("Failed to allocate VBuffer! %s, w %u h %u bpp %u, rmask %x gmask %x bmask %x amask %x, %x %x %x\n", SDL_GetError(), fmt->width, fmt->height, fmt->format.bpp, rbitmask, gbitmask, bbitmask, abitmask, fmt->format.r_bits, fmt->format.g_bits, fmt->format.b_bits);
        assert(0);
    }
    
    out->sdlSurface = surface;
    
    return out;
}

int stdDisplay_VBufferLock(stdVBuffer *buf)
{
    if (!buf) return 0;

    SDL_LockSurface(buf->sdlSurface);
    buf->surface_lock_alloc = buf->sdlSurface->pixels;
    return 1;
}

void stdDisplay_VBufferUnlock(stdVBuffer *buf)
{
    if (!buf) return;
    
    buf->surface_lock_alloc = NULL;
    SDL_UnlockSurface(buf->sdlSurface);
}

int stdDisplay_VBufferCopy(stdVBuffer *vbuf, stdVBuffer *vbuf2, unsigned int blit_x, int blit_y, rdRect *rect, int alpha_maybe)
{
    if (!vbuf || !vbuf2) return 1;
    
    rdRect fallback = {0,0,vbuf2->format.width, vbuf2->format.height};
    if (!rect)
    {
        rect = &fallback;
        //memcpy(vbuf->sdlSurface->pixels, vbuf2->sdlSurface->pixels, 640*480);
        //return;
    }
    
    //if (vbuf == &Video_menuBuffer)
    //    printf("Vbuffer copy to menu %u,%u %ux%u %u,%u\n", rect->x, rect->y, rect->width, rect->height, blit_x, blit_y);
    
    if (vbuf->palette)
    {
        rdColor24* pal24 = vbuf->palette;
        SDL_Color* tmp = malloc(sizeof(SDL_Color) * 256);
        for (int i = 0; i < 256; i++)
        {
            tmp[i].r = pal24[i].r;
            tmp[i].g = pal24[i].g;
            tmp[i].b = pal24[i].b;
            tmp[i].a = 0xFF;
        }
    
        SDL_SetPaletteColors(vbuf->sdlSurface->format->palette, tmp, 0, 256);
        free(tmp);
    }
    
    if (vbuf2->palette)
    {
        rdColor24* pal24 = vbuf2->palette;
        SDL_Color* tmp = malloc(sizeof(SDL_Color) * 256);
        for (int i = 0; i < 256; i++)
        {
            tmp[i].r = pal24[i].r;
            tmp[i].g = pal24[i].g;
            tmp[i].b = pal24[i].b;
            tmp[i].a = 0xFF;
        }
        
        SDL_SetPaletteColors(vbuf2->sdlSurface->format->palette, tmp, 0, 256);
        free(tmp);
    }

    SDL_Rect dstRect = {blit_x, blit_y, rect->width, rect->height};
    SDL_Rect srcRect = {rect->x, rect->y, rect->width, rect->height};
    
    uint8_t* srcPixels = vbuf2->sdlSurface->pixels;
    uint8_t* dstPixels = vbuf->sdlSurface->pixels;
    uint32_t srcStride = vbuf2->format.width_in_bytes;
    uint32_t dstStride = vbuf->format.width_in_bytes;

    int self_copy = 0;

    if (dstPixels == srcPixels)
    {
        size_t buf_len = srcStride * dstRect.w * dstRect.h;
        uint8_t* dstPixels = malloc(buf_len);
        int has_alpha = 0;//!(rect->width == 640);

        SDL_Rect dstRect_inter = {0, 0, rect->width, rect->height};

        for (int i = 0; i < rect->width; i++)
        {
            for (int j = 0; j < rect->height; j++)
            {
                if ((uint32_t)(i + srcRect.x) > (uint32_t)vbuf2->format.width) continue;
                if ((uint32_t)(j + srcRect.y) > (uint32_t)vbuf2->format.height) continue;
                
                uint8_t pixel = srcPixels[(i + srcRect.x) + ((j + srcRect.y)*srcStride)];

                if (!pixel && has_alpha) continue;
                if ((uint32_t)(i + dstRect_inter.x) > (uint32_t)vbuf->format.width) continue;
                if ((uint32_t)(j + dstRect_inter.y) > (uint32_t)vbuf->format.height) continue;

                dstPixels[(i + dstRect_inter.x) + ((j + dstRect_inter.y)*srcStride)] = pixel;
            }
        }
        
        

        srcPixels = dstPixels;
        srcRect.x = 0;
        srcRect.y = 0;

        self_copy = 1;
    }
    
    int once = 0;
    int has_alpha = !(rect->width == 640) && (alpha_maybe & 1);
    
    for (int i = 0; i < rect->width; i++)
    {
        for (int j = 0; j < rect->height; j++)
        {
            if ((uint32_t)(i + srcRect.x) > (uint32_t)vbuf2->format.width) continue;
            if ((uint32_t)(j + srcRect.y) > (uint32_t)vbuf2->format.height) continue;
            
            uint8_t pixel = srcPixels[(i + srcRect.x) + ((j + srcRect.y)*srcStride)];

            if (!pixel && has_alpha) continue;
            if ((uint32_t)(i + dstRect.x) > (uint32_t)vbuf->format.width) continue;
            if ((uint32_t)(j + dstRect.y) > (uint32_t)vbuf->format.height) continue;

            dstPixels[(i + dstRect.x) + ((j + dstRect.y)*dstStride)] = pixel;
        }
    }

    if (self_copy)
    {
        free(srcPixels);
    }
    
    //SDL_BlitSurface(vbuf2->sdlSurface, &srcRect, vbuf->sdlSurface, &dstRect); //TODO error check
    return 1;
}

int stdDisplay_VBufferFill(stdVBuffer *vbuf, int fillColor, rdRect *rect)
{    
    rdRect fallback = {0,0,vbuf->format.width, vbuf->format.height};
    if (!rect)
    {
        rect = &fallback;
    }
    
    //if (vbuf == &Video_menuBuffer)
    //    printf("Vbuffer fill to menu %u,%u %ux%u\n", rect->x, rect->y, rect->width, rect->height);

    SDL_Rect dstRect = {rect->x, rect->y, rect->width, rect->height};
    
    //printf("%x; %u %u %u %u\n", fillColor, rect->x, rect->y, rect->width, rect->height);
    
    uint8_t* dstPixels = vbuf->sdlSurface->pixels;
    uint32_t dstStride = vbuf->format.width_in_bytes;
    uint32_t max_idx = dstStride * vbuf->format.height;
    for (int i = 0; i < rect->width; i++)
    {
        for (int j = 0; j < rect->height; j++)
        {
            uint32_t idx = (i + dstRect.x) + ((j + dstRect.y)*dstStride);
            if (idx > max_idx)
                continue;
            
            dstPixels[idx] = fillColor;
        }
    }
    
    //SDL_FillRect(vbuf, &dstRect, fillColor); //TODO error check

    return 1;
}

int stdDisplay_VBufferSetColorKey(stdVBuffer *vbuf, int color)
{
    //DDCOLORKEY v3; // [esp+0h] [ebp-8h] BYREF

    if ( vbuf->bSurfaceLocked )
    {
        /*if ( vbuf->bSurfaceLocked == 1 )
        {
            v3.dwColorSpaceLowValue = color;
            v3.dwColorSpaceHighValue = color;
            vbuf->ddraw_surface->lpVtbl->SetColorKey(vbuf->ddraw_surface, 8, &v3);
            return 1;
        }*/
        vbuf->transparent_color = color;
    }
    else
    {
        vbuf->transparent_color = color;
    }
    return 1;
}

void stdDisplay_VBufferFree(stdVBuffer *vbuf)
{
    stdDisplay_VBufferUnlock(vbuf);
    SDL_FreeSurface(vbuf->sdlSurface);
    std_pHS->free(vbuf);
}

void stdDisplay_ddraw_surface_flip2()
{
}

void stdDisplay_RestoreDisplayMode()
{

}

stdVBuffer* stdDisplay_VBufferConvertColorFormat(void* a, stdVBuffer* b)
{
    return b;
}

int stdDisplay_GammaCorrect3(int a1)
{
    jk_printf("STUB: stdDisplay_GammaCorrect3\n");
    return 1;
}
#endif
