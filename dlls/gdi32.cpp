#include "gdi32.h"

#include "vm.h"
#include "kernel32.h"
#include "main.h"
#include "user32.h"

#include <GL/glew.h>

#include "3rdparty/imgui/imgui.h"
#include "3rdparty/imgui/imgui_impl_sdl.h"
#include "3rdparty/imgui/imgui_impl_opengl3.h"
#include "renderer.h"

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
    
    dc_surface[hdc] = {.w = pbmi->bmiHeader.biWidth, .h = -pbmi->bmiHeader.biHeight};
    
    GLuint image_texture, pal_texture;
    glGenTextures(1, &image_texture);
    glGenTextures(1, &pal_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);

    
    void* image_data = malloc(dc_surface[hdc].w*dc_surface[hdc].h*sizeof(uint8_t));
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RED, dc_surface[hdc].w, dc_surface[hdc].h, 0, GL_RED, GL_UNSIGNED_BYTE, image_data);
    
    glBindTexture(GL_TEXTURE_1D, pal_texture);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    
    memset(image_data, 0xFF, 256);
    glTexImage1D(GL_TEXTURE_1D, 0, GL_RGBA8, 256, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
    
    //SDL_SetWindowSize(displayWindow, abs(pbmi->bmiHeader.biWidth), abs(pbmi->bmiHeader.biHeight));
    
    dc_surfacebuf[hdc] = image_data;
    dc_surfacetex[hdc] = image_texture;
    dc_surfacepal[hdc] = pal_texture;
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
    return 0x8123ACB;
}

uint32_t Gdi32::GdiFlush()
{
    //SDL_UpdateWindowSurface(displayWindow);
    //SDL_RenderPresent(displayRenderer);

    return 1;
}

static void onTexDestroy(void* textureArg)
{
	GLuint image_texture = (GLuint)textureArg;
	
	//glDeleteTextures(1, &image_texture);
}

uint32_t Gdi32::BitBlt(uint32_t hdc, int x, int y, int cx, int cy, uint32_t hdcSrc, int x1, int y1, struct color rop)
{
    if (!dc_fbufs[hdc]) return 1;

    //printf("STUB: BitBlt hdc %x, x %i, y %i, cx %i, cy %i, hdcSrc %x, x1 %i, y1 %i, rop %x\n", hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
    
    if (gdi_render)
    {
        //TODO this is duplicated in GDI32
        //TODO use shaders

        GLuint image_texture = dc_surfacetex[hdc];
        GLuint image_pal = dc_surfacepal[hdc];

        void* image_data = dc_surfacebuf[hdc];
        uint8_t* paletted_img = (uint8_t*)dc_fbufs[hdc];
        
        glBindTexture(GL_TEXTURE_1D, image_pal);
        glTexSubImage1D(GL_TEXTURE_1D, 0, 0, 256, GL_RGBA, GL_UNSIGNED_BYTE, &dc_palettes[hdcSrc]);

        if (dc_fbufs[hdc])
        {
            uint8_t* img_out = (uint8_t*)image_data;
            /*uint32_t* pal = (uint32_t*)&dc_palettes[hdcSrc];
            for (size_t i = 0; i < dc_surface[hdc].w*dc_surface[hdc].h; i++)
            {
                *img_out++ = pal[*paletted_img++];
            }*/
            //memcpy(img_out, paletted_img, dc_surface[hdc].w*dc_surface[hdc].h);
        }
        else
        {
            memset(image_data, 0, dc_surface[hdc].w*dc_surface[hdc].h*sizeof(uint32_t));
        }
        
        glBindTexture(GL_TEXTURE_2D, image_texture);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, dc_surface[hdc].w, dc_surface[hdc].h, GL_RED, GL_UNSIGNED_BYTE, paletted_img);
        
        //TODO this is leaking texture allocs (one on every pause)
        
        //ImGui::SetNextWindowSize(ImVec2(dc_surface[hdc].w, dc_surface[hdc].h));
        /*ImGui::Begin("GDI32 Render", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
        ImVec2 screen_pos = ImGui::GetCursorScreenPos();
        ImGui::Image((void*)(intptr_t)whichID, ImVec2(dc_surface[hdc].w, dc_surface[hdc].h));
        ImGui::End();*/
        renderer_feedwindowinfo("GDI32 Render", image_texture, image_pal, ImVec2(dc_surface[hdc].w, dc_surface[hdc].h), onTexDestroy, NULL, image_texture);
        //renderer_waitforvblank();
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
    
    this->defaultHdcPal = hdc;
    for (uint32_t i = 0; i < cEntries; i++)
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
