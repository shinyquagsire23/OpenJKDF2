
#ifndef IDIRECT3DDEVICE_H
#define IDIRECT3DDEVICE_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "main.h"
#include "dlls/winutils.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include "dlls/ddraw/IDirect3DExecuteBuffer.h"

#include "3rdparty/imgui/imgui.h"
#include "3rdparty/imgui/imgui_impl_sdl.h"
#include "3rdparty/imgui/imgui_impl_opengl3.h"

class IDirect3DDevice : public QObject
{
Q_OBJECT
private:
    GLint window_fbo;

public:

    Q_INVOKABLE IDirect3DDevice() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3DDevice::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3DDevice::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3DDevice::Release\n");
        
        idirect3dexecutebuffer->free_resources();
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DDevice methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirect3DDevice::Initialize\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::GetCaps\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SwapTextureHandles(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::SwapTextureHandles\n");

        return 0;
    }

    Q_INVOKABLE uint32_t CreateExecuteBuffer(void* this_ptr, struct D3DEXECUTEBUFFERDESC* desc, uint32_t* lpDirect3DExecuteBuffer, uint32_t pUnkOuter)
    {
        printf("STUB:: IDirect3DDevice::CreateExecuteBuffer\n");
        
        printf("desc size %x, flags %x, caps %x, buffer size %x, buf %x\n", desc->dwSize, desc->dwFlags, desc->dwCaps, desc->dwBufferSize, desc->lpData);

        *lpDirect3DExecuteBuffer = CreateInterfaceInstance("IDirect3DExecuteBuffer", 200);

        return 0;
    }

    Q_INVOKABLE uint32_t GetStats(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::GetStats\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Execute(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        //printf("STUB:: IDirect3DDevice::Execute\n");

        return 0;
    }

    Q_INVOKABLE uint32_t AddViewport(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::AddViewport\n");

        return 0;
    }

    Q_INVOKABLE uint32_t DeleteViewport(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::DeleteViewport\n");

        return 0;
    }

    Q_INVOKABLE uint32_t NextViewport(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirect3DDevice::\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Pick(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB:: IDirect3DDevice::Pick\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetPickRecords(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::GetPickRecords\n");

        return 0;
    }

    Q_INVOKABLE uint32_t EnumTextureFormats(void* this_ptr, uint32_t callback, uint32_t pUnkOuter)
    {
        printf("STUB:: IDirect3DDevice::EnumTextureFormats\n");
        
        // Device descs
        uint32_t desc_ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
        vm_ptr<struct DDSURFACEDESC*> desc(desc_ptr);
        
        desc->dwSize = sizeof(desc);
        desc->dwFlags = DDSD_PIXELFORMAT | DDSD_CAPS;
        desc->ddsCaps = DDSCAPS_TEXTURE;
        desc->ddpfPixelFormat.dwSize = sizeof(desc->ddpfPixelFormat);
        
        /* B5G5R5X1_UNORM, */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 16;
        desc->ddpfPixelFormat.dwRBitMask = 0x7C00;
        desc->ddpfPixelFormat.dwGBitMask = 0x03E0;
        desc->ddpfPixelFormat.dwBBitMask = 0x001F;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0x8000;
        vm_call_func(callback, desc_ptr, pUnkOuter);
        
        /* B5G5R5A1_UNORM */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_ALPHAPIXELS;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 16;
        desc->ddpfPixelFormat.dwRBitMask = 0x7C00;
        desc->ddpfPixelFormat.dwGBitMask = 0x03E0;
        desc->ddpfPixelFormat.dwBBitMask = 0x001F;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0x8000;
        vm_call_func(callback, desc_ptr, pUnkOuter);

        /* B4G4R4A4_UNORM */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_ALPHAPIXELS;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 16;
        desc->ddpfPixelFormat.dwRBitMask = 0x0F00;
        desc->ddpfPixelFormat.dwGBitMask = 0x00F0;
        desc->ddpfPixelFormat.dwBBitMask = 0x000F;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0xF000;
        vm_call_func(callback, desc_ptr, pUnkOuter);

        /* B5G6R5_UNORM */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 16;
        desc->ddpfPixelFormat.dwRBitMask = 0xF800;
        desc->ddpfPixelFormat.dwGBitMask = 0x07E0;
        desc->ddpfPixelFormat.dwBBitMask = 0x001F;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0x0;
        vm_call_func(callback, desc_ptr, pUnkOuter);
        
        /* B8G8R8X8_UNORM */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 32;
        desc->ddpfPixelFormat.dwRBitMask = 0x00ff0000;
        desc->ddpfPixelFormat.dwGBitMask = 0x0000ff00;
        desc->ddpfPixelFormat.dwBBitMask = 0x000000ff;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0x0;
        vm_call_func(callback, desc_ptr, pUnkOuter);
        
        /* B8G8R8A8_UNORM */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_ALPHAPIXELS;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 32;
        desc->ddpfPixelFormat.dwRBitMask = 0x00ff0000;
        desc->ddpfPixelFormat.dwGBitMask = 0x0000ff00;
        desc->ddpfPixelFormat.dwBBitMask = 0x000000ff;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0xff000000;
        vm_call_func(callback, desc_ptr, pUnkOuter);
#if 0        
        /* B2G3R3_UNORM */
        desc->ddpfPixelFormat.dwFlags = DDPF_RGB;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 8;
        desc->ddpfPixelFormat.dwRBitMask = 0xE0;
        desc->ddpfPixelFormat.dwGBitMask = 0x1C;
        desc->ddpfPixelFormat.dwBBitMask = 0x03;
        desc->ddpfPixelFormat.dwRGBAlphaBitMask = 0x0;
        vm_call_func(callback, desc_ptr, pUnkOuter);

        /* P8_UINT */
        desc->ddpfPixelFormat.dwFlags = DDPF_PALETTEINDEXED8 | DDPF_RGB;
        desc->ddpfPixelFormat.dwFourCC = 0;
        desc->ddpfPixelFormat.dwRGBBitCount = 8;
        desc->ddpfPixelFormat.dwRBitMask = 0x00;
        desc->ddpfPixelFormat.dwGBitMask = 0x00;
        desc->ddpfPixelFormat.dwBBitMask = 0x00;
        vm_call_func(callback, desc_ptr, pUnkOuter);
#endif
        kernel32->VirtualFree(desc_ptr, 0, 0);

        return 0;
    }

    Q_INVOKABLE uint32_t CreateMatrix(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::CreateMatrix\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetMatrix(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::SetMatrix\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetMatrix(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::GetMatrix\n");

        return 0;
    }

    Q_INVOKABLE uint32_t DeleteMatrix(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::DeleteMatrix\n");

        return 0;
    }

    Q_INVOKABLE uint32_t BeginScene(void* this_ptr)
    {
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &window_fbo);
    
        printf("IDirect3DDevice::BeginScene\n");
        gdi32->gdi_render = false;
        idirect3dexecutebuffer->init_resources();
        
        //SDL_SetRenderTarget(displayRenderer, idirect3dexecutebuffer->fb_texture);
        
        glBindFramebuffer(GL_FRAMEBUFFER, idirect3dexecutebuffer->fb);
        glEnable(GL_BLEND);
	    glEnable(GL_DEPTH_TEST);
	    glDepthFunc(GL_LESS);
	    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	    
	    // Technically this should be from Clear2
	    glClearColor(0.0, 0.0, 0.0, 1.0);
	    glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);

        return 0;
    }

    Q_INVOKABLE uint32_t EndScene(void* this_ptr)
    {
        printf("IDirect3DDevice::EndScene\n");
        
        glBindFramebuffer(GL_FRAMEBUFFER, window_fbo);
        SDL_SetRenderTarget(displayRenderer, NULL);
        glBindTexture(GL_TEXTURE_2D, 0);
		
		//TODO: idk how I feel about this
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame(displayWindow);
        ImGui::NewFrame();
        
        //ImGui::SetNextWindowSize(ImVec2(dc_surface[hdc]->w, dc_surface[hdc]->h));
        ImGui::Begin("D3D Render", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
        ImVec2 screen_pos = ImGui::GetCursorScreenPos();
        ImGui::Image((void*)(intptr_t)idirect3dexecutebuffer->fbTex, ImVec2(idirect3dexecutebuffer->view.dwWidth, idirect3dexecutebuffer->view.dwHeight));
        ImGui::End();
        
        user32->SetMouseOffset(screen_pos.x, screen_pos.y);
        
        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        
        //SDL_GL_UnbindTexture(idirect3dexecutebuffer->fb_texture);
        
   	    SDL_GL_SwapWindow(displayWindow);

        return 0;
    }

    Q_INVOKABLE uint32_t GetDirect3D(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::GetDirect3D\n");

        return 0;
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DDevice* idirect3ddevice;

#endif // IDIRECT3DDEVICE_H
