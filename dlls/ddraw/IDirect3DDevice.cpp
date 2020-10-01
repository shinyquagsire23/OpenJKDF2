#include "IDirect3DDevice.h"

#include <pthread.h>

uint32_t IDirect3DDevice::Initialize(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
{
    printf("STUB:: IDirect3DDevice::Initialize\n");

    return 0;
}

uint32_t IDirect3DDevice::GetCaps(void* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB:: IDirect3DDevice::GetCaps\n");

    return 0;
}

uint32_t IDirect3DDevice::SwapTextureHandles(void* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB:: IDirect3DDevice::SwapTextureHandles\n");

    return 0;
}

uint32_t IDirect3DDevice::CreateExecuteBuffer(void* this_ptr, struct D3DEXECUTEBUFFERDESC* desc, uint32_t* lpDirect3DExecuteBuffer, uint32_t pUnkOuter)
{
    printf("STUB:: IDirect3DDevice::CreateExecuteBuffer\n");
    
    printf("desc size %x, flags %x, caps %x, buffer size %x, buf %x\n", desc->dwSize, desc->dwFlags, desc->dwCaps, desc->dwBufferSize, desc->lpData);

    *lpDirect3DExecuteBuffer = CreateInterfaceInstance("IDirect3DExecuteBuffer", 200);

    return 0;
}

uint32_t IDirect3DDevice::GetStats(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DDevice::GetStats\n");

    return 0;
}

uint32_t IDirect3DDevice::Execute(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
{
    //printf("STUB:: IDirect3DDevice::Execute\n");

    return 0;
}

uint32_t IDirect3DDevice::AddViewport(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DDevice::AddViewport\n");

    return 0;
}

uint32_t IDirect3DDevice::DeleteViewport(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DDevice::DeleteViewport\n");

    return 0;
}

uint32_t IDirect3DDevice::NextViewport(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
{
    printf("STUB:: IDirect3DDevice::\n");

    return 0;
}

uint32_t IDirect3DDevice::Pick(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    printf("STUB:: IDirect3DDevice::Pick\n");

    return 0;
}

uint32_t IDirect3DDevice::GetPickRecords(void* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB:: IDirect3DDevice::GetPickRecords\n");

    return 0;
}

uint32_t IDirect3DDevice::EnumTextureFormats(void* this_ptr, uint32_t callback, uint32_t pUnkOuter)
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

uint32_t IDirect3DDevice::CreateMatrix(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DDevice::CreateMatrix\n");

    return 0;
}

uint32_t IDirect3DDevice::SetMatrix(void* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB:: IDirect3DDevice::SetMatrix\n");

    return 0;
}

uint32_t IDirect3DDevice::GetMatrix(void* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB:: IDirect3DDevice::GetMatrix\n");

    return 0;
}

uint32_t IDirect3DDevice::DeleteMatrix(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DDevice::DeleteMatrix\n");

    return 0;
}

pthread_mutex_t vblank_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t IDirect3DDevice::BeginScene(void* this_ptr)
{
    printf("IDirect3DDevice::BeginScene\n");
    gdi32->gdi_render = false;
    idirect3dexecutebuffer->init_resources();
    
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

static void onD3DVblank(void* textureArg)
{
}

uint32_t IDirect3DDevice::EndScene(void* this_ptr)
{
    printf("IDirect3DDevice::EndScene\n");
    
    idirect3dexecutebuffer->renderOverlay();

    renderer_feedwindowinfo("D3D Render", idirect3dexecutebuffer->fbTex, 0, ImVec2(idirect3dexecutebuffer->view.dwWidth, idirect3dexecutebuffer->view.dwHeight), NULL, onD3DVblank, NULL);
    idirect3dexecutebuffer->swap_framebuffers();

    return 0;
}

uint32_t IDirect3DDevice::GetDirect3D(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DDevice::GetDirect3D\n");

    return 0;
}
