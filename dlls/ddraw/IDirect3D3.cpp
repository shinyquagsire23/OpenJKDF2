#include "IDirect3D3.h"

uint32_t IDirect3D3::Initialize(void* this_ptr, uint32_t REFCLSID)
{
    printf("STUB: IDirect3D3::Initialize\n");

    return 0;
}

uint32_t IDirect3D3::EnumDevices(vm_ptr<void*> this_ptr, uint32_t callback, void* unkOuter)
{
    printf("STUB: IDirect3D3::EnumDevices\n");
    
    // Map some memory for these strings
    uint32_t name_ptrs = kernel32->VirtualAlloc(0, 0x1000, 0, 0);

    char* device_desc = (char*)"Direct3D meme";
    char* device_name = (char*)"idk";
    uint32_t iid[4] = {0x62626262, 0x62626262, 0x62626262, 0x62626262};
    
    uint32_t device_desc_ptr = name_ptrs;
    uint32_t device_name_ptr = name_ptrs+strlen(device_desc)+1;
    uint32_t iid_ptr = device_name_ptr+strlen(device_name)+1;
    
    vm_mem_write(device_desc_ptr, device_desc, strlen(device_desc));
    vm_mem_write(device_name_ptr, device_name, strlen(device_name));
    vm_mem_write(iid_ptr, iid, 0x10);
    
    // Device descs
    uint32_t device_ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
    vm_ptr<struct D3DDeviceDesc*> desc(device_ptr);
    desc->dcmColorModel = D3DCOLOR_RGB;
    desc->dwDeviceZBufferBitDepth = 0x400;
    desc->dpcTriCaps.dwTextureCaps = D3DPTEXTURECAPS_PERSPECTIVE | D3DPTEXTURECAPS_ALPHA | D3DPTEXTURECAPS_SQUAREONLY | D3DPTEXTURECAPS_TRANSPARENCY;
    desc->dpcTriCaps.dwZCmpCaps = 0xFF; // we support anything for z comparison
    desc->dpcTriCaps.dwShadeCaps = D3DPSHADECAPS_ALPHAFLATSTIPPLED;
    desc->dpcTriCaps.dwTextureBlendCaps = D3DPTBLENDCAPS_DECALALPHA | D3DPTBLENDCAPS_MODULATEALPHA;
    desc->dwMaxBufferSize = 0;
    desc->dwMaxVertexCount = 65536;
    desc->dwMinTextureWidth = 1;
    desc->dwMinTextureHeight = 1;
    desc->dwMaxTextureWidth = 4096;
    desc->dwMaxTextureHeight = 4096;
    desc->dwMinStippleWidth = 1;
    desc->dwMaxStippleWidth = 4096;
    desc->dwMinStippleHeight = 1;
    desc->dwMaxStippleHeight = 4096;
    desc->dwDeviceRenderBitDepth = DDBD_8 | DDBD_16 | DDBD_24 | DDBD_32;

    vm_call_func(callback, iid_ptr, device_desc_ptr, device_name_ptr, device_ptr,device_ptr, 0xabcdef);
    
    kernel32->VirtualFree(device_ptr, 0, 0);
    kernel32->VirtualFree(name_ptrs, 0, 0);

    return 0;
}

uint32_t IDirect3D3::CreateLight(void* this_ptr, uint32_t* LPDIRECT3DLIGHT, uint32_t* IUnknown)
{
    printf("STUB: IDirect3D3::CreateLight\n");
    
    return 0;
}

uint32_t IDirect3D3::CreateMaterial(void* this_ptr, uint32_t* LPDIRECT3DMATERIAL, uint32_t* IUnknown)
{
    printf("STUB: IDirect3D3::CreateMaterial\n");
    
    return 0;
}

uint32_t IDirect3D3::CreateViewport(void* this_ptr, uint32_t* lpDirect3DViewport, uint32_t* IUnknown)
{
    printf("STUB: IDirect3D3::CreateViewport\n");
    
    *lpDirect3DViewport = CreateInterfaceInstance("IDirect3DViewport", 200);
    
    return 0;
}

uint32_t IDirect3D3::FindDevice(void* this_ptr, uint32_t LPD3DFINDDEVICESEARCH, uint32_t LPD3DFINDDEVICERESULT)
{
    printf("STUB: IDirect3D3::FindDevice\n");
    
    return 0;
}
