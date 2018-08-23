
#ifndef IDIRECT3D3_H
#define IDIRECT3D3_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

#define D3DCOLOR_MONO 1
#define D3DCOLOR_RGB  2

#define D3DPTEXTURECAPS_PERSPECTIVE 1
#define D3DPTEXTURECAPS_ALPHA 4
#define D3DPTEXTURECAPS_TRANSPARENCY 8
#define D3DPTEXTURECAPS_SQUAREONLY 0x20

struct D3DPrimCaps
{
    uint32_t dwSize;
    uint32_t dwMiscCaps;
    uint32_t dwRasterCaps;
    uint32_t dwZCmpCaps;
    uint32_t dwSrcBlendCaps;
    uint32_t dwDestBlendCaps;
    uint32_t dwAlphaCmpCaps;
    uint32_t dwShadeCaps;
    uint32_t dwTextureCaps;
    uint32_t dwTextureFilterCaps;
    uint32_t dwTextureBlendCaps;
    uint32_t dwTextureAddressCaps;
    uint32_t dwStippleWidth;
    uint32_t dwStippleHeight;
};

struct D3DTransformCaps
{
    uint32_t dwSize;
    uint32_t dwCaps;
};

struct D3DLightingCaps
{
    uint32_t dwSize;
    uint32_t dwCaps;
    uint32_t dwLightingModel;
    uint32_t dwNumLights;
};

struct D3DDeviceDesc
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dcmColorModel;
    uint32_t dwDevCaps;
    struct D3DTransformCaps dtcTransformCaps;
    uint32_t  bClipping;
    struct D3DLightingCaps dlcLightingCaps;
    struct D3DPrimCaps dpcLineCaps;
    struct D3DPrimCaps dpcTriCaps;
    uint32_t dwDeviceRenderBitDepth;
    uint32_t dwDeviceZBufferBitDepth;
    uint32_t dwMaxBufferSize;
    uint32_t dwMaxVertexCount;
    uint32_t dwMinTextureWidth;
    uint32_t dwMinTextureHeight;
    uint32_t dwMaxTextureWidth;
    uint32_t dwMaxTextureHeight;
    uint32_t dwMinStippleWidth;
    uint32_t dwMaxStippleWidth;
    uint32_t dwMinStippleHeight;
    uint32_t dwMaxStippleHeight;
};

class IDirect3D3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirect3D3() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3D3::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3D3::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3D3::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3D3 methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t REFCLSID)
    {
        printf("STUB: IDirect3D3::Initialize\n");

        return 0;
    }
	Q_INVOKABLE uint32_t EnumDevices(vm_ptr<void*> this_ptr, uint32_t callback, void* unkOuter)
    {
        printf("STUB: IDirect3D3::EnumDevices\n");
        
        // Map some memory for these strings
        uint32_t name_ptrs = kernel32->VirtualAlloc(0, 0x1000, 0, 0);

        char* device_desc = "Direct3D meme";
        char* device_name = "idk";
        char* iid = "bbbbbbbbbbbbbbbb";
        
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
        desc->dpcTriCaps.dwTextureCaps = D3DPTEXTURECAPS_PERSPECTIVE | D3DPTEXTURECAPS_ALPHA /*| D3DPTEXTURECAPS_SQUAREONLY*/ | D3DPTEXTURECAPS_TRANSPARENCY;
        desc->dpcTriCaps.dwZCmpCaps = 0xFF; // we support anything for z comparison
        desc->dwMaxBufferSize = 0x10000000;
        desc->dwMaxVertexCount = 0x10000000;

        uint32_t ret = vm_call_func(callback, iid_ptr, device_desc_ptr, device_name_ptr, device_ptr,device_ptr, 0xabcdef);
        
        kernel32->VirtualFree(device_ptr, 0, 0);
        kernel32->VirtualFree(name_ptrs, 0, 0);
        
        //TODO: HACK
        **vm_ptr<uint32_t*>(0x8605C8) = 0;

        return 0;
    }
	Q_INVOKABLE void CreateLight(void* this_ptr, uint32_t* LPDIRECT3DLIGHT, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateLight\n");
    }

	Q_INVOKABLE void CreateMaterial(void* this_ptr, uint32_t* LPDIRECT3DMATERIAL, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateMaterial\n");
    }

	Q_INVOKABLE uint32_t CreateViewport(void* this_ptr, uint32_t* lpDirect3DViewport, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateViewport\n");
        
        *lpDirect3DViewport = CreateInterfaceInstance("IDirect3DViewport", 200);
        
        return 0;
    }

	Q_INVOKABLE void FindDevice(void* this_ptr, uint32_t LPD3DFINDDEVICESEARCH, uint32_t LPD3DFINDDEVICERESULT)
    {
        printf("STUB: IDirect3D3::FindDevice\n");
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3D3* idirect3d3;

#endif // IDIRECT3D3_H
