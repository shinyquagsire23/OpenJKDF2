
#ifndef IDIRECT3D3_H
#define IDIRECT3D3_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

#define D3DCOLOR_MONO 1
#define D3DCOLOR_RGB  2

#define D3DPSHADECAPS_ALPHAFLATBLEND       0x00001000
#define D3DPSHADECAPS_ALPHAFLATSTIPPLED    0x00002000

#define D3DPTBLENDCAPS_DECAL               0x00000001
#define D3DPTBLENDCAPS_MODULATE            0x00000002
#define D3DPTBLENDCAPS_DECALALPHA          0x00000004
#define D3DPTBLENDCAPS_MODULATEALPHA       0x00000008
#define D3DPTBLENDCAPS_DECALMASK           0x00000010
#define D3DPTBLENDCAPS_MODULATEMASK        0x00000020
#define D3DPTBLENDCAPS_COPY                0x00000040
#define D3DPTBLENDCAPS_ADD                 0x00000080

#define D3DPTEXTURECAPS_PERSPECTIVE        0x01
#define D3DPTEXTURECAPS_ALPHA              0x04
#define D3DPTEXTURECAPS_TRANSPARENCY       0x08
#define D3DPTEXTURECAPS_SQUAREONLY         0x20

#define DDBD_1                             0x00004000
#define DDBD_2                             0x00002000
#define DDBD_4                             0x00001000
#define DDBD_8                             0x00000800
#define DDBD_16                            0x00000400
#define DDBD_24                            0x00000200
#define DDBD_32                            0x00000100

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

struct D3DVIEWPORT {
 uint32_t dwSize;
 uint32_t dwX;
 uint32_t dwY;
 uint32_t dwWidth;
 uint32_t dwHeight;
 float dvScaleX;
 float dvScaleY;
 float dvMaxX;
 float dvMaxY;
 float dvMinZ;
 float dvMaxZ;
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

        uint32_t ret = vm_call_func(callback, iid_ptr, device_desc_ptr, device_name_ptr, device_ptr,device_ptr, 0xabcdef);
        
        kernel32->VirtualFree(device_ptr, 0, 0);
        kernel32->VirtualFree(name_ptrs, 0, 0);

        return 0;
    }
	Q_INVOKABLE uint32_t CreateLight(void* this_ptr, uint32_t* LPDIRECT3DLIGHT, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateLight\n");
        
        return 0;
    }

	Q_INVOKABLE uint32_t CreateMaterial(void* this_ptr, uint32_t* LPDIRECT3DMATERIAL, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateMaterial\n");
        
        return 0;
    }

	Q_INVOKABLE uint32_t CreateViewport(void* this_ptr, uint32_t* lpDirect3DViewport, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateViewport\n");
        
        *lpDirect3DViewport = CreateInterfaceInstance("IDirect3DViewport", 200);
        
        return 0;
    }

	Q_INVOKABLE uint32_t FindDevice(void* this_ptr, uint32_t LPD3DFINDDEVICESEARCH, uint32_t LPD3DFINDDEVICERESULT)
    {
        printf("STUB: IDirect3D3::FindDevice\n");
        
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3D3* idirect3d3;

#endif // IDIRECT3D3_H
