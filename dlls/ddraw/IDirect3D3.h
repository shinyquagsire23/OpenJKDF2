
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

typedef struct D3DPrimCaps
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
} D3DPrimCaps;

typedef struct D3DTransformCaps
{
    uint32_t dwSize;
    uint32_t dwCaps;
} D3DTransformCaps;

typedef struct D3DLightingCaps
{
    uint32_t dwSize;
    uint32_t dwCaps;
    uint32_t dwLightingModel;
    uint32_t dwNumLights;
} D3DLightingCaps;

typedef struct D3DDeviceDesc
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dcmColorModel;
    uint32_t dwDevCaps;
    D3DTransformCaps dtcTransformCaps;
    uint32_t  bClipping;
    D3DLightingCaps dlcLightingCaps;
    D3DPrimCaps dpcLineCaps;
    D3DPrimCaps dpcTriCaps;
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
} D3DDeviceDesc;

typedef struct D3DVIEWPORT
{
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
} D3DVIEWPORT;

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
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t REFCLSID);
    Q_INVOKABLE uint32_t EnumDevices(vm_ptr<void*> this_ptr, uint32_t callback, void* unkOuter);
    Q_INVOKABLE uint32_t CreateLight(void* this_ptr, uint32_t* LPDIRECT3DLIGHT, uint32_t* IUnknown);
    Q_INVOKABLE uint32_t CreateMaterial(void* this_ptr, uint32_t* LPDIRECT3DMATERIAL, uint32_t* IUnknown);
    Q_INVOKABLE uint32_t CreateViewport(void* this_ptr, uint32_t* lpDirect3DViewport, uint32_t* IUnknown);
    Q_INVOKABLE uint32_t FindDevice(void* this_ptr, uint32_t LPD3DFINDDEVICESEARCH, uint32_t LPD3DFINDDEVICERESULT);

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3D3* idirect3d3;

#endif // IDIRECT3D3_H
