
#ifndef IDIRECT3D3_H
#define IDIRECT3D3_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

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
        
        return 1;
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3D3::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3D3::Release\n");
    }
    
    /* IDirect3D3 methods */
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t REFCLSID)
    {
        printf("STUB: IDirect3D3::Initialize\n");
    }
	Q_INVOKABLE uint32_t EnumDevices(vm_ptr<void*> this_ptr, uint32_t callback, void* unkOuter)
    {
        printf("STUB: IDirect3D3::EnumDevices\n");
        
        // Map some memory for these strings
        uint32_t name_ptrs = kernel32->VirtualAlloc(0, 0x1000, 0, 0);

        char* device_desc = "Direct3D meme";
        char* device_name = "idk";
        
        uint32_t device_desc_ptr = name_ptrs;
        uint32_t device_name_ptr = name_ptrs+strlen(device_desc)+1;
        
        vm_mem_write(device_desc_ptr, device_desc, strlen(device_desc));
        vm_mem_write(device_name_ptr, device_name, strlen(device_name));
        
        // Device descs
        uint32_t device_ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
        
            
        uint32_t callback_args[6] = {0xabcdef, device_ptr, device_ptr, device_name_ptr, device_desc_ptr, this_ptr.raw_vm_ptr};
        uint32_t ret = vm_call_function(callback, 6, callback_args);
        
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
	Q_INVOKABLE void CreateViewport(void* this_ptr, uint32_t* LPDIRECT3DVIEWPORT, uint32_t* IUnknown)
    {
        printf("STUB: IDirect3D3::CreateViewport\n");
    }
	Q_INVOKABLE void FindDevice(void* this_ptr, uint32_t LPD3DFINDDEVICESEARCH, uint32_t LPD3DFINDDEVICERESULT)
    {
        printf("STUB: IDirect3D3::FindDevice\n");
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3D3* idirect3d3;

#endif // IDIRECT3D3_H
