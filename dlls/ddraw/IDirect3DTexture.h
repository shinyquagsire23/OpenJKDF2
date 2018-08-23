
#ifndef IDIRECT3DTEXTURE_H
#define IDIRECT3DTEXTURE_H

#include <QObject>
#include "vm.h"
#include "dlls/winutils.h"

class IDirect3DTexture : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirect3DTexture() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3DTexture::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3DTexture::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3DTexture::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DTexture methods */
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t device, uint32_t surface)
    {
        printf("STUB: IDirect3DTexture::Initialize\n");
    }
	
	Q_INVOKABLE void GetHandle(void* this_ptr, uint32_t device, uint32_t handle)
    {
        printf("STUB: IDirect3DTexture::GetHandle\n");
    }
    
    Q_INVOKABLE void PaletteChanged(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirect3DTexture::PaletteChanged\n");
    }
    
    Q_INVOKABLE uint32_t Load(void* this_ptr, uint32_t texture, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirect3DTexture::Load %x %x %x %x\n", texture, b, c, d);
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t Unload(void* this_ptr)
    {
        printf("STUB: IDirect3DTexture::Unload\n");
        
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DTexture* idirect3dtexture;

#endif // IDIRECT3DTEXTURE_H
