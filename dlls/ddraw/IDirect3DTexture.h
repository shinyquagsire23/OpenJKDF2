
#ifndef IDIRECT3DTEXTURE_H
#define IDIRECT3DTEXTURE_H

#include <QObject>
#include "vm.h"
#include "dlls/winutils.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include <GL/glew.h>

class IDirect3DTexture : public QObject
{
Q_OBJECT

public:
    Q_INVOKABLE IDirect3DTexture() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(struct d3dtex_ext* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        //printf("STUB: IDirect3DTexture::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(struct d3dtex_ext* this_ptr)
    {
        //printf("STUB: IDirect3DTexture::AddRef\n");
    }

    Q_INVOKABLE void Release(struct d3dtex_ext* this_ptr)
    {
        //printf("STUB: IDirect3DTexture::Release\n");
        
        GlobalRelease(this_ptr);
        
        if (this_ptr->handle)
            glDeleteTextures(1, &this_ptr->handle);
    }
    
    /* IDirect3DTexture methods */
    Q_INVOKABLE void Initialize(struct d3dtex_ext* this_ptr, uint32_t device, uint32_t surface);
	Q_INVOKABLE uint32_t GetHandle(struct d3dtex_ext* this_ptr, uint32_t device, uint32_t* handle);
    Q_INVOKABLE void PaletteChanged(struct d3dtex_ext* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t Load(struct d3dtex_ext* this_ptr, struct d3dtex_ext* texture);
    Q_INVOKABLE uint32_t Unload(struct d3dtex_ext* this_ptr);

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DTexture* idirect3dtexture;

#endif // IDIRECT3DTEXTURE_H
