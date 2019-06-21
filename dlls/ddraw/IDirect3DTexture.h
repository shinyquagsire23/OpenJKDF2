
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
        printf("STUB: IDirect3DTexture::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(struct d3dtex_ext* this_ptr)
    {
        printf("STUB: IDirect3DTexture::AddRef\n");
    }

    Q_INVOKABLE void Release(struct d3dtex_ext* this_ptr)
    {
        printf("STUB: IDirect3DTexture::Release\n");
        
        GlobalRelease(this_ptr);
        
        if (this_ptr->handle)
            glDeleteTextures(1, &this_ptr->handle);
    }
    
    /* IDirect3DTexture methods */
    Q_INVOKABLE void Initialize(struct d3dtex_ext* this_ptr, uint32_t device, uint32_t surface)
    {
        printf("STUB: IDirect3DTexture::Initialize\n");
    }
	
	Q_INVOKABLE uint32_t GetHandle(struct d3dtex_ext* this_ptr, uint32_t device, uint32_t* handle)
    {
        printf("STUB: IDirect3DTexture::GetHandle\n");
        
        if (this_ptr->handle) 
        {
            *handle = this_ptr->handle;
            return 0;
        }
        
        GLuint id;
        glGenTextures(1, &id);

        // "Bind" the newly created texture : all future texture functions will modify this texture
        glBindTexture(GL_TEXTURE_2D, id);
        glPixelStorei(GL_UNPACK_ROW_LENGTH, this_ptr->parent_surface->locked_desc.dwWidth);
        
        int format = GL_UNSIGNED_SHORT_1_5_5_5_REV;
        if (this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwRBitMask == 0xF00)
            format = GL_UNSIGNED_SHORT_4_4_4_4_REV;

        bool has_alpha = false;
        if (this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwFlags & DDPF_ALPHAPIXELS)
            has_alpha = true;

        glTexImage2D(GL_TEXTURE_2D,
                 0, 
                 has_alpha ? GL_RGBA : GL_RGB,
                 (GLsizei)this_ptr->parent_surface->locked_desc.dwWidth, 
                 (GLsizei)this_ptr->parent_surface->locked_desc.dwHeight,
                 0, 
                 has_alpha ? GL_BGRA : GL_BGRA, 
                 format,
                 vm_ptr_to_real_ptr(this_ptr->parent_surface->alloc));

        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        //glGenerateMipmap(GL_TEXTURE_2D);
        
        glBindTexture(GL_TEXTURE_2D, 0); // unbind
        
        *handle = id;
        this_ptr->handle = *handle;
        
        printf("%ux%u id %x\n", this_ptr->parent_surface->locked_desc.dwWidth, this_ptr->parent_surface->locked_desc.dwHeight, id);
        
        return 0;
    }
    
    Q_INVOKABLE void PaletteChanged(struct d3dtex_ext* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirect3DTexture::PaletteChanged\n");
    }
    
    Q_INVOKABLE uint32_t Load(struct d3dtex_ext* this_ptr, struct d3dtex_ext* texture)
    {
        printf("STUB: IDirect3DTexture::Load %x\n", real_ptr_to_vm_ptr(texture));
        
        //TODO actually copy the surfaces?
        
        this_ptr->parent_surface = texture->parent_surface;
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t Unload(struct d3dtex_ext* this_ptr)
    {
        printf("STUB: IDirect3DTexture::Unload\n");
        
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DTexture* idirect3dtexture;

#endif // IDIRECT3DTEXTURE_H
