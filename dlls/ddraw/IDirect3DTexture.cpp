#include "IDirect3DTexture.h"

/* IDirect3DTexture methods */
void IDirect3DTexture::Initialize(struct d3dtex_ext* this_ptr, uint32_t device, uint32_t surface)
{
    //printf("STUB: IDirect3DTexture::Initialize\n");
}

uint32_t IDirect3DTexture::GetHandle(struct d3dtex_ext* this_ptr, uint32_t device, uint32_t* handle)
{
    //printf("STUB: IDirect3DTexture::GetHandle\n");
    
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
    
    bool has_alpha = false;
    if (this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwFlags & DDPF_ALPHAPIXELS)
        has_alpha = true;
    
    // These textures are actually BGRA usually.
    // However, BGR565 is invalid for some reason, so we just swap colors
    // in the shader.
    int format_order = GL_RGBA;
    int format = GL_UNSIGNED_SHORT_1_5_5_5_REV;
    if (this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwRBitMask == 0x7C00)
    {
        format = GL_UNSIGNED_SHORT_1_5_5_5_REV;
        format_order = GL_RGBA;
    }
    else if (this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwRBitMask == 0xF00)
    {
        has_alpha = true;
        format = GL_UNSIGNED_SHORT_4_4_4_4_REV;
        format_order = GL_RGBA;
    }
    else if (this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwRBitMask == 0xF800)
    {
        format = GL_UNSIGNED_SHORT_5_6_5_REV;
        format_order = GL_RGB;
        has_alpha = false;
    }
    else
    {
        //printf("IDirect3DTexture::GetHandle Unknown texture format? Rbitmask %x\n", this_ptr->parent_surface->locked_desc.ddpfPixelFormat.dwRBitMask);
    }

    glTexImage2D(GL_TEXTURE_2D,
             0, 
             has_alpha ? GL_RGBA : GL_RGB,
             (GLsizei)this_ptr->parent_surface->locked_desc.dwWidth, 
             (GLsizei)this_ptr->parent_surface->locked_desc.dwHeight,
             0, 
             format_order,
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
    
    //printf("%ux%u id %x\n", this_ptr->parent_surface->locked_desc.dwWidth, this_ptr->parent_surface->locked_desc.dwHeight, id);
    
    return 0;
}


void IDirect3DTexture::PaletteChanged(struct d3dtex_ext* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB: IDirect3DTexture::PaletteChanged\n");
}

uint32_t IDirect3DTexture::Load(struct d3dtex_ext* this_ptr, struct d3dtex_ext* texture)
{
    //printf("STUB: IDirect3DTexture::Load %x\n", real_ptr_to_vm_ptr(texture));
    
    //TODO actually copy the surfaces?
    
    this_ptr->parent_surface = texture->parent_surface;
    
    return 0;
}

uint32_t IDirect3DTexture::Unload(struct d3dtex_ext* this_ptr)
{
    //printf("STUB: IDirect3DTexture::Unload\n");
    
    return 0;
}
