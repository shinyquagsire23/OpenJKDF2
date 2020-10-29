
#ifndef IDIRECT3DEXECUTEBUFFER_H
#define IDIRECT3DEXECUTEBUFFER_H

#include <QObject>
#include <cmath>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/gdi32.h"
#include "dlls/winutils.h"
#include "main.h"
#include "dlls/user32.h"

#include "dlls/ddraw/IDirect3D3.h"
#include "dlls/ddraw/IDirectDraw4.h"

#include "render/shader_utils.h"
#include <GL/glew.h>
#include <glm/glm.hpp>
#include <glm/gtc/matrix_transform.hpp>
#include <glm/gtc/type_ptr.hpp>

#define D3DTRIFLAG_EDGEENABLE1 0x100
#define D3DTRIFLAG_EDGEENABLE2 0x200
#define D3DTRIFLAG_EDGEENABLE3 0x400

enum D3DOPCODE
{
    D3DOP_POINT            = 1,
    D3DOP_LINE             = 2,
    D3DOP_TRIANGLE         = 3,
    D3DOP_MATRIXLOAD       = 4,
    D3DOP_MATRIXMULTIPLY   = 5,
    D3DOP_STATETRANSFORM   = 6,
    D3DOP_STATELIGHT       = 7,
    D3DOP_STATERENDER      = 8,
    D3DOP_PROCESSVERTICES  = 9,
    D3DOP_TEXTURELOAD      = 10,
    D3DOP_EXIT             = 11,
    D3DOP_BRANCHFORWARD    = 12,
    D3DOP_SPAN             = 13,
    D3DOP_SETSTATUS        = 14,
};

enum D3DRENDERSTATE
{
    D3DRENDERSTATE_TEXTUREHANDLE      = 1,
    D3DRENDERSTATE_TEXTUREPERSPECTIVE = 4,
    D3DRENDERSTATE_MONOENABLE         = 11,
    D3DRENDERSTATE_ZWRITEENABLE       = 14,
    D3DRENDERSTATE_SRCBLEND           = 19,
    D3DRENDERSTATE_DESTBLEND          = 20,
    D3DRENDERSTATE_TEXTUREMAPBLEND    = 21,
    D3DRENDERSTATE_ZFUNC              = 23,
    D3DRENDERSTATE_ALPHABLENDENABLE   = 27,
    D3DRENDERSTATE_FOGENABLE          = 28,
    D3DRENDERSTATE_FOGCOLOR           = 34,
    D3DRENDERSTATE_FOGTABLEMODE       = 35,
    D3DRENDERSTATE_FOGTABLESTART      = 36,
    D3DRENDERSTATE_FOGTABLEEND        = 37,
};

enum D3DBLEND
{
    D3DBLEND_ZERO             = 1,
    D3DBLEND_ONE              = 2,
    D3DBLEND_SRCCOLOR         = 3,
    D3DBLEND_INVSRCCOLOR      = 4,
    D3DBLEND_SRCALPHA         = 5,
    D3DBLEND_INVSRCALPHA      = 6,
    D3DBLEND_DESTALPHA        = 7,
    D3DBLEND_INVDESTALPHA     = 8,
    D3DBLEND_DESTCOLOR        = 9,
    D3DBLEND_INVDESTCOLOR     = 10,
    D3DBLEND_SRCALPHASAT      = 11,
    D3DBLEND_BOTHSRCALPHA     = 12,
    D3DBLEND_BOTHINVSRCALPHA  = 13,
};

enum D3DCMP
{
    D3DCMP_NEVER               = 1,
    D3DCMP_LESS                = 2,
    D3DCMP_EQUAL               = 3,
    D3DCMP_LESSEQUAL           = 4,
    D3DCMP_GREATER             = 5,
    D3DCMP_NOTEQUAL            = 6,
    D3DCMP_GREATEREQUAL        = 7,
    D3DCMP_ALWAYS              = 8,
};

typedef struct D3DVERTEX
{
    float x;
    float y;
    float z;
    float nx;
    float ny;
    float nz;
    float tu;
    float tv;
} D3DVERTEX;

typedef struct D3DTRIANGLE
{
    uint16_t v1;
    uint16_t v2;
    uint16_t v3;
    uint16_t flags;
} D3DTRIANGLE;

typedef struct D3DINSTRUCTION
{
    uint8_t bOpcode;
    uint8_t bSize;
    uint16_t wCount;
} D3DINSTRUCTION;

typedef struct D3DRECT
{
    uint32_t x1;
    uint32_t y1;
    uint32_t x2;
    uint32_t y2;
} D3DRECT;

typedef struct D3DSTATUS {
  uint32_t dwFlags;
  uint32_t dwStatus;
  D3DRECT drExtent;
} D3DSTATUS;

typedef struct D3DEXECUTEBUFFERDESC
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwCaps;
    uint32_t dwBufferSize;
    uint32_t lpData;
} D3DEXECUTEBUFFERDESC;

typedef struct D3DEXECUTEDATA
{
  uint32_t dwSize;
  uint32_t dwVertexOffset;
  uint32_t dwVertexCount;
  uint32_t dwInstructionOffset;
  uint32_t dwInstructionLength;
  uint32_t dwHVertexOffset;
  D3DSTATUS dsStatus;
} D3DEXECUTEDATA;

#define TEX_MODE_BGR 0
#define TEX_MODE_RGB 1
#define TEX_MODE_BGR_WHITETRANSPARENCY 2
#define TEX_MODE_TEST 3

class IDirect3DExecuteBuffer : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint32_t> locked_objs;

    GLuint program;
    GLint attribute_coord3d, attribute_v_color, attribute_v_uv, attribute_v_norm;
    GLint uniform_mvp, uniform_tex, uniform_tex_mode, uniform_blend_mode;

    const char* gl_frag = 
    "uniform sampler2D tex;\n"
    "uniform int tex_mode;\n"
    "uniform int blend_mode;\n"
    "varying vec4 f_color;\n"
    "varying vec2 f_uv;\n"
    "varying vec3 f_coord;\n"
    "void main(void) {\n"
    "  vec4 sampled = texture2D(tex, f_uv);\n"
    "  vec4 sampled_color = vec4(0.0, 0.0, 0.0, 0.0);\n"
    "  vec4 vertex_color = f_color;\n"
    "  vec4 blend = vec4(1.0, 1.0, 1.0, 1.0);\n"
    "  \n"
    "  if (tex_mode == 0)\n"
    "    sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);\n"
    "  else if (tex_mode == 1)\n"
    "    sampled_color = vec4(sampled.r, sampled.g, sampled.b, sampled.a);\n"
    "  else if (tex_mode == 2)\n"
    "  {\n"
    "    float transparency = sampled.a;\n"
    "    if (sampled.r == 1.0 && sampled.g == 0.0 && sampled.b == 1.0)\n"
    "      transparency = 0.0;\n"
    "    sampled_color = vec4(sampled.b, sampled.g, sampled.r, transparency);\n"
    "  }\n"
    "  else if (tex_mode == 3)\n"
    "  {\n"
    "    sampled_color = vec4(1.0, 1.0, 1.0, 1.0);\n"
    "  }\n"
    "  \n"
    "  if (blend_mode == 5)\n"
    "  {\n"
    "    blend = vec4(1.0, 1.0, 1.0, 1.0);\n"
    "    if (sampled_color.a < 0.1)\n"
    "      discard;\n"
    "  }\n"
    "  gl_FragColor = sampled_color * vertex_color * blend;\n"
    "}";

    const char* gl_vert = 
    "attribute vec3 coord3d;\n"
    "attribute vec4 v_color;\n"
    "attribute vec2 v_uv;\n"
    "uniform mat4 mvp;\n"
    "varying vec4 f_color;\n"
    "varying vec2 f_uv;\n"
    "varying vec3 f_coord;\n"
    "void main(void) {\n"
    "  vec4 pos = mvp * vec4(coord3d, 1.0);\n"
    "  pos.w = 1/coord3d.z;\n"
    "  pos.xyz *= pos.w;\n"
    "  gl_Position = pos;\n"
    "  f_color = v_color;\n"
    "  f_uv = v_uv;\n"
    "  f_coord = coord3d;\n"
    "}";

	void generateFramebuffer(GLuint* fbOut, GLuint* fbTexOut, GLuint* fbRboOut);
	void deleteFramebuffer(GLuint fbIn, GLuint fbTexIn, GLuint fbRboIn);

public:

    bool has_initted = false;
    D3DVIEWPORT view;
    GLuint fb;
    GLuint fbTex;
    GLuint fbRbo;
    
    GLuint fb1;
    GLuint fbTex1;
    GLuint fbRbo1;
    
    GLuint fb2;
    GLuint fbTex2;
    GLuint fbRbo2;
    
    void* last_overlay = NULL;
    
    int activeFb;

	void swap_framebuffers();
    bool init_resources();
    void free_resources();

    void logic();
    void render(SDL_Window* window);
    
    void renderOverlay()
    {
        GLuint vbo_vertices, vbo_colors, vbo_uvs;
        GLuint ibo_triangles;
        GLfloat data_vertices[4 * 3 * sizeof(GLfloat)];
        GLfloat data_colors[4 * 3 * sizeof(GLfloat)];
        GLfloat data_uvs[4 * 2 * sizeof(GLfloat)];
        
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        glDepthFunc(GL_ALWAYS);
        
        // Set texture
        glActiveTexture(GL_TEXTURE0);
        //glBindTexture(GL_TEXTURE_2D, texid);
        
        struct ddsurface_ext* primary = idirectdraw4->primary_surface;
        //printf("overlay?\n");
        if (!primary->alloc)
            return;

        int w_int = primary->desc.dwWidth;
        int h_int = primary->desc.dwHeight;
        float w = (float)w_int;
        float h = (float)h_int;
        
        SDL_Surface* surface = NULL;
        SDL_Texture* texture = NULL;

        if (!primary->desc.ddpfPixelFormat.dwRGBBitCount
            ||primary->desc.ddpfPixelFormat.dwRGBBitCount == 8)
        {
            //printf("overlaying 8bpp\n");
            surface = SDL_CreateRGBSurface(0, w_int, h_int, 8, 0,0,0,0);
            memcpy(surface->pixels, vm_ptr_to_real_ptr(primary->alloc), w_int*h_int);
            memset(vm_ptr_to_real_ptr(primary->alloc), 0, w_int*h_int);
            
            SDL_Color* palette = NULL;
            //TODO: ehhhh
            if (primary->palette != (uint32_t)-1)
                palette = idirectdraw4->palettes[primary->palette];
            else
                palette = gdi32->getDefaultPal();

            if (palette)
                SDL_SetPaletteColors(surface->format->palette, palette, 0, 256);
            texture = SDL_CreateTextureFromSurface(displayRenderer, surface);

            SDL_GL_BindTexture(texture, NULL, NULL);
            glUniform1i(uniform_tex_mode, TEX_MODE_RGB);
            glUniform1i(uniform_blend_mode, D3DBLEND_ONE);
        }
        else
        {
            //printf("overlaying 16bpp\n");
            bool newtex = false;
            if (!primary->handle)
            {
                GLuint id;
                glGenTextures(1, &id);
                primary->handle = id;
                newtex = true;
            }

            glBindTexture(GL_TEXTURE_2D, primary->handle);
            glPixelStorei(GL_UNPACK_ROW_LENGTH, primary->locked_desc.dwWidth);
            
            bool has_alpha = false;
            
            // These textures are actually BGRA usually.
            // However, BGR565 is invalid for some reason, so we just swap colors
            // in the shader.
            //printf("overlay %x\n", primary->locked_desc.ddpfPixelFormat.dwRBitMask);
            int format_order = GL_RGB;
            int format = GL_UNSIGNED_SHORT_5_6_5_REV;
            if (primary->locked_desc.ddpfPixelFormat.dwRBitMask == 0x7C00)
            {
                format = GL_UNSIGNED_SHORT_1_5_5_5_REV;
                format_order = GL_RGBA;
                has_alpha = true;
            }
            else if (primary->locked_desc.ddpfPixelFormat.dwRBitMask == 0xF00)
            {
                has_alpha = true;
                format = GL_UNSIGNED_SHORT_4_4_4_4_REV;
                format_order = GL_RGBA;
            }
            else if (primary->locked_desc.ddpfPixelFormat.dwRBitMask == 0xF800)
            {
                format = GL_UNSIGNED_SHORT_5_6_5_REV;
                format_order = GL_RGB;
                has_alpha = false;
            }
            else
            {
                //printf("IDirect3DTexture::GetHandle Unknown texture format? Rbitmask %x\n", primary->locked_desc.ddpfPixelFormat.dwRBitMask);
            }
            
            bool needs_update = false;
            if (last_overlay)
            {
                if (memcmp(last_overlay, vm_ptr_to_real_ptr(primary->alloc), w_int*h_int*sizeof(uint16_t)))
                    needs_update = true;
            }
            else
            {
                last_overlay = malloc(w_int*h_int*sizeof(uint16_t));
            }
            if (last_overlay)
                memcpy(last_overlay, vm_ptr_to_real_ptr(primary->alloc), w_int*h_int*sizeof(uint16_t));

            if (newtex)
            {
                glTexImage2D(GL_TEXTURE_2D,
                         0, 
                         has_alpha ? GL_RGBA : GL_RGB,
                         (GLsizei)primary->locked_desc.dwWidth, 
                         (GLsizei)primary->locked_desc.dwHeight,
                         0, 
                         format_order,
                         format,
                         vm_ptr_to_real_ptr(primary->alloc));
            }
            else if (needs_update)
            {
                glTexSubImage2D(GL_TEXTURE_2D,
                         0,
                         0,
                         0, 
                         (GLsizei)primary->locked_desc.dwWidth, 
                         (GLsizei)primary->locked_desc.dwHeight,
                         format_order,
                         format,
                         vm_ptr_to_real_ptr(primary->alloc));
            }

            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
            glUniform1i(uniform_tex_mode, TEX_MODE_BGR_WHITETRANSPARENCY);
            glUniform1i(uniform_blend_mode, D3DBLEND_ONE);
            
            
            if (format == GL_UNSIGNED_SHORT_1_5_5_5_REV)
            {
                uint16_t transparent = 0x3C0F;
                uint16_t* pixels = (uint16_t*)vm_ptr_to_real_ptr(primary->alloc);
                for (uint32_t i = 0; i < primary->locked_desc.dwWidth*primary->locked_desc.dwHeight; i++)
                {
                    pixels[i] = transparent;
                }
            }
            else if (format == GL_UNSIGNED_SHORT_4_4_4_4_REV)
            {
                uint16_t transparent = 0xF0F;
                uint16_t* pixels = (uint16_t*)vm_ptr_to_real_ptr(primary->alloc);
                for (uint32_t i = 0; i < primary->locked_desc.dwWidth*primary->locked_desc.dwHeight; i++)
                {
                    pixels[i] = transparent;
                }
            }
            else if (format == GL_UNSIGNED_SHORT_5_6_5_REV)
            {
                uint16_t transparent = 0xF81F;
                uint16_t* pixels = (uint16_t*)vm_ptr_to_real_ptr(primary->alloc);
                for (uint32_t i = 0; i < primary->locked_desc.dwWidth*primary->locked_desc.dwHeight; i++)
                {
                    pixels[i] = transparent;
                }
            }
        }
        glUniform1i(uniform_tex, 0);
        
        
        // Top-left
        data_vertices[0 * 3 + 0] = 0.0f;
        data_vertices[0 * 3 + 1] = 0.0f;
        data_vertices[0 * 3 + 2] = 1.0f;
        data_colors[0 * 3 + 0] = 1.0f;
        data_colors[0 * 3 + 1] = 1.0f;
        data_colors[0 * 3 + 2] = 1.0f;
        data_uvs[0 * 2 + 0] = 0.0f;
        data_uvs[0 * 2 + 1] = 0.0f;
        
        //Bottom-left
        data_vertices[1 * 3 + 0] = 0.0f;
        data_vertices[1 * 3 + 1] = h;
        data_vertices[1 * 3 + 2] = 1.0f;
        data_colors[1 * 3 + 0] = 1.0f;
        data_colors[1 * 3 + 1] = 1.0f;
        data_colors[1 * 3 + 2] = 1.0f;
        data_uvs[1 * 2 + 0] = 0.0f;
        data_uvs[1 * 2 + 1] = 1.0f;
        
        //Bottom-right
        data_vertices[2 * 3 + 0] = w;
        data_vertices[2 * 3 + 1] = h;
        data_vertices[2 * 3 + 2] = 1.0f;
        data_colors[2 * 3 + 0] = 1.0f;
        data_colors[2 * 3 + 1] = 1.0f;
        data_colors[2 * 3 + 2] = 1.0f;
        data_uvs[2 * 2 + 0] = 1.0f;
        data_uvs[2 * 2 + 1] = 1.0f;
        
        //Top-right
        data_vertices[3 * 3 + 0] = w;
        data_vertices[3 * 3 + 1] = 0.0f;
        data_vertices[3 * 3 + 2] = 1.0f;
        data_colors[3 * 3 + 0] = 1.0f;
        data_colors[3 * 3 + 1] = 1.0f;
        data_colors[3 * 3 + 2] = 1.0f;
        data_uvs[3 * 2 + 0] = 1.0f;
        data_uvs[3 * 2 + 1] = 0.0f;
        
        glGenBuffers(1, &vbo_vertices);
        glBindBuffer(GL_ARRAY_BUFFER, vbo_vertices);
        glBufferData(GL_ARRAY_BUFFER, 4 * 3 * sizeof(GLfloat), data_vertices, GL_STATIC_DRAW);
        
        glGenBuffers(1, &vbo_colors);
        glBindBuffer(GL_ARRAY_BUFFER, vbo_colors);
        glBufferData(GL_ARRAY_BUFFER, 4 * 3 * sizeof(GLfloat), data_colors, GL_STATIC_DRAW);
        
        glGenBuffers(1, &vbo_uvs);
        glBindBuffer(GL_ARRAY_BUFFER, vbo_uvs);
        glBufferData(GL_ARRAY_BUFFER, 4 * 2 * sizeof(GLfloat), data_uvs, GL_STATIC_DRAW);
        
        glUseProgram(program);
        glEnableVertexAttribArray(attribute_coord3d);
        glEnableVertexAttribArray(attribute_v_color);
        glEnableVertexAttribArray(attribute_v_uv);
        
        // Describe our vertices array to OpenGL (it can't guess its format automatically)
        glBindBuffer(GL_ARRAY_BUFFER, vbo_vertices);
        glVertexAttribPointer(
            attribute_coord3d, // attribute
            3,                 // number of elements per vertex, here (x,y,z)
            GL_FLOAT,          // the type of each element
            GL_FALSE,          // take our values as-is
            0,                 // no extra data between each position
            0                  // offset of first element
        );
        
        
        glBindBuffer(GL_ARRAY_BUFFER, vbo_colors);
        glVertexAttribPointer(
            attribute_v_color, // attribute
            3,                 // number of elements per vertex, here (R,G,B)
            GL_FLOAT,          // the type of each element
            GL_FALSE,          // take our values as-is
            0,                 // no extra data between each position
            0                  // offset of first element
        );
        
        
        glBindBuffer(GL_ARRAY_BUFFER, vbo_uvs);
        glVertexAttribPointer(
            attribute_v_uv,    // attribute
            2,                 // number of elements per vertex, here (U,V)
            GL_FLOAT,          // the type of each element
            GL_FALSE,          // take our values as-is
            0,                 // no extra data between each position
            0                  // offset of first element
        );

        GLushort data_elements[1 * 4];
        data_elements[0 * 4 + 0] = 0;
        data_elements[0 * 4 + 1] = 1;
        data_elements[0 * 4 + 2] = 3;
        data_elements[0 * 4 + 3] = 2;
    
        glGenBuffers(1, &ibo_triangles);
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ibo_triangles);
        glBufferData(GL_ELEMENT_ARRAY_BUFFER, 1 * 4 * sizeof(GLushort), data_elements, GL_STATIC_DRAW);

        int tris_size;  
        glGetBufferParameteriv(GL_ELEMENT_ARRAY_BUFFER, GL_BUFFER_SIZE, &tris_size);
        glDrawElements(GL_TRIANGLE_STRIP, tris_size / sizeof(GLushort), GL_UNSIGNED_SHORT, 0);

        glDisableVertexAttribArray(attribute_v_uv);
        glDisableVertexAttribArray(attribute_v_color);
        glDisableVertexAttribArray(attribute_coord3d);

        glDeleteBuffers(1, &ibo_triangles);
        glDeleteBuffers(1, &vbo_vertices);
        glDeleteBuffers(1, &vbo_colors);
        glDeleteBuffers(1, &vbo_uvs);
        
        if (texture)
            SDL_DestroyTexture(texture);
        if (surface)
            SDL_FreeSurface(surface);
    }

    Q_INVOKABLE IDirect3DExecuteBuffer() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3DExecuteBuffer::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3DExecuteBuffer::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3DExecuteBuffer::Release\n");
        
        if (locked_objs[real_ptr_to_vm_ptr(this_ptr)])
        {
            kernel32->VirtualFree(locked_objs[real_ptr_to_vm_ptr(this_ptr)], 0, 0);
            locked_objs[real_ptr_to_vm_ptr(this_ptr)] = 0;
        }
        
        free(last_overlay);
        last_overlay = NULL;
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DExecuteBuffer methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t Lock(void* this_ptr, D3DEXECUTEBUFFERDESC* desc);
    Q_INVOKABLE uint32_t Unlock(void* this_ptr);
    Q_INVOKABLE uint32_t SetExecuteData(void* this_ptr, D3DEXECUTEDATA* desc);
    Q_INVOKABLE uint32_t GetExecuteData(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t Validate(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t Optimize(void* this_ptr, uint32_t a);


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DExecuteBuffer* idirect3dexecutebuffer;

#endif // IDIRECT3DEXECUTEBUFFER_H
