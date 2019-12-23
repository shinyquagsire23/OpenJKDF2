
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

enum D3DOPCODE {
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

struct D3DVERTEX
{
    float x;
    float y;
    float z;
    float nx;
    float ny;
    float nz;
    float tu;
    float tv;
};

struct D3DTRIANGLE
{
    uint16_t v1;
    uint16_t v2;
    uint16_t v3;
    uint16_t flags;
};

struct D3DINSTRUCTION
{
    uint8_t bOpcode;
    uint8_t bSize;
    uint16_t wCount;
};

struct D3DRECT
{
    uint32_t x1;
    uint32_t y1;
    uint32_t x2;
    uint32_t y2;
};

typedef struct D3DSTATUS {
  uint32_t dwFlags;
  uint32_t dwStatus;
  struct D3DRECT drExtent;
};

struct D3DEXECUTEBUFFERDESC
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwCaps;
    uint32_t dwBufferSize;
    uint32_t lpData;
};

struct D3DEXECUTEDATA {
  uint32_t dwSize;
  uint32_t dwVertexOffset;
  uint32_t dwVertexCount;
  uint32_t dwInstructionOffset;
  uint32_t dwInstructionLength;
  uint32_t dwHVertexOffset;
  struct D3DSTATUS dsStatus;
};

#define TEX_MODE_BGR 0
#define TEX_MODE_RGB 1

class IDirect3DExecuteBuffer : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint32_t> locked_objs;

    GLuint program;
    GLint attribute_coord3d, attribute_v_color, attribute_v_uv;
    GLint uniform_mvp, uniform_tex, uniform_tex_mode;

    const char* gl_frag = 
    "uniform sampler2D tex;\n"
    "uniform int tex_mode;\n"
    "varying vec3 f_color;\n"
    "varying vec2 f_uv;\n"
    "varying vec3 f_coord;\n"
    "void main(void) {\n"
    "  vec4 sampled = texture2D(tex, f_uv);\n"
    "  if (tex_mode == 0)\n"
    "    gl_FragColor = vec4(sampled.b, sampled.g, sampled.r, sampled.a) * vec4(f_color.r, f_color.g, f_color.b, 1.0);\n"
    "  else if (tex_mode == 1)\n"
    "    gl_FragColor = vec4(sampled.r, sampled.g, sampled.b, sampled.a) * vec4(f_color.r, f_color.g, f_color.b, 1.0);\n"
    "}";

    const char* gl_vert = 
    "attribute vec3 coord3d;\n"
    "attribute vec3 v_color;\n"
    "attribute vec2 v_uv;\n"
    "uniform mat4 mvp;\n"
    "varying vec3 f_color;\n"
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

public:

    bool has_initted = false;
    D3DVIEWPORT view;
    GLuint fb;
    GLuint fbTex;
    GLuint fbRbo;

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
        
        // Set texture
        glActiveTexture(GL_TEXTURE0);
        //glBindTexture(GL_TEXTURE_2D, texid);
        
        struct ddsurface_ext* primary = idirectdraw4->primary_surface;
        if (!primary->alloc)
            return;

        int w_int = primary->desc.dwWidth;
        int h_int = primary->desc.dwHeight;
        float w = (float)w_int;
        float h = (float)h_int;

        SDL_Surface *surface = SDL_CreateRGBSurface(0, w_int, h_int, 8, 0,0,0,0);
        memcpy(surface->pixels, vm_ptr_to_real_ptr(primary->alloc), w_int*h_int);
        memset(surface->pixels, 0xFF, w_int*h_int);
        memset(vm_ptr_to_real_ptr(primary->alloc), 0, w_int*h_int);
        SDL_SetPaletteColors(surface->format->palette, idirectdraw4->palettes[primary->palette], 0, 256);
        SDL_Texture* texture = SDL_CreateTextureFromSurface(displayRenderer, surface);

        SDL_GL_BindTexture(texture, NULL, NULL);
        glUniform1i(uniform_tex, 0);
        glUniform1i(uniform_tex_mode, TEX_MODE_RGB);
        
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
        
        SDL_DestroyTexture(texture);
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
        
        
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DExecuteBuffer methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t Lock(void* this_ptr, struct D3DEXECUTEBUFFERDESC* desc);
    Q_INVOKABLE uint32_t Unlock(void* this_ptr);
    Q_INVOKABLE uint32_t SetExecuteData(void* this_ptr, struct D3DEXECUTEDATA* desc);
    Q_INVOKABLE uint32_t GetExecuteData(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t Validate(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t Optimize(void* this_ptr, uint32_t a);


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DExecuteBuffer* idirect3dexecutebuffer;

#endif // IDIRECT3DEXECUTEBUFFER_H
