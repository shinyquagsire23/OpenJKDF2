
#ifndef IDIRECT3DEXECUTEBUFFER_H
#define IDIRECT3DEXECUTEBUFFER_H

#include <QObject>
#include <cmath>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/gdi32.h"
#include "dlls/winutils.h"
#include "main.h"

#include "dlls/ddraw/IDirect3D3.h"

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

class IDirect3DExecuteBuffer : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint32_t> locked_objs;

    GLuint program;
    GLint attribute_coord3d, attribute_v_color, attribute_v_uv;
    GLint uniform_mvp, uniform_tex;

    const char* gl_frag = 
    "uniform sampler2D tex;\n"
    "varying vec3 f_color;\n"
    "varying vec2 f_uv;\n"
    "varying vec3 f_coord;\n"
    "void main(void) {\n"
    "  vec4 sampled = texture2D(tex, f_uv);\n"
    "  float transparency = 1.0;\n"
    "  if (sampled.a < 1.0) {\n"
    "    transparency = sampled.a;\n"
    "  }\n"
    "  gl_FragColor = vec4(sampled.r, sampled.g, sampled.b, sampled.a) * vec4(f_color.r, f_color.g, f_color.b, 1.0);\n"
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

    bool init_resources() 
    {
        if (has_initted) return true;
	    GLint link_ok = GL_FALSE;
	    
	    GLuint vs, fs;
	    if ((vs = create_shader(gl_vert, GL_VERTEX_SHADER))   == 0) return false;
	    if ((fs = create_shader(gl_frag, GL_FRAGMENT_SHADER)) == 0) return false;
	    
	    program = glCreateProgram();
	    glAttachShader(program, vs);
	    glAttachShader(program, fs);
	    glLinkProgram(program);
	    glGetProgramiv(program, GL_LINK_STATUS, &link_ok);
	    if (!link_ok) 
	    {
		    print_log(program);
		    return false;
	    }
	    
	    const char* attribute_name;
	    attribute_name = "coord3d";
	    attribute_coord3d = glGetAttribLocation(program, attribute_name);
	    if (attribute_coord3d == -1) {
	        printf("Could not bind attribute %s!\n", attribute_name);
		    return false;
	    }

	    attribute_name = "v_color";
	    attribute_v_color = glGetAttribLocation(program, attribute_name);
	    if (attribute_v_color == -1) 
	    {
		    printf("Could not bind attribute %s!\n", attribute_name);
		    return false;
	    }
	    
	    attribute_name = "v_uv";
	    attribute_v_uv = glGetAttribLocation(program, attribute_name);
	    if (attribute_v_uv == -1) 
	    {
		    printf("Could not bind attribute %s!\n", attribute_name);
		    return false;
	    }

	    const char* uniform_name;
	    uniform_name = "mvp";
	    uniform_mvp = glGetUniformLocation(program, uniform_name);
	    if (uniform_mvp == -1) 
	    {
		    printf("Could not bind attribute %s!\n", attribute_name);
		    return false;
	    }
	    
	    uniform_name = "tex";
	    uniform_tex = glGetUniformLocation(program, uniform_name);
	    if (uniform_tex == -1) 
	    {
		    printf("Could not bind attribute %s!\n", attribute_name);
		    return false;
	    }
	    
	    glEnable(GL_BLEND);
	    glEnable(GL_DEPTH_TEST);
	    glDepthFunc(GL_LESS);
	    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	    
	    has_initted = true;
	    
	    return true;
    }

    void logic() 
    {
        //TODO: camera freelook stuff, maybe
        glm::mat4 viewmat;
	    glm::mat4 glmmodel = glm::translate(glm::mat4(1.0f), glm::vec3(0.0, 0.0, 0.0));
	    glm::mat4 glmview = glm::lookAt(glm::vec3(-1.0, 0.5, 0.5), glm::vec3(-1.0, 0.5, -4.0), glm::vec3(0.0, -1.0, 0.0));
	    glm::mat4 glmprojection = glm::perspectiveFov(90.0f, (float)1, (float)1, 0.1f, 1000.0f);

        float d3dmat[16] = {
           view.dvMaxX*1/(float)view.dvScaleX,      0,                                          0,      0, // right
           0,                                       -view.dvMaxY*1/view.dvScaleY,               0,      0, // up
           0,                                       0,                                          -1,     0, // forward
           -((float)view.dwWidth/2)/view.dvScaleX,  ((float)view.dwHeight/2)/view.dvScaleY,     1,      1  // pos
        };

        memcpy(glm::value_ptr(viewmat), d3dmat, sizeof(d3dmat));
	    
	    glm::mat4 mvp = viewmat; // glmprojection * glmview * glmmodel;
	    
	    glUseProgram(program);
	    glUniformMatrix4fv(uniform_mvp, 1, GL_FALSE, glm::value_ptr(mvp));
	    glViewport(0, 0, view.dwWidth, view.dwHeight);
    }

    void render(SDL_Window* window) 
    {
	    glUseProgram(program);
    }

    void free_resources() 
    {
	    glDeleteProgram(program);
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
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Initialize\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Lock(void* this_ptr, struct D3DEXECUTEBUFFERDESC* desc)
    {
        if (locked_objs[real_ptr_to_vm_ptr(this_ptr)])
        {
            kernel32->VirtualFree(locked_objs[real_ptr_to_vm_ptr(this_ptr)], 0, 0);
            locked_objs[real_ptr_to_vm_ptr(this_ptr)] = 0;
        }

        desc->lpData = kernel32->VirtualAlloc(0, 0x10000, 0, 0);
        locked_objs[real_ptr_to_vm_ptr(this_ptr)] = desc->lpData;

        return 0;
    }

    Q_INVOKABLE uint32_t Unlock(void* this_ptr)
    {
        return 0;
    }

    Q_INVOKABLE uint32_t SetExecuteData(void* this_ptr, struct D3DEXECUTEDATA* desc)
    {
        //TODO: wait for Execute
        //printf("execute offset %x, count %x,  instr offset %x, instr count %x, hvertex offset %x\n", desc->dwVertexOffset, desc->dwVertexCount, desc->dwInstructionOffset, desc->dwInstructionLength, desc->dwHVertexOffset);

        // Generate vertices list
        GLuint vbo_vertices, vbo_colors, vbo_uvs;
        GLuint ibo_triangle;
        GLfloat* data_vertices = (GLfloat*)malloc(desc->dwVertexCount * 3 * sizeof(GLfloat));
        GLfloat* data_colors = (GLfloat*)malloc(desc->dwVertexCount * 3 * sizeof(GLfloat));
        GLfloat* data_uvs = (GLfloat*)malloc(desc->dwVertexCount * 2 * sizeof(GLfloat));

        struct D3DVERTEX* vertexes = (struct D3DVERTEX*)vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)] + desc->dwVertexOffset);

        for (int i = 0; i < desc->dwVertexCount; i++)
        {
            /*printf("%f %f %f, %f %f %f, %f %f\n", vertexes[i].x, vertexes[i].y, vertexes[i].z,
                                                  vertexes[i].nx, vertexes[i].ny, vertexes[i].nz,
                                                  vertexes[i].tu, vertexes[i].tv);*/
                                                  
            data_vertices[(i*3)+0] = vertexes[i].x;
            data_vertices[(i*3)+1] = vertexes[i].y;
            data_vertices[(i*3)+2] = vertexes[i].z;
            data_colors[(i*3)+0] = 1.0f;
            data_colors[(i*3)+1] = 1.0f;
            data_colors[(i*3)+2] = 1.0f;
            
            data_uvs[(i*2)+0] = vertexes[i].tu;
            data_uvs[(i*2)+1] = vertexes[i].tv;
        }
        
        glGenBuffers(1, &vbo_vertices);
	    glBindBuffer(GL_ARRAY_BUFFER, vbo_vertices);
	    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 3 * sizeof(GLfloat), data_vertices, GL_STATIC_DRAW);
	    
	    
	    glGenBuffers(1, &vbo_colors);
	    glBindBuffer(GL_ARRAY_BUFFER, vbo_colors);
	    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 3 * sizeof(GLfloat), data_colors, GL_STATIC_DRAW);
	    
	    glGenBuffers(1, &vbo_uvs);
	    glBindBuffer(GL_ARRAY_BUFFER, vbo_uvs);
	    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 2 * sizeof(GLfloat), data_uvs, GL_STATIC_DRAW);
	    
	    
        logic();
        
        int offset = desc->dwInstructionOffset;
        for (int i = 0; i < desc->dwInstructionLength; i++)
        {
            struct D3DINSTRUCTION* instr = (struct D3DINSTRUCTION*)vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)] + offset);
            
            //printf("instr opcode %x, size %x, count %x\n", instr->bOpcode, instr->bSize, instr->wCount);
            
            offset += sizeof(D3DINSTRUCTION);
            void* opData = vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)] + offset);
            
            if (instr->bOpcode == D3DOP_EXIT) break;
            else if (instr->bOpcode == D3DOP_TRIANGLE)
            {
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
            
                GLushort* data_elements = new GLushort[instr->wCount * 3];
                struct D3DTRIANGLE* tris = (struct D3DTRIANGLE*)opData;
                for (int j = 0; j < instr->wCount; j++)
                {
                    //printf("tri %u,%u,%u, flags %x\n", tris[j].v1, tris[j].v2, tris[j].v3, tris[j].flags);
                    data_elements[(j*3)+0] = tris[j].v1;
                    data_elements[(j*3)+1] = tris[j].v2;
                    data_elements[(j*3)+2] = tris[j].v3;
                    
                    /*int vert = tris[j].v1;
                    printf("%u: %f %f %f, %f %f %f, %f %f\n", vert, vertexes[vert].x, vertexes[vert].y, vertexes[vert].z,
                                                  vertexes[vert].nx, vertexes[vert].ny, vertexes[vert].nz,
                                                  vertexes[vert].tu, vertexes[vert].tv);
                    
                    vert = tris[j].v2;
                    printf("%u: %f %f %f, %f %f %f, %f %f\n", vert, vertexes[vert].x, vertexes[vert].y, vertexes[vert].z,
                                                  vertexes[vert].nx, vertexes[vert].ny, vertexes[vert].nz,
                                                  vertexes[vert].tu, vertexes[vert].tv);
                    
                    vert = tris[j].v3;
                    printf("%u: %f %f %f, %f %f %f, %f %f\n", vert, vertexes[vert].x, vertexes[vert].y, vertexes[vert].z,
                                                  vertexes[vert].nx, vertexes[vert].ny, vertexes[vert].nz,
                                                  vertexes[vert].tu, vertexes[vert].tv);*/
                }
                
                
	            glGenBuffers(1, &ibo_triangle);
	            glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ibo_triangle);
	            glBufferData(GL_ELEMENT_ARRAY_BUFFER, instr->wCount * 3 * sizeof(GLushort), data_elements, GL_STATIC_DRAW);

	            int tris_size;  
	            glGetBufferParameteriv(GL_ELEMENT_ARRAY_BUFFER, GL_BUFFER_SIZE, &tris_size);
	            glDrawElements(GL_TRIANGLES, tris_size / sizeof(GLushort), GL_UNSIGNED_SHORT, 0);

	            glDisableVertexAttribArray(attribute_v_uv);
	            glDisableVertexAttribArray(attribute_v_color);
	            glDisableVertexAttribArray(attribute_coord3d);
	            glDeleteBuffers(1, &ibo_triangle);
	            delete data_elements;
                
            }
            else if (instr->bOpcode == D3DOP_PROCESSVERTICES)
            {
                //idk on this one
            }
            else if (instr->bOpcode == D3DOP_STATERENDER)
            {
                uint32_t renderOp = *(uint32_t*)(opData+0);
                uint32_t renderArg = *(uint32_t*)(opData+4);
                //printf("op %u arg %u\n", renderOp, renderArg);
                
                if (renderOp == 1) // Texture
                {
                    //printf("texture %x\n", renderArg);
                    
                    glActiveTexture(GL_TEXTURE0);
                    glBindTexture(GL_TEXTURE_2D, renderArg);
                    glUniform1i(uniform_tex, 0);
                }
                else if (renderOp == 23)
                {
                    //printf("zfunc %x\n", renderArg);
                    /*
                    D3DCMP_NEVER               = 1,
                    D3DCMP_LESS                = 2,
                    D3DCMP_EQUAL               = 3,
                    D3DCMP_LESSEQUAL           = 4,
                    D3DCMP_GREATER             = 5,
                    D3DCMP_NOTEQUAL            = 6,
                    D3DCMP_GREATEREQUAL        = 7,
                    D3DCMP_ALWAYS              = 8,
                    */
                }
            }
            
            offset += instr->bSize * instr->wCount;
        }
	    
	    glDeleteBuffers(1, &vbo_vertices);
	    glDeleteBuffers(1, &vbo_colors);
	    glDeleteBuffers(1, &vbo_uvs);
        free(data_vertices);
        free(data_colors);	
        free(data_uvs);    

		//render(displayWindow);
		
		glBindTexture(GL_TEXTURE_2D, 0);

        return 0;
    }

    Q_INVOKABLE uint32_t GetExecuteData(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DExecuteBuffer::GetExecuteData\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Validate(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Validate\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Optimize(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Optimize\n");

        return 0;
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DExecuteBuffer* idirect3dexecutebuffer;

#endif // IDIRECT3DEXECUTEBUFFER_H
