#include "std3D.h"

#include "Engine/rdCache.h"
#include "Win95/stdDisplay.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"

#ifdef LINUX
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "Linux/shader_utils.h"
#include <SDL2/SDL.h>
#include <GL/gl.h>

#define TEX_MODE_BGR 0
#define TEX_MODE_RGB 1
#define TEX_MODE_BGR_WHITETRANSPARENCY 2
#define TEX_MODE_TEST 3
#define TEX_MODE_WORLDPAL 4

static bool has_initted = false;
static GLuint fb;
static GLuint fbTex;
static GLuint fbRbo;

static GLuint fb1;
static GLuint fbTex1;
static GLuint fbRbo1;

static GLuint fb2;
static GLuint fbTex2;
static GLuint fbRbo2;

static void* last_overlay = NULL;

static int activeFb;

int init_once = 0;
GLuint program;
GLint attribute_coord3d, attribute_v_color, attribute_v_uv, attribute_v_norm;
GLint uniform_mvp, uniform_tex, uniform_tex_mode, uniform_blend_mode, uniform_worldPalette;
GLuint worldpal_texture;
void* worldpal_data;

const char* gl_frag = 
"uniform sampler2D tex;\n"
"uniform sampler1D worldPalette;\n"
"uniform int tex_mode;\n"
"uniform int blend_mode;\n"
"varying vec4 f_color;\n"
"varying vec2 f_uv;\n"
"varying vec3 f_coord;\n"
"void main(void) {\n"
"  vec4 sampled = texture2D(tex, f_uv);\n"
"  vec4 sampled_color = vec4(0.0, 0.0, 0.0, 0.0);\n"
"  vec4 vertex_color = f_color;\n"
"  float index = sampled.r;\n"
"  vec4 palval = texture1D(worldPalette, index);\n"
"  vec4 blend = vec4(1.0, 1.0, 1.0, 1.0);\n"
"  \n"
"  if (tex_mode == 0)\n"
"  {\n"
"    sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);\n"
"  }\n"
"  else if (tex_mode == 1)\n"
"  {\n"
"    sampled_color = vec4(sampled.r, sampled.g, sampled.b, sampled.a);\n"
"  }\n"
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
"  else if (tex_mode == 4)\n"
"  {\n"
"      sampled_color = vec4(palval.r, palval.g, palval.b, 1.0);\n"
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
"  pos.w = 1/(1.0-coord3d.z);\n"
"  pos.xyz *= pos.w;\n"
"  gl_Position = pos;\n"
"  f_color = v_color;\n"
"  f_uv = v_uv;\n"
"  f_coord = coord3d;\n"
"}";

static rdTri GL_tmpTris[4096];
static size_t GL_tmpTrisAmt = 0;
static D3DVERTEX GL_tmpVertices[4096];
static size_t GL_tmpVerticesAmt = 0;

void generateFramebuffer(GLuint* fbOut, GLuint* fbTexOut, GLuint* fbRboOut)
{
	// Generate the framebuffer
    *fbOut = 0;
    glGenFramebuffers(1, fbOut);
    glBindFramebuffer(GL_FRAMEBUFFER, *fbOut);
    
    // Set up our framebuffer texture
    glGenTextures(1, fbTexOut);
    glBindTexture(GL_TEXTURE_2D, *fbTexOut);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 640, 480, 0, GL_RGB, GL_UNSIGNED_BYTE, NULL);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);
    
    // Attach fbTex to our currently bound framebuffer fb
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, *fbTexOut, 0); 
    
    // Set up our render buffer
    glGenRenderbuffers(1, fbRboOut);
    glBindRenderbuffer(GL_RENDERBUFFER, *fbRboOut);
    glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH24_STENCIL8, 640, 480);
    glBindRenderbuffer(GL_RENDERBUFFER, 0);
    
    // Bind it to our framebuffer fb
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_RENDERBUFFER, *fbRboOut);
    if(glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
            printf("ERROR: Framebuffer is incomplete!\n");
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void deleteFramebuffer(GLuint fbIn, GLuint fbTexIn, GLuint fbRboIn)
{
	glDeleteFramebuffers(1, &fbIn);
	glDeleteTextures(1, &fbTexIn);
	glDeleteRenderbuffers(1, &fbRboIn);
}

void swap_framebuffers()
{
	if (activeFb == 2)
	{
		activeFb = 1;
		fb = fb1;
   		fbTex = fbTex1;
	    fbRbo = fbRbo1;
	}
	else
	{
		activeFb = 2;
		fb = fb2;
   		fbTex = fbTex2;
	    fbRbo = fbRbo2;
	}
}

int init_resources()
{
    printf("OpenGL init...\n");
    generateFramebuffer(&fb1, &fbTex1, &fbRbo1);
    generateFramebuffer(&fb2, &fbTex2, &fbRbo2);

    activeFb = 1;
    fb = fb1;
    fbTex = fbTex1;
    fbRbo = fbRbo1;
    
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
    
    // World palette
    glGenTextures(1, &worldpal_texture);
    worldpal_data = malloc(0x300);
    
    memcpy(worldpal_data, sithWorld_pCurWorld->colormaps->colors, 0x300);
    
    glBindTexture(GL_TEXTURE_1D, worldpal_texture);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    
    glTexImage1D(GL_TEXTURE_1D, 0, GL_RGB8, 256, 0, GL_RGB, GL_UNSIGNED_BYTE, worldpal_data);
    
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
        printf("Could not bind uniform %s!\n", uniform_name);
        return false;
    }
    
    uniform_name = "tex";
    uniform_tex = glGetUniformLocation(program, uniform_name);
    if (uniform_tex == -1) 
    {
        printf("Could not bind uniform %s!\n", uniform_name);
        return false;
    }
    
    uniform_name = "worldPalette";
    uniform_worldPalette = glGetUniformLocation(program, uniform_name);
    if (uniform_worldPalette == -1) 
    {
        printf("Could not bind uniform %s!\n", uniform_name);
        return false;
    }
    
    uniform_name = "tex_mode";
    uniform_tex_mode = glGetUniformLocation(program, uniform_name);
    if (uniform_tex_mode == -1) 
    {
        printf("Could not bind uniform %s!\n", uniform_name);
        return false;
    }
    
    uniform_name = "blend_mode";
    uniform_blend_mode = glGetUniformLocation(program, uniform_name);
    if (uniform_blend_mode == -1) 
    {
        printf("Could not bind uniform %s!\n", uniform_name);
        return false;
    }

    has_initted = true;
}

void free_resources()
{
    glDeleteProgram(program);
    deleteFramebuffer(fb1, fbTex1, fbRbo1);
    deleteFramebuffer(fb2, fbTex2, fbRbo2);
    glDeleteTextures(1, &worldpal_texture);
    free(worldpal_data);
    has_initted = false;
}

void logic()
{
    float maxX, maxY, scaleX, scaleY, width, height;
    
    scaleX = 1.0/320.0;
    scaleY = 1.0/240.0;
    maxX = 1.0;
    maxY = 1.0;
    width = 640.0;
    height = 480.0;
    
    float d3dmat[16] = {
       maxX*scaleX,      0,                                          0,      0, // right
       0,                                       -maxY*scaleY,               0,      0, // up
       0,                                       0,                                          1,     0, // forward
       -(width/2)*scaleX,  (height/2)*scaleY,     -1,      1  // pos
    };
    
    glUseProgram(program);
    glUniformMatrix4fv(uniform_mvp, 1, GL_FALSE, d3dmat);
    glViewport(0, 0, width, height);
}

int std3D_StartScene()
{
    //printf("Begin draw\n");
    if (!has_initted)
    {
        init_resources();
    }
    
    //glBindFramebuffer(GL_FRAMEBUFFER, idirect3dexecutebuffer->fb);
    glEnable(GL_BLEND);
	glEnable(GL_DEPTH_TEST);
	glDepthFunc(GL_LESS);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	    
	// Technically this should be from Clear2
	glClearColor(0.0, 0.0, 0.0, 1.0);
	glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
	
    return 1;
}

int std3D_EndScene()
{
    //printf("End draw\n");
    return 1;
}

void std3D_ResetRenderList()
{
    GL_tmpVerticesAmt = 0;
    GL_tmpTrisAmt = 0;
}

int std3D_RenderListVerticesFinish()
{
    return 1;
}

void std3D_DrawRenderList()
{
    /*GL_tmpVertices[0].x = 0.0;
    GL_tmpVertices[0].y = 0.0;
    GL_tmpVertices[0].z = 1.0;
    GL_tmpVertices[0].tu = 0.0;
    GL_tmpVertices[0].tv = 0.0;
    *(uint32_t*)&GL_tmpVertices[0].nx = 0;
    *(uint32_t*)&GL_tmpVertices[0].ny = 0xFF0000FF;
    *(uint32_t*)&GL_tmpVertices[0].nz = 0;
    
    GL_tmpVertices[1].x = 0.0;
    GL_tmpVertices[1].y = 480.0;
    GL_tmpVertices[1].z = 1.0;
    GL_tmpVertices[1].tu = 0.0;
    GL_tmpVertices[1].tv = 0.0;
    *(uint32_t*)&GL_tmpVertices[1].nx = 0;
    *(uint32_t*)&GL_tmpVertices[1].ny = 0xFF00FF00;
    *(uint32_t*)&GL_tmpVertices[1].nz = 0;
    
    GL_tmpVertices[2].x = 640.0;
    GL_tmpVertices[2].y = 480.0;
    GL_tmpVertices[2].z = 1.0;
    GL_tmpVertices[2].tu = 0.0;
    GL_tmpVertices[2].tv = 0.0;
    *(uint32_t*)&GL_tmpVertices[2].nx = 0;
    *(uint32_t*)&GL_tmpVertices[2].ny = 0xFFFF0000;
    *(uint32_t*)&GL_tmpVertices[2].nz = 0;
    
    GL_tmpTris[0].v1 = 1;
    GL_tmpTris[0].v2 = 0;
    GL_tmpTris[0].v3 = 2;
    
    GL_tmpVerticesAmt = 3;
    GL_tmpTrisAmt = 1;*/

    // Generate vertices list
    GLuint vbo_vertices, vbo_colors, vbo_uvs;
    GLuint ibo_triangle;
    GLfloat* data_vertices = (GLfloat*)malloc(GL_tmpVerticesAmt * 3 * sizeof(GLfloat));
    GLfloat* data_colors = (GLfloat*)malloc(GL_tmpVerticesAmt * 4 * sizeof(GLfloat));
    GLfloat* data_uvs = (GLfloat*)malloc(GL_tmpVerticesAmt * 2 * sizeof(GLfloat));
    GLfloat* data_norms = (GLfloat*)malloc(GL_tmpVerticesAmt * 3 * sizeof(GLfloat));

    D3DVERTEX* vertexes = GL_tmpVertices;

    for (int i = 0; i < GL_tmpVerticesAmt; i++)
    {
        uint32_t v_color = *(uint32_t*)&vertexes[i].ny;
        uint32_t v_unknx = *(uint32_t*)&vertexes[i].nx;
        uint32_t v_unknz = *(uint32_t*)&vertexes[i].nz;
        
        /*printf("%f %f %f, %x %x %x, %f %f\n", vertexes[i].x, vertexes[i].y, vertexes[i].z,
                                              v_unknx, v_color, v_unknz,
                                              vertexes[i].tu, vertexes[i].tv);*/
                                             
        
        uint8_t v_a = (v_color >> 24) & 0xFF;
        uint8_t v_r = (v_color >> 16) & 0xFF;
        uint8_t v_g = (v_color >> 8) & 0xFF;
        uint8_t v_b = v_color & 0xFF;
 
        data_vertices[(i*3)+0] = vertexes[i].x;
        data_vertices[(i*3)+1] = vertexes[i].y;
        data_vertices[(i*3)+2] = vertexes[i].z;
        data_colors[(i*4)+0] = (float)v_r / 255.0f;
        data_colors[(i*4)+1] = (float)v_g / 255.0f;
        data_colors[(i*4)+2] = (float)v_b / 255.0f;
        data_colors[(i*4)+3] = (float)v_a / 255.0f;
        
        data_uvs[(i*2)+0] = vertexes[i].tu;
        data_uvs[(i*2)+1] = vertexes[i].tv;
        
        data_norms[(i*3)+0] = vertexes[i].nx;
        data_norms[(i*3)+1] = vertexes[i].ny;
        data_norms[(i*3)+2] = vertexes[i].nz;
        //printf("nx, ny, nz %x %x %x, %f %f, %f\n", v_unknx, v_color, v_unknz, vertexes[i].nx, vertexes[i].nz, vertexes[i].z);
    }
    
    glGenBuffers(1, &vbo_vertices);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_vertices);
    glBufferData(GL_ARRAY_BUFFER, GL_tmpVerticesAmt * 3 * sizeof(GLfloat), data_vertices, GL_STATIC_DRAW);
    
    
    glGenBuffers(1, &vbo_colors);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_colors);
    glBufferData(GL_ARRAY_BUFFER, GL_tmpVerticesAmt * 4 * sizeof(GLfloat), data_colors, GL_STATIC_DRAW);
    
    glGenBuffers(1, &vbo_uvs);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_uvs);
    glBufferData(GL_ARRAY_BUFFER, GL_tmpVerticesAmt * 2 * sizeof(GLfloat), data_uvs, GL_STATIC_DRAW);
    
    /*glGenBuffers(1, &vbo_norms);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_norms);
    glBufferData(GL_ARRAY_BUFFER, GL_tmpVerticesAmt * 3 * sizeof(GLfloat), data_norms, GL_STATIC_DRAW);*/
    
    glUniform1i(uniform_tex_mode, TEX_MODE_BGR);
    glUniform1i(uniform_blend_mode, 2);
    
    logic();
    
    rdTri* tris = GL_tmpTris;
    glUseProgram(program);
    glEnableVertexAttribArray(attribute_coord3d);
    glEnableVertexAttribArray(attribute_v_color);
    glEnableVertexAttribArray(attribute_v_uv);
    //glEnableVertexAttribArray(attribute_v_norm);
    
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
        4,                 // number of elements per vertex, here (R,G,B,A)
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
    
    /*glBindBuffer(GL_ARRAY_BUFFER, vbo_norms);
    glVertexAttribPointer(
        attribute_v_uv,    // attribute
        3,                 // number of elements per vertex, here (nX, nY, nZ)
        GL_FLOAT,          // the type of each element
        GL_FALSE,          // take our values as-is
        0,                 // no extra data between each position
        0                  // offset of first element
    );*/

    rdDDrawSurface* last_tex = NULL;
    int last_tex_idx = 0;
    GLushort* data_elements = malloc(sizeof(GLushort) * 3 * GL_tmpTrisAmt);
    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        data_elements[(j*3)+0] = tris[j].v1;
        data_elements[(j*3)+1] = tris[j].v2;
        data_elements[(j*3)+2] = tris[j].v3;
    }
    
    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        if (tris[j].texture != last_tex)
        {
            int num_tris_batch = j - last_tex_idx;
            rdDDrawSurface* tex = tris[j].texture;

            if (num_tris_batch)
            {
                glGenBuffers(1, &ibo_triangle);
                glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ibo_triangle);
                glBufferData(GL_ELEMENT_ARRAY_BUFFER, num_tris_batch * 3 * sizeof(GLushort), &data_elements[last_tex_idx * 3], GL_STATIC_DRAW);

                int tris_size;  
                glGetBufferParameteriv(GL_ELEMENT_ARRAY_BUFFER, GL_BUFFER_SIZE, &tris_size);
                glDrawElements(GL_TRIANGLES, tris_size / sizeof(GLushort), GL_UNSIGNED_SHORT, 0);

                //glDisableVertexAttribArray(attribute_v_norm);
                glDisableVertexAttribArray(attribute_v_uv);
                glDisableVertexAttribArray(attribute_v_color);
                glDisableVertexAttribArray(attribute_coord3d);
                glDeleteBuffers(1, &ibo_triangle);
            }
            
            int tex_id = tex->texture_id;
            glActiveTexture(GL_TEXTURE0 + 1);
            glBindTexture(GL_TEXTURE_1D, worldpal_texture);
            glActiveTexture(GL_TEXTURE0 + 0);
            glBindTexture(GL_TEXTURE_2D, tex_id);
            glUniform1i(uniform_tex, 0);
            glUniform1i(uniform_worldPalette, 1);
            glUniform1i(uniform_tex_mode, TEX_MODE_WORLDPAL);//TEX_MODE_BGR
            
            if (tex_id == 0)
                glUniform1i(uniform_tex_mode, TEX_MODE_TEST);
            
            last_tex = tris[j].texture;
            last_tex_idx = j;
        }
        //printf("tri %u,%u,%u, flags %x\n", tris[j].v1, tris[j].v2, tris[j].v3, tris[j].flags);
        
        
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
    
    int remaining_batch = GL_tmpTrisAmt - last_tex_idx;

    if (remaining_batch)
    {
        glGenBuffers(1, &ibo_triangle);
        glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ibo_triangle);
        glBufferData(GL_ELEMENT_ARRAY_BUFFER, remaining_batch * 3 * sizeof(GLushort), &data_elements[last_tex_idx * 3], GL_STATIC_DRAW);

        int tris_size;  
        glGetBufferParameteriv(GL_ELEMENT_ARRAY_BUFFER, GL_BUFFER_SIZE, &tris_size);
        glDrawElements(GL_TRIANGLES, tris_size / sizeof(GLushort), GL_UNSIGNED_SHORT, 0);

        //glDisableVertexAttribArray(attribute_v_norm);
        glDisableVertexAttribArray(attribute_v_uv);
        glDisableVertexAttribArray(attribute_v_color);
        glDisableVertexAttribArray(attribute_coord3d);
        glDeleteBuffers(1, &ibo_triangle);
    }
    

    
    free(data_elements);
        
    glDeleteBuffers(1, &vbo_vertices);
    glDeleteBuffers(1, &vbo_colors);
    glDeleteBuffers(1, &vbo_uvs);
    //glDeleteBuffers(1, &vbo_norms);
    free(data_vertices);
    free(data_colors);    
    free(data_uvs);
    free(data_norms);
        
    glBindTexture(GL_TEXTURE_2D, 0);
}

int std3D_SetCurrentPalette(rdColor24 *a1, int a2)
{
    return 1;
}

void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int *outW, unsigned int *outH)
{
    // TODO
    *outW = inW;
    *outH = inH;
}

int std3D_DrawOverlay()
{
    return 1;
}

void std3D_UnloadAllTextures()
{
    
}

void std3D_AddRenderListTris(rdTri *tris, unsigned int num_tris)
{
    if (GL_tmpTrisAmt + num_tris > 4096)
    {
        return 0;
    }
    
    memcpy(&GL_tmpTris[GL_tmpTrisAmt], tris, sizeof(rdTri) * num_tris);
    
    GL_tmpTrisAmt += num_tris;
}

int std3D_AddRenderListVertices(D3DVERTEX *vertices, int count)
{
    if (GL_tmpVerticesAmt + count > 4096)
    {
        return 0;
    }
    
    memcpy(&GL_tmpVertices[GL_tmpVerticesAmt], vertices, sizeof(D3DVERTEX) * count);
    
    GL_tmpVerticesAmt += count;
    
    return 1;
}

int std3D_ClearZBuffer()
{
    return 1;
}

int std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_16bit_maybe, int no_alpha)
{
    //printf("Add to texture cache\n");
    
    GLuint image_texture;
    glGenTextures(1, &image_texture);
    uint8_t* image_8bpp = vbuf->sdlSurface->pixels;
    uint16_t* image_16bpp = vbuf->sdlSurface->pixels;
    uint8_t* pal = vbuf->palette;
    
    uint32_t width, height;
    width = vbuf->format.width;
    height = vbuf->format.height;

#if 0    
    void* image_data = malloc(width*height*4);
    
    for (int j = 0; j < height; j++)
    {
        for (int i = 0; i < width; i++)
        {
            uint32_t index = (i*height) + j;
            uint32_t val_rgba = 0xFF000000;
            
            if (pal)
            {
                uint8_t val = image_8bpp[index];
                val_rgba |= (pal[(val * 3) + 2] << 16);
                val_rgba |= (pal[(val * 3) + 1] << 8);
                val_rgba |= (pal[(val * 3) + 0] << 0);
            }
            else
            {
                uint8_t val = image_8bpp[index];
                rdColor24* pal_master = (rdColor24*)sithWorld_pCurWorld->colormaps->colors;//stdDisplay_gammaPalette;
                rdColor24* color = &pal_master[val];
                val_rgba |= (color->r << 16);
                val_rgba |= (color->g << 8);
                val_rgba |= (color->b << 0);
            }
            
            *(uint32_t*)(image_data + index*4) = val_rgba;
        }
        
        
    }
    
    glBindTexture(GL_TEXTURE_2D, image_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
#endif

    glBindTexture(GL_TEXTURE_2D, image_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RED, width, height, 0, GL_RED, GL_UNSIGNED_BYTE, image_8bpp);
    
    /*ext->surfacebuf = image_data;
    ext->surfacetex = image_texture;
    ext->surfacepaltex = pal_texture;*/
    
    texture->texture_id = image_texture;
    texture->texture_loaded = 1;
    
    return 1;
}

void std3D_UpdateFrameCount(rdDDrawSurface *surface)
{
}

// Added helpers
int std3D_HasAlpha()
{
    return 1;
}

int std3D_HasModulateAlpha()
{
    return 1;
}

int std3D_HasAlphaFlatStippled()
{
    return 1;
}
#else
// Added helpers
int std3D_HasAlpha()
{
    return d3d_device_ptr->hasAlpha;
}

int std3D_HasModulateAlpha()
{
    return d3d_device_ptr->hasModulateAlpha;
}

int std3D_HasAlphaFlatStippled()
{
    return d3d_device_ptr->hasAlphaFlatStippled;
}
#endif
