#include "std3D.h"

#include "Engine/rdCache.h"
#include "Win95/stdDisplay.h"
#include "Win95/Window.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"
#include "Main/jkGame.h"

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
#define TEX_MODE_DISPPAL 5

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
GLuint programDefault, programMenu;
GLint attribute_coord3d, attribute_v_color, attribute_v_uv, attribute_v_norm;
GLint uniform_mvp, uniform_tex, uniform_tex_mode, uniform_blend_mode, uniform_worldPalette;

GLint programMenu_attribute_coord3d, programMenu_attribute_v_color, programMenu_attribute_v_uv, programMenu_attribute_v_norm;
GLint programMenu_uniform_mvp, programMenu_uniform_tex, programMenu_uniform_displayPalette;

GLuint worldpal_texture;
void* worldpal_data;
GLuint displaypal_texture;
void* displaypal_data;

static rdDDrawSurface* std3D_aLoadedSurfaces[1024];
static GLuint std3D_aLoadedTextures[1024];
static size_t std3D_loadedTexturesAmt = 0;
static rdTri GL_tmpTris[4096];
static size_t GL_tmpTrisAmt = 0;
static rdLine GL_tmpLines[4096];
static size_t GL_tmpLinesAmt = 0;
static D3DVERTEX GL_tmpVertices[4096];
static size_t GL_tmpVerticesAmt = 0;

rdDDrawSurface* last_tex = NULL;
int last_flags = 0;

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

GLuint std3D_loadProgram(const char* fpath_base)
{
    GLuint out;
    GLint link_ok = GL_FALSE;
    
    char* tmp_vert = malloc(strlen(fpath_base) + 32);
    char* tmp_frag = malloc(strlen(fpath_base) + 32);
    
    strcpy(tmp_vert, fpath_base);
    strcat(tmp_vert, "_v.glsl");
    
    strcpy(tmp_frag, fpath_base);
    strcat(tmp_frag, "_f.glsl");
    
    GLuint vs, fs;
    if ((vs = load_shader_file(tmp_vert, GL_VERTEX_SHADER))   == 0) return 0;
    if ((fs = load_shader_file(tmp_frag, GL_FRAGMENT_SHADER)) == 0) return 0;
    
    free(tmp_vert);
    free(tmp_frag);
    
    out = glCreateProgram();
    glAttachShader(out, vs);
    glAttachShader(out, fs);
    glLinkProgram(out);
    glGetProgramiv(out, GL_LINK_STATUS, &link_ok);
    if (!link_ok) 
    {
        print_log(out);
        return 0;
    }
    
    return out;
}

GLint std3D_tryFindAttribute(GLuint program, const char* attribute_name)
{
    GLint out = glGetAttribLocation(program, attribute_name);
    if (out == -1) {
        printf("Could not bind attribute %s!\n", attribute_name);
    }
    return out;
}

GLint std3D_tryFindUniform(GLuint program, const char* uniform_name)
{
    GLint out = glGetUniformLocation(program, uniform_name);
    if (out == -1) {
        printf("Could not bind uniform %s!\n", uniform_name);
    }
    return out;
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
    
    if ((programDefault = std3D_loadProgram("resource/shaders/default")) == 0) return false;
    if ((programMenu = std3D_loadProgram("resource/shaders/menu")) == 0) return false;
    
    // Attributes/uniforms
    attribute_coord3d = std3D_tryFindAttribute(programDefault, "coord3d");
    attribute_v_color = std3D_tryFindAttribute(programDefault, "v_color");
    attribute_v_uv = std3D_tryFindAttribute(programDefault, "v_uv");
    uniform_mvp = std3D_tryFindUniform(programDefault, "mvp");
    uniform_tex = std3D_tryFindUniform(programDefault, "tex");
    uniform_worldPalette = std3D_tryFindUniform(programDefault, "worldPalette");
    uniform_tex_mode = std3D_tryFindUniform(programDefault, "tex_mode");
    uniform_blend_mode = std3D_tryFindUniform(programDefault, "blend_mode");
    
    programMenu_attribute_coord3d = std3D_tryFindAttribute(programMenu, "coord3d");
    programMenu_attribute_v_color = std3D_tryFindAttribute(programMenu, "v_color");
    programMenu_attribute_v_uv = std3D_tryFindAttribute(programMenu, "v_uv");
    programMenu_uniform_mvp = std3D_tryFindUniform(programMenu, "mvp");
    programMenu_uniform_tex = std3D_tryFindUniform(programMenu, "tex");
    programMenu_uniform_displayPalette = std3D_tryFindUniform(programMenu, "displayPalette");
    
    // World palette
    glGenTextures(1, &worldpal_texture);
    worldpal_data = malloc(0x300);
    memset(worldpal_data, 0xFF, 0x300);
    
    glBindTexture(GL_TEXTURE_1D, worldpal_texture);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    
    glTexImage1D(GL_TEXTURE_1D, 0, GL_RGB8, 256, 0, GL_RGB, GL_UNSIGNED_BYTE, worldpal_data);
    
    
    // Display palette
    glGenTextures(1, &displaypal_texture);
    displaypal_data = malloc(0x400);
    memset(displaypal_data, 0xFF, 0x300);
    
    glBindTexture(GL_TEXTURE_1D, displaypal_texture);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_1D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    
    glTexImage1D(GL_TEXTURE_1D, 0, GL_RGB8, 256, 0, GL_RGB, GL_UNSIGNED_BYTE, displaypal_data);

    has_initted = true;
    return true;
}

void free_resources()
{
    glDeleteProgram(programDefault);
    glDeleteProgram(programMenu);
    deleteFramebuffer(fb1, fbTex1, fbRbo1);
    deleteFramebuffer(fb2, fbTex2, fbRbo2);
    glDeleteTextures(1, &worldpal_texture);
    glDeleteTextures(1, &displaypal_texture);
    free(worldpal_data);
    free(displaypal_data);
    has_initted = false;
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
	glBlendEquation(GL_FUNC_ADD);
	    
	// Technically this should be from Clear2
	glClearColor(0.0, 0.0, 0.0, 1.0);
	glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
	
	glBindTexture(GL_TEXTURE_1D, worldpal_texture);
	if (sithWorld_pCurWorld && sithWorld_pCurWorld->colormaps)
	{
	    memcpy(worldpal_data, sithWorld_pCurWorld->colormaps->colors, 0x300);
        glTexSubImage1D(GL_TEXTURE_1D, 0, 0, 256, GL_RGB, GL_UNSIGNED_BYTE, worldpal_data);
    }
    
    glBindTexture(GL_TEXTURE_1D, displaypal_texture);
    memcpy(displaypal_data, stdDisplay_masterPalette, 0x300);
    glTexSubImage1D(GL_TEXTURE_1D, 0, 0, 256, GL_RGB, GL_UNSIGNED_BYTE, displaypal_data);
	
	glBindTexture(GL_TEXTURE_2D, 0);
	
    return 1;
}

int std3D_EndScene()
{
    //printf("End draw\n");
    last_tex = NULL;
    last_flags = 0;
    std3D_ResetRenderList();
    return 1;
}

void std3D_ResetRenderList()
{
    
    GL_tmpVerticesAmt = 0;
    GL_tmpTrisAmt = 0;
    GL_tmpLinesAmt = 0;
    
    //memset(GL_tmpTris, 0, sizeof(GL_tmpTris));
    //memset(GL_tmpVertices, 0, sizeof(GL_tmpVertices));
}

int std3D_RenderListVerticesFinish()
{
    return 1;
}

static rdDDrawSurface* test_idk = NULL;

void std3D_DrawMenu()
{
    glDepthFunc(GL_ALWAYS);
    glUseProgram(programMenu);
    
    float menu_w, menu_h;
    menu_w = (double)Window_xSize;
    menu_h = (double)Window_ySize;
    
    if (!jkGame_isDDraw)
    {
        //menu_w = 640.0;
        //menu_h = 480.0;
    }

    GL_tmpVertices[0].x = 0.0;
    GL_tmpVertices[0].y = 0.0;
    GL_tmpVertices[0].z = 0.0;
    GL_tmpVertices[0].tu = 0.0;
    GL_tmpVertices[0].tv = 0.0;
    *(uint32_t*)&GL_tmpVertices[0].nx = 0;
    *(uint32_t*)&GL_tmpVertices[0].ny = 0xFFFFFFFF;
    *(uint32_t*)&GL_tmpVertices[0].nz = 0;
    
    GL_tmpVertices[1].x = 0.0;
    GL_tmpVertices[1].y = menu_h;
    GL_tmpVertices[1].z = 0.0;
    GL_tmpVertices[1].tu = 0.0;
    GL_tmpVertices[1].tv = 1.0;
    *(uint32_t*)&GL_tmpVertices[1].nx = 0;
    *(uint32_t*)&GL_tmpVertices[1].ny = 0xFFFFFFFF;
    *(uint32_t*)&GL_tmpVertices[1].nz = 0;
    
    GL_tmpVertices[2].x = menu_w;
    GL_tmpVertices[2].y = menu_h;
    GL_tmpVertices[2].z = 0.0;
    GL_tmpVertices[2].tu = 1.0;
    GL_tmpVertices[2].tv = 1.0;
    *(uint32_t*)&GL_tmpVertices[2].nx = 0;
    *(uint32_t*)&GL_tmpVertices[2].ny = 0xFFFFFFFF;
    *(uint32_t*)&GL_tmpVertices[2].nz = 0;
    
    GL_tmpVertices[3].x = menu_w;
    GL_tmpVertices[3].y = 0.0;
    GL_tmpVertices[3].z = 0.0;
    GL_tmpVertices[3].tu = 1.0;
    GL_tmpVertices[3].tv = 0.0;
    *(uint32_t*)&GL_tmpVertices[3].nx = 0;
    *(uint32_t*)&GL_tmpVertices[3].ny = 0xFFFFFFFF;
    *(uint32_t*)&GL_tmpVertices[3].nz = 0;
    
    GL_tmpTris[0].v1 = 1;
    GL_tmpTris[0].v2 = 0;
    GL_tmpTris[0].v3 = 2;
    
    GL_tmpTris[1].v1 = 2;
    GL_tmpTris[1].v2 = 3;
    GL_tmpTris[1].v3 = 0;
    
    GL_tmpVerticesAmt = 4;
    GL_tmpTrisAmt = 2;
    
    glActiveTexture(GL_TEXTURE0 + 0);
    glBindTexture(GL_TEXTURE_2D, Video_menuTexId);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, Video_menuBuffer.format.width, Video_menuBuffer.format.height, GL_RED, GL_UNSIGNED_BYTE, Video_menuBuffer.sdlSurface->pixels);

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
    
    glActiveTexture(GL_TEXTURE0 + 1);
    glBindTexture(GL_TEXTURE_1D, displaypal_texture);
    glUniform1i(programMenu_uniform_tex, 0);
    glUniform1i(programMenu_uniform_displayPalette, 1);
    
    {

    float maxX, maxY, scaleX, scaleY, width, height;
    
    scaleX = 1.0/((double)Window_xSize / 2.0);
    scaleY = 1.0/((double)Window_ySize / 2.0);
    maxX = 1.0;
    maxY = 1.0;
    width = Window_xSize;
    height = Window_ySize;
    
    float d3dmat[16] = {
       maxX*scaleX,      0,                                          0,      0, // right
       0,                                       -maxY*scaleY,               0,      0, // up
       0,                                       0,                                          1,     0, // forward
       -(width/2)*scaleX,  (height/2)*scaleY,     -1,      1  // pos
    };
    
    glUniformMatrix4fv(programMenu_uniform_mvp, 1, GL_FALSE, d3dmat);
    glViewport(0, 0, width, height);

    }
    
    rdTri* tris = GL_tmpTris;
    glEnableVertexAttribArray(programMenu_attribute_coord3d);
    glEnableVertexAttribArray(programMenu_attribute_v_color);
    glEnableVertexAttribArray(programMenu_attribute_v_uv);
    
    // Describe our vertices array to OpenGL (it can't guess its format automatically)
    glBindBuffer(GL_ARRAY_BUFFER, vbo_vertices);
    glVertexAttribPointer(
        programMenu_attribute_coord3d, // attribute
        3,                 // number of elements per vertex, here (x,y,z)
        GL_FLOAT,          // the type of each element
        GL_FALSE,          // take our values as-is
        0,                 // no extra data between each position
        0                  // offset of first element
    );
    
    
    glBindBuffer(GL_ARRAY_BUFFER, vbo_colors);
    glVertexAttribPointer(
        programMenu_attribute_v_color, // attribute
        4,                 // number of elements per vertex, here (R,G,B,A)
        GL_FLOAT,          // the type of each element
        GL_FALSE,          // take our values as-is
        0,                 // no extra data between each position
        0                  // offset of first element
    );
    
    
    glBindBuffer(GL_ARRAY_BUFFER, vbo_uvs);
    glVertexAttribPointer(
        programMenu_attribute_v_uv,    // attribute
        2,                 // number of elements per vertex, here (U,V)
        GL_FLOAT,          // the type of each element
        GL_FALSE,          // take our values as-is
        0,                 // no extra data between each position
        0                  // offset of first element
    );
    
    rdDDrawSurface* last_tex = (void*)-1;
    int last_tex_idx = 0;
    GLushort* data_elements = malloc(sizeof(GLushort) * 3 * GL_tmpTrisAmt);
    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        data_elements[(j*3)+0] = tris[j].v1;
        data_elements[(j*3)+1] = tris[j].v2;
        data_elements[(j*3)+2] = tris[j].v3;
    }

    glGenBuffers(1, &ibo_triangle);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ibo_triangle);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, GL_tmpTrisAmt * 3 * sizeof(GLushort), data_elements, GL_STATIC_DRAW);

    int tris_size;  
    glGetBufferParameteriv(GL_ELEMENT_ARRAY_BUFFER, GL_BUFFER_SIZE, &tris_size);
    glDrawElements(GL_TRIANGLES, tris_size / sizeof(GLushort), GL_UNSIGNED_SHORT, 0);

    glDisableVertexAttribArray(programMenu_attribute_v_uv);
    glDisableVertexAttribArray(programMenu_attribute_v_color);
    glDisableVertexAttribArray(programMenu_attribute_coord3d);
    glDeleteBuffers(1, &ibo_triangle);
    
    free(data_elements);
        
    glDeleteBuffers(1, &vbo_vertices);
    glDeleteBuffers(1, &vbo_colors);
    glDeleteBuffers(1, &vbo_uvs);
    free(data_vertices);
    free(data_colors);    
    free(data_uvs);
    free(data_norms);
        
    glBindTexture(GL_TEXTURE_2D, 0);
}

void std3D_DrawRenderList()
{
    glUseProgram(programDefault);
    
    last_tex = NULL;

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
        data_vertices[(i*3)+2] = (!rdCamera_pCurCamera || rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) ? vertexes[i].z : -(1.0-vertexes[i].z);
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
    
    glUniform1i(uniform_tex_mode, TEX_MODE_TEST);
    glUniform1i(uniform_blend_mode, 2);
    glActiveTexture(GL_TEXTURE0 + 1);
    glBindTexture(GL_TEXTURE_1D, worldpal_texture);
    glActiveTexture(GL_TEXTURE0 + 0);
    glBindTexture(GL_TEXTURE_2D, 0);
    glUniform1i(uniform_tex, 0);
    glUniform1i(uniform_worldPalette, 1);
    
    {
    
    float maxX, maxY, scaleX, scaleY, width, height;
    
    scaleX = 1.0/((double)Window_xSize / 2.0);
    scaleY = 1.0/((double)Window_ySize / 2.0);
    maxX = 1.0;
    maxY = 1.0;
    width = Window_xSize;
    height = Window_ySize;
    
    float d3dmat[16] = {
       maxX*scaleX,      0,                                          0,      0, // right
       0,                                       -maxY*scaleY,               0,      0, // up
       0,                                       0,                                          1,     0, // forward
       -(width/2)*scaleX,  (height/2)*scaleY,     (!rdCamera_pCurCamera || rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) ? -1 : 1,      1  // pos
    };
    
    glUniformMatrix4fv(uniform_mvp, 1, GL_FALSE, d3dmat);
    glViewport(0, 0, width, height);
    
    }
    
    rdTri* tris = GL_tmpTris;
    rdLine* lines = GL_tmpLines;
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
    
    int last_tex_idx = 0;
    GLushort* data_elements = malloc(sizeof(GLushort) * 3 * GL_tmpTrisAmt);
    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        data_elements[(j*3)+0] = tris[j].v1;
        data_elements[(j*3)+1] = tris[j].v2;
        data_elements[(j*3)+2] = tris[j].v3;
    }
    
    int do_batch = 0;
    
    glDepthFunc(GL_LESS);
    glDepthMask(GL_TRUE);
    
    for (int j = 0; j < GL_tmpTrisAmt; j++)
    {
        if (tris[j].texture != last_tex || tris[j].flags != last_flags)
        {
            do_batch = 1;
        }
        
        if (do_batch)
        {
            int num_tris_batch = j - last_tex_idx;
            rdDDrawSurface* tex = tris[j].texture;
            
            test_idk = tex;

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

            if (tex)
            {
                int tex_id = tex->texture_id;
                glActiveTexture(GL_TEXTURE0 + 0);
                glBindTexture(GL_TEXTURE_2D, tex_id);
                glUniform1i(uniform_tex_mode, TEX_MODE_WORLDPAL);//TEX_MODE_BGR
                
                if (tex_id == 0)
                    glUniform1i(uniform_tex_mode, TEX_MODE_TEST);
            }
            else
            {
                glActiveTexture(GL_TEXTURE0 + 0);
                glBindTexture(GL_TEXTURE_2D, 0);
                glUniform1i(uniform_tex_mode, TEX_MODE_TEST);
            }
            
            int changed_flags = (last_flags ^ tris[j].flags);

            if (changed_flags & 0x600)
            {
                if (tris[j].flags & 0x600)
                    glUniform1i(uniform_blend_mode, 5);
                else
                    glUniform1i(uniform_blend_mode, 2);
            }
            
            if (changed_flags & 0x1800)
            {
                if (tris[j].flags & 0x800)
                {
                    glDepthFunc(GL_LESS);
                }
                else
                {
                    glDepthFunc(GL_ALWAYS);
                    glClear(GL_DEPTH_BUFFER_BIT);
                }
                
                if (changed_flags & 0x1000)
                {
                    glDepthMask(GL_TRUE);
                }
                else
                {
                    //glDepthMask(GL_FALSE);
                }
            }
            
            last_tex = tris[j].texture;
            last_flags = tris[j].flags;
            last_tex_idx = j;

            do_batch = 0;
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
    
    // Draw all lines
    data_elements = malloc(sizeof(GLushort) * 2 * GL_tmpLinesAmt);
    for (int j = 0; j < GL_tmpLinesAmt; j++)
    {
        data_elements[(j*2)+0] = lines[j].v1;
        data_elements[(j*2)+1] = lines[j].v2;
    }
    
    glGenBuffers(1, &ibo_triangle);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, ibo_triangle);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, GL_tmpLinesAmt * 2 * sizeof(GLushort), data_elements, GL_STATIC_DRAW);

    int lines_size;
    glGetBufferParameteriv(GL_ELEMENT_ARRAY_BUFFER, GL_BUFFER_SIZE, &lines_size);
    glDrawElements(GL_LINES, lines_size / sizeof(GLushort), GL_UNSIGNED_SHORT, 0);

    glDisableVertexAttribArray(attribute_v_uv);
    glDisableVertexAttribArray(attribute_v_color);
    glDisableVertexAttribArray(attribute_coord3d);
    glDeleteBuffers(1, &ibo_triangle);
        
    // Done drawing
    glDeleteBuffers(1, &vbo_vertices);
    glDeleteBuffers(1, &vbo_colors);
    glDeleteBuffers(1, &vbo_uvs);
    //glDeleteBuffers(1, &vbo_norms);
    free(data_vertices);
    free(data_colors);    
    free(data_uvs);
    free(data_norms);
        
    glBindTexture(GL_TEXTURE_2D, 0);
    
    std3D_ResetRenderList();
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
    glDeleteTextures(std3D_loadedTexturesAmt, std3D_aLoadedTextures);
    std3D_loadedTexturesAmt = 0;
}

void std3D_AddRenderListTris(rdTri *tris, unsigned int num_tris)
{
    if (GL_tmpTrisAmt + num_tris > 4096)
    {
        return;
    }
    
    memcpy(&GL_tmpTris[GL_tmpTrisAmt], tris, sizeof(rdTri) * num_tris);
    
    GL_tmpTrisAmt += num_tris;
}

void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines)
{
    if (GL_tmpLinesAmt + num_lines > 4096)
    {
        return;
    }
    
    memcpy(&GL_tmpLines[GL_tmpLinesAmt], lines, sizeof(rdLine) * num_lines);
    GL_tmpLinesAmt += num_lines;
}

int std3D_AddRenderListVertices(D3DVERTEX *vertices, int count)
{
    if (GL_tmpVerticesAmt + count >= 4096)
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
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RED, width, height, 0, GL_RED, GL_UNSIGNED_BYTE, image_8bpp);
    
    std3D_aLoadedSurfaces[std3D_loadedTexturesAmt] = texture;
    std3D_aLoadedTextures[std3D_loadedTexturesAmt++] = image_texture;
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

void std3D_PurgeTextureCache()
{
    for (int i = 0; i < 1024; i++)
    {
        rdDDrawSurface* tex = std3D_aLoadedSurfaces[i];
        if (!tex) continue;

        if (std3D_aLoadedTextures[i])
            glDeleteTextures(1, &std3D_aLoadedTextures[i]);

        std3D_aLoadedTextures[i] = 0;

        tex->texture_loaded = 0;
        tex->texture_id = 0;

        std3D_aLoadedSurfaces[i] = NULL;
    }
    std3D_loadedTexturesAmt = 0;
}
void std3D_Shutdown(){}
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
