#include "IDirect3DExecuteBuffer.h"

void IDirect3DExecuteBuffer::generateFramebuffer(GLuint* fbOut, GLuint* fbTexOut, GLuint* fbRboOut)
{
	// Generate the framebuffer
    *fbOut = 0;
    glGenFramebuffers(1, fbOut);
    glBindFramebuffer(GL_FRAMEBUFFER, *fbOut);
    
    // Set up our framebuffer texture
    glGenTextures(1, fbTexOut);
    glBindTexture(GL_TEXTURE_2D, *fbTexOut);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, view.dwWidth, view.dwHeight, 0, GL_RGB, GL_UNSIGNED_BYTE, NULL);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glBindTexture(GL_TEXTURE_2D, 0);
    
    // Attach fbTex to our currently bound framebuffer fb
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, *fbTexOut, 0); 
    
    // Set up our render buffer
    glGenRenderbuffers(1, fbRboOut);
    glBindRenderbuffer(GL_RENDERBUFFER, *fbRboOut);
    glRenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH24_STENCIL8, view.dwWidth, view.dwHeight);
    glBindRenderbuffer(GL_RENDERBUFFER, 0);
    
    // Bind it to our framebuffer fb
    glFramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT, GL_RENDERBUFFER, *fbRboOut);
    if(glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
            printf("ERROR: Framebuffer is incomplete!\n");
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

void IDirect3DExecuteBuffer::deleteFramebuffer(GLuint fbIn, GLuint fbTexIn, GLuint fbRboIn)
{
	glDeleteFramebuffers(1, &fbIn);
	glDeleteTextures(1, &fbTexIn);
	glDeleteRenderbuffers(1, &fbRboIn);
}

void IDirect3DExecuteBuffer::swap_framebuffers()
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

bool IDirect3DExecuteBuffer::init_resources() 
{
    if (has_initted) return true;
    
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
    
    uniform_name = "tex_mode";
    uniform_tex_mode = glGetUniformLocation(program, uniform_name);
    if (uniform_tex_mode == -1) 
    {
        printf("Could not bind attribute %s!\n", attribute_name);
        return false;
    }
    
    uniform_name = "blend_mode";
    uniform_blend_mode = glGetUniformLocation(program, uniform_name);
    if (uniform_blend_mode == -1) 
    {
        printf("Could not bind attribute %s!\n", attribute_name);
        return false;
    }

    has_initted = true;
    
    return true;
}

void IDirect3DExecuteBuffer::free_resources() 
{
    glDeleteProgram(program);
    deleteFramebuffer(fb1, fbTex1, fbRbo1);
    deleteFramebuffer(fb2, fbTex2, fbRbo2);
    has_initted = false;
}

void IDirect3DExecuteBuffer::logic() 
{
    //TODO: camera freelook stuff, maybe
    glm::mat4 viewmat;
    glm::mat4 glmmodel = glm::translate(glm::mat4(1.0f), glm::vec3(0.0, 0.0, 0.0));
    glm::mat4 glmview = glm::lookAt(glm::vec3(-1.0, 0.5, 0.5), glm::vec3(-1.0, 0.5, -4.0), glm::vec3(0.0, -1.0, 0.0));
    glm::mat4 glmprojection = glm::perspectiveFov(90.0f, (float)1, (float)1, 0.1f, 1000.0f);

    float d3dmat[16] = {
       view.dvMaxX*1/(float)view.dvScaleX,      0,                                          0,      0, // right
       0,                                       view.dvMaxY*1/view.dvScaleY,               0,      0, // up
       0,                                       0,                                          -1,     0, // forward
       -((float)view.dwWidth/2)/view.dvScaleX,  -((float)view.dwHeight/2)/view.dvScaleY,     1,      1  // pos
    };

    memcpy(glm::value_ptr(viewmat), d3dmat, sizeof(d3dmat));
    
    glm::mat4 mvp = viewmat; // glmprojection * glmview * glmmodel;
    
    glUseProgram(program);
    glUniformMatrix4fv(uniform_mvp, 1, GL_FALSE, glm::value_ptr(mvp));
    glViewport(0, 0, view.dwWidth, view.dwHeight);
}

void IDirect3DExecuteBuffer::render(SDL_Window* window) 
{
    glUseProgram(program);
}

/* IDirect3DExecuteBuffer methods */
uint32_t IDirect3DExecuteBuffer::Initialize(void* this_ptr, uint32_t a, uint32_t b)
{
    printf("STUB:: IDirect3DExecuteBuffer::Initialize\n");

    return 0;
}

uint32_t IDirect3DExecuteBuffer::Lock(void* this_ptr, D3DEXECUTEBUFFERDESC* desc)
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

uint32_t IDirect3DExecuteBuffer::Unlock(void* this_ptr)
{
    return 0;
}

uint32_t IDirect3DExecuteBuffer::SetExecuteData(void* this_ptr, D3DEXECUTEDATA* desc)
{
    //TODO: wait for Execute
   //printf("IDirect3DExecuteBuffer::SetExecuteData: execute offset %x, count %x,  instr offset %x, instr count %x, hvertex offset %x\n", desc->dwVertexOffset, desc->dwVertexCount, desc->dwInstructionOffset, desc->dwInstructionLength, desc->dwHVertexOffset);

    // Generate vertices list
    GLuint vbo_vertices, vbo_colors, vbo_uvs;
    GLuint ibo_triangle;
    GLfloat* data_vertices = (GLfloat*)malloc(desc->dwVertexCount * 3 * sizeof(GLfloat));
    GLfloat* data_colors = (GLfloat*)malloc(desc->dwVertexCount * 4 * sizeof(GLfloat));
    GLfloat* data_uvs = (GLfloat*)malloc(desc->dwVertexCount * 2 * sizeof(GLfloat));
    GLfloat* data_norms = (GLfloat*)malloc(desc->dwVertexCount * 3 * sizeof(GLfloat));

    D3DVERTEX* vertexes = (D3DVERTEX*)vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)] + desc->dwVertexOffset);

    for (int i = 0; i < desc->dwVertexCount; i++)
    {
        /*printf("%f %f %f, %f %f %f, %f %f\n", vertexes[i].x, vertexes[i].y, vertexes[i].z,
                                              vertexes[i].nx, vertexes[i].ny, vertexes[i].nz,
                                              vertexes[i].tu, vertexes[i].tv);*/
                                             
        uint32_t v_color = *(uint32_t*)&vertexes[i].ny;
        uint32_t v_unknx = *(uint32_t*)&vertexes[i].nx;
        uint32_t v_unknz = *(uint32_t*)&vertexes[i].nz;
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
    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 3 * sizeof(GLfloat), data_vertices, GL_STATIC_DRAW);
    
    
    glGenBuffers(1, &vbo_colors);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_colors);
    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 4 * sizeof(GLfloat), data_colors, GL_STATIC_DRAW);
    
    glGenBuffers(1, &vbo_uvs);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_uvs);
    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 2 * sizeof(GLfloat), data_uvs, GL_STATIC_DRAW);
    
    /*glGenBuffers(1, &vbo_norms);
    glBindBuffer(GL_ARRAY_BUFFER, vbo_norms);
    glBufferData(GL_ARRAY_BUFFER, desc->dwVertexCount * 3 * sizeof(GLfloat), data_norms, GL_STATIC_DRAW);*/
    
    glUniform1i(uniform_blend_mode, D3DBLEND_ONE);
    
    logic();
    
    int offset = desc->dwInstructionOffset;
    for (int i = 0; i < desc->dwInstructionLength; i++)
    {
        D3DINSTRUCTION* instr = (D3DINSTRUCTION*)vm_ptr_to_real_ptr(locked_objs[real_ptr_to_vm_ptr(this_ptr)] + offset);
        
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
    
            GLushort* data_elements = new GLushort[instr->wCount * 3];
            D3DTRIANGLE* tris = (D3DTRIANGLE*)opData;
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

            //glDisableVertexAttribArray(attribute_v_norm);
            glDisableVertexAttribArray(attribute_v_uv);
            glDisableVertexAttribArray(attribute_v_color);
            glDisableVertexAttribArray(attribute_coord3d);
            glDeleteBuffers(1, &ibo_triangle);
            delete data_elements;
        
        }
        else if (instr->bOpcode == D3DOP_PROCESSVERTICES)
        {
            //idk on this one
            //printf("STUB: D3DOP_PROCESSVERTICES size 0x%x count %u\n", instr->bSize, instr->wCount);
        }
        else if (instr->bOpcode == D3DOP_STATERENDER)
        {
            //printf("STUB: D3DOP_STATERENDER size 0x%x count %u\n", instr->bSize, instr->wCount);
            for (int i = 0; i < instr->wCount; i++)
            {
                uint32_t renderOp = *(uint32_t*)(opData+0);
                uint32_t renderArg = *(uint32_t*)(opData+4);
                //printf("op %u arg %u\n", renderOp, renderArg);
                
                if (renderOp == D3DRENDERSTATE_TEXTUREHANDLE) // Texture
                {
                    //printf("texture %x\n", renderArg);

                    glActiveTexture(GL_TEXTURE0);
                    glBindTexture(GL_TEXTURE_2D, renderArg);
                    glUniform1i(uniform_tex, 0);
                    glUniform1i(uniform_tex_mode, TEX_MODE_BGR);
                    
                    if (renderArg == 0)
                        glUniform1i(uniform_tex_mode, TEX_MODE_TEST);
                }
                else if (renderOp == D3DRENDERSTATE_ZFUNC)
                {
                    //printf("zfunc %x\n", renderArg);
                    switch (renderArg)
                    {
                        case D3DCMP_NEVER:
                            glDepthFunc(GL_NEVER);
                            break;
                        case D3DCMP_LESS:
                            glDepthFunc(GL_GREATER);
                            break;
                        case D3DCMP_EQUAL:
                            glDepthFunc(GL_EQUAL);
                            break;
                        case D3DCMP_LESSEQUAL:
                            glDepthFunc(GL_GEQUAL);
                            break;
                        case D3DCMP_GREATER:
                            glDepthFunc(GL_LESS);
                            break;
                        case D3DCMP_NOTEQUAL:
                            glDepthFunc(GL_NOTEQUAL);
                            break;
                        case D3DCMP_GREATEREQUAL:
                            glDepthFunc(GL_LEQUAL);
                            break;
                        case D3DCMP_ALWAYS:
                            glDepthFunc(GL_ALWAYS);
                            break;
                    }
                }
                else if (renderOp == D3DRENDERSTATE_SRCBLEND)
                {
                    //printf("D3DRENDERSTATE_SRCBLEND: %u\n", renderArg);
                    glUniform1i(uniform_blend_mode, renderArg);
                }
                else if (renderOp == D3DRENDERSTATE_TEXTUREPERSPECTIVE)
                {
                    //printf("D3DRENDERSTATE_TEXTUREPERSPECTIVE: %u\n", renderArg);
                }
                else if (renderOp == D3DRENDERSTATE_MONOENABLE)
                {
                    //printf("D3DRENDERSTATE_MONOENABLE: %u\n", renderArg);
                }
                else if (renderOp == D3DRENDERSTATE_ZWRITEENABLE)
                {
                    //printf("D3DRENDERSTATE_ZWRITEENABLE: %u\n", renderArg);
                }
                else if (renderOp == D3DRENDERSTATE_DESTBLEND)
                {
                    //printf("D3DRENDERSTATE_DESTBLEND: %u\n", renderArg);
                }
                else if (renderOp == D3DRENDERSTATE_TEXTUREMAPBLEND)
                {
                    //printf("D3DRENDERSTATE_TEXTUREMAPBLEND: %u\n", renderArg);
                }
                else if (renderOp == D3DRENDERSTATE_ALPHABLENDENABLE)
                {
                    //printf("D3DRENDERSTATE_ALPHABLENDENABLE: %u\n", renderArg);
                }
                else
                {
                    //printf("IDirect3DExecuteBuffer::SetExecuteData: Unhandled STATERENDER operation %u!\n", renderOp);
                }
                opData += instr->bSize;
            }
        }
        else
        {
            printf("Uprocessed D3DOP %u\n", instr->bOpcode);
        }
        
        offset += instr->bSize * instr->wCount;
    }
        
    glDeleteBuffers(1, &vbo_vertices);
    glDeleteBuffers(1, &vbo_colors);
    glDeleteBuffers(1, &vbo_uvs);
    //glDeleteBuffers(1, &vbo_norms);
    free(data_vertices);
    free(data_colors);    
    free(data_uvs);
    free(data_norms);
        
    glBindTexture(GL_TEXTURE_2D, 0);

    return 0;
}

uint32_t IDirect3DExecuteBuffer::GetExecuteData(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DExecuteBuffer::GetExecuteData\n");

    return 0;
}

uint32_t IDirect3DExecuteBuffer::Validate(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    printf("STUB:: IDirect3DExecuteBuffer::Validate\n");

    return 0;
}

uint32_t IDirect3DExecuteBuffer::Optimize(void* this_ptr, uint32_t a)
{
    printf("STUB:: IDirect3DExecuteBuffer::Optimize\n");

    return 0;
}
