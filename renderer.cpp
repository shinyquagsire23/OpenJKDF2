#include "renderer.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include <GL/glew.h>

#include "3rdparty/imgui/imgui.h"
#include "3rdparty/imgui/imgui_impl_sdl.h"
#include "3rdparty/imgui/imgui_impl_opengl3.h"
#include "3rdparty/imgui/imgui_memory_editor.h"

#include "dlls/user32.h"
#include "dlls/gdi32.h"
#include "dlls/nmm.h"

pthread_cond_t cond_vblank = PTHREAD_COND_INITIALIZER; 
pthread_cond_t cond_update = PTHREAD_COND_INITIALIZER; 
pthread_mutex_t context_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_t render_thread;
bool renderer_active = false;

ImGuiIO io;
SDL_Renderer* renderRenderer;
SDL_Window* renderWindow;
SDL_GLContext renderContext;
GLint window_fbo;

bool hasDestroyedTex = false;
bool gameRendering = false;
std::string gameTitle = "";
GLint gameTex = 0;
GLint gamePal = 0;
ImVec2 gameDims(640,480);
void (*gameTexDestroy)(void*) = NULL;
void (*gameOnVblank)(void*) = NULL;
void* gameTexDestroyArg = NULL;
GLsync renderSync = 0;

static uint32_t last_ms = 0;
static uint32_t game_ms = 0;
static uint32_t last_game_ms = 0;

static MemoryEditor mem_edit1;
static MemoryEditor mem_edit2;
static MemoryEditor mem_edit3;
static MemoryEditor mem_edit4;

std::string console = "";

char toHexViewerCharacter(uint8_t val)
{
    if (val < ' ' || val > '~') return '.';

    return (char)val;
}

void *renderer_thread(void *threadid) 
{
    printf("render_thread: starting...\n");
    
    SDL_GL_MakeCurrent(renderWindow, renderContext);
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &window_fbo);
    
    io = ImGui::GetIO();
   
    while (renderer_active)
    {
        //Lock to game FPS
        /*if (gdi32 && !gdi32->gdi_render)
        {
            pthread_mutex_lock(&context_lock);
            pthread_cond_wait(&cond_update, &context_lock);
            pthread_mutex_unlock(&context_lock);
        }*/
    
        //TODO: Why do we need framelimiting?
    	uint32_t ms = nmm->timeGetTime();
        uint32_t ms_diff = ms - last_ms;
        uint32_t game_ms_diff = game_ms - last_game_ms;
        last_ms = ms;
        
        //if (ms_diff < (1000/120))
        //    usleep(((1000/120) - ms_diff) * 1000);

        glBindFramebuffer(GL_FRAMEBUFFER, window_fbo);
        SDL_SetRenderTarget(renderRenderer, NULL);
        glBindTexture(GL_TEXTURE_2D, 0);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame(renderWindow);
        ImGui::NewFrame();
        
        //ImGui::SetNextWindowSize(ImVec2(dc_surface[hdc]->w, dc_surface[hdc]->h));
        if (renderSync)
	        glClientWaitSync(renderSync,0,100000000);
	    renderSync = 0;
        
        pthread_mutex_lock(&context_lock);
        if (gameRendering)
        {
            //ImGui::SetNextWindowPos(ImVec2(0,0));
            ImGui::SetNextWindowCollapsed(false);
            ImGui::Begin(gameTitle.c_str(), NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
            ImVec2 screen_pos = ImGui::GetCursorScreenPos();
            if (gamePal)
            {
                ImGui::Image((void*)((intptr_t)gamePal), gameDims, 2);
                ImGui::Image((void*)((intptr_t)gameTex), gameDims, 1);
            }
            else
            {
                ImGui::Image((void*)((intptr_t)gameTex), gameDims, 0);
            }
            ImGui::End();

            if (user32)
                user32->SetMouseOffset(screen_pos.x, screen_pos.y);
        }
        
        // Information window
        //ImGui::SetNextWindowPos(ImVec2(gameDims.x+32,0));
        ImGui::SetNextWindowCollapsed(false);
        ImGui::Begin("Info", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
        ImGui::Text("imgui FPS = %i", ms_diff ? 1000 / ms_diff : 0);
        ImGui::Text("game FPS = %i", game_ms_diff ? 1000 / game_ms_diff : 0);
        ImGui::End();
        
        ImGui::SetNextWindowCollapsed(false);
        ImGui::Begin("Console", NULL);
        //ImGui::Text((char*)vm_ptr_to_real_ptr(0x8BC020));
        ImGui::End();
        
        /*ImGui::SetNextWindowCollapsed(false);
        ImGui::Begin("Memory Viewer", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
        for (int i = 0; i < 10; i++)
        {
            uint32_t vm_ptr = memviewer_addr + i*0x10;
            
            if (!line_mem) break;
            ImGui::Text("%08x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x | %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
                        vm_ptr,
                        line_mem[0], line_mem[1], line_mem[2], line_mem[3], 
                        line_mem[4], line_mem[5], line_mem[6], line_mem[7], 
                        line_mem[8], line_mem[9], line_mem[10], line_mem[11], 
                        line_mem[12], line_mem[13], line_mem[14], line_mem[15],
                        toHexViewerCharacter(line_mem[0]), toHexViewerCharacter(line_mem[1]), 
                        toHexViewerCharacter(line_mem[2]), toHexViewerCharacter(line_mem[3]), 
                        toHexViewerCharacter(line_mem[4]), toHexViewerCharacter(line_mem[5]), 
                        toHexViewerCharacter(line_mem[6]), toHexViewerCharacter(line_mem[7]), 
                        toHexViewerCharacter(line_mem[8]), toHexViewerCharacter(line_mem[9]), 
                        toHexViewerCharacter(line_mem[10]), toHexViewerCharacter(line_mem[11]), 
                        toHexViewerCharacter(line_mem[12]), toHexViewerCharacter(line_mem[13]), 
                        toHexViewerCharacter(line_mem[14]), toHexViewerCharacter(line_mem[15]));
        }
        ImGui::End();*/
        
        uint8_t* heap_mem = (uint8_t*)vm_ptr_to_real_ptr(0x90000000);
        if (heap_mem)
            mem_edit1.DrawWindow("Heap Memory Viewer", heap_mem, 0x8000000, 0x90000000);
        
        uint8_t* virt_mem = (uint8_t*)vm_ptr_to_real_ptr(0x80000000);
        if (heap_mem)
            mem_edit2.DrawWindow("Virtual Memory Viewer", heap_mem, 0x10000000, 0x80000000);
            
        //if (image_mem)
        //    mem_edit3.DrawWindow("EXE Memory Viewer", image_mem, image_mem_size, image_mem_addr);
            
        /*uint8_t* stack_mem = (uint8_t*)vm_ptr_to_real_ptr(stack_addr);
        if (image_mem)
            mem_edit.DrawWindow("Stack Memory Viewer", stack_mem, stack_size, stack_addr);*/

        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
        ImGui::Render();
        //glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        
        //TODO: figure out a better way to handle this
        //if (gameTexDestroy)
           //    gameTexDestroy(gameTexDestroyArg);
        //hasDestroyedTex = true;

        SDL_GL_SwapWindow(renderWindow);

        if (gameOnVblank)
	        gameOnVblank(gameTexDestroyArg);
        pthread_cond_signal(&cond_vblank);
        pthread_mutex_unlock(&context_lock);
    }
   
    pthread_exit(NULL);
    return NULL;
}

int renderer_spawnthread(SDL_Window* window, SDL_Renderer* renderer, SDL_GLContext context)
{
    renderWindow = window;
    renderRenderer = renderer;
    renderContext = context;
    
    renderer_active = true;

    return pthread_create(&render_thread, NULL, renderer_thread, (void *)NULL);
}

int renderer_jointhread()
{
    void* status;
    
    renderer_active = false;
    
    pthread_cond_signal(&cond_update);
    pthread_mutex_destroy(&context_lock);
    return pthread_join(render_thread, &status);
}

void renderer_feedwindowinfo(std::string title, GLint texID, GLint palTexId, ImVec2 dims, void (*onTexDestroy)(void*), void (*onVblank)(void*), void* destroyExtra)
{
	last_game_ms = game_ms;
	game_ms = nmm->timeGetTime();

    pthread_mutex_lock(&context_lock);
    
    renderSync = glFenceSync(GL_SYNC_GPU_COMMANDS_COMPLETE, 0);
    glFlush();
    
    // If this function gets called before the last texture got freed, free it first
    if (!hasDestroyedTex && gameTexDestroy)
        gameTexDestroy(gameTexDestroyArg);
    hasDestroyedTex = false;
    
    gameTitle = title;
    gameTex = texID;
    gamePal = palTexId;
    gameDims = dims;
    gameTexDestroy = onTexDestroy;
    gameOnVblank = onVblank;
    gameTexDestroyArg = destroyExtra;
    gameRendering = true;
    
    pthread_cond_signal(&cond_update);
       
    pthread_mutex_unlock(&context_lock);
}


void renderer_waitforvblank()
{
    pthread_cond_signal(&cond_update);

    pthread_mutex_lock(&context_lock);
    pthread_cond_wait(&cond_vblank, &context_lock);
    pthread_mutex_unlock(&context_lock);
}

void renderer_print(std::string new_line)
{
    console += new_line;
}
