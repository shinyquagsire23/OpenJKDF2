#include "main.h"

#include <stdint.h>

#include <cstring>
#include <iostream>
#include <vector>

#include <QMetaMethod>
#include <QDebug>

#include <GL/glew.h>
#include <SDL2/SDL_mixer.h>

#include "dlls/kernel32.h"
#include "dlls/user32.h"
#include "dlls/gdi32.h"
#include "dlls/comctl32.h"
#include "dlls/advapi32.h"
#include "dlls/ole32.h"
#include "dlls/nmm.h"
#include "dlls/ddraw/ddraw.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include "dlls/ddraw/IDirectDrawSurface3.h"
#include "dlls/ddraw/IDirectDrawPalette.h"
#include "dlls/ddraw/IDirect3D3.h"
#include "dlls/ddraw/IDirect3DDevice.h"
#include "dlls/ddraw/IDirect3DTexture.h"
#include "dlls/ddraw/IDirect3DViewport.h"
#include "dlls/ddraw/IDirect3DExecuteBuffer.h"
#include "dlls/dsound/dsound.h"
#include "dlls/dplay/dplay.h"
#include "dlls/dinput/dinput.h"
#include "dlls/dplay/IDirectPlay3.h"
#include "dlls/dplay/IDirectPlayLobby3.h"
#include "dlls/dsound/IDirectSound.h"
#include "dlls/dsound/IDirectSoundBuffer.h"
#include "dlls/dinput/IDirectInputA.h"
#include "dlls/dinput/IDirectInputDeviceA.h"
#include "dlls/smackw32.h"
#include "dlls/msvcrt.h"
#include "dlls/jk.h"

#include "3rdparty/imgui/imgui.h"
#include "3rdparty/imgui/imgui_impl_sdl.h"
#include "3rdparty/imgui/imgui_impl_opengl3.h"

#include "loaders/exe.h"
#include "uc_utils.h"
#include "vm.h"

uint32_t next_hook;

Kernel32 *kernel32;
User32 *user32;
Gdi32 *gdi32;
ComCtl32 *comctl32;
AdvApi32 *advapi32;
Ole32 *ole32;
Nmm *nmm;
DDraw *ddraw;
DSound *dsound;
DPlay *dplay;
DInput *dinput;
IDirect3D3 *idirect3d3;
IDirect3DDevice *idirect3ddevice;
IDirect3DTexture *idirect3dtexture;
IDirect3DViewport *idirect3dviewport;
IDirect3DExecuteBuffer *idirect3dexecutebuffer;
IDirectDraw4 *idirectdraw4;
IDirectDrawSurface3 *idirectdrawsurface3;
IDirectDrawPalette *idirectdrawpalette;
IDirectPlay3 *idirectplay3;
IDirectPlayLobby3 *idirectplaylobby3;
IDirectSound *idirectsound;
IDirectInputA *idirectinputa;
IDirectInputDeviceA* idirectinputdevicea;
IDirectSoundBuffer *idirectsoundbuffer;
SmackW32 *smackw32;
Msvcrt *msvcrt;
JK *jk;

ImGuiIO io;
SDL_Window* displayWindow;
SDL_Renderer* displayRenderer;
SDL_RendererInfo displayRendererInfo;
SDL_Event event;

std::map<std::string, ImportTracker*> import_store;
std::map<std::string, QObject*> dll_store;
std::map<std::string, QObject*> interface_store;

std::map<std::string, std::map<std::string, int> > method_cache;

uint32_t import_get_hook_addr(std::string dll, std::string name)
{
    std::string import_name = dll + "::" + name;
    return import_store[import_name]->hook;
}

void register_hook(std::string dll, std::string name, uint32_t hook_addr)
{
    std::string import_name = dll + "::" + name;

    if (import_store[import_name]) return;

    import_store[import_name] = new ImportTracker(dll, name, 0, hook_addr);
    import_store[import_name]->is_hook = true;

    // Write UND instruction for VM hook
    vm_ptr<uint8_t*> und_write = {hook_addr};
    und_write.translated()[0] = 0x0f;
    und_write.translated()[1] = 0x0b;

    auto obj = dll_store[dll];
    if (obj && method_cache[dll].find(name) != method_cache[dll].end())
    {
        auto method = obj->metaObject()->method(method_cache[dll][name]);
        import_store[import_name]->method = method;
        import_store[import_name]->obj = obj;
        
        for (int i = 0; i < method.parameterCount(); i++)
        {
            if (method.parameterTypes()[i].data()[strlen(method.parameterTypes()[i].data()) - 1] == '*')
            {
                import_store[import_name]->is_param_ptr.push_back(true);
            }
            else 
            {
                import_store[import_name]->is_param_ptr.push_back(false);
            }
            
        }
    }

    next_hook += 1;
}


void register_import(std::string dll, std::string name, uint32_t import_addr)
{
    std::string import_name = dll + "::" + name;

    if (import_store[import_name]) return;

    import_store[import_name] = new ImportTracker(dll, name, import_addr, next_hook);
    
    auto obj = dll_store[dll];
    if (obj && method_cache[dll].find(name) != method_cache[dll].end())
    {
        auto method = obj->metaObject()->method(method_cache[dll][name]);
        import_store[import_name]->method = method;
        import_store[import_name]->obj = obj;
        
        for (int i = 0; i < method.parameterCount(); i++)
        {
            if (method.parameterTypes()[i].data()[strlen(method.parameterTypes()[i].data()) - 1] == '*')
            {
                import_store[import_name]->is_param_ptr.push_back(true);
            }
            else 
            {
                import_store[import_name]->is_param_ptr.push_back(false);
            }
            
        }
    }

    next_hook += 1;
}

static void hook_test(uc_engine *uc, uint64_t address, uint32_t size)
{
    printf("Hook at %x\n", address);
    uc_print_regs(uc);
}

void GLAPIENTRY glMessageCallback(GLenum source,
                 GLenum type,
                 GLuint id,
                 GLenum severity,
                 GLsizei length,
                 const GLchar* message,
                 const void* userParam)
{
    fprintf( stderr, "GL CALLBACK: %s type = 0x%x, severity = 0x%x, message = %s\n",
           (type == GL_DEBUG_TYPE_ERROR ? "** GL ERROR **" : ""),
            type, severity, message);
}

int main(int argc, char **argv, char **envp)
{
    struct vm_inst vm;
    bool no_jk_hax = false;
    bool do_memdump = false;
    bool force_swrend = false;
    
    if (argc < 2)
    {
        printf("Usage: %s [options] <to_run.exe>\n", argv[0]);
        printf("\n");
        printf("Options:\n");
        printf("-forceswrend        Sets DirectDrawCreate to error, forcing GDI32 rendering\n");
        printf("-nojk               Disable JK.EXE hacks\n");
        printf("-memdump            Dump memory before exiting\n");
        printf("-cwd <path>         Change current working directory\n");
        return 0;
    }

    // Parse arguments
    char* exe_path = argv[argc-1];
    for (int i = 1; i < argc-1; i++)
    {
        if (!strcmp(argv[i], "-forceswrend"))
        {
            force_swrend = true;
        }
        
        if (!strcmp(argv[i], "-nojk"))
        {
            no_jk_hax = true;
        }
        
        if (!strcmp(argv[i], "-memdump"))
        {
            do_memdump = true;
        }
        
        if (!strcmp(argv[i], "-cwd"))
        {
            chdir(argv[i+1]);
            i++;
        }
    }

    // Init SDL
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_NOPARACHUTE);

    SDL_CreateWindowAndRenderer(640*2, 480*2, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE, &displayWindow, &displayRenderer);
    SDL_GetRendererInfo(displayRenderer, &displayRendererInfo);
    SDL_SetRenderDrawBlendMode(displayRenderer, SDL_BLENDMODE_BLEND);
    
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
	//SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	
	SDL_GLContext gl_context = SDL_GL_CreateContext(displayWindow);
	if (gl_context == NULL)
		return EXIT_FAILURE;
		
    SDL_GL_MakeCurrent(displayWindow, gl_context);
    SDL_GL_SetSwapInterval(1); // Enable vsync
	
	if (Mix_OpenAudio(48000, AUDIO_S16SYS, 2, 1024) < 0)
	    return EXIT_FAILURE;

	Mix_AllocateChannels(32);

	GLenum glew_status = glewInit();
	if (glew_status != GLEW_OK)
		return -1;

	if (!GLEW_VERSION_2_0)
		return -1;

    glEnable(GL_DEBUG_OUTPUT);
    glDebugMessageCallback(glMessageCallback, 0);

    // Set up DLL classes
    kernel32 = new Kernel32();
    user32 = new User32();
    gdi32 = new Gdi32();
    comctl32 = new ComCtl32();
    advapi32 = new AdvApi32();
    ole32 = new Ole32();
    nmm = new Nmm();
    ddraw = new DDraw();
    dplay = new DPlay();
    dsound = new DSound();
    dinput = new DInput();
    idirectdraw4 = new IDirectDraw4();
    idirectdrawsurface3 = new IDirectDrawSurface3();
    idirectdrawpalette = new IDirectDrawPalette();
    idirect3d3 = new IDirect3D3();
    idirect3ddevice = new IDirect3DDevice();
    idirect3dtexture = new IDirect3DTexture();
    idirect3dviewport = new IDirect3DViewport();
    idirect3dexecutebuffer = new IDirect3DExecuteBuffer();
    idirectplay3 = new IDirectPlay3();
    idirectplaylobby3 = new IDirectPlayLobby3();
    idirectsound = new IDirectSound();
    idirectsoundbuffer = new IDirectSoundBuffer();
    idirectinputa = new IDirectInputA();
    idirectinputdevicea = new IDirectInputDeviceA();
    smackw32 = new SmackW32();
    msvcrt = new Msvcrt();    
    jk = new JK();

    dll_store["KERNEL32.dll"] = (QObject*)kernel32;
    dll_store["USER32.dll"] = (QObject*)user32;
    dll_store["user32.dll"] = (QObject*)user32;
    dll_store["GDI32.dll"] = (QObject*)gdi32;
    dll_store["COMCTL32.dll"] = (QObject*)comctl32;
    dll_store["ADVAPI32.dll"] = (QObject*)advapi32;
    dll_store["ole32.dll"] = (QObject*)ole32;
    dll_store["__NMM.dll"] = (QObject*)nmm;
    dll_store["WINMM.dll"] = (QObject*)nmm;
    dll_store["DDRAW.dll"] = (QObject*)ddraw;
    dll_store["DPLAYX.dll"] = (QObject*)dplay;
    dll_store["DSOUND.dll"] = (QObject*)dsound;
    dll_store["DINPUT.dll"] = (QObject*)dinput;
    dll_store["IDirect3D3"] = (QObject*)idirect3d3;
    dll_store["IDirect3DDevice"] = (QObject*)idirect3ddevice;
    dll_store["IDirect3DTexture"] = (QObject*)idirect3dtexture;
    dll_store["IDirect3DViewport"] = (QObject*)idirect3dviewport;
    dll_store["IDirect3DExecuteBuffer"] = (QObject*)idirect3dexecutebuffer;
    dll_store["IDirectDraw4"] = (QObject*)idirectdraw4;
    dll_store["IDirectDrawSurface3"] = (QObject*)idirectdrawsurface3;
    dll_store["IDirectDrawPalette"] = (QObject*)idirectdrawpalette;
    dll_store["IDirectPlay3"] = (QObject*)idirectplay3;
    dll_store["IDirectPlayLobby3"] = (QObject*)idirectplaylobby3;
    dll_store["IDirectSound"] = (QObject*)idirectsound;
    dll_store["IDirectSoundBuffer"] = (QObject*)idirectsoundbuffer;
    dll_store["IDirectInputA"] = (QObject*)idirectinputa;
    dll_store["IDirectInputDeviceA"] = (QObject*)idirectinputdevicea;
    dll_store["smackw32.DLL"] = (QObject*)smackw32;
    dll_store["msvcrt.dll"] = (QObject*)msvcrt;
    dll_store["JK.EXE"] = (QObject*)jk;
    
    interface_store["IDirect3D3"] = (QObject*)idirect3d3;
    interface_store["IDirect3DDevice"] = (QObject*)idirect3ddevice;
    interface_store["IDirect3DTexture"] = (QObject*)idirect3dtexture;
    interface_store["IDirect3DViewport"] = (QObject*)idirect3dviewport;
    interface_store["IDirect3DExecuteBuffer"] = (QObject*)idirect3dexecutebuffer;
    interface_store["IDirectDraw4"] = (QObject*)idirectdraw4;
    interface_store["IDirectDrawSurface3"] = (QObject*)idirectdrawsurface3;
    interface_store["IDirectDrawPalette"] = (QObject*)idirectdrawpalette;
    interface_store["IDirectPlay3"] = (QObject*)idirectplay3;
    interface_store["IDirectPlayLobby3"] = (QObject*)idirectplaylobby3;
    interface_store["IDirectSound"] = (QObject*)idirectsound;
    interface_store["IDirectSoundBuffer"] = (QObject*)idirectsoundbuffer;
    interface_store["IDirectInputA"] = (QObject*)idirectinputa;
    interface_store["IDirectInputDeviceA"] = (QObject*)idirectinputdevicea;
    
    qRegisterMetaType<char*>("char*");
    qRegisterMetaType<uint32_t*>("uint32_t*");
    
    printf("Caching functions\n");
    for (auto obj_pair : dll_store)
    {
        auto obj = obj_pair.second;
        for (int i = 0; i < obj->metaObject()->methodCount(); i++)
        {
            QMetaMethod method = obj->metaObject()->method(i);
            std::string strname = std::string(method.name().data());
            
            method_cache[obj_pair.first][strname] = i;
            //printf("%s %s %i\n", obj_pair.first.c_str(), name, i);
        }
    }

    // Map hook mem
    next_hook = 0xd0000000;
    uint32_t start_addr = load_executable(exe_path, &image_mem_addr, &image_mem, &image_mem_size, &stack_addr, &stack_size);
    
    // Apply options
    ddraw->force_error = force_swrend ? 1 : 0;
    
    // Hook JK
    if (!no_jk_hax)
    {
        jk->hook();
    }
    
    // Hook DLLs
    msvcrt->hook();
    
    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    io = ImGui::GetIO(); (void)io;
    //io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    //io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsClassic();

    // Setup Platform/Renderer bindings
    ImGui_ImplSDL2_InitForOpenGL(displayWindow, gl_context);
    ImGui_ImplOpenGL3_Init("#version 120");

    // Start VM
    register_import("dummy", "dummy", 0);
    vm_run(&vm, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, start_addr, 0, 0);
    
#if 0
    for (int i = 0; i < 2; i++)
    {
        uint32_t base = 0x522BF8; // 0x90518470
        uint32_t stride = 0x30;
        
        if (i == 1)
            base = 0x8605DC-stride;
        
        printf("%08x\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x\n", 
        base+stride*i,
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i), 
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+4), 
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+8),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0xC),        
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x10),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x14),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x18),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x1C),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x20),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x24), 
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x28),
        *(uint32_t*)vm_ptr_to_real_ptr(base+stride*i+0x2C));
    }
#endif

    // Post-VM dumps and cleanup
    if (do_memdump)
    {
        FILE* dump1 = fopen("heap_dump.bin", "wb");
        fwrite(kernel32->heap_mem, kernel32->heap_size_actual, 1, dump1);
        fclose(dump1);
        
        FILE* dump2 = fopen("mem_dump.bin", "wb");
        fwrite(image_mem, image_mem_size, 1, dump2);
        fclose(dump2);
        
        FILE* dump3 = fopen("stack_dump.bin", "wb");
        fwrite(image_mem + image_mem_size, stack_size, 1, dump3);
        fclose(dump3);
        
        FILE* dump4 = fopen("virt_dump.bin", "wb");
        fwrite(kernel32->virtual_mem, kernel32->virtual_size_actual, 1, dump4);
        fclose(dump4);
    }
    
    Mix_CloseAudio();
    
    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    
    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(displayWindow);
    SDL_Quit();

    return 0;
}
