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
#include "renderer.h"

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

SDL_Window* displayWindow;
SDL_Renderer* displayRenderer;
SDL_RendererInfo displayRendererInfo;
SDL_Event event;
SDL_GLContext glWindowContext, glVmContext;

void GLAPIENTRY glMessageCallback(GLenum source,
                 GLenum type,
                 GLuint id,
                 GLenum severity,
                 GLsizei length,
                 const GLchar* message,
                 const void* userParam)
{
    /*fprintf( stderr, "GL CALLBACK: %s type = 0x%x, severity = 0x%x, message = %s\n",
           (type == GL_DEBUG_TYPE_ERROR ? "** GL ERROR **" : ""),
            type, severity, message);*/
}


int init_renderer()
{
	int retval = 0;

	// Init SDL
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_NOPARACHUTE);

    SDL_CreateWindowAndRenderer(640*2, 480*2, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE, &displayWindow, &displayRenderer);
    SDL_GetRendererInfo(displayRenderer, &displayRendererInfo);
    SDL_SetRenderDrawBlendMode(displayRenderer, SDL_BLENDMODE_BLEND);
    
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
	//SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	
	SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
	glWindowContext = SDL_GL_CreateContext(displayWindow);
	glVmContext = SDL_GL_CreateContext(displayWindow);
	if (glWindowContext == NULL || glVmContext == NULL)
		return EXIT_FAILURE;
		
    SDL_GL_MakeCurrent(displayWindow, glWindowContext);
    SDL_GL_SetSwapInterval(0); // Enable vsync

	GLenum glew_status = glewInit();
	if (glew_status != GLEW_OK)
		return EXIT_FAILURE;

	if (!GLEW_VERSION_2_0)
		return EXIT_FAILURE;

    glEnable(GL_DEBUG_OUTPUT);
    glDebugMessageCallback(glMessageCallback, 0);
    
    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    
    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsClassic();

    // Setup Platform/Renderer bindings
    ImGui_ImplSDL2_InitForOpenGL(displayWindow, glWindowContext);
    ImGui_ImplOpenGL3_Init("#version 120");
    
    // Begin the render thread
    retval = renderer_spawnthread(displayWindow, displayRenderer, glWindowContext);
    if (retval)
    {
    	printf("Failed to create render thread! Retval %i\n", retval);
    	return EXIT_FAILURE;
    }
    
    // Switch to the VM context
    SDL_GL_MakeCurrent(displayWindow, glVmContext);
    
    return 0;
}

int init_audio()
{
	if (Mix_OpenAudio(48000, AUDIO_S16SYS, 2, 1024) < 0)
	    return EXIT_FAILURE;

	Mix_AllocateChannels(32);
	
	return 0;
}

int deinit_audio()
{
    Mix_CloseAudio();
    
    return 0;
}

int deinit_renderer()
{
	int retval = 0;
	
	retval = renderer_jointhread();
	if (retval)
	{
		printf("Failed to join render thread...\n");
	}

	ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    
    SDL_GL_DeleteContext(glWindowContext);
    SDL_GL_DeleteContext(glVmContext);
    SDL_DestroyWindow(displayWindow);
    SDL_Quit();

	return 0;
}

int main(int argc, char **argv, char **envp)
{
	int retval;
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

    retval = init_renderer();
    if (retval) return retval;
    
    retval = init_audio();
    if (retval) return retval;

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
    //jk = new JK();

    vm_dll_register("KERNEL32.dll", (QObject*)kernel32);
    vm_dll_register("USER32.dll", (QObject*)user32);
    vm_dll_register("user32.dll", (QObject*)user32);
    vm_dll_register("GDI32.dll", (QObject*)gdi32);
    vm_dll_register("COMCTL32.dll", (QObject*)comctl32);
    vm_dll_register("ADVAPI32.dll", (QObject*)advapi32);
    vm_dll_register("ole32.dll", (QObject*)ole32);
    vm_dll_register("__NMM.dll", (QObject*)nmm);
    vm_dll_register("WINMM.dll", (QObject*)nmm);
    vm_dll_register("DDRAW.dll", (QObject*)ddraw);
    vm_dll_register("DPLAYX.dll", (QObject*)dplay);
    vm_dll_register("DSOUND.dll", (QObject*)dsound);
    vm_dll_register("DINPUT.dll", (QObject*)dinput);
    vm_dll_register("IDirect3D3", (QObject*)idirect3d3);
    vm_dll_register("IDirect3DDevice", (QObject*)idirect3ddevice);
    vm_dll_register("IDirect3DTexture", (QObject*)idirect3dtexture);
    vm_dll_register("IDirect3DViewport", (QObject*)idirect3dviewport);
    vm_dll_register("IDirect3DExecuteBuffer", (QObject*)idirect3dexecutebuffer);
    vm_dll_register("IDirectDraw4", (QObject*)idirectdraw4);
    vm_dll_register("IDirectDrawSurface3", (QObject*)idirectdrawsurface3);
    vm_dll_register("IDirectDrawPalette", (QObject*)idirectdrawpalette);
    vm_dll_register("IDirectPlay3", (QObject*)idirectplay3);
    vm_dll_register("IDirectPlayLobby3", (QObject*)idirectplaylobby3);
    vm_dll_register("IDirectSound", (QObject*)idirectsound);
    vm_dll_register("IDirectSoundBuffer", (QObject*)idirectsoundbuffer);
    vm_dll_register("IDirectInputA", (QObject*)idirectinputa);
    vm_dll_register("IDirectInputDeviceA", (QObject*)idirectinputdevicea);
    vm_dll_register("smackw32.DLL", (QObject*)smackw32);
    vm_dll_register("msvcrt.dll", (QObject*)msvcrt);
    //vm_dll_register("JK.EXE", (QObject*)jk);
    
    vm_interface_register("IDirect3D3", (QObject*)idirect3d3);
    vm_interface_register("IDirect3DDevice", (QObject*)idirect3ddevice);
    vm_interface_register("IDirect3DTexture", (QObject*)idirect3dtexture);
    vm_interface_register("IDirect3DViewport", (QObject*)idirect3dviewport);
    vm_interface_register("IDirect3DExecuteBuffer", (QObject*)idirect3dexecutebuffer);
    vm_interface_register("IDirectDraw4", (QObject*)idirectdraw4);
    vm_interface_register("IDirectDrawSurface3", (QObject*)idirectdrawsurface3);
    vm_interface_register("IDirectDrawPalette", (QObject*)idirectdrawpalette);
    vm_interface_register("IDirectPlay3", (QObject*)idirectplay3);
    vm_interface_register("IDirectPlayLobby3", (QObject*)idirectplaylobby3);
    vm_interface_register("IDirectSound", (QObject*)idirectsound);
    vm_interface_register("IDirectSoundBuffer", (QObject*)idirectsoundbuffer);
    vm_interface_register("IDirectInputA", (QObject*)idirectinputa);
    vm_interface_register("IDirectInputDeviceA", (QObject*)idirectinputdevicea);
    
    qRegisterMetaType<char*>("char*");
    qRegisterMetaType<uint32_t*>("uint32_t*");
    
    vm_cache_functions();

    // Map hook mem
    vm_set_hookmem(0xd0000000);
    PortableExecutable exe = PortableExecutable(std::string(exe_path), 0);
    uint32_t exe_addr, exe_size;
    void* exe_mem;
    uint32_t start_addr = exe.load_executable(&exe_addr, &exe_mem, &exe_size, &stack_addr, &stack_size);
    vm_register_image(exe_mem, exe_addr, exe_size+stack_size);
#if 1    
    PortableExecutable replace = PortableExecutable("df2_reimpl_kvm.dll", stack_addr + stack_size); // "SMACKW32.DLL"
#endif
    uint32_t dll_addr,dll_size,dll_stackaddr,dll_stacksize;
    void* dll_mem;
#if 1
    printf("Loading dlls...\n");
    uint32_t dllentry = replace.load_executable(&dll_addr, &dll_mem, &dll_size, &dll_stackaddr, &dll_stacksize);
    vm_register_image(dll_mem, dll_addr, dll_size+dll_stacksize);
#endif
    exe.load_imports();
#if 1
    replace.load_imports();
#endif
    printf("Done loading\n");
    
    // Apply options
    ddraw->force_error = force_swrend ? 1 : 0;
    
    // Hook JK
    /*if (!no_jk_hax)
    {
        jk->hook();
    }*/
    
    // Hook DLLs
    msvcrt->hook();
    
    // Start VM
    vm_import_register("dummy", "dummy", 0);
    
    //printf("jump to %08x\n", dllentry);
    uint32_t dllmain_args[3] = {1,1,1};
    
    uint32_t esp_dll = stack_addr+stack_size-0x10;
    *(uint32_t*)vm_ptr_to_real_ptr(esp_dll) = 0xF00FF00F;
    *(uint32_t*)vm_ptr_to_real_ptr(esp_dll+4) = 1;
    *(uint32_t*)vm_ptr_to_real_ptr(esp_dll+8) = 1;
    *(uint32_t*)vm_ptr_to_real_ptr(esp_dll+12) = 1;
#if 1
    //*(uint8_t*)vm_ptr_to_real_ptr(0x40880B - 0x401000 + 0x9f6000) = 0x0f;
    //*(uint8_t*)vm_ptr_to_real_ptr(0x40880C - 0x401000 + 0x9f6000) = 0x0b;
    if (!no_jk_hax)
        vm_run(&vm, stack_addr, stack_size, dllentry, 0, esp_dll);
#endif
    printf("asdf\n");
    
    memset(vm_ptr_to_real_ptr(stack_addr), 0, stack_size);
    
    
    //*(uint8_t*)vm_ptr_to_real_ptr(0x513a00 ) = 0x0f;
    //*(uint8_t*)vm_ptr_to_real_ptr(0x513a00+1) = 0x0b;
    
    esp_dll = stack_addr+stack_size-0x4;
    *(uint32_t*)vm_ptr_to_real_ptr(esp_dll) = 0xF00FF00F;
    vm_run(&vm, stack_addr, stack_size, start_addr, 0, esp_dll);
    
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

    {
        FILE* dump3 = fopen("stack_dump.bin", "wb");
        fwrite((void*)((intptr_t)exe_mem + exe_size), stack_size, 1, dump3);
        fclose(dump3);
    }

    // Post-VM dumps and cleanup
    if (do_memdump)
    {
        FILE* dump1 = fopen("heap_dump.bin", "wb");
        fwrite(kernel32->heap_mem, kernel32->heap_size_actual, 1, dump1);
        fclose(dump1);
        
        FILE* dump2 = fopen("mem_dump.bin", "wb");
        fwrite(exe_mem, exe_size, 1, dump2);
        fclose(dump2);
        
        FILE* dump3 = fopen("stack_dump.bin", "wb");
        fwrite((void*)((intptr_t)exe_mem + exe_size), stack_size, 1, dump3);
        fclose(dump3);
        
        FILE* dump4 = fopen("virt_dump.bin", "wb");
        fwrite(kernel32->virtual_mem, kernel32->virtual_size_actual, 1, dump4);
        fclose(dump4);
    }
    
    // Cleanup
    deinit_audio();
    deinit_renderer();

    return 0;
}
