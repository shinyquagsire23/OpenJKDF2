#include "main.h"

#include <stdint.h>

#include <cstring>
#include <iostream>
#include <vector>

#include <QMetaMethod>
#include <QDebug>

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
IDirectPlay3 *idirectplay3;
IDirectPlayLobby3 *idirectplaylobby3;
IDirectSound *idirectsound;
IDirectInputA *idirectinputa;
SmackW32 *smackw32;

SDL_Window* displayWindow;
SDL_Renderer* displayRenderer;
SDL_RendererInfo displayRendererInfo;
SDL_Event event;

std::map<std::string, ImportTracker*> import_store;
std::map<std::string, QObject*> dll_store;
std::map<std::string, QObject*> interface_store;

std::map<std::string, std::map<std::string, int> > method_cache;

uint32_t import_get_hook_addr(std::string name)
{
    return import_store[name]->hook;
}

void register_import(std::string dll, std::string name, uint32_t import_addr)
{
    if (import_store[name]) return;

    import_store[name] = new ImportTracker(dll, name, import_addr, next_hook);
    
    auto obj = dll_store[dll];
    if (obj)
    {
        auto method = obj->metaObject()->method(method_cache[dll][name]);
        import_store[name]->method = method;
        import_store[name]->obj = obj;
        
        for (int i = 0; i < method.parameterCount(); i++)
        {
            char *param_type = (char*)method.parameterTypes()[i].data();
            if (param_type[strlen(param_type) - 1] == '*')
            {
                import_store[name]->is_param_ptr.push_back(true);
            }
            else 
            {
                import_store[name]->is_param_ptr.push_back(false);
            }
            
        }
    }

    next_hook += 1;
}

void *uc_ptr_to_real_ptr(uint32_t uc_ptr)
{
    if (uc_ptr == 0) return nullptr;

    if (uc_ptr >= image_mem_addr && uc_ptr <= image_mem_addr + image_mem_size + stack_size)
    {
        return image_mem + uc_ptr - image_mem_addr;
    }
    else if (uc_ptr >= kernel32->heap_addr && uc_ptr <= kernel32->heap_addr + kernel32->heap_size)
    {
        return kernel32->heap_mem + uc_ptr - kernel32->heap_addr;
    }
    else if (uc_ptr >= kernel32->virtual_addr && uc_ptr <= kernel32->virtual_addr + kernel32->virtual_size)
    {
        return kernel32->virtual_mem + uc_ptr - kernel32->virtual_addr;
    }
    else
    {
        printf("Could not convert uc ptr %x to real pointer\n", uc_ptr);
        return nullptr;
    }
}

uint32_t real_ptr_to_uc_ptr(void* real_ptr)
{
    if (real_ptr == nullptr) return 0;

    if (real_ptr >= image_mem && real_ptr <= image_mem + image_mem_size + stack_size)
    {
        return image_mem_addr + ((size_t)real_ptr - (size_t)image_mem);
    }
    else if (real_ptr >= kernel32->heap_mem && real_ptr <= kernel32->heap_mem + kernel32->heap_size)
    {
        return kernel32->heap_addr + ((size_t)real_ptr - (size_t)kernel32->heap_mem);
    }
    else if (real_ptr >= kernel32->virtual_mem && real_ptr <= kernel32->virtual_mem + kernel32->virtual_size)
    {
        return kernel32->virtual_addr + ((size_t)real_ptr - (size_t)kernel32->virtual_mem);
    }
    else
    {
        printf("Could not convert real ptr %p to Unicorn pointer\n", real_ptr);
        return 0;
    }
}

static void hook_test(uc_engine *uc, uint64_t address, uint32_t size)
{
    printf("Hook at %x\n", address);
    uc_print_regs(uc);
}

int main(int argc, char **argv, char **envp)
{
    struct vm_inst vm;

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
    idirectplay3 = new IDirectPlay3();
    idirectplaylobby3 = new IDirectPlayLobby3();
    idirectsound = new IDirectSound();
    idirectinputa = new IDirectInputA();
    smackw32 = new SmackW32();
    dll_store["KERNEL32.dll"] = (QObject*)kernel32;
    dll_store["USER32.dll"] = (QObject*)user32;
    dll_store["user32.dll"] = (QObject*)user32;
    dll_store["GDI32.dll"] = (QObject*)gdi32;
    dll_store["COMCTL32.dll"] = (QObject*)comctl32;
    dll_store["ADVAPI32.dll"] = (QObject*)advapi32;
    dll_store["ole32.dll"] = (QObject*)ole32;
    dll_store["__NMM.dll"] = (QObject*)nmm;
    dll_store["DDRAW.dll"] = (QObject*)ddraw;
    dll_store["DPLAYX.dll"] = (QObject*)dplay;
    dll_store["DSOUND.dll"] = (QObject*)dsound;
    dll_store["DINPUT.dll"] = (QObject*)dinput;
    dll_store["IDirectPlay3"] = (QObject*)idirectplay3;
    dll_store["IDirectPlayLobby3"] = (QObject*)idirectplaylobby3;
    dll_store["IDirectSound"] = (QObject*)idirectsound;
    dll_store["IDirectInputA"] = (QObject*)idirectinputa;
    dll_store["smackw32.DLL"] = (QObject*)smackw32;
    
    interface_store["IDirectPlay3"] = (QObject*)idirectplay3;
    interface_store["IDirectPlayLobby3"] = (QObject*)idirectplaylobby3;
    interface_store["IDirectSound"] = (QObject*)idirectsound;
    interface_store["IDirectInputA"] = (QObject*)idirectinputa;
    
    qRegisterMetaType<char*>("char*");
    qRegisterMetaType<char*>("uint32_t*");
    
    // Init SDL
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_NOPARACHUTE);

    SDL_CreateWindowAndRenderer(640, 480, 0, &displayWindow, &displayRenderer);
    SDL_GetRendererInfo(displayRenderer, &displayRendererInfo);
    SDL_SetRenderDrawBlendMode(displayRenderer, SDL_BLENDMODE_BLEND);
    
    printf("Caching functions\n");
    for (auto obj_pair : dll_store)
    {
        auto obj = obj_pair.second;
        for (int i = 0; i < obj->metaObject()->methodCount(); i++)
        {
            QMetaMethod method = obj->metaObject()->method(i);
            char* name = method.name().data();
            std::string strname = std::string(name);
            
            method_cache[obj_pair.first][strname] = i;
            printf("%s %s %i\n", obj_pair.first.c_str(), name, i);
        }
    }

    // Map hook mem
    next_hook = 0xd0000000;
    uint32_t start_addr = load_executable(&image_mem_addr, &image_mem, &image_mem_size, &stack_addr, &stack_size);
    
    register_import("dummy", "dummy", 0);
    //uc_hook trace;
    //uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_test, nullptr, 0x426838, 0x426838);

    vm_run(&vm, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, start_addr, 0, 0);
    //uc_run(uc, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, start_addr, 0, 0);

    return 0;
}
