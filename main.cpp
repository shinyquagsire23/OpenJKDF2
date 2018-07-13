#include "main.h"

#include <stdint.h>

#include <cstring>
#include <iostream>
#include <vector>

#include <QMetaMethod>
#include <QDebug>

#include "loaders/exe.h"
#include "uc_utils.h"

uint32_t image_mem_addr;
void* image_mem;
uint32_t image_mem_size;
uint32_t stack_size, stack_addr;

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

static void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ImportTracker *import);

uint32_t import_get_hook_addr(std::string name)
{
    return import_store[name]->hook;
}

void register_import(std::string dll, std::string name, uint32_t import_addr)
{
    import_store[name] = new ImportTracker(dll, name, import_addr, next_hook);

    next_hook += 1;
}

void sync_imports(uc_engine *uc)
{
    for (auto pair : import_store)
    {
        auto import = pair.second;
        
        if (import->addr)
            uc_mem_write(uc, import->addr, &import->hook, sizeof(uint32_t));
        
        uc_mem_map(uc, import->hook, 0x1000, UC_PROT_ALL);
        uc_hook_add(uc, &import->trace, UC_HOOK_CODE, (void*)hook_import, (void*)import, import->hook, import->hook);
    }
}

void *uc_ptr_to_real_ptr(uint32_t uc_ptr)
{
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

QGenericArgument q_args[9];
static void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ImportTracker *import)
{
    uint32_t ret_addr;
    uc_stack_pop(uc, &ret_addr, 1);
    
    //printf("Hit import %s, ret %x\n", import->name.c_str(), ret_addr);
    
    //TODO DLL names
    
    auto obj = dll_store[import->dll];
    if (obj)
    {
        for (int i = 0; i < obj->metaObject()->methodCount(); i++)
        {
            QMetaMethod method = obj->metaObject()->method(i);
            //qDebug() << method.methodSignature();
            
            if (method.name() == import->name.c_str() && method.parameterCount() <= 9)
            {
                void* trans_args[9];
                uint32_t args[9];
                uint32_t retVal;
                
                uc_stack_pop(uc, args, method.parameterCount());
                
                // Translate args from Unicorn pointers to usable pointers
                char* idk;
                for (int j = 0; j < method.parameterCount(); j++)
                {
                    char *param_type = (char*)method.parameterTypes()[j].data();
                    if (param_type[strlen(param_type) - 1] == '*')
                    {
                        trans_args[j] = uc_ptr_to_real_ptr(args[j]);
                        q_args[j] = QGenericArgument(method.parameterTypes()[j], &trans_args[j]);
                    }
                    else 
                    {
                        q_args[j] = Q_ARG(uint32_t, args[j]);
                    }
                }
                
                bool succ;
                if (method.returnType() == QMetaType::Void)
                    succ = method.invoke(obj, q_args[0], q_args[1], q_args[2], q_args[3], q_args[4], q_args[5], q_args[6], q_args[7], q_args[8]);
                else
                    succ = method.invoke(obj, Q_RETURN_ARG(uint32_t, retVal), q_args[0], q_args[1], q_args[2], q_args[3], q_args[4], q_args[5], q_args[6], q_args[7], q_args[8]);

                //printf("%x %x %x\n", succ, retVal, method.parameterCount());
                if (succ)
                {
                    if (method.returnType() != QMetaType::Void)
                        uc_reg_write(uc, UC_X86_REG_EAX, &retVal);

                    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
                    return;
                }
                else
                {
                    uc_stack_push(uc, args, method.parameterCount());
                }
            }
        }
    }
    
    
    if (!strcmp(import->name.c_str(), "IsProcessorFeaturePresent"))
    {
        uint32_t args[1];
        uint32_t eax;
        
        uc_stack_pop(uc, args, 1); //TODO: real handles
        
        eax = 0;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }
    else if (!strcmp(import->name.c_str(), "CreateWindowExA"))
    {
        uint32_t args[12];
        uint32_t eax;
        
        uc_stack_pop(uc, args, 12); //TODO
        
        eax = user32->CreateWindowExA(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }
    else if (!strcmp(import->name.c_str(), "CreateFontA"))
    {
        uint32_t args[14];
        uint32_t eax;
        
        uc_stack_pop(uc, args, 14); //TODO
        
        //int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t    cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName
        eax = gdi32->CreateFontA(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], (char*)uc_ptr_to_real_ptr(args[13]));
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }
    else
    {
        printf("Import %s from %s doesn't have impl, exiting\n", import->name.c_str(), import->dll.c_str());
        uc_emu_stop(uc);
        return;
    }
    
    uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
}

uint32_t call_function(uint32_t addr, uint32_t num_args, uint32_t* args, bool push_ret)
{
    uc_engine *uc_new;
    uint32_t esp, eax, dummy;

    dummy = import_store["dummy"]->hook;

    uc_stack_push(current_uc, args, num_args);
    if (push_ret)
        uc_stack_push(current_uc, &dummy, 1);
    uc_reg_read(current_uc, UC_X86_REG_ESP, &esp);

    eax = uc_run(uc_new, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, addr, dummy, esp);
    if (push_ret)
        uc_stack_pop(current_uc, &dummy, 1);
    uc_stack_pop(current_uc, args, num_args);

    return eax;
}

static void hook_test(uc_engine *uc, uint64_t address, uint32_t size)
{
    printf("Hook at %x\n", address);
    uc_print_regs(uc);
}

int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;

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

    
    // Map hook mem
    next_hook = 0xd0000000;
    uint32_t start_addr = load_executable(&image_mem_addr, &image_mem, &image_mem_size, &stack_addr, &stack_size);
    
    register_import("dummy", "dummy", 0);
    //uc_hook trace;
    //uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_test, nullptr, 0x426838, 0x426838);

    uc_run(uc, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, start_addr, 0, 0);

    return 0;
}
