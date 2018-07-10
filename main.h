#ifndef MAIN_H
#define MAIN_H

#include <unicorn/unicorn.h>
#include <stdint.h>

#include <map>
#include <string>

#include "dlls/kernel32.h"
#include "dlls/user32.h"
#include "dlls/gdi32.h"
#include "dlls/comctl32.h"
#include "dlls/advapi32.h"
#include "dlls/ole32.h"
#include "dlls/nmm.h"
#include "dlls/ddraw.h"
#include "dlls/dsound/dsound.h"
#include "dlls/dinput/dinput.h"
#include "dlls/dplay/IDirectPlay3.h"
#include "dlls/dsound/IDirectSound.h"
#include "dlls/dinput/IDirectInputA.h"

class ImportTracker
{
public:
    std::string dll;
    std::string name;
    uint32_t addr;
    uint32_t hook;
    
    uc_hook trace;

    ImportTracker(std::string dll, std::string name, uint32_t addr, uint32_t hook) : dll(dll), name(name), addr(addr), hook(hook)
    {
    }
};

extern std::map<std::string, ImportTracker*> import_store;
extern std::map<std::string, QObject*> interface_store;

extern Kernel32 *kernel32;
extern User32 *user32;
extern Gdi32 *gdi32;
extern ComCtl32 *comctl32;
extern AdvApi32 *advapi32;
extern Ole32 *ole32;
extern Nmm *nmm;
extern DDraw *ddraw;
extern IDirectPlay3 *idirectplay3;
extern IDirectSound* idirectsound;
extern IDirectInputA* idirectinputa;
extern DSound* dsound;
extern DInput* dinput;

void *uc_ptr_to_real_ptr(uint32_t uc_ptr);
uint32_t real_ptr_to_uc_ptr(void* real_ptr);
uint32_t import_get_hook_addr(std::string name);
void register_import(std::string dll, std::string name, uint32_t import_addr);
void sync_imports(uc_engine *uc);

uint32_t call_function(uint32_t addr, uint32_t num_args, uint32_t* args);

#endif // MAIN_H
