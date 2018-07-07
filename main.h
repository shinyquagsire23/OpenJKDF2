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
#include "dlls/ddraw.h"

class ImportTracker
{
public:
    std::string name;
    uint32_t addr;
    uint32_t hook;
    
    uc_hook trace;

    ImportTracker(std::string name, uint32_t addr, uint32_t hook) : name(name), addr(addr), hook(hook)
    {
    }
};

extern std::map<std::string, ImportTracker*> import_store;

extern Kernel32 *kernel32;
extern User32 *user32;
extern Gdi32 *gdi32;
extern ComCtl32 *comctl32;
extern AdvApi32 *advapi32;
extern Ole32 *ole32;
extern DDraw *ddraw;

void register_import(std::string name, uint32_t import_addr);
void sync_imports(uc_engine *uc);
void print_registers(uc_engine *uc);
std::string uc_read_string(uc_engine *uc, uint32_t addr);
std::string uc_read_wstring(uc_engine *uc, uint32_t addr);
void uc_stack_pop(uc_engine *uc, uint32_t *out, int num);
void uc_stack_push(uc_engine *uc, uint32_t *in, int num);

#endif // MAIN_H
