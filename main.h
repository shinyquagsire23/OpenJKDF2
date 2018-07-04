#ifndef MAIN_H
#define MAIN_H

#include <unicorn/unicorn.h>
#include <stdint.h>

#include <map>
#include <string>


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

void register_import(uc_engine *uc, std::string name, uint32_t import_addr);
void print_registers(uc_engine *uc);
std::string uc_read_string(uc_engine *uc, uint32_t addr);
std::string uc_read_wstring(uc_engine *uc, uint32_t addr);

#endif // MAIN_H
