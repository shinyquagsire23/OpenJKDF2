#ifndef MSVCRT_H
#define MSVCRT_H

#include <QObject>
#include "dlls/kernel32.h"
#include "main.h"
#include "vm.h"

char* strstr_wrap(char* a, char* b);
int atoi_wrap(char* str);
float floor_wrap(float a);

class Msvcrt : public QObject
{
Q_OBJECT

public:

    uint32_t stash;

    Q_INVOKABLE Msvcrt() 
    {
        stash = kernel32->VirtualAlloc(0, 0x1000, 0, 0);

    }
    
    void hook()
    {
        ImportTracker* adjust_fdiv_import = import_store["msvcrt.dll::_adjust_fdiv"];
        ImportTracker* acmdln_import = import_store["msvcrt.dll::_acmdln"];
        
        if (!adjust_fdiv_import || !acmdln_import) return;

        vm_ptr<uint32_t*> import_ptr = {adjust_fdiv_import->addrs[0]};
        *import_ptr.translated() = stash + 0x20;
        adjust_fdiv_import->hook = stash + 0x20;
        
        vm_ptr<uint32_t*> acmdln_ptr = {acmdln_import->addrs[0]};
        *acmdln_ptr.translated() = stash + 0x50;
        acmdln_import->hook = stash + 0x50;
        
        vm_ptr<uint32_t*> acmdln_ptr_2 = {stash + 0x50};
        **acmdln_ptr_2 = stash + 0x54;
    }
    
    Q_INVOKABLE void __set_app_type(int type);
    Q_INVOKABLE uint32_t __p__fmode(uint32_t a);
    Q_INVOKABLE uint32_t __p__commode(void);
    Q_INVOKABLE uint32_t _controlfp(uint32_t a, uint32_t b)
    {
        //TODO hack?
        uint32_t idk[2] = {0,0};
        vm_stack_push(idk, 2);
        return 1;
    }
    
    Q_INVOKABLE void _initterm(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t __getmainargs(int* out_argc, uint32_t* out_argv, uint32_t* out_env, int dowildcard, uint32_t startupinfo);
    
    Q_INVOKABLE uint32_t malloc(uint32_t size)
    {
        uint32_t idk[1] = {0};
        vm_stack_push(idk, 1);
        return kernel32->VirtualAlloc(0, size, 0, 0);
    }
    
    Q_INVOKABLE uint32_t calloc(uint32_t num, int32_t size)
    {
        uint32_t idk[2] = {0,0};
        vm_stack_push(idk, 2);
        uint32_t ptr = kernel32->VirtualAlloc(0, size*num, 0, 0);
        
        memset(vm_ptr_to_real_ptr(ptr), 0, size*num);
        
        return ptr;
    }
    
    Q_INVOKABLE void free(uint32_t ptr)
    {
        uint32_t idk[1] = {0};
        vm_stack_push(idk, 1);
        kernel32->VirtualFree(ptr, 0, 0);
    }
    
    Q_INVOKABLE uint32_t strstr(char* a, char* b)
    {
        uint32_t idk[2] = {0,0};
        vm_stack_push(idk, 2);
        char* out = strstr_wrap(a, b);
        if (!out) return 0;

        return real_ptr_to_vm_ptr((void*)out);
    }
    
    Q_INVOKABLE uint32_t _strnicmp(char* a, char* b, int len)
    {
        uint32_t idk[3] = {0,0,0};
        vm_stack_push(idk, 3);
        return strncmp(a, b, len);
    }
    
    Q_INVOKABLE uint32_t atoi(char* str)
    {
        uint32_t idk[1] = {0};
        vm_stack_push(idk, 1);
        return atoi_wrap(str);
    }
    
    Q_INVOKABLE uint32_t fopen(char* fname, char* mode)
    {
        printf("STUB: msvcrt::fopen(`%s', `%s')\n", fname, mode);
        return 1;
    }
    
    Q_INVOKABLE uint32_t fclose(uint32_t hand)
    {
        uint32_t idk[1] = {0};
        vm_stack_push(idk, 1);
        return 0;
    }
    
    Q_INVOKABLE uint32_t floor(float a)
    {
        float val = floor_wrap(a);
        
        return *(uint32_t*)(&val);
    }
    
    Q_INVOKABLE uint32_t _ftol(float a)
    {
        return (uint32_t)a;
    }
};

extern Msvcrt* msvcrt;

#endif // MSVCRT_H
