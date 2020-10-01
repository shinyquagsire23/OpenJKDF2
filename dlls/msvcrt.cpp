#include "msvcrt.h"

#include "vm.h"
#include "kernel32.h"
#include <cmath>

float floor_wrap(float a)
{
    return floor(a);
}

char* strstr_wrap(char* a, char* b)
{
    return strstr(a,b);
}

int atoi_wrap(char* str)
{
    return atoi(str);
}

void Msvcrt::__set_app_type(int type)
{
    printf("STUB: msvcrt.dll::__set_app_type(%u)\n", type);
}

uint32_t Msvcrt::__p__fmode(uint32_t a)
{
    printf("STUB: msvcrt.dll::__p__fmode(%x)\n",a);
    
    return stash;
}

uint32_t Msvcrt::__p__commode(void)
{
    printf("STUB:: msvcrt.dll::__p__commode()\n");
    
    return stash + 0x10;
}

void Msvcrt::_initterm(uint32_t a, uint32_t b)
{
    printf("STUB: msvcrt.dll::__initterm(%x, %x)\n", a, b);
    uint32_t idk[2] = {0x1234,0x5678};
    vm_stack_push(idk, 2);
}

uint32_t Msvcrt::__getmainargs(int* out_argc, uint32_t* out_argv, uint32_t* out_env, int dowildcard, uint32_t startupinfo)
{
    *out_argc = 1;
    
    // Set up argv char**
    *out_argv = stash + 0x30;
    vm_ptr<uint32_t*> argv = {*out_argv};
    vm_ptr<char*> arg0 = {stash + 0x38};
    argv.translated()[0] = stash + 0x38;
    argv.translated()[1] = 0;
    strcpy(*arg0, "wrap");
    
    // Set up env char**
    *out_env = stash + 0x40;
    vm_ptr<uint32_t*> env = {*out_env};
    env.translated()[0] = 0;
    
    return 0;
}
