#include "hook.h"

#ifdef LINUX
#include <sys/mman.h>
#endif

#include "jk.h"

void hook_function(uint32_t hook_addr, void* hook_dst)
{
    if (hook_addr == (intptr_t)hook_dst) {
        jk_printf("Attempted to hook addr %x to itself!\n", hook_addr);
        return;
    }

    *(uint8_t*)(hook_addr) = 0xe9; // jmp
    *(uint32_t*)(hook_addr+1) = ((uintptr_t)hook_dst - hook_addr - 5);
}

void hook_function_inv(uint32_t hook_addr, void* hook_dst)
{
    uint32_t hook_int_addr = (intptr_t)hook_dst;
    intptr_t hook_addr_ptr = (intptr_t)hook_addr;

#ifdef LINUX
    mprotect((void*)(hook_int_addr & ~0xFFF), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
    
    *(uint8_t*)(hook_int_addr) = 0xe9; // jmp
    *(uint32_t*)(hook_int_addr+1) = ((uintptr_t)hook_addr_ptr - hook_int_addr - 5);

#ifdef LINUX
    mprotect((void*)(hook_int_addr & ~0xFFF), 0x1000, PROT_READ | PROT_EXEC);
#endif
}

void hook_abort(uint32_t hook_addr)
{
    *(uint8_t*)(hook_addr) = 0x0f; // und
    *(uint8_t*)(hook_addr+1) = 0x0b;
}
