#include "hook.h"

void hook_function(uint32_t hook_addr, void* hook_dst)
{
    *(uint8_t*)(hook_addr) = 0xe9; // jmp
    *(uint32_t*)(hook_addr+1) = ((uintptr_t)hook_dst - hook_addr - 5);
}

void hook_abort(uint32_t hook_addr)
{
    *(uint8_t*)(hook_addr) = 0x0f; // und
    *(uint8_t*)(hook_addr+1) = 0x0b;
}
