#ifndef HOOK_H
#define HOOK_H

#include "types.h"

void hook_function(intptr_t hook_addr, void* hook_dst);
void hook_function_inv(intptr_t hook_addr, void* hook_dst);
void hook_abort(intptr_t hook_addr);

#define IMPORT_FUNC(name, ret_type, aArgs, addr) static ret_type (__cdecl* name)aArgs = (ret_type(*)aArgs)addr;

#endif // HOOK_H
