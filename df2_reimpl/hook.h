#ifndef HOOK_H
#define HOOK_H

#include "types.h"

void hook_function(uint32_t hook_addr, uintptr_t hook_dst);
void hook_abort(uint32_t hook_addr);

#endif // HOOK_H
