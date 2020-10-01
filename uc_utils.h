#ifndef UC_UTILS_H
#define UC_UTILS_H

#include <unicorn/unicorn.h>
#include <stdint.h>
#include <string>

extern uc_engine *current_uc;

void uc_print_regs(uc_engine *uc);
void uc_stack_dump(uc_engine *uc);

uint32_t uc_run(uc_engine *uc, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp);

#endif // UC_UTILS_H
