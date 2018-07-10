#ifndef UC_UTILS_H
#define UC_UTILS_H

#include <unicorn/unicorn.h>
#include <stdint.h>
#include <string>


#pragma pack(push, 1)
struct SegmentDescriptor {
   union {
      struct {   
#if __BYTE_ORDER == __LITTLE_ENDIAN
         unsigned short limit0;
         unsigned short base0;
         unsigned char base1;
         unsigned char type:4;
         unsigned char system:1;      /* S flag */
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned char limit1:4;
         unsigned char avail:1;
         unsigned char is_64_code:1;  /* L flag */
         unsigned char db:1;          /* DB flag */
         unsigned char granularity:1; /* G flag */
         unsigned char base2;
#else
         unsigned char base2;
         unsigned char granularity:1; /* G flag */
         unsigned char db:1;          /* DB flag */
         unsigned char is_64_code:1;  /* L flag */
         unsigned char avail:1;
         unsigned char limit1:4;
         unsigned char present:1;     /* P flag */
         unsigned char dpl:2;
         unsigned char system:1;      /* S flag */
         unsigned char type:4;
         unsigned char base1;
         unsigned short base0;
         unsigned short limit0;
#endif
      };
      uint64_t desc;
   };
};

#pragma pack(pop)

extern uc_engine *current_uc;

void uc_print_regs(uc_engine *uc);
void uc_stack_pop(uc_engine *uc, uint32_t *out, int num);
void uc_stack_push(uc_engine *uc, uint32_t *in, int num);
std::string uc_read_string(uc_engine *uc, uint32_t addr);
std::string uc_read_wstring(uc_engine *uc, uint32_t addr);
void uc_stack_dump(uc_engine *uc);

uint32_t uc_run(uc_engine *uc, uint32_t image_addr, void* image_mem, uint32_t image_mem_size, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp);

#endif // UC_UTILS_H
