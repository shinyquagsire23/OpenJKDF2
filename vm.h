#ifndef VM_H
#define VM_H

#include <stdint.h>
#include <cstring>

#include <unicorn/unicorn.h>
#include <QMetaMethod>

#include "kvm.h"

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

class ImportTracker
{
public:
    std::string dll;
    std::string name;
    QObject* obj;
    QMetaMethod method;
    std::vector<bool> is_param_ptr;
    uint32_t addr;
    uint32_t hook;
    
    uc_hook trace;

    ImportTracker(std::string dll, std::string name, uint32_t addr, uint32_t hook) : dll(dll), name(name), addr(addr), hook(hook)
    {
    }
};

struct vm_inst
{
    uc_engine *uc;
    struct vm kvm;
};

extern uint32_t image_mem_addr;
extern void* image_mem;
extern uint32_t image_mem_size;
extern uint32_t stack_size, stack_addr;
extern std::map<uint32_t, ImportTracker*> import_hooks;
extern std::map<std::string, ImportTracker*> import_store;

void *vm_ptr_to_real_ptr(uint32_t vm_ptr);
uint32_t real_ptr_to_vm_ptr(void* real_ptr);

void vm_init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code);

void vm_mem_map_ptr(uint64_t address, size_t size, uint32_t perms, void *ptr);
void vm_mem_read(uint32_t addr, void* out, size_t size);
void vm_mem_write(uint32_t addr, void* in, size_t size);
std::string vm_read_string(uint32_t addr);
std::string vm_read_wstring(uint32_t addr);

uint32_t vm_reg_read(int id);
void vm_reg_write(int id, uint32_t value);

void vm_stack_pop(uint32_t *out, int num);
void vm_stack_push(uint32_t *in, int num);

void* vm_alloc(uint32_t size);
void vm_sync_imports();
void vm_process_import(ImportTracker* import);
uint32_t vm_call_function(uint32_t addr, uint32_t num_args, uint32_t* args, bool push_ret = true);
uint32_t vm_run(struct vm_inst *vm, uint32_t image_addr, void* image_mem, uint32_t image_mem_size, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp);
void vm_stop();


template <typename T>
struct vm_ptr
{
    uint32_t raw_vm_ptr;
    
    T translated()
    {
        return (T)vm_ptr_to_real_ptr(this->raw_vm_ptr);
    }

    T operator* ()
    {
        return (T)vm_ptr_to_real_ptr(this->raw_vm_ptr);
    }

    T operator-> ()
    {
        return (T)vm_ptr_to_real_ptr(this->raw_vm_ptr);
    }
};

#endif // VM_H
