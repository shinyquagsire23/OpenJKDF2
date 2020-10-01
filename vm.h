#ifndef VM_H
#define VM_H

#include <stdint.h>
#include <cstring>
#include <unordered_map>

#include <unicorn/unicorn.h>
#include <QMetaMethod>

#include "kvm.h"
#include "narg.h"

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
    std::string pe;
    std::string dll;
    std::string name;
    QObject* obj;
    QMetaMethod method;
    std::vector<bool> is_param_ptr;
    std::vector<uint32_t> addrs;
    uint32_t hook;

    bool is_hook;

    uc_hook trace;

    ImportTracker(std::string dll, std::string name, uint32_t addr, uint32_t hook) : dll(dll), name(name), hook(hook), is_hook(false)
    {
        addrs = std::vector<uint32_t>();
        addrs.push_back(addr);
    }
};

struct vm_inst
{
    uc_engine *uc;
    struct vm kvm;
};

extern uint32_t stack_addr, stack_size;
extern uint32_t image_mem_addr[16];
extern void* image_mem[16];
extern uint32_t image_mem_size[16];
extern std::unordered_map<uint32_t, ImportTracker*> import_hooks;
extern std::map<std::string, ImportTracker*> import_store;
extern std::map<std::string, QObject*> interface_store;

// Address translation
void vm_register_image(void* mem, uint32_t addr, uint32_t size);
void vm_map_images();
void *vm_ptr_to_real_ptr(uint32_t vm_ptr);
uint32_t real_ptr_to_vm_ptr(void* real_ptr);

// Helper function
void vm_init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code);

// Memory mapping, memory reading, memory writing
void vm_mem_map_ptr(uint64_t address, size_t size, uint32_t perms, void *ptr);
void vm_mem_read(uint32_t addr, void* out, size_t size);
void vm_mem_write(uint32_t addr, void* in, size_t size);
std::string vm_read_string(uint32_t addr);
std::string vm_read_wstring(uint32_t addr);

// Register read/write
uint32_t vm_reg_read(int id);
void vm_reg_write(int id, uint32_t value);

// Stack helpers, push/pop
void vm_stack_pop(uint32_t *out, int num);
void vm_stack_push(uint32_t *in, int num);

// Reimplementation helpers
void* vm_alloc(uint32_t size);

// DLL/COM registration, synchronization
void vm_sync_imports();
void vm_process_import(ImportTracker* import);
void vm_dll_register(std::string dll_fname, QObject* dll_obj);
void vm_interface_register(std::string interface_name, QObject* interface_obj);
void vm_cache_functions();

// Function hooking
void vm_set_hookmem(uint32_t addr);
uint32_t vm_import_get_hook_addr(std::string dll, std::string name);
void vm_hook_register(std::string dll, std::string name, uint32_t hook_addr);
void vm_import_register(std::string dll, std::string name, uint32_t import_addr);
uint32_t vm_call_function(uint32_t addr, uint32_t num_args...);
uint32_t vm_call_function(uint32_t addr, uint32_t num_args, uint32_t* args, bool push_ret = true);
uint32_t vm_run(struct vm_inst *vm, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp);
void vm_stop();

#define vm_call_func(addr, ...) vm_call_function(addr, PP_NARG(__VA_ARGS__), __VA_ARGS__)


template <typename T>
struct vm_ptr
{
    uint32_t raw_vm_ptr;
    
    vm_ptr() : raw_vm_ptr(0) {}
    vm_ptr(uint32_t ptr) : raw_vm_ptr(ptr) {}

    vm_ptr<T> operator=(const T& other) // copy assignment
    {
        //printf("assigned to %x\n", other);

        // handle nullptr assignment
        if (other == 0)
            raw_vm_ptr = 0;

        //TODO: translate non-VM ptrs to VM ptrs
        //this->translated() = 

        return *this;
    }

    T translated()
    {
        //printf("translating %x to %p\n", raw_vm_ptr, vm_ptr_to_real_ptr(this->raw_vm_ptr));
        return (T)vm_ptr_to_real_ptr(this->raw_vm_ptr);
    }

    T operator* ()
    {
        return this->translated();
    }

    T operator-> ()
    {
        return this->translated();
    }
};

#endif // VM_H
