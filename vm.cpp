#include "vm.h"

#include <sys/mman.h>
#include <stdlib.h>

#include "kvm.h"
#include "uc_utils.h"

#include "dlls/kernel32.h"
#include "dlls/user32.h"
#include "dlls/gdi32.h"

uint32_t image_mem_addr;
void* image_mem;
uint32_t image_mem_size;
uint32_t stack_size, stack_addr;

bool using_kvm = false;

std::unordered_map<uint32_t, ImportTracker*> import_hooks;

QGenericArgument q_args[9];


void *vm_ptr_to_real_ptr(uint32_t vm_ptr)
{
    if (vm_ptr == 0) return nullptr;

    if (vm_ptr >= image_mem_addr && vm_ptr <= image_mem_addr + image_mem_size + stack_size)
    {
        return image_mem + vm_ptr - image_mem_addr;
    }
    else if (kernel32 && vm_ptr >= kernel32->heap_addr && vm_ptr <= kernel32->heap_addr + kernel32->heap_size)
    {
        return kernel32->heap_mem + vm_ptr - kernel32->heap_addr;
    }
    else if (kernel32 && vm_ptr >= kernel32->virtual_addr && vm_ptr <= kernel32->virtual_addr + kernel32->virtual_size_actual)
    {
        return kernel32->virtual_mem + vm_ptr - kernel32->virtual_addr;
    }
    else
    {
        printf("Could not convert VM ptr %x to real pointer\n", vm_ptr);
        return nullptr;
    }
}

uint32_t real_ptr_to_vm_ptr(void* real_ptr)
{
    if (real_ptr == nullptr) return 0;

    if (real_ptr >= image_mem && real_ptr <= image_mem + image_mem_size + stack_size)
    {
        return image_mem_addr + ((size_t)real_ptr - (size_t)image_mem);
    }
    else if (real_ptr >= kernel32->heap_mem && real_ptr <= kernel32->heap_mem + kernel32->heap_size)
    {
        return kernel32->heap_addr + ((size_t)real_ptr - (size_t)kernel32->heap_mem);
    }
    else if (real_ptr >= kernel32->virtual_mem && real_ptr <= kernel32->virtual_mem + kernel32->virtual_size_actual)
    {
        return kernel32->virtual_addr + ((size_t)real_ptr - (size_t)kernel32->virtual_mem);
    }
    else
    {
        printf("Could not convert real ptr %p to VM pointer\n", real_ptr);
        return 0;
    }
}

//VERY basic descriptor init function, sets many fields to user space sane defaults
void vm_init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
    desc->desc = 0;  //clear the descriptor
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = base >> 24;
    if (limit > 0xfffff) {
        //need Giant granularity
        limit >>= 12;
        desc->granularity = 1;
    }
    desc->limit0 = limit & 0xffff;
    desc->limit1 = limit >> 16;

    //some sane defaults
    desc->dpl = 3;
    desc->present = 1;
    desc->db = 1;   //32 bit
    desc->type = is_code ? 0xb : 3;
    desc->system = 1;  //code or data
}

void* vm_alloc(uint32_t size)
{
    void* ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if (ret == MAP_FAILED)
        return nullptr;
        
    madvise(ret, size, MADV_MERGEABLE);
    
    return ret;
}

void vm_mem_map_ptr(uint64_t address, size_t size, uint32_t perms, void *ptr)
{
    if (using_kvm)
    {
        kvm_mem_map_ptr(current_kvm, address, size, perms, ptr);
    }
    else
    {
        uc_mem_map_ptr(current_uc, address, size, perms, ptr);
    }
}

void vm_stack_pop(uint32_t *out, int num)
{
    uint32_t esp = vm_reg_read(UC_X86_REG_ESP);
    
    for (int i = 0; i < num; i++)
    {
        vm_mem_read(esp + i * sizeof(uint32_t), &out[i], sizeof(uint32_t));
    }
    
    esp += num * sizeof(uint32_t);
    
    vm_reg_write(UC_X86_REG_ESP, esp);
}

void vm_stack_push(uint32_t *in, int num)
{
    uint32_t esp = vm_reg_read(UC_X86_REG_ESP);
    
    for (int i = 1; i < num+1; i++)
    {
        vm_mem_write(esp - i * sizeof(uint32_t), &in[i-1], sizeof(uint32_t));
    }
    
    esp -= num * sizeof(uint32_t);
    
    vm_reg_write(UC_X86_REG_ESP, esp);
}

void vm_reg_write(int id, uint32_t value)
{
    if (using_kvm)
    {
        kvm_reg_write(current_kvm, id, value);
    }
    else
    {
        uc_reg_write(current_uc, id, &value);
    }
}

uint32_t vm_reg_read(int id)
{
    uint32_t val;
    if (using_kvm)
    {
        val = kvm_reg_read(current_kvm, id);
    }
    else
    {
        uc_reg_read(current_uc, id, &val);
    }
    
    return val;
}

void vm_mem_read(uint32_t addr, void* out, size_t size)
{
    memcpy(out, vm_ptr_to_real_ptr(addr), size);
}

void vm_mem_write(uint32_t addr, void* in, size_t size)
{
    memcpy(vm_ptr_to_real_ptr(addr), in, size);
}


std::string vm_read_string(uint32_t addr)
{
    char c;
    std::string str;

    do
    {
        vm_mem_read(addr + str.length(), &c, sizeof(char));
                    
        str += c;
     }
     while(c);
     
     return str;
}

std::string vm_read_wstring(uint32_t addr)
{
    char c;
    std::string str;
    
    int num_zeroes = 0;
    int count = 0;

    do
    {
        vm_mem_read(addr + count++, &c, sizeof(char));

        if (c)
        {
            str += c;
            num_zeroes = 0;
        }
        else
        {
            num_zeroes++;
        }
     }
     while(num_zeroes < 2);
     
     return str;
}

static void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ImportTracker *import)
{
    vm_process_import(import);
}

void vm_sync_imports()
{
    for (auto pair : import_store)
    {
        auto import = pair.second;
        
        if (import->addr)
            vm_mem_write(import->addr, &import->hook, sizeof(uint32_t));
        
        import_hooks[import->hook] = import;
        
        if (!using_kvm)
        {
            uc_mem_map(current_uc, import->hook, 0x1000, UC_PROT_ALL);
            uc_hook_add(current_uc, &import->trace, UC_HOOK_CODE, (void*)hook_import, (void*)import, import->hook, import->hook);
        }
    }
}

void vm_process_import(ImportTracker* import)
{
    uint32_t ret_addr;
    vm_stack_pop(&ret_addr, 1);
    
    //printf("Hit import %s, ret %x\n", import->name.c_str(), ret_addr);

    if (import->obj)
    {
        QMetaMethod method = import->method;

        if (method.parameterCount() <= 9)
        {
            void* trans_args[9];
            uint32_t args[9];
            uint32_t retVal;
            
            vm_stack_pop(args, method.parameterCount());

            if (import->is_hook)
                vm_stack_push(args, method.parameterCount());
            
            // Translate args from Unicorn pointers to usable pointers
            for (int j = 0; j < method.parameterCount(); j++)
            {
                if (import->is_param_ptr[j])
                {
                    trans_args[j] = vm_ptr_to_real_ptr(args[j]);
                    q_args[j] = QGenericArgument(method.parameterTypes()[j], &trans_args[j]);
                }
                else 
                {
                    q_args[j] = Q_ARG(uint32_t, args[j]);
                }
            }
                
            bool succ;
            if (method.returnType() == QMetaType::Void)
                succ = method.invoke(import->obj, q_args[0], q_args[1], q_args[2], q_args[3], q_args[4], q_args[5], q_args[6], q_args[7], q_args[8]);
            else
                succ = method.invoke(import->obj, Q_RETURN_ARG(uint32_t, retVal), q_args[0], q_args[1], q_args[2], q_args[3], q_args[4], q_args[5], q_args[6], q_args[7], q_args[8]);

            //printf("%x %x %x %x\n", succ, retVal, method.parameterCount(), ret_addr);

            if (succ)
            {
                if (method.returnType() != QMetaType::Void)
                    vm_reg_write(UC_X86_REG_EAX, retVal);

                vm_reg_write(UC_X86_REG_EIP, ret_addr);
                return;
            }
            else
            {
                vm_stack_push(args, method.parameterCount());
            }
        }
    }
    
    
    if (!strcmp(import->name.c_str(), "IsProcessorFeaturePresent"))
    {
        uint32_t args[1];
        uint32_t eax;
        
        vm_stack_pop(args, 1); //TODO: real handles
        
        eax = 0;
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else if (!strcmp(import->name.c_str(), "CreateWindowExA"))
    {
        uint32_t args[12];
        uint32_t eax;
        
        vm_stack_pop(args, 12); //TODO
        
        eax = user32->CreateWindowExA(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else if (!strcmp(import->name.c_str(), "CreateFontA"))
    {
        uint32_t args[14];
        uint32_t eax;
        
        vm_stack_pop(args, 14); //TODO
        
        //int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t    cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName
        eax = gdi32->CreateFontA(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], (char*)vm_ptr_to_real_ptr(args[13]));
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else
    {
        printf("Import %s from %s doesn't have impl, exiting\n", import->name.c_str(), import->dll.c_str());
        vm_stop();
        return;
    }
    
    vm_reg_write(UC_X86_REG_EIP, ret_addr);
}

uint32_t vm_call_function(uint32_t addr, uint32_t num_args...)
{
    va_list args;
    va_start(args, num_args);

    uint32_t* arg_list = (uint32_t*)malloc(num_args * sizeof(uint32_t));

    for (int i = 0; i < num_args; i++)
    {
        arg_list[i] = va_arg(args, uint32_t);
    }

    vm_call_function(addr, num_args, arg_list, true);

    va_end(args);
}

uint32_t vm_call_function(uint32_t addr, uint32_t num_args, uint32_t* args, bool push_ret)
{
    struct vm_inst new_vm;
    uint32_t esp, eax, dummy;

    dummy = import_store["dummy::dummy"]->hook;

    uint32_t old_esp = vm_reg_read(UC_X86_REG_ESP);

    for (int i = 0; i < num_args; i++)
    {
        vm_stack_push(&args[num_args-i-1], 1);
    }

    if (push_ret)
        vm_stack_push(&dummy, 1);
    esp = vm_reg_read(UC_X86_REG_ESP);

    eax = vm_run(&new_vm, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, addr, dummy, esp);

    vm_reg_write(UC_X86_REG_ESP, old_esp);

    return eax;
}

uint32_t vm_run(struct vm_inst *vm, uint32_t image_addr, void* image_mem, uint32_t image_mem_size, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp)
{
    uint32_t eax;
    using_kvm = true;
    if (using_kvm)
        eax = kvm_run(&vm->kvm, image_addr, image_mem, image_mem_size, stack_addr, stack_size, start_addr, end_addr, esp);
    else
        eax = uc_run(vm->uc, image_mem_addr, image_mem, image_mem_size, stack_addr, stack_size, start_addr, end_addr, esp);

    return eax;
}

void vm_stop()
{
    if (using_kvm)
        kvm_stop(current_kvm);
    else
        uc_emu_stop(current_uc);
}
