#include "vm.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <cwchar>

#include "kvm.h"
#include "uc_utils.h"

#include "dlls/kernel32.h"
#include "dlls/user32.h"
#include "dlls/gdi32.h"
#include "dlls/msvcrt.h"

uint32_t image_mem_addr[16];
void* image_mem[16];
uint32_t image_mem_size[16];
uint32_t stack_addr, stack_size;
uint32_t num_images = 0;

uint32_t next_hook;

bool using_kvm = false;

std::unordered_map<uint32_t, ImportTracker*> import_hooks;
std::map<std::string, ImportTracker*> import_store;
std::map<std::string, QObject*> dll_store;
std::map<std::string, QObject*> interface_store;
std::map<std::string, std::map<std::string, int> > method_cache;

QGenericArgument q_args[9];

void vm_register_image(void* mem, uint32_t addr, uint32_t size)
{
    image_mem[num_images] = mem;
    image_mem_addr[num_images] = addr;
    image_mem_size[num_images++] = size;
}

void vm_map_images()
{
    for (int i = 0; i < num_images; i++)
    {
        vm_mem_map_ptr(image_mem_addr[i], image_mem_size[i], 0, image_mem[i]);
    }
}

void *vm_ptr_to_real_ptr(uint32_t vm_ptr)
{
    if (vm_ptr == 0) return nullptr;

    for (int i = 0; i < num_images; i++)
    {
        if (vm_ptr >= image_mem_addr[i] && vm_ptr <= image_mem_addr[i] + image_mem_size[i])
        {
            return (void*)((intptr_t)image_mem[i] + vm_ptr - image_mem_addr[i]);
        }
    }
    
    if (kernel32 && vm_ptr >= kernel32->heap_addr && vm_ptr <= kernel32->heap_addr + kernel32->heap_size)
    {
        return (void*)((intptr_t)kernel32->heap_mem + vm_ptr - kernel32->heap_addr);
    }
    else if (kernel32 && vm_ptr >= kernel32->virtual_addr && vm_ptr <= kernel32->virtual_addr + kernel32->virtual_size_actual)
    {
        return (void*)((intptr_t)kernel32->virtual_mem + vm_ptr - kernel32->virtual_addr);
    }
    else
    {
        printf("Could not convert VM ptr %x to real pointer %x\n", vm_ptr, image_mem_addr);
        return nullptr;
    }
}

uint32_t real_ptr_to_vm_ptr(void* real_ptr)
{
    if (real_ptr == nullptr) return 0;

    for (int i = 0; i < num_images; i++)
    {
        if (real_ptr >= image_mem[i] && (intptr_t)real_ptr <= (intptr_t)image_mem[i] + image_mem_size[i])
        {
            return image_mem_addr[i] + ((intptr_t)real_ptr - (intptr_t)image_mem[i]);
        }
    }
    
    if (real_ptr >= kernel32->heap_mem && (intptr_t)real_ptr <= (intptr_t)kernel32->heap_mem + kernel32->heap_size)
    {
        return kernel32->heap_addr + ((intptr_t)real_ptr - (intptr_t)kernel32->heap_mem);
    }
    else if (real_ptr >= kernel32->virtual_mem && (intptr_t)real_ptr <= (intptr_t)kernel32->virtual_mem + kernel32->virtual_size_actual)
    {
        return kernel32->virtual_addr + ((intptr_t)real_ptr - (intptr_t)kernel32->virtual_mem);
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
        kvm_mem_map_ptr(current_kvm, address, size, 0, ptr);
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

void vm_print_regs()
{
    if (using_kvm)
    {
        kvm_print_regs(current_kvm);
    }
    else
    {
        uc_print_regs(current_uc);
    }
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

void vm_dll_register(std::string dll_fname, QObject* dll_obj)
{
	dll_store[dll_fname] = (QObject*)dll_obj;
}

void vm_interface_register(std::string interface_name, QObject* interface_obj)
{
	interface_store[interface_name] = (QObject*)interface_obj;
}

void vm_cache_functions()
{
	printf("Caching functions\n");
    for (auto obj_pair : dll_store)
    {
        auto obj = obj_pair.second;
        for (int i = 0; i < obj->metaObject()->methodCount(); i++)
        {
            QMetaMethod method = obj->metaObject()->method(i);
            std::string strname = std::string(method.name().data());
            
            method_cache[obj_pair.first][strname] = i;
            //printf("%s %s %i\n", obj_pair.first.c_str(), name, i);
        }
    }
}

void vm_set_hookmem(uint32_t addr)
{
	next_hook = addr;
}

uint32_t vm_import_get_hook_addr(std::string dll, std::string name)
{
    std::string import_name = dll + "::" + name;
    if (!import_store[import_name])
        return 0;
    return import_store[import_name]->hook;
}

void vm_hook_register(std::string dll, std::string name, uint32_t hook_addr)
{
    std::string import_name = dll + "::" + name;

    if (import_store[import_name]) return;

    import_store[import_name] = new ImportTracker(dll, name, 0, hook_addr);
    import_store[import_name]->is_hook = true;

    // Write UND instruction for VM hook
    vm_ptr<uint8_t*> und_write = {hook_addr};
    und_write.translated()[0] = 0x0f;
    und_write.translated()[1] = 0x0b;

    auto obj = dll_store[dll];
    if (obj && method_cache[dll].find(name) != method_cache[dll].end())
    {
        auto method = obj->metaObject()->method(method_cache[dll][name]);
        import_store[import_name]->method = method;
        import_store[import_name]->obj = obj;
        
        for (int i = 0; i < method.parameterCount(); i++)
        {
            if (method.parameterTypes()[i].data()[strlen(method.parameterTypes()[i].data()) - 1] == '*')
            {
                import_store[import_name]->is_param_ptr.push_back(true);
            }
            else 
            {
                import_store[import_name]->is_param_ptr.push_back(false);
            }
            
        }
    }

    next_hook += 1;
}


void vm_import_register(std::string dll, std::string name, uint32_t import_addr)
{
    std::string import_name = dll + "::" + name;

    if (import_store[import_name])
    {
        import_store[import_name]->addrs.push_back(import_addr);
        return;
    }

    import_store[import_name] = new ImportTracker(dll, name, import_addr, next_hook);
    
    auto obj = dll_store[dll];
    if (obj && method_cache[dll].find(name) != method_cache[dll].end())
    {
        auto method = obj->metaObject()->method(method_cache[dll][name]);
        import_store[import_name]->method = method;
        import_store[import_name]->obj = obj;
        
        for (int i = 0; i < method.parameterCount(); i++)
        {
            if (method.parameterTypes()[i].data()[strlen(method.parameterTypes()[i].data()) - 1] == '*')
            {
                import_store[import_name]->is_param_ptr.push_back(true);
            }
            else 
            {
                import_store[import_name]->is_param_ptr.push_back(false);
            }
            
        }
    }

    next_hook += 1;
}

static void vm_import_hook(uc_engine *uc, uint64_t address, uint32_t size, ImportTracker *import)
{
    vm_process_import(import);
}

void vm_sync_imports()
{
    for (auto pair : import_store)
    {
        auto import = pair.second;
        if (!import) continue;
        
        for(auto it = std::begin(import->addrs); it != std::end(import->addrs); ++it) {
            if (*it)
                vm_mem_write(*it, &import->hook, sizeof(uint32_t));
        }
        
        import_hooks[import->hook] = import;
        
        if (!using_kvm)
        {
            uc_mem_map(current_uc, import->hook, 0x1000, UC_PROT_ALL);
            uc_hook_add(current_uc, &import->trace, UC_HOOK_CODE, (void*)vm_import_hook, (void*)import, import->hook, import->hook);
        }
    }
}

void vm_process_import(ImportTracker* import)
{
    uint32_t ret_addr;
    vm_stack_pop(&ret_addr, 1);
    
    //if (import->dll != "KERNEL32.dll" && import->dll != "USER32.dll" && import->dll != "WINMM.dll")
    //    printf("Hit %s import %s, ret %x\n", import->dll.c_str(), import->name.c_str(), ret_addr);

    //vm_print_regs();
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
    else if (import->name == "CreateWindowExA")
    {
        uint32_t args[12];
        uint32_t eax;
        
        vm_stack_pop(args, 12); //TODO
        
        eax = user32->CreateWindowExA(args[0], (char*)vm_ptr_to_real_ptr(args[1]), (char*)vm_ptr_to_real_ptr(args[2]), args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else if (import->name == "CreateFontA")
    {
        uint32_t args[14];
        uint32_t eax;
        
        vm_stack_pop(args, 14); //TODO
        
        //int16_t cHeight, int16_t cWidth, int16_t cEscapement, int16_t cOrientation, int16_t    cWeight, uint32_t bItalic, uint32_t bUnderline, uint32_t bStrikeOut, uint32_t iCharSet, uint32_t iOutPrecision, uint32_t iClipPrecision, uint32_t iQuality, uint32_t iPitchAndFamily, char* pszFaceName
        eax = gdi32->CreateFontA(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], (char*)vm_ptr_to_real_ptr(args[13]));
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else if (import->name == "sprintf")
    {
        uint32_t args[2];
        
        vm_stack_pop(args, 2); //TODO
        
        char* out = (char*)vm_ptr_to_real_ptr(args[0]);
        char* format = (char*)vm_ptr_to_real_ptr(args[1]);
        char** format_split = nullptr;
        
        int num_args = 0;
        int last_arg_start = 0;
        for (int i = 0; i < (int)strlen(format); i++)
        {
            if (format[i] != '%') continue;
            if (format[i+1] == '%') continue;

            num_args++;
            
            format_split = (char**)realloc(format_split, sizeof(char*) * num_args);
            
            if (num_args > 1)
            {
                format_split[num_args-2] = (char*)malloc(i - last_arg_start + 1);
                strncpy(format_split[num_args-2], &format[last_arg_start], i - last_arg_start);
                last_arg_start = i;
            }
        }
        
        if (num_args >= 1)
        {
            format_split[num_args-1] = (char*)malloc(strlen(format) - last_arg_start + 1);
            strncpy(format_split[num_args-1], &format[last_arg_start], strlen(format) - last_arg_start);
            
            out[0] = 0;
            for (int i = 0; i < num_args; i++)
            {
                uint32_t popped = 0;
                vm_stack_pop(&popped, 1);
                
                //printf("%s %s\n", out, format_split[i]);
                sprintf(out + strlen(out), format_split[i], popped);
                free(format_split[i]);
            }
            free(format_split);
            //printf("%s\n", out);
        }
        else
        {
            sprintf(out, format);
        }
        
        
        printf("IFFY: msvcrt.dll::sprintf(0x%x, \"%s\") -> \n", args[0], format/*, out*/);
    }
    else if (import->name == "wsprintfA")
    {
        uint32_t args[2];
        
        vm_stack_pop(args, 2); //TODO
        
        wchar_t* out = (wchar_t*)vm_ptr_to_real_ptr(args[0]);
        char* format = (char*)vm_ptr_to_real_ptr(args[1]);
        char** format_split = nullptr;
        wchar_t tmp[255];
        
        int num_args = 0;
        int last_arg_start = 0;
        for (int i = 0; i < (int)strlen(format); i++)
        {
            if (format[i] != '%') continue;
            if (format[i+1] == '%') continue;

            num_args++;
            
            format_split = (char**)realloc(format_split, sizeof(char*) * num_args);
            
            if (num_args > 1)
            {
                format_split[num_args-2] = (char*)malloc(i - last_arg_start + 1);
                strncpy(format_split[num_args-2], &format[last_arg_start], i - last_arg_start);
                last_arg_start = i;
            }
        }
        
        if (num_args >= 1)
        {
            format_split[num_args-1] = (char*)malloc((strlen(format) - last_arg_start + 1) * sizeof(char));
            strncpy(format_split[num_args-1], &format[last_arg_start], strlen(format) - last_arg_start);
            
            out[0] = 0;
            for (int i = 0; i < num_args; i++)
            {
                uint32_t popped = 0;
                vm_stack_pop(&popped, 1);
                
                //printf("%s %s\n", out, format_split[i]);
                
                swprintf(tmp, 255, L"%hs", format_split[i]);
                
                swprintf(out + wcslen(out) * sizeof(wchar_t), 255, tmp, popped);
                free(format_split[i]);
            }
            free(format_split);
            //printf("%s\n", out);
        }
        else
        {
            swprintf(tmp, 255, L"%hs", format);
            
            swprintf(out, 255, tmp);
        }
        
        
        printf("IFFY: msvcrt.dll::wsprintfA(0x%x, \"%s\") -> \n", args[0], format/*, out*/);
    }
    else if (import->name == "StretchDIBits")
    {
        uint32_t args[13];
        uint32_t eax;
        
        vm_stack_pop(args, 13); //TODO
        
        eax = gdi32->StretchDIBits(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], (void*)vm_ptr_to_real_ptr(args[9]), (BITMAPINFO*)vm_ptr_to_real_ptr(args[10]), args[11], args[12]);
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else if (import->name == "??2@YAPAXI@Z")
    {
        uint32_t args[1];
        uint32_t eax;
        
        vm_stack_pop(args, 1); //TODO: real handles
        
        eax = msvcrt->malloc(args[0]);
        vm_reg_write(UC_X86_REG_EAX, eax);
    }
    else if (import->name == "??3@YAXPAX@Z")
    {
        uint32_t args[1];
        
        vm_stack_pop(args, 1); //TODO: real handles
        
        msvcrt->free(args[0]);
    }
    else
    {
        if (import->name != "dummy")
            printf("Import %s from %s doesn't have impl, exiting\n", import->name.c_str(), import->dll.c_str());
        vm_stop();
        return;
    }
    
    vm_reg_write(UC_X86_REG_EIP, ret_addr);
}

uint32_t vm_call_function(uint32_t addr, uint32_t num_args...)
{
	uint32_t eax;
    va_list args;
    va_start(args, num_args);

    uint32_t* arg_list = (uint32_t*)malloc(num_args * sizeof(uint32_t));

    for (uint32_t i = 0; i < num_args; i++)
    {
        arg_list[i] = va_arg(args, uint32_t);
    }

    eax = vm_call_function(addr, num_args, arg_list, true);

    va_end(args);
    
    return eax;
}

uint32_t vm_call_function(uint32_t addr, uint32_t num_args, uint32_t* args, bool push_ret)
{
    struct vm_inst new_vm;
    uint32_t esp, eax, dummy;

    dummy = import_store["dummy::dummy"]->hook;

    uint32_t old_esp = vm_reg_read(UC_X86_REG_ESP);

    for (uint32_t i = 0; i < num_args; i++)
    {
        vm_stack_push(&args[num_args-i-1], 1);
    }

    if (push_ret)
        vm_stack_push(&dummy, 1);
    esp = vm_reg_read(UC_X86_REG_ESP);

    // TODO is this kosher?
    eax = vm_run(&new_vm, stack_addr, stack_size, addr, dummy, esp);

    vm_reg_write(UC_X86_REG_ESP, old_esp);

    return eax;
}

uint32_t vm_run(struct vm_inst *vm, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp)
{
    uint32_t eax;
    using_kvm = true;
    if (using_kvm)
        eax = kvm_run(&vm->kvm, stack_addr, stack_size, start_addr, end_addr, esp);
    else
        eax = uc_run(vm->uc, stack_addr, stack_size, start_addr, end_addr, esp);

    return eax;
}

void vm_stop()
{
    if (using_kvm)
        kvm_stop(current_kvm);
    else
        uc_emu_stop(current_uc);
}
