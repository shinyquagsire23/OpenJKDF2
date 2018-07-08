#include "uc_utils.h"

#include "main.h"

uc_engine *current_uc = nullptr;

void uc_print_regs(uc_engine *uc)
{
    int32_t eax, ecx, edx, ebx;
    int32_t esp, ebp, esi, edi;
    int32_t eip;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);
    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("Register dump:\n");
    printf("eax %8.8x ", eax);
    printf("ecx %8.8x ", ecx);
    printf("edx %8.8x ", edx);
    printf("ebx %8.8x\n", ebx);
    printf("esp %8.8x ", esp);
    printf("ebp %8.8x ", ebp);
    printf("esi %8.8x ", esi);
    printf("edi %8.8x ", edi);
    printf("\n");
    printf("eip %8.8x ", eip);
    printf("\n");
}

void uc_stack_pop(uc_engine *uc, uint32_t *out, int num)
{
    uint32_t esp;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    
    for (int i = 0; i < num; i++)
    {
        uc_mem_read(uc, esp + i * sizeof(uint32_t), &out[i], sizeof(uint32_t));
    }
    
    esp += num * sizeof(uint32_t);
    
    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
}

void uc_stack_push(uc_engine *uc, uint32_t *in, int num)
{
    uint32_t esp;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    
    for (int i = 1; i < num+1; i++)
    {
        uc_mem_write(uc, esp - i * sizeof(uint32_t), &in[i-1], sizeof(uint32_t));
    }
    
    esp -= num * sizeof(uint32_t);
    
    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
}

std::string uc_read_string(uc_engine *uc, uint32_t addr)
{
    char c;
    std::string str;

    do
    {
        uc_mem_read(uc, addr + str.length(), &c, sizeof(char));
                    
        str += c;
     }
     while(c);
     
     return str;
}

std::string uc_read_wstring(uc_engine *uc, uint32_t addr)
{
    char c;
    std::string str;
    
    int num_zeroes = 0;
    int count = 0;

    do
    {
        uc_mem_read(uc, addr + count++, &c, sizeof(char));

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

void uc_stack_dump(uc_engine *uc)
{
    uint32_t esp;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    
    for (int i = 0; i < 10; i++)
    {
        uint32_t tmp;

        uc_mem_read(uc, esp + i*sizeof(uint32_t), &tmp, sizeof(uint32_t));
        printf("@%08x: %08x\n", esp + i*sizeof(uint32_t), tmp);
    }
}


static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    //printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int eflags;
    //printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    //printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
    
    if (address == 0x512458) //JK
    {
        uint32_t eax, ecx;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
        std::string fname = uc_read_string(uc, ecx);
        std::string mode = uc_read_string(uc, eax);
        
        //printf("fopen(\"%s\", \"%s\")\n", fname.c_str(), mode.c_str());
    }
    else if (address == 0x513C12)
    {
        uint32_t ebp, edi;
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
        uc_reg_read(uc, UC_X86_REG_EDI, &edi);
        
        //printf("fread(0x%x, 0x%x, 1, ...)\n", edi, ebp);
    }
    else if (address == 0x51522B)
    {
        uc_print_regs(uc);
    }
    else if (address == 0x43621E)
    {
        uint32_t eax, esi;
        uc_reg_read(uc, UC_X86_REG_ESI, &eax);
        std::string fname = uc_read_string(uc, eax);
        
        printf("idk(0x%x, \"%s\" (%x))\n", esi, fname.c_str(), eax);
        //uc_emu_stop(uc);
    }
    else if (address == 0x425950)
    {
        uc_print_regs(uc);
        uc_stack_dump(uc);
    }
}


// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_READ_UNMAPPED:
            printf(">>> Missing memory is being READ at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
            uc_print_regs(uc);
            return false;
        case UC_MEM_WRITE_UNMAPPED:
            printf(">>> Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
            uc_print_regs(uc);
            return false;
        case UC_ERR_FETCH_UNMAPPED:
            printf(">>> Missing memory is being EXEC at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
            return false;
    }
}

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
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

void uc_run(uc_engine *uc, uint32_t image_addr, void* image_mem, uint32_t image_mem_size, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp)
{
    uc_err err;
    uc_hook trace1, trace2, trace3;
    uc_x86_mmr gdtr;
    uc_engine *uc_last;

    const uint64_t gdt_address = 0xc0000000;
    const uint64_t fs_address = 0x7efdd000;
    int r_cs = 0x73;
    int r_ss = 0x88;      //ring 0
    int r_ds = 0x7b;
    int r_es = 0x7b;
    int r_fs = 0x83;

    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    if (!esp)
        esp = stack_addr + stack_size;
    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    
    uc_mem_map_ptr(uc, image_addr, image_mem_size + stack_size, UC_PROT_ALL, image_mem);

    struct SegmentDescriptor *gdt = (struct SegmentDescriptor*)calloc(31, sizeof(struct SegmentDescriptor));
    gdtr.base = gdt_address;  
    gdtr.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

    init_descriptor(&gdt[14], 0, 0xfffff000, 1);  //code segment
    init_descriptor(&gdt[15], 0, 0xfffff000, 0);  //data segment
    init_descriptor(&gdt[16], gdt_address, 0xfff, 0);  //one page data segment simulate fs
    init_descriptor(&gdt[17], 0, 0xfffff000, 0);  //ring 0 data
    gdt[17].dpl = 0;  //set descriptor privilege level

    err = uc_mem_map(uc, gdt_address, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    err = uc_mem_write(uc, gdt_address, gdt, 31 * sizeof(struct SegmentDescriptor));
    err = uc_mem_map(uc, fs_address, 0x1000, UC_PROT_WRITE | UC_PROT_READ);

    err = uc_reg_write(uc, UC_X86_REG_SS, &r_ss);

    err = uc_reg_write(uc, UC_X86_REG_CS, &r_cs);
    err = uc_reg_write(uc, UC_X86_REG_DS, &r_ds);
    err = uc_reg_write(uc, UC_X86_REG_ES, &r_es);
    err = uc_reg_write(uc, UC_X86_REG_FS, &r_fs);

    //uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, (void*)hook_block, NULL, 1, 0);
    //uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void*)hook_code, NULL, 1, 0);
    uc_hook_add(uc, &trace3, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_ERR_FETCH_UNMAPPED, (void*)hook_mem_invalid, NULL, 1, 0);

    sync_imports(uc);
    uc_last = current_uc;
    current_uc = uc;

    kernel32->Unicorn_MapHeaps();
    printf("Emulation instance at %x\n", start_addr);

    err = uc_emu_start(uc, start_addr, end_addr, 0, 0);
    if (err) 
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf(">>> Emulation done. Below is the CPU context\n");
    uc_print_regs(uc);

    uc_close(uc);

    // Re-sync last instance
    current_uc = uc_last;
    if (current_uc)
    {
        sync_imports(current_uc);
        kernel32->Unicorn_MapHeaps();
    }
}
