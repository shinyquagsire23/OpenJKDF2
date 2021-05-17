#include "kvm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

#include <map>

#include "vm.h"
#include "main.h"
#include "dlls/kernel32.h"
#include "dlls/user32.h"

// 32-bit page directory entry bits
#define PDE32_PRESENT 1
#define PDE32_RW (1 << 1)
#define PDE32_USER (1 << 2)
#define PDE32_PS (1 << 7)

// 64-bit page * entry bits
#define PDE64_PRESENT 1
#define PDE64_RW (1 << 1)
#define PDE64_USER (1 << 2)
#define PDE64_ACCESSED (1 << 5)
#define PDE64_DIRTY (1 << 6)
#define PDE64_PS (1 << 7)
#define PDE64_G (1 << 8)

#define CR4_PSE (1 << 8)

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

#define CR4_OSFXSR (1 << 8)
#define CR4_OSXMMEXCPT (1 << 10)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

const uint64_t gdt_address  = 0xc0000000;
const uint64_t fs_address   = 0x7efdd000;
const uint64_t es_address   = 0x7efde000;
const uint64_t pd_address   = 0x7efdc000;

void* fs_mem;
void* es_mem;
void* gdt_mem;
void* pd_mem;

int sys_fd;
int vm_fd;
int vcpu_fd;

struct vm *current_kvm = nullptr;

void kvm_reg_write(struct vm *vm, int id, uint32_t value)
{
    if (ioctl(vcpu_fd, KVM_GET_REGS, &vm->vcpu.regs) < 0)
    {
        perror("KVM_GET_REGS");
        exit(1);
    }

    switch (id)
    {
        case UC_X86_REG_EAX:
            vm->vcpu.regs.rax = value;
        break;
        case UC_X86_REG_ECX:
            vm->vcpu.regs.rcx = value;
        break;
        case UC_X86_REG_EDX:
            vm->vcpu.regs.rdx = value;
        break;
        case UC_X86_REG_EBX:
            vm->vcpu.regs.rbx = value;
        break;
        case UC_X86_REG_ESP:
            vm->vcpu.regs.rsp = value;
        break;
        case UC_X86_REG_EBP:
            vm->vcpu.regs.rbp = value;
        break;
        case UC_X86_REG_ESI:
            vm->vcpu.regs.rsi = value;
        break;
        case UC_X86_REG_EDI:
            vm->vcpu.regs.rdi = value;
        break;
        case UC_X86_REG_EIP:
            vm->vcpu.regs.rip = value;
        break;
        default:
            printf("Unknown reg %i\n", id);
            break;
    }
    
    if (ioctl(vcpu_fd, KVM_SET_REGS, &vm->vcpu.regs) < 0) {
        perror("KVM_SET_REGS");
        exit(1);
    }
}

uint32_t kvm_reg_read(struct vm *vm, int id)
{
    if (ioctl(vcpu_fd, KVM_GET_REGS, &vm->vcpu.regs) < 0) 
    {
        perror("KVM_GET_REGS");
        exit(1);
    }

    switch (id)
    {
        case UC_X86_REG_EAX:
            return vm->vcpu.regs.rax;
        case UC_X86_REG_ECX:
            return vm->vcpu.regs.rcx;
        case UC_X86_REG_EDX:
            return vm->vcpu.regs.rdx;
        case UC_X86_REG_EBX:
            return vm->vcpu.regs.rbx;
        case UC_X86_REG_ESP:
            return vm->vcpu.regs.rsp;
        case UC_X86_REG_EBP:
            return vm->vcpu.regs.rbp;
        case UC_X86_REG_ESI:
            return vm->vcpu.regs.rsi;
        case UC_X86_REG_EDI:
            return vm->vcpu.regs.rdi;
        case UC_X86_REG_EIP:
            return vm->vcpu.regs.rip;
        default:
            printf("Unknown reg %i\n", id);
            return 0;
    }
}

void kvm_print_regs(struct vm *vm)
{
    struct kvm_regs regs;
    if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) 
    {
        perror("KVM_GET_REGS");
        exit(1);
    }

    printf("Register dump:\n");
    printf("eax %8.8" PRIx64 " ", regs.rax);
    printf("ecx %8.8" PRIx64 " ", regs.rcx);
    printf("edx %8.8" PRIx64 " ", regs.rdx);
    printf("ebx %8.8" PRIx64 "\n", regs.rbx);
    printf("esp %8.8" PRIx64 " ", regs.rsp);
    printf("ebp %8.8" PRIx64 " ", regs.rbp);
    printf("esi %8.8" PRIx64 " ", regs.rsi);
    printf("edi %8.8" PRIx64 " ", regs.rdi);
    printf("\n");
    printf("eip %8.8" PRIx64 " ", regs.rip);
    if (regs.rip > 0x9f6000)
        printf(" (%8.8" PRIx64 ") ", (regs.rip - 0x9f6000l + 0x70380000l));
    printf("\n");
}

void kvm_mem_map_ptr(struct vm *vm, uint64_t address, size_t size, uint32_t perms, void *ptr)
{
    static int slot_count = 0;

    struct kvm_userspace_memory_region memreg;
    memreg.slot = slot_count++;
    memreg.flags = 0;
    memreg.guest_phys_addr = address;
    memreg.memory_size = size;
    memreg.userspace_addr = (unsigned long)ptr;

    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) 
    {
        perror("KVM_SET_USER_MEMORY_REGION");
        printf("Failed to map address %" PRIx64 ", size %zx, perms %" PRIx32 ", ptr %p\n", address, size, perms, ptr);
    }
    else
    {
        printf("Mapped address %" PRIx64 ", size %zx, perms %" PRIx32 ", ptr %p\n", address, size, perms, ptr);
    }
}

void vm_init(struct vm *vm)
{
    int api_ver;

    sys_fd = open("/dev/kvm", O_RDWR);
    if (sys_fd < 0) {
        perror("open /dev/kvm");
        exit(1);
    }

    api_ver = ioctl(sys_fd, KVM_GET_API_VERSION, 0);
    if (api_ver < 0) {
        perror("KVM_GET_API_VERSION");
        exit(1);
    }

    if (api_ver != KVM_API_VERSION) {
        fprintf(stderr, "Got KVM api version %d, expected %d\n",
            api_ver, KVM_API_VERSION);
        exit(1);
    }

    vm_fd = ioctl(sys_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) {
        perror("KVM_CREATE_VM");
        exit(1);
    }

    if (ioctl(vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
        perror("KVM_SET_TSS_ADDR");
        exit(1);
    }
    
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        exit(1);
    }
}

void vm_exit(struct vm *vm)
{
    close(vm_fd);
    close(sys_fd);
}

void vcpu_init(struct vm *vm)
{
    int vcpu_mmap_size;

    vcpu_mmap_size = ioctl(sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (vcpu_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
                exit(1);
    }

    vm->vcpu.kvm_run = (struct kvm_run*)mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED, vcpu_fd, 0);
    if (vm->vcpu.kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        exit(1);
    }
}

uint32_t run_vm(struct vm *vm, size_t sz)
{
    struct kvm_regs regs;
    ImportTracker *import;
    
    vm->stopped = false;

    for (;;) {
        if (vm->stopped) break;
        
        if (ioctl(vcpu_fd, KVM_SET_REGS, &vm->vcpu.regs) < 0) {
            perror("KVM_SET_REGS");
            exit(1);
        }
        
        if (ioctl(vcpu_fd, KVM_SET_SREGS, &vm->vcpu.sregs) < 0) {
            perror("KVM_SET_SREGS");
            exit(1);
        }
    
        if (ioctl(vcpu_fd, KVM_RUN, 0) < 0) {
            perror("KVM_RUN");
            kvm_print_regs(vm);
            exit(1);
        }

        switch (vm->vcpu.kvm_run->exit_reason) {

        case 17:
            if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) {
                perror("KVM_GET_REGS");
                exit(1);
            }

            struct kvm_vcpu_events events;
            if (ioctl(vcpu_fd, KVM_GET_VCPU_EVENTS, &events) < 0)
            {
                perror("KVM_GET_VCPU_EVENTS");
                exit(1);
            }
            
            //printf("%x %x %x %x %x\n", events.exception.injected, events.exception.nr, events.exception.has_error_code, events.exception.error_code, regs.rip);
            
            import = import_hooks[regs.rip];
            
            /*if (events.exception.nr == 0xd && regs.rip < 0x80000000)
            {
                //uint32_t popped = 0;
                //vm_stack_pop(&popped, 1);
                //printf("%08x\n", popped);
                vm_reg_write(UC_X86_REG_EIP, regs.rip + 2);
                kvm_print_regs(vm);
            }
            else */if (import)
            {
                //printf("Hit import %s::%s\n", import->dll.c_str(), import->name.c_str());
                vm_process_import(import);
                //kvm_print_regs(vm);
            }
            else
            {
                printf("Failed import %" PRIx64 "\n", regs.rip);
                kvm_print_regs(vm);
                kvm_stop(vm);
                
                printf("%08x\n", current_kvm->vcpu.sregs.es.selector);
            }

            memset(&events, 0, sizeof(events));
            if (ioctl(vcpu_fd, KVM_SET_VCPU_EVENTS, &events) < 0)
            {
                perror("KVM_SET_VCPU_EVENTS");
                exit(1);
            }

            break;

            /* fall through */
        default:
            user32->stopping = true;
            fprintf(stderr,    "Got exit_reason %d,"
                " expected KVM_EXIT_HLT (%d)\n",
                vm->vcpu.kvm_run->exit_reason, KVM_EXIT_HLT);  
            kvm_print_regs(vm);
            kvm_stop(vm);
            break;
        }
    }

    if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) {
        perror("KVM_GET_REGS");
        exit(1);
    }

    return regs.rax;
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
    struct kvm_segment seg;
    seg.base = 0;
    seg.limit = 0xffffffff;
    seg.selector = 1 << 3;
    seg.present = 1;
    seg.type = 11; /* Code: execute, read, accessed */
    seg.dpl = 0;
    seg.db = 1;
    seg.s = 1; /* Code/data */
    seg.l = 0;
    seg.g = 1; /* 4KB granularity */
    
    // Set up paging
    uint64_t *pd = pd_mem;
    
    for (int i = 0; i < 0x10000/8; i++)
    {
        pd[i] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS | (i * 0x400000);
    }

    //sregs->cr3 = pd_address;
    //sregs->cr4 = CR4_PSE;
    sregs->cr0 = CR0_PE;// | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM;

    //sregs->cr0 |= CR0_PE | CR0_ET | CR0_PG; /* enter protected mode */

    sregs->cs = seg;
    
    seg.type = 3; /* Data: read/write, accessed */
    seg.selector = 2 << 3;
    sregs->ds = seg;
    sregs->es = seg;
    
    seg.type = 3; /* Data: read/write, accessed */
    seg.selector = 2 << 3;
    sregs->gs = seg;
    sregs->ss = seg;
    
    seg.base = fs_address;
    sregs->fs = seg;

#if 0
    seg.type = 3; /* Data: read/write, accessed */
    seg.selector = 0 << 3;
    sregs->gs = sregs->ss = seg;
    
    seg.base = fs_address;
    sregs->fs = seg;
    
    seg.selector = 0 << 3;
    seg.base = 0; // TODO?
    sregs->ds = seg;
    
    seg.selector = 0 << 3;
    seg.base = es_address;
    sregs->es = seg;
#endif
}

uint32_t run_protected_mode(struct vm *vm, uint32_t start, uint32_t esp)
{
    if (ioctl(vcpu_fd, KVM_GET_SREGS, &vm->vcpu.sregs) < 0) {
        perror("KVM_GET_SREGS (run_protected_mode)");
        exit(1);
    }

    setup_protected_mode(&vm->vcpu.sregs);

    if (ioctl(vcpu_fd, KVM_SET_SREGS, &vm->vcpu.sregs) < 0) {
        perror("KVM_SET_SREGS (run_protected_mode)");
        exit(1);
    }

    memset(&vm->vcpu.regs, 0, sizeof(vm->vcpu.regs));
    /* Clear all FLAGS bits, except bit 1 which is always set. */
    vm->vcpu.regs.rflags = 2;
    vm->vcpu.regs.rip = start;
    vm->vcpu.regs.rsp = esp;
    
    vm->vcpu.sregs.gdt.base = gdt_address;
    vm->vcpu.sregs.gdt.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

    if (ioctl(vcpu_fd, KVM_SET_REGS, &vm->vcpu.regs) < 0) {
        perror("KVM_SET_REGS (run_protected_mode end)");
        exit(1);
    }

    return run_vm(vm, 4);
}

bool initialized = false;

uint32_t kvm_run(struct vm *kvm, uint32_t stack_addr, uint32_t stack_size, uint32_t start_addr, uint32_t end_addr, uint32_t esp)
{
    //printf("KVM run %" PRIx32 "\n", start_addr);
    
    // Save state
    if (current_kvm)
    {
        if (ioctl(vcpu_fd, KVM_GET_SREGS, &current_kvm->vcpu.sregs) < 0) {
            perror("KVM_GET_SREGS (kvm_run)");
            exit(1);
        }
        
        if (ioctl(vcpu_fd, KVM_GET_REGS, &current_kvm->vcpu.regs) < 0) {
            perror("KVM_GET_REGS (kvm_run)");
            exit(1);
        }
    }
    
    struct vm *last_kvm = current_kvm;
    current_kvm = kvm;
    
    if (!esp)
        esp = stack_addr + stack_size;
    
    if (!initialized)
    {
        vm_init(kvm);
        
        vm_map_images();
        
        fs_mem = vm_alloc(0x1000);
        es_mem = vm_alloc(0x1000);
        gdt_mem = vm_alloc(0x10000);
        pd_mem = vm_alloc(0x10000);
        
        memset(gdt_mem, 0, 0x10000);
        
        // init gdt
        struct SegmentDescriptor *gdt = (struct SegmentDescriptor*)gdt_mem;
        vm_init_descriptor(&gdt[14], 0, 0xfffff000, 1);  //code segment
        vm_init_descriptor(&gdt[15], 0, 0xfffff000, 0);  //data segment
        vm_init_descriptor(&gdt[16], gdt_address, 0xfff, 0);  //one page data segment simulate fs
        vm_init_descriptor(&gdt[17], 0, 0xfffff000, 0);  //ring 0 data
        gdt[17].dpl = 0;  //set descriptor privilege level
        
        vm_init_descriptor(&gdt[0], 0, 0xfffff000, 0);
        vm_init_descriptor(&gdt[1], 0, 0xfffff000, 1);
        vm_init_descriptor(&gdt[2], 0, 0xfffff000, 0);
        
        kvm_mem_map_ptr(kvm, fs_address, 0x1000, 0, fs_mem);
        kvm_mem_map_ptr(kvm, es_address, 0x1000, 0, es_mem);
        kvm_mem_map_ptr(kvm, pd_address, 0x1000, 0, pd_mem);

        //*(uint32_t*)(image_mem + 0x8F0524 - image_addr) = 0x12345678;
        vm_sync_imports();
        
        kernel32->VM_MapHeaps();
        initialized = true;
    }

    vcpu_init(kvm);
    uint32_t eax = run_protected_mode(kvm, start_addr, esp);

    //printf("%08x\n", current_kvm->vcpu.sregs.es.selector);

    // Restore state
    current_kvm = last_kvm;
    
    if (!current_kvm)
        return eax;

    if (ioctl(vcpu_fd, KVM_SET_SREGS, &current_kvm->vcpu.sregs) < 0) {
        perror("KVM_SET_SREGS (kvm_run)");
        //exit(1);
    }
    
    if (ioctl(vcpu_fd, KVM_SET_REGS, &current_kvm->vcpu.regs) < 0) {
        perror("KVM_SET_REGS (kvm_run)");
        //exit(1);
    }
    
    return eax;
}

void kvm_stop(struct vm *kvm)
{
    kvm->stopped = true;
}
