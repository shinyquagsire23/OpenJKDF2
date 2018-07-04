#include "main.h"

#include <stdint.h>

#include <cstring>
#include <iostream>
#include <vector>

#include <QMetaMethod>
#include <QDebug>

struct DosHeader
{
     uint8_t signature[2];
     uint16_t lastsize;
     uint16_t nblocks;
     uint16_t nreloc;
     uint16_t hdrsize;
     uint16_t minalloc;
     uint16_t maxalloc;
     uint16_t ss; // 2 byte ptr
     uint16_t sp; // 2 byte ptr
     uint16_t checksum;
     uint16_t ip; // 2 byte ptr
     uint16_t cs; // 2 byte ptr
     uint16_t relocpos;
     uint16_t noverlay;
     uint16_t reserved1[4];
     uint16_t oem_id;
     uint16_t oem_info;
     uint16_t reserved2[10];
     uint32_t  e_lfanew;
};

struct COFFHeader
{
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

#define COFF_I386 0x14c

struct data_directory
{ 
    uint32_t virtualAddress;
    uint32_t size;
};

struct PEOptHeader
 {
    uint16_t signature; //decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image. 
    uint8_t majorLinkerVersion; 
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;  //The RVA of the code entry point
    uint32_t baseOfCode;
    uint32_t baseOfData;
    /*The next 21 fields are an extension to the COFF optional header format*/
    uint32_t imageBase;
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOSVersion;
    uint16_t minorOSVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t DLLCharacteristics;
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    struct data_directory dataDirectory[16];
};

struct PESection
{
    char name[8];
    union {
        uint32_t physicalAddress;
        uint32_t virtualSize;
    } addr;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
};

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


struct ImportDesc {
	uint32_t name_desc_ptr;
	uint32_t timestamp;
	uint32_t forwarder_chain;
	uint32_t name;
	uint32_t import_ptr_list;
};

#pragma pack(pop)

#define IMAGE_DIRECTORY_ENTRY_EXPORT	        0
#define IMAGE_DIRECTORY_ENTRY_IMPORT	        1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE	        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION	        3
#define IMAGE_DIRECTORY_ENTRY_SECURITY	        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC	        5
#define IMAGE_DIRECTORY_ENTRY_DEBUG	            6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE	    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR	        8
#define IMAGE_DIRECTORY_ENTRY_TLS	            9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	    11
#define IMAGE_DIRECTORY_ENTRY_IAT	            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	    13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14

uint32_t code_addr;
uint32_t stack_addr;
uint32_t start_addr;
uint32_t next_hook;
uint32_t ret_addr;
uint32_t callret_addr;
uint32_t callret_ret;
uint32_t callret_ret_addr;
bool pc_over;

Kernel32 *kernel32;
User32 *user32;
Gdi32 *gdi32;
ComCtl32 *comctl32;
AdvApi32 *advapi32;
Ole32 *ole32;
DDraw *ddraw;

std::map<std::string, ImportTracker*> import_store;
std::vector<QObject*> dll_store;


void print_registers(uc_engine *uc)
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

static void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ImportTracker *import);

void register_import(uc_engine *uc, std::string name, uint32_t import_addr)
{
    if (import_addr)
        uc_mem_write(uc, import_addr, &next_hook, sizeof(uint32_t));

    import_store[name] = new ImportTracker(name, import_addr, next_hook);

    uc_hook_add(uc, &import_store[name]->trace, UC_HOOK_CODE, (void*)hook_import, (void*)import_store[name], next_hook, next_hook);
    next_hook += 1;
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
        print_registers(uc);
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
        print_registers(uc);
        uc_stack_dump(uc);
    }
}

static void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ImportTracker *import)
{
    printf("Hit import %s\n", import->name.c_str());
    
    uc_stack_pop(uc, &ret_addr, 1);
    
    //TODO DLL names
    
    for (auto obj : dll_store)
    {
        for (int i = 0; i < obj->metaObject()->methodCount(); i++)
        {
            QMetaMethod method = obj->metaObject()->method(i);
            //qDebug() << method.methodSignature();
            
            if (method.name() == import->name.c_str())
            {
                uint32_t args[9];
                uint32_t retVal;
                
                uc_stack_pop(uc, args, method.parameterCount());
                
                bool succ;
                if (method.returnType() == QMetaType::Void)
                    succ = method.invoke(obj, Q_ARG(uint32_t, args[0]), Q_ARG(uint32_t, args[1]), Q_ARG(uint32_t, args[2]), Q_ARG(uint32_t, args[3]), Q_ARG(uint32_t, args[4]), Q_ARG(uint32_t, args[5]), Q_ARG(uint32_t, args[6]), Q_ARG(uint32_t, args[7]), Q_ARG(uint32_t, args[8]));
                else
                    succ = method.invoke(obj, Q_RETURN_ARG(uint32_t, retVal), Q_ARG(uint32_t, args[0]), Q_ARG(uint32_t, args[1]), Q_ARG(uint32_t, args[2]), Q_ARG(uint32_t, args[3]), Q_ARG(uint32_t, args[4]), Q_ARG(uint32_t, args[5]), Q_ARG(uint32_t, args[6]), Q_ARG(uint32_t, args[7]), Q_ARG(uint32_t, args[8]));

                //printf("%x %x %x\n", succ, retVal, method.parameterCount());
                if (succ)
                {
                    if (method.returnType() != QMetaType::Void)
                        uc_reg_write(uc, UC_X86_REG_EAX, &retVal);

                    if (!pc_over)
                        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
                    return;
                }
                else
                {
                    uc_stack_push(uc, args, method.parameterCount());
                }
            }
        }
    }
    
    
    if (!strcmp(import->name.c_str(), "IsProcessorFeaturePresent"))
    {
        uint32_t args[1];
        uint32_t eax;
        
        uc_stack_pop(uc, args, 1); //TODO: real handles
        
        eax = 0;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }
    else if (!strcmp(import->name.c_str(), "CreateWindowExA"))
    {
        uint32_t args[12];
        uint32_t eax;
        
        uc_stack_pop(uc, args, 12); //TODO
        
        eax = user32->CreateWindowExA(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11]);
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }
    else if (!strcmp(import->name.c_str(), "CallRet"))
    {
        ret_addr = callret_ret_addr;
        uc_stack_push(uc, &ret_addr, 1);
    
        uint32_t eax = callret_ret;
        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    }
    else
    {
        printf("Import doesn't have impl, exiting\n");
        uc_emu_stop(uc);
        return;
    }
    
    if (!pc_over)
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
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
            print_registers(uc);
            return false;
        case UC_MEM_WRITE_UNMAPPED:
            printf(">>> Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
                         address, size, value);
            print_registers(uc);
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

int load_executable(uc_engine *uc)
{
    struct DosHeader dosHeader;
    struct COFFHeader coffHeader;
    struct PEOptHeader peHeader;
    
    FILE *f = fopen("JK.EXE", "rb");
    if (!f)
    {
        printf("Failed to open JK.EXE, exiting\n");
        return -1;
    }
    
    fread(&dosHeader, sizeof(struct DosHeader), 1, f);
    fseek(f, dosHeader.e_lfanew + sizeof(uint32_t), SEEK_SET);
    fread(&coffHeader, sizeof(struct COFFHeader), 1, f);
    
    printf("PE header at 0x%08x\n", dosHeader.e_lfanew);
    printf("COFF:\nMachine %x\nNum Sections %x\nTimeDateStamp %x\nSymbol Table Ptr %x\nNum Symbols %x\nOpt Hdr Size %x\nCharacteristics %x\n", coffHeader.machine, coffHeader.numberOfSections, coffHeader.timeDateStamp, coffHeader.pointerToSymbolTable, coffHeader.numberOfSymbols, coffHeader.sizeOfOptionalHeader, coffHeader.characteristics);
    
    if (coffHeader.machine != COFF_I386)
    {
        printf("Bad COFF machine type %x, expected %x, exiting\n", coffHeader.machine, COFF_I386);
        return -1;
    }
    
    fread(&peHeader, sizeof(struct PEOptHeader), 1, f);
    
    printf("Code size %x section starts at %x, execution starts at %x, %x\n", peHeader.sizeOfCode, peHeader.baseOfCode + peHeader.imageBase, peHeader.addressOfEntryPoint, peHeader.sizeOfImage);
    
    //TODO: should this be here
    printf("Stack size %x, %x heap %x %x\n", peHeader.sizeOfStackReserve, peHeader.sizeOfStackCommit, peHeader.sizeOfHeapReserve, peHeader.sizeOfHeapCommit);
    
    code_addr = peHeader.baseOfCode + peHeader.imageBase;
    stack_addr = peHeader.imageBase - peHeader.sizeOfStackReserve;
    kernel32->heap_addr = 0x90000000;
    kernel32->last_alloc = 0x80000000;
    
    uc_mem_map(uc, stack_addr, peHeader.sizeOfStackReserve, UC_PROT_ALL);
    uc_reg_write(uc, UC_X86_REG_ESP, &peHeader.imageBase);
    
    uc_mem_map(uc, peHeader.imageBase, peHeader.sizeOfImage, UC_PROT_ALL);
    
    for (int i = 0; i < coffHeader.numberOfSections; i++)
    {
        uint64_t temp;
        struct PESection peSection;
        fread(&peSection, sizeof(struct PESection), 1, f);
        temp = ftell(f);
        
        printf("Section %.8s size 0x%x, vsize 0x%x, vaddr 0x%0x at file 0x%x. %x relocs, %x lines\n", peSection.name, peSection.sizeOfRawData, peSection.addr.virtualSize, peSection.virtualAddress, peSection.pointerToRawData, peSection.numberOfRelocations, peSection.numberOfLinenumbers);
        
        void *section = malloc(peSection.sizeOfRawData);
        fseek(f, peSection.pointerToRawData, SEEK_SET);
        fread(section, peSection.sizeOfRawData, 1, f);

        if (uc_mem_write(uc, peHeader.imageBase + peSection.virtualAddress, section, peSection.sizeOfRawData)) {
            printf("Failed to write emulation code to memory, quit!\n");
            return -1;
        }
        free(section);
        
        fseek(f, temp, SEEK_SET);
    }
    
    // Iterate directories and link
    for (int i = 0; i < 16; i++)
    {
        //printf("directory %i, %x size %x\n", i, peHeader.dataDirectory[i].virtualAddress, peHeader.dataDirectory[i].size);
        
        struct ImportDesc tmp;
        if (i != IMAGE_DIRECTORY_ENTRY_IMPORT) continue;

        for (int j = 0; j < peHeader.dataDirectory[i].size / sizeof(struct ImportDesc); j++)
        {
            if (uc_mem_read(uc, peHeader.imageBase + peHeader.dataDirectory[i].virtualAddress + j*sizeof(struct ImportDesc), &tmp, sizeof(struct ImportDesc))) continue;

            std::string name = uc_read_string(uc, peHeader.imageBase + tmp.name);
            printf("%s:\n", name.c_str());
            
            printf("%x %x\n", peHeader.imageBase + tmp.name_desc_ptr, peHeader.imageBase + tmp.import_ptr_list);
            
            for (int i = 0; true; i++)
            {
                uint32_t importEntryRelAddr;
                uc_mem_read(uc, peHeader.imageBase + tmp.name_desc_ptr + i*sizeof(uint32_t), &importEntryRelAddr, sizeof(uint32_t));
                
                if (!importEntryRelAddr) break;
                if (importEntryRelAddr & 0x80000000)
                {
                    uint32_t index = importEntryRelAddr & ~0x80000000;
                    std::string to_register = "";
                    if (!strcmp(name.c_str(), "COMCTL32.dll") && index == 17)
                    {
                        to_register = "InitCommonControls";
                    }
                    else if (!strcmp(name.c_str(), "DPLAYX.dll") && index == 4)
                    {
                        to_register = "DirectPlayLobbyCreateA";
                    }
                    else
                    {
                        printf("Unknown index %i for %s\n", index, name.c_str());
                        continue;
                    }
                    
                    register_import(uc, to_register, peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));
                    printf("%s at 0x%x\n", to_register.c_str(), peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));
                    continue;
                }
                
                uint16_t hint;
                uc_mem_read(uc, peHeader.imageBase + importEntryRelAddr, &hint, sizeof(uint16_t));

                std::string funcName = uc_read_string(uc, peHeader.imageBase + importEntryRelAddr + sizeof(uint16_t));
                register_import(uc, funcName, peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));

                printf("%s at 0x%x\n", funcName.c_str(), peHeader.imageBase + tmp.import_ptr_list + i*sizeof(uint32_t));
            }
            printf("\n");
        }
    }
    
    start_addr = peHeader.imageBase + peHeader.addressOfEntryPoint;
    
    fclose(f);

    return 0;
}

int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2, trace3;
    uc_x86_mmr gdtr;

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
        return -1;
    }
    
    kernel32 = new Kernel32(uc);
    user32 = new User32(uc);
    gdi32 = new Gdi32(uc);
    comctl32 = new ComCtl32(uc);
    advapi32 = new AdvApi32(uc);
    ole32 = new Ole32(uc);
    ddraw = new DDraw(uc);
    dll_store.push_back((QObject*)kernel32);
    dll_store.push_back((QObject*)user32);
    dll_store.push_back((QObject*)gdi32);
    dll_store.push_back((QObject*)comctl32);
    dll_store.push_back((QObject*)advapi32);
    dll_store.push_back((QObject*)ole32);
    dll_store.push_back((QObject*)ddraw);

    // Map hook mem
    next_hook = 0xd0000000;
    err = uc_mem_map(uc, next_hook, 0x10000, UC_PROT_ALL);
    
    char ret_val = 0xc3;
    for (int i = 0; i < 0x10000; i++)
    {
        err = uc_mem_write(uc, next_hook + i, &ret_val, sizeof(char));
    }

    load_executable(uc);

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
    
    register_import(uc, "CallRet", NULL);
    callret_addr = import_store["CallRet"]->hook;

    printf("Emulation begins at %x\n", start_addr);

    err = uc_emu_start(uc, start_addr, start_addr + 0x193, 0, 0);
    if (err) 
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf(">>> Emulation done. Below is the CPU context\n");
    print_registers(uc);

    uc_close(uc);

    return 0;
}
