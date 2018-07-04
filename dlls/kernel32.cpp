#include "kernel32.h"

#include "main.h"

uint32_t Kernel32::HeapCreate(uint32_t a, uint32_t b, uint32_t c)
{
    return heap_handle++;
}

uint32_t Kernel32::HeapAlloc(uint32_t a, uint32_t b, uint32_t alloc_size)
{
    uint32_t retval = heap_addr;

    printf("%x %x %x\n", a, b, alloc_size);

    heap_max = (heap_addr & ~0xFFF);
    while (heap_max < heap_addr + alloc_size)
    {
        //printf("mapping %x\n", heap_max);
        uc_mem_map(uc, heap_max, 0x1000, UC_PROT_ALL);
        heap_max += 0x1000;
    }

    heap_addr += alloc_size;
        
    return retval;
}

uint32_t Kernel32::VirtualAlloc(uint32_t lpAddress, uint32_t dwSize, uint32_t flAllocationType, uint32_t flProtect)
{
    uint32_t alloc_addr = lpAddress ? lpAddress : last_alloc + dwSize;
    uc_mem_map(uc, alloc_addr, dwSize, UC_PROT_ALL); //TODO prot
        
    if (!lpAddress)
        last_alloc = last_alloc + dwSize;
        
    return alloc_addr;
}

uint32_t Kernel32::GetStartupInfoA(uint32_t lpStartupInfo)
{
    struct StartupInfo out;
    memset(&out, 0, sizeof(out));
    out.cb = sizeof(out);
    out.hStdInput = STD_INPUT_HANDLE;
    out.hStdOutput = STD_OUTPUT_HANDLE;
    out.hStdError = STD_ERROR_HANDLE;
    //TODO
        
    uc_mem_write(uc, lpStartupInfo, &out, sizeof(out));
}

uint32_t Kernel32::GetStdHandle(uint32_t nStdHandle)
{
    return nStdHandle;
}

uint32_t Kernel32::GetFileType(uint32_t hFile)
{
    switch (hFile)
    {
        case STD_INPUT_HANDLE:
        case STD_OUTPUT_HANDLE:
        case STD_ERROR_HANDLE:
            return FILE_TYPE_CHAR;
            break;
        default:
            return FILE_TYPE_DISK;
    }
}

uint32_t Kernel32::SetHandleCount(uint32_t uNumber)
{
    printf("Handle count %x\n", uNumber);
}

uint32_t Kernel32::GetACP()
{
    return 20127;
}

uint32_t Kernel32::GetCPInfo(uint32_t a, uint32_t outPtr)
{
    struct CpInfo out;
    memset(&out, 0, sizeof(out));
    out.maxCharSize = 1;
    out.defaultChar[0] = '?';

    uc_mem_write(uc, outPtr, &out, sizeof(out));
    
    return true;
}

uint32_t Kernel32::GetStringTypeW(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    return 1;
}

uint32_t Kernel32::MultiByteToWideChar(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
{
    return 0;
}

uint32_t Kernel32::WideCharToMultiByte(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h)
{
    return 1;
}

uint32_t Kernel32::LCMapStringW(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
{
    return 2;
}

uint32_t Kernel32::GetCommandLineA()
{
    const char *args = ""; //TODO
    uint32_t ptr = VirtualAlloc(0, 0x1000, 0, 0);

    uc_mem_write(uc, ptr, args, strlen(args)+1);
    return ptr;
}

uint32_t Kernel32::GetEnvironmentStringsW()
{
    const char *args = ""; //TODO
    uint32_t ptr = VirtualAlloc(0, 0x1000, 0, 0);

    uc_mem_write(uc, ptr, args, strlen(args)+1);
    return ptr;
}

uint32_t Kernel32::FreeEnvironmentStringsW(uint32_t ptr)
{
    return 1;
}

uint32_t Kernel32::GetModuleFileNameA(uint32_t a, uint32_t b, uint32_t c)
{        
    char* out = "ABC";
    uc_mem_write(uc, b, &out, sizeof(out));
        
    return 3;
}

uint32_t Kernel32::GetModuleHandleA(uint32_t a)
{
    return 999;
}

uint32_t Kernel32::GetProcAddress(uint32_t a, uint32_t funcName)
{
    std::string requested = uc_read_string(uc, funcName);
    printf("requested addr for %s\n", requested.c_str());
        
    if (import_store.find(requested) == import_store.end())
        register_import(uc, requested, 0);
        
    return import_store[requested]->hook;
}

/*uint32_t Kernel32::(uint32_t )
{
}*/
