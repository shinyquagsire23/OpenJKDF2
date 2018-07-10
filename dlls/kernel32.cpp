#include "kernel32.h"

#include <regex>
#include <deque>
#include <experimental/filesystem>

#include "uc_utils.h"
#include "main.h"

namespace fs = std::experimental::filesystem;

std::map<int, std::deque<fs::path>> file_searches;

std::deque<fs::path> file_search(fs::path dir, std::regex pattern)
{
    std::deque<fs::path> result;

    for (const auto& p : fs::recursive_directory_iterator(dir))
    {
        if (fs::is_regular_file(p) && std::regex_match(p.path().string(), pattern))
        {
            //printf("%s\n", p.path().string().c_str());
            result.push_back(p);
        }
    }
    
    return result;
}

uint32_t Kernel32::Unicorn_MapHeaps()
{
    uc_err ret;
    uc_mem_region *regions;
    uint32_t count;

    uc_mem_regions(current_uc, &regions, &count);
    for (int i = 0; i < count; i++)
    {
        if (regions[i].begin == heap_addr || regions[i].begin == virtual_addr)
            uc_mem_unmap(current_uc, regions[i].begin, regions[i].end-regions[i].begin+1);
    }
    
    ret = uc_mem_map_ptr(current_uc, heap_addr, heap_size_actual, UC_PROT_ALL, heap_mem);
    //printf("%x %s\n", heap_size_actual, uc_strerror(ret));
    
    ret = uc_mem_map_ptr(current_uc, virtual_addr, virtual_size, UC_PROT_ALL, virtual_mem);
    //printf("%x %s\n", virtual_size, uc_strerror(ret));
}

uint32_t Kernel32::HeapCreate(uint32_t a, uint32_t b, uint32_t c)
{
    return heap_handle++;
}

uint32_t Kernel32::HeapAlloc(uint32_t a, uint32_t b, uint32_t alloc_size)
{
    uint32_t retval = heap_addr + heap_size;

    //printf("%x %x %x\n", a, b, alloc_size);

    heap_size += alloc_size;
    heap_size_actual = (heap_size & ~0xFFF) + 0x1000;
    heap_mem = realloc(heap_mem, heap_size_actual);
    Unicorn_MapHeaps();
    
    //printf("return %x, %x %x\n", retval, heap_size_actual, heap_size);
        
    return retval;
}

uint32_t Kernel32::VirtualAlloc(uint32_t lpAddress, uint32_t dwSize, uint32_t flAllocationType, uint32_t flProtect)
{
    /*uint32_t alloc_addr = lpAddress ? lpAddress : last_alloc + dwSize;
    uc_mem_map(current_uc, alloc_addr, dwSize, UC_PROT_ALL); //TODO prot
        
    if (!lpAddress)
        last_alloc = last_alloc + dwSize;
        
    return alloc_addr;*/
    
    uint32_t retval = virtual_addr + virtual_size;
    
    //printf("alloc %x\n", dwSize);
    
    dwSize = (dwSize & ~0xFFF) + 0x1000;

    virtual_size += dwSize;
    virtual_mem = realloc(virtual_mem, virtual_size);
    Unicorn_MapHeaps();
    
    //printf("return %x, %x %x\n", retval, virtual_size, virtual_size);
        
    return retval;
}

uint32_t Kernel32::GetStartupInfoA(struct StartupInfo* lpStartupInfo)
{
    memset(lpStartupInfo, 0, sizeof(struct StartupInfo));
    lpStartupInfo->cb = sizeof(struct StartupInfo);
    lpStartupInfo->hStdInput = STD_INPUT_HANDLE;
    lpStartupInfo->hStdOutput = STD_OUTPUT_HANDLE;
    lpStartupInfo->hStdError = STD_ERROR_HANDLE;
    //TODO
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

uint32_t Kernel32::GetCPInfo(uint32_t a, void* outPtr)
{
    struct CpInfo* out = (struct CpInfo*)outPtr;
    memset(out, 0, sizeof(out));
    out->maxCharSize = 1;
    out->defaultChar[0] = '?';

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

    uc_mem_write(current_uc, ptr, args, strlen(args)+1);
    return ptr;
}

uint32_t Kernel32::GetEnvironmentStringsW()
{
    const char *args = ""; //TODO
    uint32_t ptr = VirtualAlloc(0, 0x1000, 0, 0);

    uc_mem_write(current_uc, ptr, args, strlen(args)+1);
    return ptr;
}

uint32_t Kernel32::FreeEnvironmentStringsW(uint32_t ptr)
{
    return 1;
}

uint32_t Kernel32::GetModuleFileNameA(uint32_t a, uint32_t b, uint32_t c)
{        
    char* out = "ABC";
    uc_mem_write(current_uc, b, &out, strlen(out)+1);
        
    return 3;
}

uint32_t Kernel32::GetModuleHandleA(uint32_t a)
{
    return 999;
}

uint32_t Kernel32::GetProcAddress(uint32_t a, uint32_t funcName)
{
    std::string requested = uc_read_string(current_uc, funcName);
    printf("requested addr for %s\n", requested.c_str());
        
    if (import_store.find(requested) == import_store.end())
    {
        register_import("idk", requested, 0);
        sync_imports(current_uc);
    }
        
    return import_store[requested]->hook;
}

void Kernel32::OutputDebugStringA(uint32_t str_ptr)
{
    std::string text = uc_read_string(current_uc, str_ptr);
    printf("OutputDebugString: %s\n", text.c_str());
}

uint32_t Kernel32::GetLastError()
{
    return last_error;
}

uint32_t Kernel32::LoadLibraryA(uint32_t dllStr_ptr)
{
    std::string text = uc_read_string(current_uc, dllStr_ptr);
    printf("Stub: Load library %s\n", text.c_str());
}

uint32_t Kernel32::FindFirstFileA(char* lpFileName, struct WIN32_FIND_DATAA* lpFindFileData)
{
    std::string match = std::string(lpFileName);

    std::string linux_path = std::regex_replace(match, std::regex("\\\\"), "/");
    std::string regex_str = std::regex_replace(match, std::regex("\\\\"), "\\/");
    regex_str = std::regex_replace(regex_str, std::regex("\\*"), ".*");

    //TODO: filenames are insensitive, but paths aren't
    printf("searching for %s\n", linux_path.c_str());
    auto files = file_search(fs::path(linux_path).parent_path(), std::regex(regex_str.c_str(), std::regex_constants::icase));
        
    //TODO errors
        
    printf("found %s\n", files[0].c_str());
    std::string windows_path = std::regex_replace(files[0].string(), std::regex("\\/"), "\\");
        
    //TODO
    /*
    uint32_t ftCreationTime;
    uint32_t ftLastAccessTime;
    uint32_t ftLastWriteTime;
    char cAlternateFileName[14]; ?
    */
        
    memset(lpFindFileData, 0, sizeof(struct WIN32_FIND_DATAA));
    lpFindFileData->dwFileAttributes = 0x80;
    lpFindFileData->nFileSizeHigh = (fs::file_size(files[0]) & 0xFFFFFFFF00000000) >> 32;
    lpFindFileData->nFileSizeLow = fs::file_size(files[0]) & 0xFFFFFFFF;
    strncpy(lpFindFileData->cFileName, files[0].filename().c_str(), 260);
    strncpy(lpFindFileData->cAlternateFileName, "test", 14);
    
    file_searches[file_search_hand] = files;

    return file_search_hand++;
}
    
uint32_t Kernel32::FindNextFileA(uint32_t hFindFile, struct WIN32_FIND_DATAA* lpFindFileData)
{
    auto files = file_searches[hFindFile];
    files.pop_front();
        
    if (files.size() > 0)
    {
        file_searches[hFindFile] = files;
        std::string windows_path = std::regex_replace(files[0].string(), std::regex("\\/"), "\\");
            
        memset(lpFindFileData, 0, sizeof(struct WIN32_FIND_DATAA));
        lpFindFileData->dwFileAttributes = 0x80;
        lpFindFileData->nFileSizeHigh = (fs::file_size(files[0]) & 0xFFFFFFFF00000000) >> 32;
        lpFindFileData->nFileSizeLow = fs::file_size(files[0]) & 0xFFFFFFFF;
        strncpy(lpFindFileData->cFileName, files[0].filename().c_str(), 260);
        strncpy(lpFindFileData->cAlternateFileName, "test", 14);

        return 1;
    }
    else
    {
        last_error = ERROR_NO_MORE_FILES;
        return 0;
    }
}
    
uint32_t Kernel32::FindClose(uint32_t hFindFile)
{
    file_searches.erase(hFindFile); //TODO errors

    return 1;
}
    
uint32_t Kernel32::FileTimeToLocalFileTime(uint32_t a, uint32_t b)
{
    return 1;
}
    
uint32_t Kernel32::FileTimeToSystemTime(uint32_t a, uint32_t b)
{
    return 1;
}

uint32_t Kernel32::CreateFileA(uint32_t lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, uint32_t lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, uint32_t hTemplateFile)
{
    std::string fname = uc_read_string(current_uc, lpFileName);
    std::string linux_path = std::regex_replace(fname, std::regex("\\\\"), "/");
    printf("Stub: Create file %s\n", linux_path.c_str());
        
    FILE *f = fopen(linux_path.c_str(), "rw");
    if (!f)
    {
        last_error = ERROR_FILE_NOT_FOUND;
        return -1;
    }
    else
        return fileno(f);
}
    
uint32_t Kernel32::ReadFile(uint32_t hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t *lpNumberOfBytesRead, uint32_t lpOverlapped)
{
    FILE* f = fdopen(hFile, "rw");
    //printf("Stub: Read file %x at %x, size %x to %x\n", hFindFile, ftell(f), nNumberOfBytesToRead, lpBuffer);
        
    *lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, f);
        
    return *lpNumberOfBytesRead;
}

uint32_t Kernel32::SetFilePointer(uint32_t hFile, uint32_t lDistanceToMove, uint32_t* lpDistanceToMoveHigh, uint32_t dwMoveMethod)
{
    printf("Stub: seek file %x\n", hFile);
        
    FILE* f = fdopen(hFile, "rw");
        
    uint32_t high_val = 0;
    if (lpDistanceToMoveHigh)
        high_val = *lpDistanceToMoveHigh;

    uint64_t pos = lDistanceToMove | (high_val << 32);
    fseek(f, pos, dwMoveMethod);
        
    return 0;
}

/*uint32_t Kernel32::(uint32_t )
{
}*/
