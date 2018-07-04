#include "kernel32.h"

#include <regex>
#include <deque>
#include <experimental/filesystem>

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
    uc_mem_write(uc, b, &out, strlen(out)+1);
        
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

void Kernel32::OutputDebugStringA(uint32_t str_ptr)
{
    std::string text = uc_read_string(uc, str_ptr);
    printf("OutputDebugString: %s\n", text.c_str());
}

uint32_t Kernel32::GetLastError()
{
    return last_error;
}

uint32_t Kernel32::LoadLibraryA(uint32_t dllStr_ptr)
{
    std::string text = uc_read_string(uc, dllStr_ptr);
    printf("Stub: Load library %s\n", text.c_str());
}

uint32_t Kernel32::FindFirstFileA(uint32_t lpFileName, uint32_t lpFindFileData)
{
    std::string match = uc_read_string(uc, lpFileName);

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
        
    struct WIN32_FIND_DATAA *out = new struct WIN32_FIND_DATAA();
    memset(out, 0, sizeof(*out));
    out->dwFileAttributes = 0x80;
    out->nFileSizeHigh = (fs::file_size(files[0]) & 0xFFFFFFFF00000000) >> 32;
    out->nFileSizeLow = fs::file_size(files[0]) & 0xFFFFFFFF;
    strncpy(out->cFileName, files[0].filename().c_str(), 260);
    strncpy(out->cAlternateFileName, "test", 14);
        
    uc_mem_write(uc, lpFindFileData, out, sizeof(struct WIN32_FIND_DATAA));
    
    file_searches[file_search_hand] = files;
    free(out);

    return file_search_hand++;
}
    
uint32_t Kernel32::FindNextFileA(uint32_t hFindFile, uint32_t lpFindFileData)
{
    auto files = file_searches[hFindFile];
    files.pop_front();
        
    if (files.size() > 0)
    {
        file_searches[hFindFile] = files;
        std::string windows_path = std::regex_replace(files[0].string(), std::regex("\\/"), "\\");
            
        struct WIN32_FIND_DATAA *out = new struct WIN32_FIND_DATAA();
        memset(out, 0, sizeof(*out));
        out->dwFileAttributes = 0x80;
        out->nFileSizeHigh = (fs::file_size(files[0]) & 0xFFFFFFFF00000000) >> 32;
        out->nFileSizeLow = fs::file_size(files[0]) & 0xFFFFFFFF;
        strncpy(out->cFileName, files[0].filename().c_str(), 260);
        strncpy(out->cAlternateFileName, "test", 14);
            
        uc_mem_write(uc, lpFindFileData, out, sizeof(struct WIN32_FIND_DATAA));
            
        free(out);
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
    std::string fname = uc_read_string(uc, lpFileName);
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
    
uint32_t Kernel32::ReadFile(uint32_t hFile, uint32_t lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t lpNumberOfBytesRead, uint32_t lpOverlapped)
{
    FILE* f = fdopen(hFile, "rw");
    //printf("Stub: Read file %x at %x, size %x to %x\n", hFindFile, ftell(f), nNumberOfBytesToRead, lpBuffer);
        
    void* buf = malloc(nNumberOfBytesToRead);
    uint32_t read = fread(buf, 1, nNumberOfBytesToRead, f);
        
    // Write bytes read and actual contents
    uc_mem_write(uc, lpNumberOfBytesRead, &read, sizeof(uint32_t));
    uc_mem_write(uc, lpBuffer, buf, read);
        
    return read;
}

uint32_t Kernel32::SetFilePointer(uint32_t hFile, uint32_t lDistanceToMove, uint32_t lpDistanceToMoveHigh, uint32_t dwMoveMethod)
{
    printf("Stub: seek file %x\n", hFile);
        
    FILE* f = fdopen(hFile, "rw");
        
    uint32_t high_val = 0;
    if (lpDistanceToMoveHigh)
        uc_mem_read(uc, lpDistanceToMoveHigh, &high_val, sizeof(uint32_t));

    uint64_t pos = lDistanceToMove | (high_val << 32);
    fseek(f, pos, dwMoveMethod);
        
    return 0;
}

/*uint32_t Kernel32::(uint32_t )
{
}*/
