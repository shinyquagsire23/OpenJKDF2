#include "kernel32.h"

#include <regex>
#include <deque>
#include <experimental/filesystem>

#include "uc_utils.h"
#include "vm.h"
#include "main.h"

namespace fs = std::experimental::filesystem;

std::map<int, std::deque<fs::path>> file_searches;

std::deque<fs::path> file_search(fs::path dir, std::regex pattern)
{
    std::deque<fs::path> result;

    try
    {
        for (const auto& p : fs::recursive_directory_iterator(dir))
        {
            if (/*fs::is_regular_file(p) && */std::regex_match(p.path().string(), pattern))
            {
                //printf("%s\n", p.path().string().c_str());
                result.push_back(p);
            }
        }
    }
    catch (...)
    {
    }
    
    return result;
}

uint32_t Kernel32::VM_MapHeaps()
{
    vm_mem_map_ptr(heap_addr, heap_size_actual, UC_PROT_ALL, heap_mem);
    //printf("%x %s\n", heap_size_actual, uc_strerror(ret));
    
    vm_mem_map_ptr(virtual_addr, virtual_size_actual, UC_PROT_ALL, virtual_mem);
    //printf("%x %s\n", virtual_size, uc_strerror(ret));
    
    return 0;
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
    
    //printf("return %x, %x %x\n", retval, heap_size_actual, heap_size);

    

    return retval;
}

uint32_t Kernel32::HeapFree(uint32_t hHeap, uint32_t dwFlags, uint32_t mem)
{
    printf("STUB: HeapFree %x, heap %x\n", mem, hHeap);
    
    return 1;
}

uint32_t Kernel32::CloseHandle(uint32_t handle)
{
    printf("STUB: CloseHandle %x\n", handle);
    
    return 1;
}

uint32_t Kernel32::VirtualAlloc(uint32_t lpAddress, uint32_t dwSize, uint32_t flAllocationType, uint32_t flProtect)
{
    //TODO: lpAddress
    printf("valloc %x %x %x %x\n", lpAddress, dwSize, flAllocationType, flProtect);

    dwSize = (dwSize & ~0xFFF) + 0x1000;
    uint32_t numBits = dwSize / 0x1000;
    
    //TODO: don't loop forever if there's no space

    bool loop_once = false;
    uint32_t i = numBits;
    while (i)
    {
        if (virtual_head >= virtual_bitmap.size())
        {
            if (loop_once)
                return 0;
            i = numBits;
            virtual_head = 0;
            loop_once = true;
        }

        if (!virtual_bitmap[virtual_head])
            i--;
        else
            i = numBits;
        
        virtual_head++;        
    }
    
    for (i = 0; i < numBits; i++)
    {
        virtual_bitmap.set(virtual_head - i - 1, true);
    }
    
    virtual_size += dwSize;
    uint32_t retval = virtual_addr + (virtual_head * 0x1000) - dwSize;
    virtual_allocs[retval] = dwSize;
    
    // SMACKW32 debug
#if 0
    printf("a %x\n", retval);
    if (flAllocationType == 0x1000)
    {
        *(uint8_t*)vm_ptr_to_real_ptr(0x4089f9 - 0x401000 + 0x9f6000) = 0x0f;
        *(uint8_t*)vm_ptr_to_real_ptr(0x4089fa - 0x401000 + 0x9f6000) = 0x0b;
        memset(vm_ptr_to_real_ptr(retval), 0, dwSize);
    }
#endif

    return retval;
}

uint32_t Kernel32::VirtualFree(uint32_t lpAddress, uint32_t dwSize, uint32_t dwFreeType)
{    
    uint32_t startBit = (lpAddress - virtual_addr) / 0x1000;
    uint32_t numBits = virtual_allocs[lpAddress] / 0x1000;

    for (uint32_t i = startBit; i < startBit+numBits; i++)
    {
        virtual_bitmap.set(i, false);
    }
    
    virtual_size -= virtual_allocs[lpAddress];
    virtual_allocs[lpAddress] = 0;
    
    return 1;
}

uint32_t Kernel32::GetStartupInfoA(struct StartupInfo* lpStartupInfo)
{
    memset(lpStartupInfo, 0, sizeof(struct StartupInfo));
    lpStartupInfo->cb = sizeof(struct StartupInfo);
    lpStartupInfo->hStdInput = STD_INPUT_HANDLE;
    lpStartupInfo->hStdOutput = STD_OUTPUT_HANDLE;
    lpStartupInfo->hStdError = STD_ERROR_HANDLE;
    //TODO
    
    return 1;
}

uint32_t Kernel32::GetStdHandle(uint32_t nStdHandle)
{
    return nStdHandle;
}

uint32_t Kernel32::GetFileType(int32_t hFile)
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
    return 1;
}

uint32_t Kernel32::GetACP()
{
    return 20127;
}

uint32_t Kernel32::GetCPInfo(uint32_t a, void* outPtr)
{
    struct CpInfo* out = (struct CpInfo*)outPtr;
    memset(out, 0, sizeof(*out));
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
    char *args = (char*)"-windowGUI -verbose 2 -debug con "; //TODO
    uint32_t ptr = VirtualAlloc(0, 0x1000, 0, 0);

    vm_mem_write(ptr, args, strlen(args)+1);
    return ptr;
}

uint32_t Kernel32::GetEnvironmentStringsW()
{
    char *args = (char*)""; //TODO
    uint32_t ptr = VirtualAlloc(0, 0x1000, 0, 0);

    vm_mem_write(ptr, args, strlen(args)+1);
    return ptr;
}

uint32_t Kernel32::FreeEnvironmentStringsW(uint32_t ptr)
{
    return 1;
}

uint32_t Kernel32::GetModuleFileNameA(uint32_t hModule, uint32_t lpFilename, uint32_t nSize)
{        
    char* out = (char*)"Yodesk.exe";
    vm_mem_write(lpFilename, out, strlen(out)+1);
        
    return strlen(out);
}

uint32_t Kernel32::GetModuleHandleA(char* module)
{
    if (!module)
        return image_mem_addr;
    printf("STUB: Kernel32.dll::GetModuleHandleA(\"%s\")\n", module);
    return 999;
}

uint32_t Kernel32::GetProcAddress(uint32_t a, char* funcName)
{
    printf("Kernel32.dll::GetProcAddress...requested addr for %s\n", funcName);
        
    if (import_store.find(std::string(funcName)) == import_store.end())
    {
        vm_import_register("idk", std::string(funcName), 0);
        vm_sync_imports();
    }
        
    return vm_import_get_hook_addr("idk", std::string(funcName));
}

void Kernel32::OutputDebugStringA(uint32_t str_ptr)
{
    std::string text = vm_read_string(str_ptr);
    printf("OutputDebugString: %s\n", text.c_str());
}

uint32_t Kernel32::GetLastError()
{
    return last_error;
}

uint32_t Kernel32::LoadLibraryA(uint32_t dllStr_ptr)
{
    std::string text = vm_read_string(dllStr_ptr);
    printf("Stub: Load library %s\n", text.c_str());
    
    return 0x999aaa9;
}

uint32_t Kernel32::FindFirstFileA(char* lpFileName, struct WIN32_FIND_DATAA* lpFindFileData)
{
    std::string match = "./" + std::string(lpFileName);

    std::string linux_path = std::regex_replace(match, std::regex("\\\\"), "/");
    linux_path = std::regex_replace(linux_path, std::regex("\\*\\.\\*"), "*");
    std::string regex_str = std::regex_replace(match, std::regex("\\\\"), "\\/");
    regex_str = std::regex_replace(regex_str, std::regex("\\*"), ".*");

    //TODO: filenames are insensitive, but paths aren't
    printf("Kernel32::FindFirstFileA: searching for %s\n", linux_path.c_str());
    auto files = file_search(fs::path(linux_path).parent_path(), std::regex(regex_str.c_str(), std::regex_constants::icase));
    
    if (!files.size())
    {
        last_error = ERROR_FILE_NOT_FOUND;
        return INVALID_HANDLE_VALUE;
    }
        
    //TODO errors
        
    printf("Kernel32::FindFirstFileA: found %s\n", files[0].c_str());
    std::string windows_path = std::regex_replace(files[0].string(), std::regex("\\/"), "\\");
        
    //TODO
    /*
    uint32_t ftCreationTime;
    uint32_t ftLastAccessTime;
    uint32_t ftLastWriteTime;
    char cAlternateFileName[14]; ?
    */
        
    memset(lpFindFileData, 0, sizeof(struct WIN32_FIND_DATAA));
    if (fs::is_regular_file(files[0]))
    {
        lpFindFileData->dwFileAttributes = 0x80;
        lpFindFileData->nFileSizeHigh = (fs::file_size(files[0]) & 0xFFFFFFFF00000000) >> 32;
        lpFindFileData->nFileSizeLow = fs::file_size(files[0]) & 0xFFFFFFFF;
    }
    else
    {
        lpFindFileData->dwFileAttributes = 0x10;
        lpFindFileData->nFileSizeHigh = 0;
        lpFindFileData->nFileSizeLow = 0;
    }
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
        if (fs::is_regular_file(files[0]))
        {
            lpFindFileData->dwFileAttributes = 0x80;
            lpFindFileData->nFileSizeHigh = (fs::file_size(files[0]) & 0xFFFFFFFF00000000) >> 32;
            lpFindFileData->nFileSizeLow = fs::file_size(files[0]) & 0xFFFFFFFF;
        }
        else
        {
            lpFindFileData->dwFileAttributes = 0x10;
            lpFindFileData->nFileSizeHigh = 0;
            lpFindFileData->nFileSizeLow = 0;
        }
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
    std::string fname = vm_read_string(lpFileName);
    std::string linux_path = std::regex_replace(fname, std::regex("\\\\"), "/");
    linux_path = std::regex_replace(linux_path, std::regex("//"), "");
    linux_path = std::regex_replace(linux_path, std::regex("[A-Z]:/"), "disk/");
    printf("Stub: Create file %s\n", linux_path.c_str());
        
    FILE *f = fopen(linux_path.c_str(), "rw");
    if (!f)
    {
        printf("Failed to open file %s\n", linux_path.c_str());
        last_error = ERROR_FILE_NOT_FOUND;
        return -1;
    }
    else
    {
        openFiles[hFileCnt] = f;
        return hFileCnt++;
    }
}

uint32_t Kernel32::OpenFile(char* lpFileName, uint32_t lpReOpenBuff, uint32_t uStyle)
{
    std::string fname = std::string(lpFileName);
    std::string linux_path = std::regex_replace(fname, std::regex("\\\\"), "/");
    linux_path = std::regex_replace(linux_path, std::regex("//"), "");
    printf("STUB: Kernel32::OpenFile %s\n", linux_path.c_str());
        
    FILE *f = fopen(linux_path.c_str(), "rw");
    if (!f)
    {
        printf("Failed to open file %s\n", linux_path.c_str());
        last_error = ERROR_FILE_NOT_FOUND;
        return -1;
    }
    else
    {
        openFiles[hFileCnt] = f;
        return hFileCnt++;
    }
}

uint32_t Kernel32::_lread(uint32_t hFile, char* buff, uint32_t bytes)
{
    FILE* f = openFiles[hFile];
    return fread(buff, bytes, 1, f);
}

uint32_t Kernel32::_lclose(uint32_t hFile)
{
    FILE* f = openFiles[hFile];
    openFiles[hFile] = nullptr;
    return fclose(f);
}
    
uint32_t Kernel32::ReadFile(uint32_t hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t *lpNumberOfBytesRead, uint32_t lpOverlapped)
{
    FILE* f = openFiles[hFile];
    //printf("Stub: Read file %x at %x, size %x to %x\n", hFindFile, ftell(f), nNumberOfBytesToRead, lpBuffer);

    *lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, f);
        
    return *lpNumberOfBytesRead;
}

uint32_t Kernel32::WriteFile(uint32_t hFile, void* lpBuffer, uint32_t nNumberOfBytesToWrite, uint32_t *lpNumberOfBytesWritten, uint32_t lpOverlapped)
{
    FILE* f = openFiles[hFile];
    //printf("Stub: Read file %x at %x, size %x to %x\n", hFindFile, ftell(f), nNumberOfBytesToRead, lpBuffer);

    *lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, f);
        
    return *lpNumberOfBytesWritten;
}

uint32_t Kernel32::SetFilePointer(uint32_t hFile, uint32_t lDistanceToMove, uint32_t* lpDistanceToMoveHigh, uint32_t dwMoveMethod)
{
    //printf("Stub: seek file %x\n", hFile);
        
    FILE* f = openFiles[hFile];
        
    uint32_t high_val = 0;
    if (lpDistanceToMoveHigh)
        high_val = *lpDistanceToMoveHigh;

    uint64_t pos = lDistanceToMove | ((uint64_t)high_val << 32);
    fseek(f, pos, dwMoveMethod);
        
    return 0;
}

uint32_t Kernel32::CreateDirectoryA(char* lpPathName, void *lpSecurityAttributes)
{
    printf("STUB: Create Dir %s\n", lpPathName);
    
    std::string linux_path = std::regex_replace(std::string(lpPathName), std::regex("\\\\"), "/");
    linux_path = std::regex_replace(linux_path, std::regex("//"), "");
    
    fs::create_directories(linux_path);
    return 1;
}

uint32_t Kernel32::SetCurrentDirectoryA(char* buf)
{
    std::string path = std::string(buf);
    std::string linux_path = std::regex_replace(path, std::regex("\\\\"), "/");
    
    printf("STUB: SetCurrentDirectoryA to %s\n", linux_path.c_str());
    chdir(linux_path.c_str());
    
    char cwd[256];
    getcwd(cwd, 256);
    printf("cwd is %s\n", cwd);
    
    return 1;
}

uint32_t Kernel32::GetDriveTypeA(char* lpRootPathName)
{
    printf("STUB: Kernel32::GetDriveTypeA(\"%s\") -> 1\n", lpRootPathName);
    
    if (!strcmp(lpRootPathName, "D:\\"))
        return 5;

    return 1;
}

/*uint32_t Kernel32::(uint32_t )
{
}*/
