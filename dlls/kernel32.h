#ifndef KERNEL32_H
#define KERNEL32_H

#include <QObject>
#include <bitset>
#include <map>
#include "loaders/exe.h"

#include "vm.h"
#include "renderer.h"

#pragma pack(push, 1)
struct StartupInfo
{
    uint32_t cb;
    uint32_t lpReserved;
    uint32_t lpDesktop;
    uint32_t lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    uint32_t lpReserved2;
    uint32_t hStdInput;
    uint32_t hStdOutput;
    int32_t hStdError;
};

struct CpInfo
{
    uint32_t maxCharSize;
    char defaultChar[2];
    char leadByte[12];
};


struct WIN32_FIND_DATAA 
{
    uint32_t dwFileAttributes;
    uint32_t ftCreationTime;
    uint32_t ftLastAccessTime;
    uint64_t idk;
    uint32_t ftLastWriteTime;
    uint32_t nFileSizeHigh;
    uint32_t nFileSizeLow;
    uint32_t dwReserved0;
    uint32_t dwReserved1;
    uint32_t idk2;
    char cFileName[260];
    char cAlternateFileName[14];
    char unk[2];
};
#pragma pack(pop)

#define STD_INPUT_HANDLE  (-10)
#define STD_OUTPUT_HANDLE (-11)
#define STD_ERROR_HANDLE  (-12)

#define FILE_TYPE_DISK 0x0001
#define FILE_TYPE_CHAR 0x0002

#define INVALID_HANDLE_VALUE -1

#define ERROR_FILE_NOT_FOUND (2)
#define ERROR_NO_MORE_FILES (18)

class Kernel32 : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint32_t> tls_vals;
    std::map<uint32_t, uint32_t> virtual_allocs;
    std::bitset<0x10000000 / 0x1000> virtual_bitmap;
    size_t virtual_head;
    int tls_index;

public:
    uint32_t heap_handle;
    void *heap_mem;
    uint32_t heap_addr;
    uint32_t heap_size;
    uint32_t heap_size_actual;
    
    void *virtual_mem;
    uint32_t virtual_addr;
    uint32_t virtual_size;
    uint32_t virtual_size_actual;
    
    uint32_t last_alloc;
    uint32_t last_error;
    uint32_t file_search_hand;
    
    uint32_t hFileCnt;
    
    std::map<uint32_t, FILE*> openFiles;

    Q_INVOKABLE Kernel32() : virtual_head(0), tls_index(0), heap_handle(1), heap_addr(0x90000000), heap_size(0), virtual_addr(0x80000000), virtual_size(0), last_alloc(0), last_error(0), file_search_hand(1) , hFileCnt(1)
    {
        qRegisterMetaType<struct WIN32_FIND_DATAA*>("struct WIN32_FIND_DATAA*");
        heap_size_actual = 0x8000000;
        virtual_size_actual = 0x10000000;
        heap_mem = vm_alloc(heap_size_actual);
        virtual_mem = vm_alloc(virtual_size_actual);
    }
    
    Q_INVOKABLE uint32_t VM_MapHeaps();
    Q_INVOKABLE uint32_t HeapCreate(uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t HeapAlloc(uint32_t a, uint32_t b, uint32_t alloc_size);
    Q_INVOKABLE uint32_t HeapFree(uint32_t hHeap, uint32_t dwFlags, uint32_t mem);
    Q_INVOKABLE uint32_t CloseHandle(uint32_t handle);
    Q_INVOKABLE uint32_t GetVersion() { return 0; };
    Q_INVOKABLE uint32_t VirtualAlloc(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t VirtualFree(uint32_t lpAddress, uint32_t dwSize, uint32_t dwFreeType);
    Q_INVOKABLE uint32_t GetStartupInfoA(struct StartupInfo* lpStartupInfo);
    Q_INVOKABLE uint32_t GetStdHandle(uint32_t nStdHandle);
    Q_INVOKABLE uint32_t GetFileType(int32_t hFile);
    Q_INVOKABLE uint32_t SetHandleCount(uint32_t uNumber);
    Q_INVOKABLE uint32_t GetACP();
    Q_INVOKABLE uint32_t GetCPInfo(uint32_t a, void* outPtr);
    Q_INVOKABLE uint32_t GetStringTypeW(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t MultiByteToWideChar(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f);
    Q_INVOKABLE uint32_t WideCharToMultiByte(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h);
    Q_INVOKABLE uint32_t LCMapStringW(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f);
    Q_INVOKABLE uint32_t GetCommandLineA();
    Q_INVOKABLE uint32_t GetEnvironmentStringsW();
    Q_INVOKABLE uint32_t FreeEnvironmentStringsW(uint32_t ptr);
    Q_INVOKABLE uint32_t GetModuleFileNameA(uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t GetModuleHandleA(char* module);
    Q_INVOKABLE uint32_t GetProcAddress(uint32_t a, char* funcName);
    Q_INVOKABLE void OutputDebugStringA(uint32_t str_ptr);
    Q_INVOKABLE uint32_t GetLastError();
    Q_INVOKABLE uint32_t LoadLibraryA(uint32_t dllStr_ptr);
    Q_INVOKABLE uint32_t FindFirstFileA(char* lpFileName, struct WIN32_FIND_DATAA* lpFindFileData);
    Q_INVOKABLE uint32_t FindNextFileA(uint32_t hFindFile, struct WIN32_FIND_DATAA* lpFindFileData);
    Q_INVOKABLE uint32_t FindClose(uint32_t hFindFile);
    Q_INVOKABLE uint32_t FileTimeToLocalFileTime(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t FileTimeToSystemTime(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t CreateFileA(uint32_t lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, uint32_t lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, uint32_t hTemplateFile);
    Q_INVOKABLE uint32_t ReadFile(uint32_t hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t *lpNumberOfBytesRead, uint32_t lpOverlapped);
    Q_INVOKABLE uint32_t WriteFile(uint32_t hFile, void* lpBuffer, uint32_t nNumberOfBytesToWrite, uint32_t *lpNumberOfBytesWritten, uint32_t lpOverlapped);
    Q_INVOKABLE uint32_t SetFilePointer(uint32_t hFile, uint32_t lDistanceToMove, uint32_t* lpDistanceToMoveHigh, uint32_t dwMoveMethod);
    Q_INVOKABLE uint32_t CreateDirectoryA(char* lpPathName, void *lpSecurityAttributes);
    Q_INVOKABLE void InitializeCriticalSection(uint32_t a){}
    Q_INVOKABLE uint32_t GetDriveTypeA(char* lpRootPathName);
    Q_INVOKABLE uint32_t TlsAlloc()
    {
        return tls_index++;
    }

    Q_INVOKABLE void EnterCriticalSection(uint32_t lpCriticalSection)
    {
    }

    Q_INVOKABLE void LeaveCriticalSection(uint32_t lpCriticalSection)
    {
    }

    Q_INVOKABLE uint32_t TlsSetValue(uint32_t dwTlsIndex, uint32_t lpTlsValue)
    {
        //printf("STUB: TlsSetValue %x to %x\n", dwTlsIndex, lpTlsValue);
        
        tls_vals[dwTlsIndex] = lpTlsValue;
        
        return 1;
    }

    Q_INVOKABLE uint32_t TlsGetValue(uint32_t dwTlsIndex)
    {
        //printf("STUB: TlsGetValue %x\n", dwTlsIndex);
        
        return tls_vals[dwTlsIndex];
    } 

    Q_INVOKABLE uint32_t GetCurrentThreadId()
    {
        printf("STUB: GetCurrentThreadId\n");
        return 0xbaddad;
    }

    Q_INVOKABLE uint32_t SetUnhandledExceptionFilter(uint32_t a)
    {
        printf("STUB: SetUnhandledExceptionFilter\n");
        return 0xaaaaaa;
    }

    Q_INVOKABLE uint32_t FindResourceA(uint32_t hModule, char* lpName, uint32_t lpType)
    {
        printf("STUB: FindResourceA %x, %s, %u\n", hModule, lpName, lpType);
        
        std::string str = std::string(lpName);
        
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c){ return std::tolower(c); });
        return real_ptr_to_vm_ptr(resource_str_map[lpType][str]);
    }
    
    Q_INVOKABLE uint32_t LoadResource(uint32_t hModule, ResourceData* hResInfo)
    {
        return hResInfo->ptr;
    }

    Q_INVOKABLE uint32_t GetCurrentDirectoryA(uint32_t bufSize, char* buf)
    {
        char cwd[256];
        getcwd(cwd, 256);

        strncpy(buf, cwd, bufSize);
        return 1;
    }

    Q_INVOKABLE uint32_t SetCurrentDirectoryA(char* buf);
    Q_INVOKABLE void SetLastError(uint32_t err)
    {
        last_error = err;
    }
    
    Q_INVOKABLE void Sleep(uint32_t ms)
    {
        //TODO
    }
    
    Q_INVOKABLE uint32_t CreateThread(uint32_t lpThreadAttributes, uint32_t dwStackSize, uint32_t lpStartAddress, uint32_t lpParameter, uint32_t dwCreationFlags, uint32_t lpThreadId)
    {
        printf("STUB: Kernel32::CreateThread %x %x %x %x %x %x\n", lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        
        //TODO: run this somehow
        //vm_call_func(lpStartAddress, lpParameter);
        
        return 0xbbbccc;
    }
    
    Q_INVOKABLE uint32_t GetCurrentThread()
    {
        return 0xcccbbb;
    }
    
    Q_INVOKABLE uint32_t SetThreadPriority(uint32_t hThread, uint32_t prio)
    {
        printf("STUB: Kernel32::SetThreadPriority(%x, %x)\n", hThread, prio);
        return 0;
    }
    
    Q_INVOKABLE uint32_t lstrlenA(char* str)
    {
        return strlen(str);
    }
    
    Q_INVOKABLE void lstrcpyA(char* dst, char* src)
    {
        strcpy(dst, src);
    }
    
    Q_INVOKABLE void lstrcatA(char* dst, char* src)
    {
        strcat(dst, src);
    }
    
    Q_INVOKABLE uint32_t lstrcmpA(char* a, char* b)
    {
        return strcmp(a, b);
    }
    
    Q_INVOKABLE void lstrcpynA(char* dst, char* src, int len)
    {
        strncpy(dst, src, len);
    }
    
    Q_INVOKABLE uint32_t GetPrivateProfileIntA(char* sect, char* key, int def, char* file)
    {
        printf("STUB: Kernel32::GetPrivateProfileIntA(`%s', `%s', %u, `%s')\n", sect, key, def, file);
        return def;
    }
    
    Q_INVOKABLE uint32_t OpenFile(char* lpFileName, uint32_t lpReOpenBuff, uint32_t uStyle);
    Q_INVOKABLE uint32_t _lread(uint32_t hFile, char* buff, uint32_t bytes);
    Q_INVOKABLE uint32_t _hread(uint32_t hFile, char* buff, uint32_t bytes)
    {
        return _lread(hFile, buff, bytes);
    }
    Q_INVOKABLE uint32_t _lclose(uint32_t hFile);
    
    Q_INVOKABLE uint32_t GlobalAlloc(uint32_t flags, uint32_t size)
    {
        return VirtualAlloc(0, size, 0, 0);
    }
    
    Q_INVOKABLE uint32_t GlobalLock(uint32_t ptr)
    {
        return ptr;
    }
    
    Q_INVOKABLE uint32_t GlobalFree(uint32_t ptr)
    {
        VirtualFree(ptr, 0, 0);
        return 0;
    }
    
    Q_INVOKABLE uint32_t GlobalUnlock(uint32_t h)
    {
        return 0;
    }
    
    Q_INVOKABLE uint32_t GetTimeZoneInformation(uint32_t lpTimeZoneInformation)
    {
        return 1; //TIME_ZONE_ID_STANDARD
    }
    
    Q_INVOKABLE void GetLocalTime(uint32_t lpSystemTime)
    {
        printf("STUB: Kernel32::GetLocalTime(%x)\n", lpSystemTime);
        return;
    }
    
    Q_INVOKABLE uint32_t LocalAlloc(uint32_t flags, uint32_t size)
    {
        return VirtualAlloc(0, size, 0, 0);
    }
    
    Q_INVOKABLE uint32_t LocalLock(uint32_t ptr)
    {
        return ptr;
    }
    
    Q_INVOKABLE uint32_t LocalFree(uint32_t ptr)
    {
        VirtualFree(ptr, 0, 0);
        return 0;
    }
    
    Q_INVOKABLE uint32_t LocalUnlock(uint32_t h)
    {
        return 0;
    }
    
    Q_INVOKABLE uint32_t LocalReAlloc(uint32_t hMem, uint32_t size, uint32_t flags)
    {
        uint32_t newptr = VirtualAlloc(0, size, 0, 0);
        void* newptr_real = vm_ptr_to_real_ptr(newptr);
        void* oldptr_real = vm_ptr_to_real_ptr(hMem);
        
        memcpy(newptr_real, oldptr_real, size); //TODO hmmmmm
        
        return newptr;
    }
    
    Q_INVOKABLE uint32_t SetErrorMode(uint32_t uMode)
    {
        printf("STUB: Kernel32::SetErrorMode(%u)\n", uMode);
        return 0;
    }
    
    Q_INVOKABLE uint32_t InterlockedDecrement(uint32_t* addend)
    {
        printf("STUB: Kernel32::InterlockedDecrement(...)\n");
        (*addend)--;
        return *addend;
    }
    
    Q_INVOKABLE uint32_t WritePrivateProfileStringA(char* lpAppName, char* lpKeyName, char* lpString, char* lpFileName)
    {
        printf("STUB: Kernel32::WritePrivateProfileStringA(`%s', `%s', `%s', `%s')\n", lpAppName, lpKeyName, lpString, lpFileName);
        return 1;
    }
    
    Q_INVOKABLE uint32_t AllocConsole()
    {
        return 1;
    }
    
    Q_INVOKABLE uint32_t SetConsoleTitleA(char* lpConsoleTitle)
    {
        return 1;
    }
    
    Q_INVOKABLE uint32_t SetConsoleTextAttribute(uint32_t handle, uint32_t attributes)
    {
        return 1;
    }
    
    Q_INVOKABLE uint32_t FillConsoleOutputCharacterA(uint32_t handle, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        return 1;
    }
    
    Q_INVOKABLE uint32_t WriteConsoleA(uint32_t handle, char* buf, uint32_t buflen, uint32_t a, uint32_t b)
    {
        printf("STUB: Kernel32::WriteConsoleA(%x, `%s`, ...)\n", handle, buf);
        renderer_print(std::string(buf));
        return 1;
    }
    
    Q_INVOKABLE void GetSystemTimeAsFileTime(void* lpSystemTimeAsFileTime)
    {
        printf("STUB: Kernel32::GetSystemTimeAsFileTime(...)\n");
        return;
    }
    
    Q_INVOKABLE uint32_t GetCurrentProcessId()
    {
        printf("STUB: Kernel32::GetCurrentProcessId(...)\n");
        return 1;
    }
    
    Q_INVOKABLE uint32_t GetTickCount()
    {
        printf("STUB: Kernel32::GetTickCount(...)\n");
        return 1;
    }
    
    Q_INVOKABLE uint32_t QueryPerformanceCounter(void* lpPerformanceCount)
    {
        printf("STUB: Kernel32::QueryPerformanceCounter(...)\n");
        return 1;
    }
    
    Q_INVOKABLE uint32_t QueryPerformanceFrequency(uint32_t* out)
    {
        *out = 0;
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern Kernel32 *kernel32;

#endif // KERNEL32_H
