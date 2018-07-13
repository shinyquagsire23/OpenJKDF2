#ifndef KERNEL32_H
#define KERNEL32_H

#include <QObject>
#include <unicorn/unicorn.h>

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
    uint32_t hStdError;
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

#define ERROR_FILE_NOT_FOUND (2)
#define ERROR_NO_MORE_FILES (18)

class Kernel32 : public QObject
{
Q_OBJECT

public:
    uint32_t heap_handle;
    void *heap_mem;
    uint32_t heap_addr;
    uint32_t heap_size;
    uint32_t heap_size_actual;
    
    void *virtual_mem;
    uint32_t virtual_addr;
    uint32_t virtual_size;
    
    uint32_t last_alloc;
    uint32_t last_error;
    uint32_t file_search_hand;

    Q_INVOKABLE Kernel32() : heap_addr(0x90000000), virtual_addr(0x80000000), heap_handle(1), heap_size(0), virtual_size(0), last_error(0), file_search_hand(1) 
    {
        qRegisterMetaType<struct WIN32_FIND_DATAA*>("struct WIN32_FIND_DATAA*");
    }
    
    Q_INVOKABLE uint32_t Unicorn_MapHeaps();
    Q_INVOKABLE uint32_t HeapCreate(uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t HeapAlloc(uint32_t a, uint32_t b, uint32_t alloc_size);
    Q_INVOKABLE uint32_t HeapFree(uint32_t hHeap, uint32_t dwFlags, uint32_t mem);
    Q_INVOKABLE uint32_t CloseHandle(uint32_t handle);
    Q_INVOKABLE uint32_t GetVersion() { return 0; };
    Q_INVOKABLE uint32_t VirtualAlloc(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t GetStartupInfoA(struct StartupInfo* lpStartupInfo);
    Q_INVOKABLE uint32_t GetStdHandle(uint32_t nStdHandle);
    Q_INVOKABLE uint32_t GetFileType(uint32_t hFile);
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
    Q_INVOKABLE uint32_t GetModuleHandleA(uint32_t a);
    Q_INVOKABLE uint32_t GetProcAddress(uint32_t a, uint32_t funcName);
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
    Q_INVOKABLE uint32_t SetFilePointer(uint32_t hFile, uint32_t lDistanceToMove, uint32_t* lpDistanceToMoveHigh, uint32_t dwMoveMethod);

//    Q_INVOKABLE uint32_t ();
};

#endif // KERNEL32_H
