#ifndef KERNEL32_H
#define KERNEL32_H

#include <QObject>
#include <unicorn/unicorn.h>

#pragma pack(push, 1)
struct StartupInfo
{
    uint32_t  cb;
    uint32_t  lpReserved;
    uint32_t  lpDesktop;
    uint32_t  lpTitle;
    uint32_t  dwX;
    uint32_t  dwY;
    uint32_t  dwXSize;
    uint32_t  dwYSize;
    uint32_t  dwXCountChars;
    uint32_t  dwYCountChars;
    uint32_t  dwFillAttribute;
    uint32_t  dwFlags;
    uint16_t   wShowWindow;
    uint16_t   cbReserved2;
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
#pragma pack(pop)

#define STD_INPUT_HANDLE  (-10)
#define STD_OUTPUT_HANDLE (-11)
#define STD_ERROR_HANDLE  (-12)

#define FILE_TYPE_DISK 0x0001
#define FILE_TYPE_CHAR 0x0002

class Kernel32 : public QObject
{
Q_OBJECT

private:
    uc_engine *uc;

public:
    uint32_t heap_handle;
    uint32_t heap_addr;
    uint32_t heap_max;
    uint32_t last_alloc;

    Q_INVOKABLE Kernel32(uc_engine *uc) : uc(uc) {}
    
    Q_INVOKABLE uint32_t HeapCreate(uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t HeapAlloc(uint32_t a, uint32_t b, uint32_t alloc_size);
    Q_INVOKABLE uint32_t GetVersion() { return 0; };
    Q_INVOKABLE uint32_t VirtualAlloc(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t GetStartupInfoA(uint32_t lpStartupInfo);
    Q_INVOKABLE uint32_t GetStdHandle(uint32_t nStdHandle);
    Q_INVOKABLE uint32_t GetFileType(uint32_t hFile);
    Q_INVOKABLE uint32_t SetHandleCount(uint32_t uNumber);
    Q_INVOKABLE uint32_t GetACP();
    Q_INVOKABLE uint32_t GetCPInfo(uint32_t a, uint32_t outPtr);
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

//    Q_INVOKABLE uint32_t ();
};

#endif // KERNEL32_H
