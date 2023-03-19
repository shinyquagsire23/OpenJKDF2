#include "jk.h"

#include "types.h"

#ifdef LINUX
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
//#include <wchar.h>
#endif

#ifdef MACOS
#include <wchar.h>
#endif

#ifdef ARCH_WASM
#include <wchar.h>
#endif

#ifdef WIN64_STANDALONE
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#endif

#if defined(TARGET_ANDROID)
#include <ctype.h>
#endif

#include "General/stdString.h"
#include "Platform/stdControl.h"

// Imports
#ifdef WIN32_BLOBS
LSTATUS (__stdcall *jk_RegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LSTATUS (__stdcall *jk_RegDeleteKeyA)(HKEY hKey, LPCSTR lpSubKey);
LSTATUS (__stdcall *jk_RegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS (__stdcall *jk_RegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS (__stdcall *jk_RegCloseKey)(HKEY hKey);
LSTATUS (__stdcall *jk_RegCreateKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);

void (__stdcall *jk_InitCommonControls)();

HRESULT (__stdcall *jk_DirectDrawEnumerateA)(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
HRESULT (__stdcall *jk_DirectDrawCreate)(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter);

HRESULT (__stdcall *jk_DirectInputCreateA)(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter);

HRESULT (__stdcall *jk_DirectPlayLobbyCreateA)(LPGUID, LPDIRECTPLAYLOBBYA *, IUnknown *, LPVOID, DWORD);

HRESULT (__stdcall *jk_DirectSoundCreate)(LPGUID, LPDIRECTSOUND *, LPUNKNOWN);

BOOL (__stdcall *jk_DeleteDC)(HDC hdc);
UINT (__stdcall *jk_GetSystemPaletteEntries)(HDC hdc, UINT iStart, UINT cEntries, LPPALETTEENTRY pPalEntries);
int (__stdcall *jk_GetDeviceCaps)(HDC hdc, int index);
BOOL (__stdcall *jk_DeleteObject)(HGDIOBJ ho);
HFONT (__stdcall *jk_CreateFontA)(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName);
BOOL (__stdcall *jk_BitBlt)(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
BOOL (__stdcall *jk_GdiFlush)();
HGDIOBJ (__stdcall *jk_SelectObject)(HDC hdc, HGDIOBJ h);
HDC (__stdcall *jk_CreateCompatibleDC)(HDC hdc);
BOOL (__stdcall *jk_TextOutA)(HDC hdc, int x, int y, LPCSTR lpString, int c);
COLORREF (__stdcall *jk_SetTextColor)(HDC hdc, COLORREF color);
int (__stdcall *jk_SetBkMode)(HDC hdc, int mode);
HBITMAP (__stdcall *jk_CreateDIBSection)(HDC hdc, const BITMAPINFO *lpbmi, UINT usage, void **ppvBits, HANDLE hSection, DWORD offset);
UINT (__stdcall *jk_RealizePalette)(HDC hdc);
BOOL (__stdcall *jk_AnimatePalette)(HPALETTE hPal, UINT iStartIndex, UINT cEntries, const PALETTEENTRY *ppe);
HPALETTE (__stdcall *jk_SelectPalette)(HDC hdc, HPALETTE hPal, BOOL bForceBkgd);
HPALETTE (__stdcall *jk_CreatePalette)(const LOGPALETTE *plpal);
UINT (__stdcall *jk_SetDIBColorTable)(HDC hdc, UINT iStart, UINT cEntries, const RGBQUAD *prgbq);
BOOL (__stdcall *jk_GetTextExtentPoint32A)(HDC hdc, LPCSTR lpString, int c, LPSIZE psizl);
HGDIOBJ (__stdcall *jk_GetStockObject)(int i);

BOOL (__stdcall *jk_CloseHandle)(HANDLE hObject);
BOOL (__stdcall *jk_UnmapViewOfFile)(LPCVOID lpBaseAddress);
BOOL (__stdcall *jk_FindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
BOOL (__stdcall *jk_DeleteFileA)(LPCSTR lpFileName);
BOOL (__stdcall *jk_FindClose)(HANDLE hFindFile);
HANDLE (__stdcall *jk_CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
HANDLE (__stdcall *jk_CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL (__stdcall *jk_RemoveDirectoryA)(LPCSTR lpPathName);
HANDLE (__stdcall *jk_FindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL (__stdcall *jk_CreateDirectoryA)(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
void (__stdcall *jk_GetLocalTime)(LPSYSTEMTIME lpSystemTime);
void (__stdcall *jk_OutputDebugStringA)(LPCSTR lpOutputString);
void (__stdcall *jk_DebugBreak)();
BOOL (__stdcall *jk_WriteConsoleA)(HANDLE hConsoleOutput, const void *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
BOOL (__stdcall *jk_FlushConsoleInputBuffer)(HANDLE hConsoleInput);
BOOL (__stdcall *jk_SetConsoleCursorInfo)(HANDLE hConsoleOutput, const CONSOLE_CURSOR_INFO *lpConsoleCursorInfo);
BOOL (__stdcall *jk_GetConsoleScreenBufferInfo)(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo);
BOOL (__stdcall *jk_SetConsoleCursorPosition)(HANDLE hConsoleOutput, COORD dwCursorPosition);
BOOL (__stdcall *jk_FreeConsole)();
BOOL (__stdcall *jk_AllocConsole)();
BOOL (__stdcall *jk_SetConsoleTitleA)(LPCSTR lpConsoleTitle);
HANDLE (__stdcall *jk_GetStdHandle)(DWORD nStdHandle);
BOOL (__stdcall *jk_SetConsoleTextAttribute)(HANDLE hConsoleOutput, WORD wAttributes);
void* (__stdcall *jk_LocalAlloc)(UINT uFlags, SIZE_T uBytes);
LPVOID (__stdcall *jk_MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
UINT (__stdcall *jk_WinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
BOOL (__stdcall *jk_SetStdHandle)(DWORD nStdHandle, HANDLE hHandle);
DWORD (__stdcall *jk_SetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
void (__stdcall *jk_RaiseException)(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments);
HANDLE (__stdcall *jk_HeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL (__stdcall *jk_SetEndOfFile)(HANDLE hFile);
int (__stdcall *jk_LCMapStringW)(LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest);
int (__stdcall *jk_LCMapStringA)(LCID Locale, DWORD dwMapFlags, LPCSTR lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest);
BOOL (__stdcall *jk_HeapDestroy)(HANDLE hHeap);
BOOL (__stdcall *jk_GetStringTypeW)(DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, LPWORD lpCharType);
BOOL (__stdcall *jk_GetStringTypeA)(LCID Locale, DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, LPWORD lpCharType);
int (__stdcall *jk_MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
BOOL (__stdcall *jk_WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
BOOL (__stdcall *jk_FlushFileBuffers)(HANDLE hFile);
int (__stdcall *jk_WideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
BOOL (__stdcall *jk_FileTimeToLocalFileTime)(const FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
BOOL (__stdcall *jk_FileTimeToSystemTime)(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
FARPROC (__stdcall *jk_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
LPVOID (__stdcall *jk_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DWORD (__stdcall *jk_GetVersion)();
LPVOID (__stdcall *jk_HeapReAlloc)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
void (__stdcall *jk_GetStartupInfoA)(LPSTARTUPINFOA lpStartupInfo);
HMODULE (__stdcall *jk_GetModuleHandleA)(LPCSTR lpModuleName);
LPSTR (__stdcall *jk_GetCommandLineA)();
BOOL (__stdcall *jk_HeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
BOOL (__stdcall *jk_SetEnvironmentVariableA)(LPCSTR lpName, LPCSTR lpValue);
DWORD (__stdcall *jk_GetLastError)();
HANDLE (__stdcall *jk_GetCurrentProcess)();
BOOL (__stdcall *jk_TerminateProcess)(HANDLE hProcess, UINT uExitCode);
void (__stdcall *jk_ExitProcess)(UINT uExitCode);
BOOL (__stdcall *jk_VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
LPVOID (__stdcall *jk_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LONG (__stdcall *jk_UnhandledExceptionFilter)(struct _EXCEPTION_POINTERS *ExceptionInfo);
DWORD (__stdcall *jk_GetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
BOOL (__stdcall *jk_FreeEnvironmentStringsA)(LPCH);
BOOL (__stdcall *jk_FillConsoleOutputCharacterA)(HANDLE hConsoleOutput, CHAR cCharacter, DWORD nLength, COORD dwWriteCoord, LPDWORD lpNumberOfCharsWritten);
DWORD (__stdcall *jk_GetTimeZoneInformation)(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
LPWCH (__stdcall *jk_GetEnvironmentStringsW)();
BOOL (__stdcall *jk_GetCPInfo)(UINT CodePage, LPCPINFO lpCPInfo);
LPCH (__stdcall *jk_GetEnvironmentStrings)();
UINT (__stdcall *jk_GetACP)();
UINT (__stdcall *jk_SetHandleCount)(UINT uNumber);
DWORD (__stdcall *jk_GetFileType)(HANDLE hFile);
void (__stdcall *jk_RtlUnwind)(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);
int (__stdcall *jk_CompareStringW)(LCID Locale, DWORD dwCmpFlags, PCNZWCH lpString1, int cchCount1, PCNZWCH lpString2, int cchCount2);
int (__stdcall *jk_CompareStringA)(LCID Locale, DWORD dwCmpFlags, PCNZCH lpString1, int cchCount1, PCNZCH lpString2, int cchCount2);
BOOL (__stdcall *jk_FreeEnvironmentStringsW)(LPWCH);
BOOL (__stdcall *jk_ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
HMODULE (__stdcall *jk_LoadLibraryA)(LPCSTR lpLibFileName);
UINT (__stdcall *jk_GetOEMCP)();


BOOL (__stdcall *jk_PostMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL (__stdcall *jk_MessageBeep)(UINT uType);
LRESULT (__stdcall *jk_DispatchMessageA)(const MSG *lpMsg);
int (__stdcall *jk_ReleaseDC)(HWND hWnd, HDC hDC);
HDC (__stdcall *jk_GetDC)(HWND hWnd);
HWND (__stdcall *jk_GetDesktopWindow)();
int (__stdcall *jk_ShowCursor)(BOOL bShow);
BOOL (__stdcall *jk_ValidateRect)(HWND hWnd, const RECT *lpRect);
int (__stdcall *jk_GetSystemMetrics)(int nIndex);
HCURSOR (__stdcall *jk_SetCursor)(HCURSOR hCursor);
HWND (__stdcall *jk_SetActiveWindow)(HWND hWnd);
HWND (__stdcall *jk_SetFocus)(HWND hWnd);
int (__stdcall *jk_MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
HWND (__stdcall *jk_CreateDialogParamA)(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam);
HWND (__stdcall *jk_GetDlgItem)(HWND hDlg, int nIDDlgItem);
BOOL (__stdcall *jk_SetDlgItemTextA)(HWND hDlg, int nIDDlgItem, LPCSTR lpString);
UINT (__stdcall *jk_GetDlgItemTextA)(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax);
HWND (__stdcall *jk_GetFocus)();
BOOL (__stdcall *jk_ShowWindow)(HWND hWnd, int nCmdShow);
HWND (__stdcall *jk_FindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName);
BOOL (__stdcall *jk_InvalidateRect)(HWND hWnd, const RECT *lpRect, BOOL bErase);
int (__stdcall *jk_MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
BOOL (__stdcall *jk_EndPaint)(HWND hWnd, const PAINTSTRUCT *lpPaint);
BOOL (__stdcall *jk_GetUpdateRect)(HWND hWnd, LPRECT lpRect, BOOL bErase);
HDC (__stdcall *jk_BeginPaint)(HWND hWnd, LPPAINTSTRUCT lpPaint);
DWORD (__stdcall *jk_GetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);
BOOL (__stdcall *jk_GetCursorPos)(LPPOINT lpPoint);
void (__stdcall *jk_PostQuitMessage)(int nExitCode);
BOOL (__stdcall *jk_SetWindowPos)(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags);
LRESULT (__stdcall *jk_DefWindowProcA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
LONG (__stdcall *jk_SetWindowLongA)(HWND hWnd, int nIndex, LONG dwNewLong);
ATOM (__stdcall *jk_RegisterClassExA)(const WNDCLASSEXA *);
HICON (__stdcall *jk_LoadIconA)(HINSTANCE hInstance, LPCSTR lpIconName);
HCURSOR (__stdcall *jk_LoadCursorA)(HINSTANCE hInstance, LPCSTR lpCursorName);
BOOL (__stdcall *jk_IsDialogMessageA)(HWND hDlg, LPMSG lpMsg);
HWND (__stdcall *jk_CreateWindowExA)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
BOOL (__stdcall *jk_UpdateWindow)(HWND hWnd);
BOOL (__stdcall *jk_TranslateMessage)(const MSG *lpMsg);
BOOL (__stdcall *jk_PeekMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
BOOL (__stdcall *jk_GetMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
LRESULT (__stdcall *jk_SendMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);


MMRESULT (__stdcall *jk_auxGetVolume)(UINT uDeviceID, LPDWORD pdwVolume);
MMRESULT (__stdcall *jk_auxSetVolume)(UINT uDeviceID, DWORD dwVolume);
MCIERROR (__stdcall *jk_mciSendCommandA)(MCIDEVICEID mciId, UINT uMsg, DWORD_PTR dwParam1, DWORD_PTR dwParam2);
UINT (__stdcall *jk_auxGetNumDevs)();
MMRESULT (__stdcall *jk_auxGetDevCapsA)(UINT_PTR uDeviceID, LPAUXCAPSA pac, UINT cbac);
MMRESULT (__stdcall *jk_joyGetPosEx)(UINT uJoyID, LPJOYINFOEX pji);
UINT (__stdcall *jk_joyGetNumDevs)();
MMRESULT (__stdcall *jk_joyGetPos)(UINT uJoyID, LPJOYINFO pji);
DWORD (__stdcall *jk_timeGetTime)();
MMRESULT (__stdcall *jk_joyGetDevCapsA)(UINT_PTR uJoyID, LPJOYCAPSA pjc, UINT cbjc);

HRESULT (__stdcall *jk_CoInitialize)(LPVOID pvReserved);
HRESULT (__stdcall *jk_CoCreateInstance)(const IID *const rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID *const riid, LPVOID *ppv);

LONG (__stdcall *jk_ChangeDisplaySettingsA)(DEVMODEA *lpDevMode, DWORD dwFlags);
BOOL (__stdcall *jk_EnumDisplaySettingsA)(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA *lpDevMode);

int (__stdcall *jk_snwprintf)(wchar_t *a1, size_t a2, const wchar_t *a3, ...);

// JK functions
void (*jk_exit)(int a) = (void*)0x512590;
int (*jk_printf)(const char* fmt, ...) = (void*)0x426E60;
#endif


#ifndef LONG_MAX
#define LONG_MAX ((long)(~0UL>>1))
#endif

#ifndef LONG_MIN
#define LONG_MIN (~LONG_MAX)
#endif

long jk_wcstol(const wchar_t *restrict nptr, wchar_t **restrict endptr, int base)
{
    const wchar_t *p = nptr, *endp;
    _Bool is_neg = 0, overflow = 0;
    /* Need unsigned so (-LONG_MIN) can fit in these: */
    unsigned long n = 0UL, cutoff;
    int cutlim;
    if (base < 0 || base == 1 || base > 36) {
#ifdef EINVAL /* errno value defined by POSIX */
        //errno = EINVAL;
#endif
        return 0L;
    }
    endp = nptr;
    while (isspace(*p))
        p++;
    if (*p == '+') {
        p++;
    } else if (*p == '-') {
        is_neg = 1, p++;
    }
    if (*p == '0') {
        p++;
        /* For strtol(" 0xZ", &endptr, 16), endptr should point to 'x';
         * pointing to ' ' or '0' is non-compliant.
         * (Many implementations do this wrong.) */
        endp = p;
        if (base == 16 && (*p == 'X' || *p == 'x')) {
            p++;
        } else if (base == 0) {
            if (*p == 'X' || *p == 'x') {
                base = 16, p++;
            } else {
                base = 8;
            }
        }
    } else if (base == 0) {
        base = 10;
    }
    cutoff = (is_neg) ? -(LONG_MIN / base) : LONG_MAX / base;
    cutlim = (is_neg) ? -(LONG_MIN % base) : LONG_MAX % base;
    while (1) {
        int c;
        if (*p >= 'A')
            c = ((*p - 'A') & (~('a' ^ 'A'))) + 10;
        else if (*p <= '9')
            c = *p - '0';
        else
            break;
        if (c < 0 || c >= base) break;
        endp = ++p;
        if (overflow) {
            /* endptr should go forward and point to the non-digit character
             * (of the given base); required by ANSI standard. */
            if (endptr) continue;
            break;
        }
        if (n > cutoff || (n == cutoff && c > cutlim)) {
            overflow = 1; continue;
        }
        n = n * base + c;
    }
    if (endptr) *endptr = (wchar_t *)endp;
    if (overflow) {
        /*errno = ERANGE;*/ return ((is_neg) ? LONG_MIN : LONG_MAX);
    }
    return (long)((is_neg) ? -n : n);
}

int _memcmp (const void* str1, const void* str2, size_t count)
{
  register const unsigned char *s1 = (const unsigned char*)str1;
  register const unsigned char *s2 = (const unsigned char*)str2;

  while (count-- > 0)
    {
      if (*s1++ != *s2++)
	  return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}

int _strlen(const char *str)
{
    int len;
    for (len = 0; str[len]; len++);
    return len;
}

char* _strcpy(char *dst, const char *src)
{
    if (!dst) return NULL;
    if (!src) return NULL;

    char *tmp = dst;
    while((*(dst++) = *(src++)));
    return tmp;
}

char* _strcat(char* str, const char* concat)
{
    _strcpy(str+_strlen(str), concat);
    return str;
}

void* _memset(void* ptr, int val, size_t num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        *(uint8_t*)((char*)ptr+i) = val;
    }
    return ptr;
}

#if !defined(MACOS) && !defined(WIN64_STANDALONE) && !defined(LINUX)
void* memset(void* ptr, int val, size_t num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        *(uint8_t*)(ptr+i) = val;
    }
    return ptr;
}
#endif

void* _memset32(void* ptr, uint32_t val, size_t num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        *(uint32_t*)((char*)ptr+(i*sizeof(uint32_t))) = val;
    }
    return ptr;
}

int _strcmp(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

int _strncmp(const char *s1, const char *s2, size_t n)
{
  unsigned char u1, u2;
  while (n-- > 0)
    {
      u1 = (unsigned char) *s1++;
      u2 = (unsigned char) *s2++;
      if (u1 != u2)
        return u1 - u2;
      if (u1 == '\0')
        return 0;
    }
  return 0;
}


float _frand()
{
    return (float)(_rand() & 0x7FFF) * 0.000030518509;
}

int __wcscmp(const wchar_t *a, const wchar_t *b)
{
    int ca, cb;

    do 
    {
        ca = (uint16_t) *a++;
        cb = (uint16_t) *b++;
    }
    while (ca == cb && ca != '\0');

    return ca - cb;
}

int __wcsicmp(const wchar_t *a, const wchar_t *b)
{
    int ca, cb;

    do 
    {
        ca = (uint16_t) *a++;
        cb = (uint16_t) *b++;
        ca = __tolower(ca);
        cb = __tolower(cb);
    }
    while (ca == cb && ca != '\0');

    return ca - cb;
}

void jk_fatal()
{
#ifndef WIN32_BLOBS
    assert(0);
#else
    *(uint32_t*)0=0x12345678;
#endif
}

void jk_init()
{
#ifdef WIN32_BLOBS
    jk_RegSetValueExA = *(void**)0x008F03D8;
    jk_RegDeleteKeyA = *(void**)0x008F03DC;
    jk_RegQueryValueExA = *(void**)0x008F03E0;
    jk_RegOpenKeyExA = *(void**)0x008F03E4;
    jk_RegCloseKey = *(void**)0x008F03E8;
    jk_RegCreateKeyExA = *(void**)0x008F03EC;

    jk_InitCommonControls = *(void**)0x008F03F4;

    jk_DirectDrawEnumerateA = *(void**)0x008F03FC;
    jk_DirectDrawCreate = *(void**)0x008F0400;

    jk_DirectInputCreateA = *(void**)0x008F0408;

    jk_DirectPlayLobbyCreateA = *(void**)0x008F0410;

    jk_DirectSoundCreate = *(void**)0x008F0418;

    jk_DeleteDC = *(void**)0x008F0420;
    jk_GetSystemPaletteEntries = *(void**)0x008F0424;
    jk_GetDeviceCaps = *(void**)0x008F0428;
    jk_DeleteObject = *(void**)0x008F042C;
    jk_CreateFontA = *(void**)0x008F0430;
    jk_BitBlt = *(void**)0x008F0434;
    jk_GdiFlush = *(void**)0x008F0438;
    jk_SelectObject = *(void**)0x008F043C;
    jk_CreateCompatibleDC = *(void**)0x008F0440;
    jk_TextOutA = *(void**)0x008F0444;
    jk_SetTextColor = *(void**)0x008F0448;
    jk_SetBkMode = *(void**)0x008F044C;
    jk_CreateDIBSection = *(void**)0x008F0450;
    jk_RealizePalette = *(void**)0x008F0454;
    jk_AnimatePalette = *(void**)0x008F0458;
    jk_SelectPalette = *(void**)0x008F045C;
    jk_CreatePalette = *(void**)0x008F0460;
    jk_SetDIBColorTable = *(void**)0x008F0464;
    jk_GetTextExtentPoint32A = *(void**)0x008F0468;
    jk_GetStockObject = *(void**)0x008F046C;

    jk_CloseHandle = *(void**)0x008F0474;
    jk_UnmapViewOfFile = *(void**)0x008F0478;
    jk_FindNextFileA = *(void**)0x008F047C;
    jk_DeleteFileA = *(void**)0x008F0480;
    jk_FindClose = *(void**)0x008F0484;
    jk_CreateFileMappingA = *(void**)0x008F0488;
    jk_CreateFileA = *(void**)0x008F048C;
    jk_RemoveDirectoryA = *(void**)0x008F0490;
    jk_FindFirstFileA = *(void**)0x008F0494;
    jk_CreateDirectoryA = *(void**)0x008F0498;
    jk_GetLocalTime = *(void**)0x008F049C;
    jk_OutputDebugStringA = *(void**)0x008F04A0;
    jk_DebugBreak = *(void**)0x008F04A4;
    jk_WriteConsoleA = *(void**)0x008F04A8;
    jk_FlushConsoleInputBuffer = *(void**)0x008F04AC;
    jk_SetConsoleCursorInfo = *(void**)0x008F04B0;
    jk_GetConsoleScreenBufferInfo = *(void**)0x008F04B4;
    jk_SetConsoleCursorPosition = *(void**)0x008F04B8;
    jk_FreeConsole = *(void**)0x008F04BC;
    jk_AllocConsole = *(void**)0x008F04C0;
    jk_SetConsoleTitleA = *(void**)0x008F04C4;
    jk_GetStdHandle = *(void**)0x008F04C8;
    jk_SetConsoleTextAttribute = *(void**)0x008F04CC;
    jk_LocalAlloc = *(void**)0x008F04D0;
    jk_MapViewOfFile = *(void**)0x008F04D4;
    jk_WinExec = *(void**)0x008F04D8;
    jk_SetStdHandle = *(void**)0x008F04DC;
    jk_SetFilePointer = *(void**)0x008F04E0;
    jk_RaiseException = *(void**)0x008F04E4;
    jk_HeapCreate = *(void**)0x008F04E8;
    jk_SetEndOfFile = *(void**)0x008F04EC;
    jk_LCMapStringW = *(void**)0x008F04F0;
    jk_LCMapStringA = *(void**)0x008F04F4;
    jk_HeapDestroy = *(void**)0x008F04F8;
    jk_GetStringTypeW = *(void**)0x008F04FC;
    jk_GetStringTypeA = *(void**)0x008F0500;
    jk_MultiByteToWideChar = *(void**)0x008F0504;
    jk_WriteFile = *(void**)0x008F0508;
    jk_FlushFileBuffers = *(void**)0x008F050C;
    jk_WideCharToMultiByte = *(void**)0x008F0510;
    jk_FileTimeToLocalFileTime = *(void**)0x008F0514;
    jk_FileTimeToSystemTime = *(void**)0x008F0518;
    jk_GetProcAddress = *(void**)0x008F051C;
    jk_HeapAlloc = *(void**)0x008F0520;
    jk_GetVersion = *(void**)0x008F0524;
    jk_HeapReAlloc = *(void**)0x008F0528;
    jk_GetStartupInfoA = *(void**)0x008F052C;
    jk_GetModuleHandleA = *(void**)0x008F0530;
    jk_GetCommandLineA = *(void**)0x008F0534;
    jk_HeapFree = *(void**)0x008F0538;
    jk_SetEnvironmentVariableA = *(void**)0x008F053C;
    jk_GetLastError = *(void**)0x008F0540;
    jk_GetCurrentProcess = *(void**)0x008F0544;
    jk_TerminateProcess = *(void**)0x008F0548;
    jk_ExitProcess = *(void**)0x008F054C;
    jk_VirtualFree = *(void**)0x008F0550;
    jk_VirtualAlloc = *(void**)0x008F0554;
    jk_UnhandledExceptionFilter = *(void**)0x008F0558;
    jk_GetModuleFileNameA = *(void**)0x008F055C;
    jk_FreeEnvironmentStringsA = *(void**)0x008F0560;
    jk_FillConsoleOutputCharacterA = *(void**)0x008F0564;
    jk_GetTimeZoneInformation = *(void**)0x008F0568;
    jk_GetEnvironmentStringsW = *(void**)0x008F056C;
    jk_GetCPInfo = *(void**)0x008F0570;
    jk_GetEnvironmentStrings = *(void**)0x008F0574;
    jk_GetACP = *(void**)0x008F0578;
    jk_SetHandleCount = *(void**)0x008F057C;
    jk_GetFileType = *(void**)0x008F0580;
    jk_RtlUnwind = *(void**)0x008F0584;
    jk_CompareStringW = *(void**)0x008F0588;
    jk_CompareStringA = *(void**)0x008F058C;
    jk_FreeEnvironmentStringsW = *(void**)0x008F0590;
    jk_ReadFile = *(void**)0x008F0594;
    jk_LoadLibraryA = *(void**)0x008F0598;
    jk_GetOEMCP = *(void**)0x008F059C;


    jk_PostMessageA = *(void**)0x008F05A4;
    jk_MessageBeep = *(void**)0x008F05A8;
    jk_DispatchMessageA = *(void**)0x008F05AC;
    jk_ReleaseDC = *(void**)0x008F05B0;
    jk_GetDC = *(void**)0x008F05B4;
    jk_GetDesktopWindow = *(void**)0x008F05B8;
    jk_ShowCursor = *(void**)0x008F05BC;
    jk_ValidateRect = *(void**)0x008F05C0;
    jk_GetSystemMetrics = *(void**)0x008F05C4;
    jk_SetCursor = *(void**)0x008F05C8;
    jk_SetActiveWindow = *(void**)0x008F05CC;
    jk_SetFocus = *(void**)0x008F05D0;
    jk_MessageBoxW = *(void**)0x008F05D4;
    jk_CreateDialogParamA = *(void**)0x008F05D8;
    jk_GetDlgItem = *(void**)0x008F05DC;
    jk_SetDlgItemTextA = *(void**)0x008F05E0;
    jk_GetDlgItemTextA = *(void**)0x008F05E4;
    jk_GetFocus = *(void**)0x008F05E8;
    jk_ShowWindow = *(void**)0x008F05EC;
    jk_FindWindowA = *(void**)0x008F05F0;
    jk_InvalidateRect = *(void**)0x008F05F4;
    jk_MessageBoxA = *(void**)0x008F05F8;
    jk_EndPaint = *(void**)0x008F05FC;
    jk_GetUpdateRect = *(void**)0x008F0600;
    jk_BeginPaint = *(void**)0x008F0604;
    jk_GetWindowThreadProcessId = *(void**)0x008F0608;
    jk_GetCursorPos = *(void**)0x008F060C;
    jk_PostQuitMessage = *(void**)0x008F0610;
    jk_SetWindowPos = *(void**)0x008F0614;
    jk_DefWindowProcA = *(void**)0x008F0618;
    jk_SetWindowLongA = *(void**)0x008F061C;
    jk_RegisterClassExA = *(void**)0x008F0620;
    jk_LoadIconA = *(void**)0x008F0624;
    jk_LoadCursorA = *(void**)0x008F0628;
    jk_IsDialogMessageA = *(void**)0x008F062C;
    jk_CreateWindowExA = *(void**)0x008F0630;
    jk_UpdateWindow = *(void**)0x008F0634;
    jk_TranslateMessage = *(void**)0x008F0638;
    jk_PeekMessageA = *(void**)0x008F063C;
    jk_GetMessageA = *(void**)0x008F0640;
    jk_SendMessageA = *(void**)0x008F0644;


    jk_auxGetVolume = *(void**)0x008F064C;
    jk_auxSetVolume = *(void**)0x008F0650;
    jk_mciSendCommandA = *(void**)0x008F0654;
    jk_auxGetNumDevs = *(void**)0x008F0658;
    jk_auxGetDevCapsA = *(void**)0x008F065C;
    jk_joyGetPosEx = *(void**)0x008F0660;
    jk_joyGetNumDevs = *(void**)0x008F0664;
    jk_joyGetPos = *(void**)0x008F0668;
    jk_timeGetTime = *(void**)0x008F066C;
    jk_joyGetDevCapsA = *(void**)0x008F0670;

    jk_CoInitialize = *(void**)0x008F0678;
    jk_CoCreateInstance = *(void**)0x008F067C;
    
    jk_ChangeDisplaySettingsA = *(void**)0x8F4153;
    jk_EnumDisplaySettingsA = *(void**)0x8F4157;
    
    jk_snwprintf = (void*)0x00512BD0;
#endif
}

#ifdef PLATFORM_POSIX
#include <ctype.h>
#include "wprintf.h"

int _sscanf(const char * s, const char * format, ...)
{
    va_list args;
    va_start (args, format);
    int ret = vsscanf (s, format, args);
    va_end (args);
    return ret;
}

int _sprintf(char * s, const char * format, ...)
{
    va_list args;
    va_start (args, format);
    int ret = vsnprintf (s, 0x7FFF, format, args);
    va_end (args);
    return ret;
}

int _rand()
{
    return rand();
}

char* _strncpy(char* dst, const char* src, size_t num)
{
    return strncpy(dst, src, num);
}

void* _memcpy(void* dst, const void* src, size_t len)
{
    return memcpy(dst, src, len);
}

double _atof(const char* str)
{
    return atof(str);
}

int _atoi(const char* str)
{
    return atoi(str);
}

uint32_t _atol(const char* s)
{
    return atol(s);
}

size_t _fwrite(const void * a, size_t b, size_t c, FILE * d)
{
    return fwrite(a,b,c,d);
}

int _fputs(const char * a, FILE * b)
{
    return fputs(a, b);
}

void jk_exit(int a)
{
    exit(a);
}

int jk_printf(const char* fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    int ret = vprintf(fmt, args);
    va_end (args);
    return ret;
}

int _printf(const char* fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    int ret = vprintf(fmt, args);
    va_end (args);
    return ret;
}

void* _malloc(size_t a)
{
    return malloc(a);
}

void _free(void* a)
{
    free(a);
}

wchar_t* _wcsncpy(wchar_t *s1, const wchar_t *s2, size_t n)
{
    wchar_t *ret = s1;
    for ( ; n; n--) if (!(*s1++ = *s2++)) break;
    for ( ; n; n--) *s1++ = 0;
    return ret;
}

void _strtolower(char* str)
{
    for(int i = 0; str[i]; i++){
      str[i] = tolower(str[i]);
    }
}

void _qsort(void *a, size_t b, size_t c, int (__cdecl *d)(const void *, const void *))
{
    qsort(a,b,c,d);
}

char* _strchr(char * a, char b)
{
    return strchr(a,b);
}

char* _strrchr(char * a, char b)
{
    return strrchr(a,b);
}

char* _strtok(char * a, const char * b)
{
    return strtok(a,b);
}

char* _strncat(char* a, const char* b, size_t c)
{
    return strncat(a,b,c);
}

size_t _strspn(const char* a, const char* b)
{
    return strspn(a,b);
}

char* _strpbrk(const char* a, const char* b)
{
    return strpbrk(a,b);
}

size_t _wcslen(const wchar_t * str)
{
    int len;
    for (len = 0; str[len]; len++);
    return len;
}

char* _strstr(const char* a, const char* b)
{
    return strstr(a,b);
}

int jk_snwprintf(wchar_t *a1, size_t a2, const wchar_t *fmt, ...)
{
#if 0
    char* tmp_fmt = malloc(_wcslen(fmt)+1);
    char* tmp_out = malloc(a2+1);
    
    stdString_WcharToChar(tmp_fmt, fmt, _wcslen(fmt)+1);
    
    va_list args;
    va_start (args, fmt);
    int ret = vsprintf(tmp_out, tmp_fmt, args); // TODO ehh
    va_end (args);
    
    stdString_CharToWchar(a1, tmp_out, a2);
    
    free(tmp_fmt);
    free(tmp_out);
    return ret;
#endif

    va_list args;
    va_start (args, fmt);
    int ret = vsnwprintf_(a1, a2, fmt, args);
    va_end(args);

    return ret;
}

int __snprintf(char *a1, size_t a2, const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    int ret = vsnprintf(a1, a2, fmt, args); // TODO ehh
    va_end (args);

    return ret;
}

int __vsnprintf(char *a1, size_t a2, const char *fmt, va_list args)
{
    return vsnprintf(a1, a2, fmt, args); // TODO ehh
}

wchar_t* _wcscpy(wchar_t * dst, const wchar_t *src)
{
    if (!dst) return NULL;
    if (!src) return NULL;

    wchar_t *tmp = dst;
    while((*(dst++) = *(src++)));
    return tmp;
}

int jk_MessageBeep(int a)
{
    return 0;
}

int __strcmpi(const char *a, const char *b)
{
    int ca, cb;

    do 
    {
        ca = (unsigned char) *a++;
        cb = (unsigned char) *b++;
        ca = tolower(toupper(ca));
        cb = tolower(toupper(cb));
    }
    while (ca == cb && ca != '\0');

    return ca - cb;
}

int __strnicmp(const char *a, const char *b, size_t c)
{
    int ca, cb, n;

    n = 0;
    do 
    {
        if (n >= c) break;
        ca = (unsigned char) *a++;
        cb = (unsigned char) *b++;
        ca = tolower(toupper(ca));
        cb = tolower(toupper(cb));
        n++;
    }
    while (ca == cb && ca != '\0');

    return ca - cb;
}

#ifndef MACOS
char __tolower(char a)
{
    return tolower(a);
}
#endif

int msvc_sub_512D30(int a, int b)
{
    assert(0);
}

int jk_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    assert(0);
}

int stdGdi_GetHwnd()
{
    //assert(0);
    return 0;
}

void jk_PostMessageA()
{
    assert(0);
}

void jk_GetCursorPos(LPPOINT lpPoint)
{
    assert(0);
}

int jk_GetUpdateRect(HWND hWnd, LPRECT lpRect, BOOL bErase)
{
    return 0;
}

void jk_BeginPaint(int a, struct tagPAINTSTRUCT * lpPaint)
{
    assert(0);
}

int jk_vsnwprintf(wchar_t * a, size_t b, const wchar_t *fmt, va_list list)
{
#ifdef ARCH_WASM
    return vswprintf(a, b, fmt, list);
#elif defined(MACOS) || defined(WIN64_STANDALONE)
    return vsnwprintf_(a,b, fmt,list);
#else
    return vsnwprintf_(a, b, fmt, list);
#endif
}

void jk_EndPaint(HWND hWnd, const PAINTSTRUCT *lpPaint)
{
    assert(0);
}

int stdGdi_GetHInstance()
{
    assert(0);
    return 0;
}

int jk_LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName)
{
    assert(0);
    return 1;
}

void jk_SetCursor(HCURSOR hCursor)
{
    assert(0);
}

void jk_InvalidateRect(HWND hWnd, const RECT *lpRect, BOOL bErase)
{
    assert(0);
}

void jk_ChangeDisplaySettingsA(int a, int b)
{
    assert(0);
}

uint32_t jk_DirectDrawEnumerateA(void* a, void** b)
{
    assert(0);
    return 0;
}

uint32_t jk_DirectDrawCreate(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter)
{
    assert(0);
    return 0;
}

uint32_t jk_DirectSoundCreate(LPGUID a, LPDIRECTSOUND *b, LPUNKNOWN c)
{
    assert(0);
    return 0;
}

uint32_t jk_DirectPlayLobbyCreateA(GUID *lpGUID, void** b, IUnknown* c, LPVOID d, int e)
{
    assert(0);
    return 0;
}

uint32_t jk_DirectInputCreateA(int a, int b, void** c, LPUNKNOWN d)
{
    assert(0);
    return 0;
}

uint32_t jk_CreateFileA()
{
    assert(0);
    return 0;
}

uint32_t jk_CreateFileMappingA()
{
    assert(0);
    return 0;
}

void* jk_LocalAlloc()
{
    assert(0);
    return 0;
}

uint32_t jk_MapViewOfFile()
{
    assert(0);
    return 0;
}

void jk_UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    assert(0);
}

void jk_CloseHandle(HANDLE hObject)
{
    assert(0);
}

uint32_t jk_GetDesktopWindow()
{
    assert(0);
    return 0;
}

uint32_t jk_GetDC(HWND hWnd)
{
    assert(0);
    return 0;
}

uint32_t jk_GetDeviceCaps(HDC hdc, int index)
{
    assert(0);
    return 0;
}

uint32_t jk_WinExec(const char* a, int b)
{
    assert(0);
    return 0;
}

int _string_modify_idk(int c)
{
    return toupper(c);
}

void jk_ReleaseDC(HWND hWnd, HDC hDC)
{
    assert(0);
}

void jk_SetFocus(HWND hWnd)
{
    //assert(0);
}

void jk_SetActiveWindow(HWND hWnd)
{
    assert(0);
}

void jk_ShowCursor(int a)
{
    //assert(0);
    stdControl_ShowCursor(a);
}

void jk_ValidateRect(HWND hWnd, const RECT *lpRect)
{
    assert(0);
}

#if !defined(ARCH_WASM)
int __isspace(int a)
{
    return isspace(a & 0xFF);
}
#endif

int _iswspace(int a)
{
    unsigned char c = a & 0x7F;
    if (c == '\t' || c == '\n' ||
        c == '\v' || c == '\f' || c == '\r' || c == ' ') {
        return 1;
    }

    return isspace(c);
}

size_t __wcslen(const wchar_t * strarg)
{
    if(!strarg)
     return -1; //strarg is NULL pointer
   const wchar_t* str = strarg;
   for(;*str;++str)
     ; // empty body
   return str-strarg;
}

wchar_t* __wcscat(wchar_t * a, const wchar_t * b)
{
    wchar_t* ret = a;
    a += __wcslen(a);
    memmove(a, b, __wcslen(b) * sizeof(wchar_t));
    return ret;
}

wchar_t* __wcschr(const wchar_t * s, wchar_t c)
{
    do {
        if (*s == c)
        {
        return (wchar_t*)s;
        }
    } while (*s++);
    return NULL;
}

wchar_t* __wcsncpy(wchar_t * a, const wchar_t * b, size_t c)
{
    wchar_t* ret = a;
    size_t len = __wcslen(b) * sizeof(wchar_t);
    if (len > c*sizeof(wchar_t)) {
        len = c*sizeof(wchar_t);
    }
    memmove(a, b, len);
    a[len] = 0;
    return &a[len];
}

wchar_t* __wcsrchr(const wchar_t * s, wchar_t c)
{
    wchar_t *rtnval = 0;
    do {
        if (*s == c)
            rtnval = (wchar_t*) s;
        } while (*s++);
    return (rtnval);
}
#else
int _iswspace(int a)
{
    return msvc_sub_512D30(a, 8);
}
#endif
