#ifndef JK_H
#define JK_H

#include "types.h"
#include <stdio.h>

#include "Cog/sithCogParse.h"

#define WinMain_ADDR (0x41EBD0)

#define VM_VAR(name, type, ptr) \
    type* name ## _ptr = (type*)ptr;
#define VM_VAR_DECL(name, type) extern type* name ## _ptr;

typedef struct common_functions
{
    uint32_t some_float;
    int (*messagePrint)(const char *, ...);
    int (*statusPrint)(const char *, ...);
    int (*warningPrint)(const char *, ...);
    int (*errorPrint)(const char *, ...);
    int (*debugPrint)(const char *, ...);
    int (*assert)(char *, char *, int);
    uint32_t unk_0;
    void *(*alloc)(unsigned int);
    void (*free)(void *);
    void *(__cdecl *realloc)(void *, unsigned int);
    uint32_t timeGetTime;
    int (*fileOpen)(char *, char *);
    int (*fileClose)(int);
    size_t (*fileRead)(int, void *, size_t);
    char *(*fileGets)(int, char *, int);
    size_t (*fileWrite)(int, void *, size_t);
    int (*feof)(int);
    int (*ftell)(int);
    int (*fseek)(int, int, int);
    int (*fileSize)(char *);
    void (*filePrintf)(int, char*, ...);
    wchar_t* (*fileGetws)(int, wchar_t *, unsigned int);
    uint32_t allocHandle;
    uint32_t freeHandle;
    uint32_t reallocHandle;
    uint32_t lockHandle;
    uint32_t unlockHandle;
} common_functions;

typedef struct hashmap_entry
{
    
} hashmap_entry;

//static void (*jk_main)(uint32_t a, uint32_t b, char* c, int d, char* e) = (void*)0x50E750;

// Imports
extern LSTATUS (__stdcall *jk_RegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
extern LSTATUS (__stdcall *jk_RegDeleteKeyA)(HKEY hKey, LPCSTR lpSubKey);
extern LSTATUS (__stdcall *jk_RegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
extern LSTATUS (__stdcall *jk_RegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
extern LSTATUS (__stdcall *jk_RegCloseKey)(HKEY hKey);
extern LSTATUS (__stdcall *jk_RegCreateKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);

extern void (__stdcall *jk_InitCommonControls)();

extern HRESULT (__stdcall *jk_DirectDrawEnumerateA)(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
extern HRESULT (__stdcall *jk_DirectDrawCreate)(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter);

extern HRESULT (__stdcall *jk_DirectInputCreateA)(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter);

extern HRESULT (__stdcall *jk_DirectPlayLobbyCreateA)(LPGUID, LPDIRECTPLAYLOBBYA *, IUnknown *, LPVOID, DWORD);

extern HRESULT (__stdcall *jk_DirectSoundCreate)(LPGUID, LPDIRECTSOUND *, LPUNKNOWN);

extern BOOL (__stdcall *jk_DeleteDC)(HDC hdc);
extern UINT (__stdcall *jk_GetSystemPaletteEntries)(HDC hdc, UINT iStart, UINT cEntries, LPPALETTEENTRY pPalEntries);
extern int (__stdcall *jk_GetDeviceCaps)(HDC hdc, int index);
extern BOOL (__stdcall *jk_DeleteObject)(HGDIOBJ ho);
extern HFONT (__stdcall *jk_CreateFontA)(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName);
extern BOOL (__stdcall *jk_BitBlt)(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
extern BOOL (__stdcall *jk_GdiFlush)();
extern HGDIOBJ (__stdcall *jk_SelectObject)(HDC hdc, HGDIOBJ h);
extern HDC (__stdcall *jk_CreateCompatibleDC)(HDC hdc);
extern BOOL (__stdcall *jk_TextOutA)(HDC hdc, int x, int y, LPCSTR lpString, int c);
extern COLORREF (__stdcall *jk_SetTextColor)(HDC hdc, COLORREF color);
extern int (__stdcall *jk_SetBkMode)(HDC hdc, int mode);
extern HBITMAP (__stdcall *jk_CreateDIBSection)(HDC hdc, const BITMAPINFO *lpbmi, UINT usage, void **ppvBits, HANDLE hSection, DWORD offset);
extern UINT (__stdcall *jk_RealizePalette)(HDC hdc);
extern BOOL (__stdcall *jk_AnimatePalette)(HPALETTE hPal, UINT iStartIndex, UINT cEntries, const PALETTEENTRY *ppe);
extern HPALETTE (__stdcall *jk_SelectPalette)(HDC hdc, HPALETTE hPal, BOOL bForceBkgd);
extern HPALETTE (__stdcall *jk_CreatePalette)(const LOGPALETTE *plpal);
extern UINT (__stdcall *jk_SetDIBColorTable)(HDC hdc, UINT iStart, UINT cEntries, const RGBQUAD *prgbq);
extern BOOL (__stdcall *jk_GetTextExtentPoint32A)(HDC hdc, LPCSTR lpString, int c, LPSIZE psizl);
extern HGDIOBJ (__stdcall *jk_GetStockObject)(int i);

extern BOOL (__stdcall *jk_CloseHandle)(HANDLE hObject);
extern BOOL (__stdcall *jk_UnmapViewOfFile)(LPCVOID lpBaseAddress);
extern BOOL (__stdcall *jk_FindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
extern BOOL (__stdcall *jk_DeleteFileA)(LPCSTR lpFileName);
extern BOOL (__stdcall *jk_FindClose)(HANDLE hFindFile);
extern HANDLE (__stdcall *jk_CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
extern HANDLE (__stdcall *jk_CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
extern BOOL (__stdcall *jk_RemoveDirectoryA)(LPCSTR lpPathName);
extern HANDLE (__stdcall *jk_FindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
extern BOOL (__stdcall *jk_CreateDirectoryA)(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
extern void (__stdcall *jk_GetLocalTime)(LPSYSTEMTIME lpSystemTime);
extern void (__stdcall *jk_OutputDebugStringA)(LPCSTR lpOutputString);
extern void (__stdcall *jk_DebugBreak)();
extern BOOL (__stdcall *jk_WriteConsoleA)(HANDLE hConsoleOutput, const void *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
extern BOOL (__stdcall *jk_FlushConsoleInputBuffer)(HANDLE hConsoleInput);
extern BOOL (__stdcall *jk_SetConsoleCursorInfo)(HANDLE hConsoleOutput, const CONSOLE_CURSOR_INFO *lpConsoleCursorInfo);
extern BOOL (__stdcall *jk_GetConsoleScreenBufferInfo)(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo);
extern BOOL (__stdcall *jk_SetConsoleCursorPosition)(HANDLE hConsoleOutput, COORD dwCursorPosition);
extern BOOL (__stdcall *jk_FreeConsole)();
extern BOOL (__stdcall *jk_AllocConsole)();
extern BOOL (__stdcall *jk_SetConsoleTitleA)(LPCSTR lpConsoleTitle);
extern HANDLE (__stdcall *jk_GetStdHandle)(DWORD nStdHandle);
extern BOOL (__stdcall *jk_SetConsoleTextAttribute)(HANDLE hConsoleOutput, WORD wAttributes);
extern HLOCAL (__stdcall *jk_LocalAlloc)(UINT uFlags, SIZE_T uBytes);
extern LPVOID (__stdcall *jk_MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
extern UINT (__stdcall *jk_WinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
extern BOOL (__stdcall *jk_SetStdHandle)(DWORD nStdHandle, HANDLE hHandle);
extern DWORD (__stdcall *jk_SetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
extern void (__stdcall *jk_RaiseException)(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments);
extern HANDLE (__stdcall *jk_HeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
extern BOOL (__stdcall *jk_SetEndOfFile)(HANDLE hFile);
extern int (__stdcall *jk_LCMapStringW)(LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest);
extern int (__stdcall *jk_LCMapStringA)(LCID Locale, DWORD dwMapFlags, LPCSTR lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest);
extern BOOL (__stdcall *jk_HeapDestroy)(HANDLE hHeap);
extern BOOL (__stdcall *jk_GetStringTypeW)(DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, LPWORD lpCharType);
extern BOOL (__stdcall *jk_GetStringTypeA)(LCID Locale, DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, LPWORD lpCharType);
extern int (__stdcall *jk_MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
extern BOOL (__stdcall *jk_WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
extern BOOL (__stdcall *jk_FlushFileBuffers)(HANDLE hFile);
extern int (__stdcall *jk_WideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
extern BOOL (__stdcall *jk_FileTimeToLocalFileTime)(const FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
extern BOOL (__stdcall *jk_FileTimeToSystemTime)(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
extern FARPROC (__stdcall *jk_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
extern LPVOID (__stdcall *jk_HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
extern DWORD (__stdcall *jk_GetVersion)();
extern LPVOID (__stdcall *jk_HeapReAlloc)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
extern void (__stdcall *jk_GetStartupInfoA)(LPSTARTUPINFOA lpStartupInfo);
extern HMODULE (__stdcall *jk_GetModuleHandleA)(LPCSTR lpModuleName);
extern LPSTR (__stdcall *jk_GetCommandLineA)();
extern BOOL (__stdcall *jk_HeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
extern BOOL (__stdcall *jk_SetEnvironmentVariableA)(LPCSTR lpName, LPCSTR lpValue);
extern DWORD (__stdcall *jk_GetLastError)();
extern HANDLE (__stdcall *jk_GetCurrentProcess)();
extern BOOL (__stdcall *jk_TerminateProcess)(HANDLE hProcess, UINT uExitCode);
extern void (__stdcall *jk_ExitProcess)(UINT uExitCode);
extern BOOL (__stdcall *jk_VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
extern LPVOID (__stdcall *jk_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
extern LONG (__stdcall *jk_UnhandledExceptionFilter)(struct _EXCEPTION_POINTERS *ExceptionInfo);
extern DWORD (__stdcall *jk_GetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
extern BOOL (__stdcall *jk_FreeEnvironmentStringsA)(LPCH);
extern BOOL (__stdcall *jk_FillConsoleOutputCharacterA)(HANDLE hConsoleOutput, CHAR cCharacter, DWORD nLength, COORD dwWriteCoord, LPDWORD lpNumberOfCharsWritten);
extern DWORD (__stdcall *jk_GetTimeZoneInformation)(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);
extern LPWCH (__stdcall *jk_GetEnvironmentStringsW)();
extern BOOL (__stdcall *jk_GetCPInfo)(UINT CodePage, LPCPINFO lpCPInfo);
extern LPCH (__stdcall *jk_GetEnvironmentStrings)();
extern UINT (__stdcall *jk_GetACP)();
extern UINT (__stdcall *jk_SetHandleCount)(UINT uNumber);
extern DWORD (__stdcall *jk_GetFileType)(HANDLE hFile);
extern void (__stdcall *jk_RtlUnwind)(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);
extern int (__stdcall *jk_CompareStringW)(LCID Locale, DWORD dwCmpFlags, PCNZWCH lpString1, int cchCount1, PCNZWCH lpString2, int cchCount2);
extern int (__stdcall *jk_CompareStringA)(LCID Locale, DWORD dwCmpFlags, PCNZCH lpString1, int cchCount1, PCNZCH lpString2, int cchCount2);
extern BOOL (__stdcall *jk_FreeEnvironmentStringsW)(LPWCH);
extern BOOL (__stdcall *jk_ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
extern HMODULE (__stdcall *jk_LoadLibraryA)(LPCSTR lpLibFileName);
extern UINT (__stdcall *jk_GetOEMCP)();


extern BOOL (__stdcall *jk_PostMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
extern BOOL (__stdcall *jk_MessageBeep)(UINT uType);
extern LRESULT (__stdcall *jk_DispatchMessageA)(const MSG *lpMsg);
extern int (__stdcall *jk_ReleaseDC)(HWND hWnd, HDC hDC);
extern HDC (__stdcall *jk_GetDC)(HWND hWnd);
extern HWND (__stdcall *jk_GetDesktopWindow)();
extern int (__stdcall *jk_ShowCursor)(BOOL bShow);
extern BOOL (__stdcall *jk_ValidateRect)(HWND hWnd, const RECT *lpRect);
extern int (__stdcall *jk_GetSystemMetrics)(int nIndex);
extern HCURSOR (__stdcall *jk_SetCursor)(HCURSOR hCursor);
extern HWND (__stdcall *jk_SetActiveWindow)(HWND hWnd);
extern HWND (__stdcall *jk_SetFocus)(HWND hWnd);
extern int (__stdcall *jk_MessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
extern HWND (__stdcall *jk_CreateDialogParamA)(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam);
extern HWND (__stdcall *jk_GetDlgItem)(HWND hDlg, int nIDDlgItem);
extern BOOL (__stdcall *jk_SetDlgItemTextA)(HWND hDlg, int nIDDlgItem, LPCSTR lpString);
extern UINT (__stdcall *jk_GetDlgItemTextA)(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax);
extern HWND (__stdcall *jk_GetFocus)();
extern BOOL (__stdcall *jk_ShowWindow)(HWND hWnd, int nCmdShow);
extern HWND (__stdcall *jk_FindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName);
extern BOOL (__stdcall *jk_InvalidateRect)(HWND hWnd, const RECT *lpRect, BOOL bErase);
extern int (__stdcall *jk_MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
extern BOOL (__stdcall *jk_EndPaint)(HWND hWnd, const PAINTSTRUCT *lpPaint);
extern BOOL (__stdcall *jk_GetUpdateRect)(HWND hWnd, LPRECT lpRect, BOOL bErase);
extern HDC (__stdcall *jk_BeginPaint)(HWND hWnd, LPPAINTSTRUCT lpPaint);
extern DWORD (__stdcall *jk_GetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);
extern BOOL (__stdcall *jk_GetCursorPos)(LPPOINT lpPoint);
extern void (__stdcall *jk_PostQuitMessage)(int nExitCode);
extern BOOL (__stdcall *jk_SetWindowPos)(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags);
extern LRESULT (__stdcall *jk_DefWindowProcA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
extern LONG (__stdcall *jk_SetWindowLongA)(HWND hWnd, int nIndex, LONG dwNewLong);
extern ATOM (__stdcall *jk_RegisterClassExA)(const WNDCLASSEXA *);
extern HICON (__stdcall *jk_LoadIconA)(HINSTANCE hInstance, LPCSTR lpIconName);
extern HCURSOR (__stdcall *jk_LoadCursorA)(HINSTANCE hInstance, LPCSTR lpCursorName);
extern BOOL (__stdcall *jk_IsDialogMessageA)(HWND hDlg, LPMSG lpMsg);
extern HWND (__stdcall *jk_CreateWindowExA)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
extern BOOL (__stdcall *jk_UpdateWindow)(HWND hWnd);
extern BOOL (__stdcall *jk_TranslateMessage)(const MSG *lpMsg);
extern BOOL (__stdcall *jk_PeekMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
extern BOOL (__stdcall *jk_GetMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
extern LRESULT (__stdcall *jk_SendMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

extern MMRESULT (__stdcall *jk_auxGetVolume)(UINT uDeviceID, LPDWORD pdwVolume);
extern MMRESULT (__stdcall *jk_auxSetVolume)(UINT uDeviceID, DWORD dwVolume);
extern MCIERROR (__stdcall *jk_mciSendCommandA)(MCIDEVICEID mciId, UINT uMsg, DWORD_PTR dwParam1, DWORD_PTR dwParam2);
extern UINT (__stdcall *jk_auxGetNumDevs)();
extern MMRESULT (__stdcall *jk_auxGetDevCapsA)(UINT_PTR uDeviceID, LPAUXCAPSA pac, UINT cbac);
extern MMRESULT (__stdcall *jk_joyGetPosEx)(UINT uJoyID, LPJOYINFOEX pji);
extern UINT (__stdcall *jk_joyGetNumDevs)();
extern MMRESULT (__stdcall *jk_joyGetPos)(UINT uJoyID, LPJOYINFO pji);
extern DWORD (__stdcall *jk_timeGetTime)();
extern MMRESULT (__stdcall *jk_joyGetDevCapsA)(UINT_PTR uJoyID, LPJOYCAPSA pjc, UINT cbjc);

extern HRESULT (__stdcall *jk_CoInitialize)(LPVOID pvReserved);
extern HRESULT (__stdcall *jk_CoCreateInstance)(const IID *const rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID *const riid, LPVOID *ppv);

extern LONG (__stdcall *jk_ChangeDisplaySettingsA)(DEVMODEA *lpDevMode, DWORD dwFlags);
extern BOOL (__stdcall *jk_EnumDisplaySettingsA)(LPCSTR lpszDeviceName, DWORD iModeNum, DEVMODEA *lpDevMode);
extern int (__stdcall *jk_snwprintf)(wchar_t *a1, size_t a2, const wchar_t *a3, ...);


// JK functions
extern void (*jk_exit)(int a);
extern int (*sub_401000)(char* a);
extern int (*sub_436D10)(int a);
extern int (*sub_436D30)(int a);
extern int (*other_window_stuff)(void);
extern int (*jk_printf)(const char* fmt, ...);
extern void (*cog_verb_register)(void* a, intptr_t func, char* cmd);
extern int (*jk_assert)(void* log_func, char* file, int line_num, char *fmt, ...);
extern hashmap_entry* (*hashmap_create_entry)(void* map, char* str);
extern cogSymbol* (*hashmap_set_entry)(hashmap_entry* map, cogSymbol* val);
static char* (*_strncpy)(char *, const char *, size_t) = (void*)0x5126A0;
static int (*__strcmpi)(const char *, const char *) = (void*)0x520D10;
static int (*_sscanf)(const char*, const char*, ...) = (void*)0x512CB0;
static void* (*_memcpy)(void*, const void*, size_t) = (void*)0x514D00;
char* _strcpy(char *dst, const char *src);
int _memcmp(const void* str1, const void* str2, size_t count);
void* _memset(void* ptr, int val, size_t num);
void* _memset32(void* ptr, uint32_t val, size_t num);

static int (*__vsnprintf)(char *a1, size_t a2, const char *a3, va_list a4) = (void*)0x512AC0;
static int (*_sprintf)(char *, const char *, ...) = (void*)0x512B60;
static char* (*_strtok)(char * a, const char * b) = (void*)0x512850;
static char* (*_strrchr)(char * a, char b) = (void*)0x514460;
static char* (*_strchr)(char * a, char b) = (void*)0x513280;
static char* (*_strncat)(char*, const char*, size_t) = (void*)0x5135E0;
static size_t (__cdecl *_wcslen)(const wchar_t *) = (void*)0x512FE0;
static wchar_t* (__cdecl *_wcscpy)(wchar_t *, const wchar_t *) = (void*)0x5130A0;
static int (*_rand)() = (void*)0x512D00;
static size_t (__cdecl *_strspn)(const char *, const char *) = (void*)0x00514510;
static char* (__cdecl *_strpbrk)(const char *, const char *) = (void*)0x5144D0;
static int (__cdecl *__tolower)(char SrcStr) = (void*)0x514550;
static void* (__cdecl *_malloc)(size_t) = (void*)0x514210;
static void (__cdecl *_free)(void *) = (void*)0x00513740;
static int (__cdecl *_atoi)(const char*) = (void*)0x512840;
static double (__cdecl *_atof)(const char*) = (void*)0x513000;
static wchar_t* (__cdecl *_wcsncpy)(wchar_t *a1, const wchar_t *a2, size_t a3) = (void*)0x512C70;
static int (__cdecl *msvc_sub_512D30)(int a, int b) = (void*)0x512D30;
static void (__cdecl *_qsort)(void *, size_t, size_t, int (__cdecl *)(const void *, const void *)) = (void*)0x00512DA0;
static int (__cdecl *_string_modify_idk)(int SrcStr) = (void*)0x00513170;
int _strlen(const char *str);
char* _strcat(char* str, const char* concat);
int _strcmp(const char* s1, const char* s2);

float _frand();

// JK globals
VM_VAR_DECL(g_hWnd, HWND);

VM_VAR_DECL(g_nShowCmd, uint32_t);
VM_VAR_DECL(g_hInstance, uint32_t);

VM_VAR_DECL(g_app_suspended, uint32_t);
VM_VAR_DECL(g_window_active, uint32_t);
VM_VAR_DECL(g_app_active, uint32_t);
VM_VAR_DECL(g_should_exit, uint32_t);
VM_VAR_DECL(g_thing_two_some_dialog_count, uint32_t);
VM_VAR_DECL(g_handler_count, uint32_t);

VM_VAR_DECL(g_855E8C, uint32_t);
VM_VAR_DECL(g_855E90, uint32_t);
VM_VAR_DECL(g_window_not_destroyed, uint32_t);

VM_VAR_DECL(g_cog_symboltable_hashmap, void*);

// TODO: defsym?

// JK globals
#define g_hWnd *(g_hWnd_ptr)

#define g_nShowCmd *(g_nShowCmd_ptr)
#define g_hInstance *(g_hInstance_ptr)

#define g_app_suspended *(g_app_suspended_ptr)
#define g_window_active *(g_window_active_ptr)
#define g_app_active *(g_app_active_ptr)
#define g_should_exit *(g_should_exit_ptr)
#define g_thing_two_some_dialog_count *(g_thing_two_some_dialog_count_ptr)
#define g_handler_count *(g_handler_count_ptr)

#define g_855E8C *(g_855E8C_ptr)
#define g_855E90 *(g_855E90_ptr)
#define g_window_not_destroyed *(g_window_not_destroyed_ptr)
#define g_cog_symboltable_hashmap *(g_cog_symboltable_hashmap_ptr)

#define wm_msg_main_handler (0x50ECB0)

#define pSithHS (*((struct common_functions **)0x82F0A4))
#define g_cog_hashtable (*(void**)0x836C3C)

void jk_init();

#endif // JK_H
