#include "jk.h"

#include "types.h"

// Imports
HWND (__stdcall *jk_CreateWindowExA)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
HWND (__stdcall *jk_FindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName);
int (__stdcall *jk_GetSystemMetrics)(int nIndex);
BOOL (__stdcall *jk_ShowWindow)(HWND hWnd, int nCmdShow);
int (__stdcall *jk_UpdateWindow)(HWND hWnd);
void (__stdcall *jk_InitCommonControls)(void);
BOOL (__stdcall *jk_PeekMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
BOOL (__stdcall *jk_GetMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
BOOL (__stdcall *jk_TranslateMessage)(const MSG* lpMsg);
LRESULT (__stdcall *jk_DispatchMessageA)(const MSG* lpMsg);
uint32_t (__stdcall *jk_RegisterClassExA)(void* a);
HICON (__stdcall *jk_LoadIconA)(uint32_t a, char* b);
HCURSOR (__stdcall *jk_LoadCursorA)(uint32_t a, char* b);
HGDIOBJ (__stdcall *jk_GetStockObject)(uint32_t a);
HANDLE (__stdcall *jk_CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE (__stdcall *jk_CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
HLOCAL (__stdcall *jk_LocalAlloc)(UINT uFlags, SIZE_T uBytes);
LPVOID (__stdcall *jk_MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
BOOL (__stdcall *jk_UnmapViewOfFile)(LPCVOID lpBaseAddress);
BOOL (__stdcall *jk_CloseHandle)(HANDLE hObject);

// JK functions
void (*jk_exit)(int a) = (void*)0x512590;
int (*sub_401000)(char* a) = (void*)0x401000;
int (*sub_436D10)(int a) = (void*)0x436D10;
int (*sub_436D30)(int a) = (void*)0x436D30;
int (*sub_4E0640)() = (void*)0x4E0640;
int (*other_window_stuff)(void) = (void*)0x4037E0;
int (*jk_printf)(const char* fmt, ...) = (void*)0x426E60;
void (*cog_verb_register)(void* a, intptr_t func, char* cmd) = (void*)0x4E0700;
int (*jk_assert)(void* log_func, char* file, int line_num, char *fmt, ...) = (void*)0x426D80;
hashmap_entry* (*hashmap_create_entry)(void* map, char* str) = (void*)0x4FD260;
cog_entry* (*hashmap_set_entry)(hashmap_entry* map, cog_entry* val) = (void*)0x4FD350;
void* (*hashmap_init_maybe)(int amt) = (void*)0x437AF0;
char* (*_strncpy)(char *, const char *, size_t) = (void*)0x5126A0;
int (*__strcmpi)(const char *, const char *) = (void*)0x520D10;
int (*_sscanf)(const char*, const char*, ...) = (void*)0x512CB0;
void* (*_memcpy)(void*, const void*, size_t) = (void*)0x514D00;

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

int _strlen(char *str)
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
    while(*dst++ = *src++);
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
        *(uint8_t*)(ptr+i) = val;
    }
    return ptr;
}

int _strcmp(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

// JK globals
VM_VAR(g_hWnd, HWND, 0x855DE0);

VM_VAR(g_nShowCmd, uint32_t, 0x855DE8);
VM_VAR(g_hInstance, uint32_t, 0x855DEC);

VM_VAR(g_app_suspended, uint32_t, 0x855E70);
VM_VAR(g_window_active, uint32_t, 0x855E74);
VM_VAR(g_app_active, uint32_t, 0x855E78);
VM_VAR(g_should_exit, uint32_t, 0x855E7C);
VM_VAR(g_thing_two_some_dialog_count, uint32_t, 0x855E80);
VM_VAR(g_handler_count, uint32_t, 0x855E84);

VM_VAR(g_855E8C, uint32_t, 0x855E8C);
VM_VAR(g_855E90, uint32_t, 0x855E90);
VM_VAR(g_window_not_destroyed, uint32_t, 0x855E94);

VM_VAR(g_cog_symboltable_hashmap, void*, 0x8B5428);

void jk_init()
{
    jk_CreateWindowExA = *(void**)0x8F0630;
    jk_FindWindowA = *(void**)0x8F05F0;
    jk_GetSystemMetrics = *(void**)0x8F05C4;
    jk_ShowWindow = *(void**)0x8F05EC;
    jk_UpdateWindow = *(void**)0x8F0634;
    jk_InitCommonControls = *(void**)0x8F03F4;
    jk_PeekMessageA = *(void**)0x8F063C;
    jk_GetMessageA = *(void**)0x8F0640;
    jk_TranslateMessage = *(void**)0x8F0638;
    jk_DispatchMessageA = *(void**)0x8F05AC;
    jk_RegisterClassExA = *(void**)0x8F0620;
    jk_LoadIconA = *(void**)0x8F0624;
    jk_LoadCursorA = *(void**)0x8F0628;
    jk_GetStockObject = *(void**)0x8F046C;
    jk_CreateFileA = *(void**)0x8F048C;
    jk_CreateFileMappingA = *(void**)0x8F0488;
    jk_LocalAlloc = *(void**)0x8F04D0;
    jk_MapViewOfFile = *(void**)0x8F04D4;
    jk_UnmapViewOfFile = *(void**)0x8F0478;
    jk_CloseHandle = *(void**)0x8F0474;
}
