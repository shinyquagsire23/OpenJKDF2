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
}
