#ifndef JK_H
#define JK_H

#include "types.h"

#define WinMain_ADDR (0x41EBD0)

#define VM_VAR(name, type, ptr) \
    type* name ## _ptr = (type*)ptr;
#define VM_VAR_DECL(name, type) extern type* name ## _ptr;

typedef struct common_functions
{
    uint32_t some_float;
    uint32_t print_loglevel1;
    uint32_t print_unk2;
    uint32_t print_unk;
    uint32_t print_loglevel0;
    uint32_t print_loglevel2;
    uint32_t messagebox;
    uint32_t unk_0;
    uint32_t alloc;
    uint32_t free;
    uint32_t realloc;
    uint32_t timeGetTime;
    uint32_t fopen;
    uint32_t fclose;
    uint32_t fread;
    uint32_t fgets;
    uint32_t fwrite;
    uint32_t feof;
    uint32_t ftell;
    uint32_t fseek;
    uint32_t getfilesize;
    uint32_t fprintf;
    uint32_t fgetws;
    uint32_t malloc_ish;
    uint32_t free_ish;
    uint32_t realloc_ish;
    uint32_t return_arg;
    uint32_t nullsub;
} common_functions;

typedef struct hashmap_entry
{
    
} hashmap_entry;

typedef struct cog_entry
{
    int type;
    int val;
    int func;
    uint32_t field_C;
} cog_entry;

//static void (*jk_main)(uint32_t a, uint32_t b, char* c, int d, char* e) = (void*)0x50E750;

// Imports
extern HWND (__stdcall *jk_CreateWindowExA)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
extern HWND (__stdcall *jk_FindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName);
extern int (__stdcall *jk_GetSystemMetrics)(int nIndex);
extern BOOL (__stdcall *jk_ShowWindow)(HWND hWnd, int nCmdShow);
extern int (__stdcall *jk_UpdateWindow)(HWND hWnd);
extern void (__stdcall *jk_InitCommonControls)(void);
extern BOOL (__stdcall *jk_PeekMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
extern BOOL (__stdcall *jk_GetMessageA)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
extern BOOL (__stdcall *jk_TranslateMessage)(const MSG* lpMsg);
extern LRESULT (__stdcall *jk_DispatchMessageA)(const MSG* lpMsg);
extern uint32_t (__stdcall *jk_RegisterClassExA)(void* a);
extern HICON (__stdcall *jk_LoadIconA)(uint32_t a, char* b);
extern HCURSOR (__stdcall *jk_LoadCursorA)(uint32_t a, char* b);
extern HGDIOBJ (__stdcall *jk_GetStockObject)(uint32_t a);

// JK functions
extern void (*jk_exit)(int a);
extern int (*sub_401000)(char* a);
extern int (*sub_436D10)(int a);
extern int (*sub_436D30)(int a);
extern int (*sub_4E0640)();
extern int (*other_window_stuff)(void);
extern int (*jk_printf)(const char* fmt, ...);
extern void (*cog_verb_register)(void* a, intptr_t func, char* cmd);
extern int (*jk_assert)(void* log_func, char* file, int line_num, char *fmt, ...);
extern hashmap_entry* (*hashmap_create_entry)(void* map, char* str);
extern cog_entry* (*hashmap_set_entry)(hashmap_entry* map, cog_entry* val);
extern void* (*hashmap_init_maybe)(int amt);
extern char* (*_strncpy)(char *, const char *, size_t);
extern int (*__strcmpi)(const char *, const char *);

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

#define common_functions_ptr_2 (*((struct common_functions **)0x82F0A4))
#define g_cog_hashtable (*(void**)0x836C3C)

void jk_init();

#endif // JK_H
