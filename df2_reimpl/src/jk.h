#ifndef JK_H
#define JK_H

#include "types.h"
#include <stdio.h>

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
    uint32_t realloc;
    uint32_t timeGetTime;
    int (*fileOpen)(char *, char *);
    int (*fileClose)(int);
    size_t (*fileRead)(int, void *, size_t);
    char *(*fileGets)(int, char *, int);
    size_t (*fileWrite)(int, void *, size_t);
    int (*feof)(FILE *);
    int (*ftell)(FILE *);
    int (*fseek)(FILE *, int, int);
    int (*fileSize)(char *);
    int (*filePrintf)(FILE *, char*, ...);
    uint32_t fgetws;
    uint32_t allocHandle;
    uint32_t freeHandle;
    uint32_t reallocHandle;
    uint32_t lockHandle;
    uint32_t unlockHandle;
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
extern int (*_sscanf)(const char*, const char*, ...);
extern void* (*_memcpy)(void*, const void*, size_t);
char* _strcpy(char *dst, const char *src);
int _memcmp(const void* str1, const void* str2, size_t count);

static int (*__vsnprintf)(char *a1, size_t a2, const char *a3, va_list a4) = 0x512AC0;
static char* (*_strtok)(char * a, const char * b) = 0x512850;
static char* (*_strchr)(char * a, char b) = 0x513280;
static char* (*strtolower)(char* str) = 0x42F4F0;
int _strlen(char *str);

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
