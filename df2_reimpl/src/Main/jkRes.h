#ifndef _JKRES_H
#define _JKRES_H

#include "types.h"

#define jkRes_Startup_ADDR (0x0040E360)
#define jkRes_Shutdown_ADDR (0x0040E490)
#define jkRes_New_ADDR (0x0040E560)
#define jkRes_LoadGob_ADDR (0x0040E5B0)
#define jkRes_LoadCd_ADDR (0x0040E980)
#define jkRes_HookHS_ADDR (0x0040EA30)
#define jkRes_UnhookHS_ADDR (0x0040EAA0)
#define jkRes_FileExists_ADDR (0x0040EB20)
#define jkRes_LoadCD_ADDR (0x0040EBB0)
#define jkRes_ReadKey_ADDR (0x0040F110)
#define jkRes_LoadNew_ADDR (0x0040F190)
#define jkRes_NewGob_ADDR (0x0040F360)
#define jkRes_FileOpen_ADDR (0x0040F4C0)
#define jkRes_FileClose_ADDR (0x0040F6B0)
#define jkRes_FileRead_ADDR (0x0040F710)
#define jkRes_FileWrite_ADDR (0x0040F770)
#define jkRes_FileGets_ADDR (0x0040F7B0)
#define jkRes_FileGetws_ADDR (0x0040F810)
#define jkRes_FEof_ADDR (0x0040F870)
#define jkRes_FTell_ADDR (0x0040F8B0)
#define jkRes_FSeek_ADDR (0x0040F8F0)
#define jkRes_FileSize_ADDR (0x0040F950)
#define jkRes_FilePrintf_ADDR (0x0040F970)

typedef struct common_functions_basic
{
    float some_float;
    int (*messagePrint)(const char *, ...);
    int (*statusPrint)(const char *, ...);
    int (*warningPrint)(const char *, ...);
    int (*errorPrint)(const char *, ...);
    int (*debugPrint)(const char *, ...);
    int assert;
    int unk_0;
    void *(__cdecl *alloc)(unsigned int);
    void (__cdecl *free)(void *);
    int realloc;
    int getTimerTick;
    int (__cdecl *fileOpen)(const char *, const char *);
    int (__cdecl *fileClose)(int);
    size_t (__cdecl *fileRead)(int, void *, size_t);
    char *(__cdecl *fileGets)(int, char *, int);
    size_t (__cdecl *fileWrite)(int, void *, size_t);
    int feof;
    int ftell;
    int (__cdecl *fseek)(int, int, int);
    int fileSize;
    void (*filePrintf)(int, const char *, ...);
    wchar_t *(__cdecl *fileGetws)(int, wchar_t *, unsigned int);
} common_functions_basic;

typedef struct jkResGob
{
  char name[128];
  int numGobs;
  stdGob *gobs[64];
} jkResGob;

typedef struct jkRes
{
    jkResGob gobs[5];
} jkRes;

typedef struct jkResFile
{
  int bOpened;
  char fpath[128];
  int useLowLevel;
  int fsHandle;
  stdGobFile *gobHandle;
} jkResFile;

#define jkRes_pHS (*(common_functions**)0x00555C68)
#define jkRes_episodeGobName ((char*)0x00555C70)
#define jkRes_curDir ((char*)0x00555C90)

#define jkRes_bHookedHS (*(int*)0x00555D18)
#define jkRes_aFiles ((jkResFile*)0x00554A68)

#define jkRes_gCtx (*(jkRes*)0x005541E0)
#define pLowLevelHS (*(common_functions**)0x00554974)
#define lowLevelHS (*(common_functions_basic*)0x00554978)

#define jkRes_idkGobPath ((char*)0x005549E8)

int jkRes_Startup(common_functions *a1);

void jkRes_New(char *path);
void jkRes_LoadGob(char *a1);
int jkRes_LoadCd(char *a1);
void jkRes_HookHS();
void jkRes_UnhookHS();
int jkRes_FileExists(const char *fpath, char *a2, int len);

int jkRes_ReadKey();
int jkRes_LoadNew(jkResGob *resGob, char *name, int a3);
int jkRes_NewGob(jkResGob *gobFullpath, char *gobFolder, char *gobFname);
int jkRes_LoadCD(int a1);

//static int (*jkRes_Startup)(common_functions *a1) = (void*)jkRes_Startup_ADDR;
//static int (*jkRes_FileExists)(char *fpath, char *a2, int len) = (void*)jkRes_FileExists_ADDR;
//static void (*jkRes_LoadGob)(char *a1) = (void*)jkRes_LoadGob_ADDR;
//static void (*jkRes_LoadCd)(char *a1) = (void*)jkRes_LoadCd_ADDR;
//static int (*jkRes_LoadCD)(int a1) = (void*)jkRes_LoadCD_ADDR;
//static int (*jkRes_LoadNew)(jkResGob *a1, char *a2, int a3) = (void*)jkRes_LoadNew_ADDR;

uint32_t jkRes_FileOpen(const char *fpath, const char *mode);
int jkRes_FileClose(int fd);
size_t jkRes_FileRead(int fd, void* out, size_t len);
size_t jkRes_FileWrite(int fd, void* out, size_t len);
char* jkRes_FileGets(int a1, char* a2, unsigned int a3);
wchar_t* jkRes_FileGetws(int fd, wchar_t* a2, unsigned int a3);
int jkRes_FEof(int fd);
size_t jkRes_FileSize(int fd, wchar_t* a2, unsigned int a3);

//static int (*jkRes_FileOpen)() = (void*)jkRes_FileOpen_ADDR;
//static int (*jkRes_FileClose)() = (void*)jkRes_FileClose_ADDR;
//static int (*jkRes_FileRead)() = (void*)jkRes_FileRead_ADDR;
//static int (*jkRes_FileGets)() = (void*)jkRes_FileGets_ADDR;
//static int (*jkRes_FileGetws)() = (void*)jkRes_FileGetws_ADDR;
//static int (*jkRes_FileWrite)() = (void*)jkRes_FileWrite_ADDR;
//static int (*jkRes_FEof)() = (void*)jkRes_FEof_ADDR;
static int (*jkRes_FTell)() = (void*)jkRes_FTell_ADDR;
static int (*jkRes_FSeek)() = (void*)jkRes_FSeek_ADDR;
//static int (*jkRes_FileSize)() = (void*)jkRes_FileSize_ADDR;
static int (*jkRes_FilePrintf)() = (void*)jkRes_FilePrintf_ADDR;

#endif // _JKRES_H
