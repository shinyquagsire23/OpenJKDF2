#ifndef _STDPLATFORM_H
#define _STDPLATFORM_H

#include "jk.h"

#define stdPlatform_Startup_ADDR (0x0042C080)
#define stdPlatform_Assert_ADDR (0x0042C090)
#define stdPlatform_Printf_ADDR (0x0042C160)
#define stdPlatform_AllocHandle_ADDR (0x0042C190)
#define stdPlatform_FreeHandle_ADDR (0x0042C1A0)
#define stdPlatform_ReallocHandle_ADDR (0x0042C1B0)
#define stdPlatform_LockHandle_ADDR (0x0042C1D0)
#define stdPlatform_UnlockHandle_ADDR (0x0042C1E0)
#define stdPlatform_InitServices_ADDR (0x0042C1F0)
#define stdPlatform_GetTimeMsec_ADDR (0x0042C2B0)
#define stdPlatform_GetDateTime_ADDR (0x0042C2C0)

#define std_genBuffer ((char*)0x866880)
#define std_pHS (*((struct common_functions **)0x866C80))

#define stdPlatform_GetTimeMsec_ADDR (0x0042C2B0)

void stdPlatform_InitServices(common_functions *handlers);
int stdPlatform_Startup();

static void (*stdPlatform_Assert)(int a1, char *a2, int a3) = (void*)stdPlatform_Assert_ADDR;

static void* (*stdPlatform_AllocHandle)(size_t) = (void*)stdPlatform_AllocHandle_ADDR;
static void (*stdPlatform_FreeHandle)(void*) = (void*)stdPlatform_FreeHandle_ADDR;
static void* (*stdPlatform_ReallocHandle)(void*, size_t) = (void*)stdPlatform_ReallocHandle_ADDR;
static int (*stdPlatform_LockHandle)(int) = (void*)stdPlatform_LockHandle_ADDR;
static void (*stdPlatform_UnlockHandle)(int) = (void*)stdPlatform_UnlockHandle_ADDR;

#ifdef WIN32
static int (*stdPrintf)(void* a1, char *a2, int line, char *fmt, ...) = (void*)0x426D80;
static int (*stdPlatform_Printf)(const char *fmt, ...) = (void*)stdPlatform_Printf_ADDR;
static int (__cdecl *stdPlatform_GetTimeMsec)(void) = (void*)stdPlatform_GetTimeMsec_ADDR;
#else
int stdPrintf(void* a1, char *a2, int line, char *fmt, ...);
int stdPlatform_Printf(char *fmt, ...);
uint32_t stdPlatform_GetTimeMsec();
#endif

#endif // _STDPLATFORM_H
