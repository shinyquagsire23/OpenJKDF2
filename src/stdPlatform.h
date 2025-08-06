#ifndef _STDPLATFORM_H
#define _STDPLATFORM_H

#include "types.h"
#include "jk.h"
#include "globals.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#define stdPlatform_GetTimeMsec_ADDR (0x0042C2B0)

void stdPlatform_InitServices(HostServices *handlers);
int stdPlatform_Startup();

#if !defined(__cplusplus) && !defined(TARGET_SWITCH)
static void (*stdPlatform_Assert)(const char* a1, const char *a2, int a3) = (void*)stdPlatform_Assert_ADDR;

static void* (*stdPlatform_AllocHandle)(size_t) = (void*)stdPlatform_AllocHandle_ADDR;
static void (*stdPlatform_FreeHandle)(void*) = (void*)stdPlatform_FreeHandle_ADDR;
static void* (*stdPlatform_ReallocHandle)(void*, size_t) = (void*)stdPlatform_ReallocHandle_ADDR;
static uint32_t (*stdPlatform_LockHandle)(uint32_t) = (void*)stdPlatform_LockHandle_ADDR;
static void (*stdPlatform_UnlockHandle)(uint32_t) = (void*)stdPlatform_UnlockHandle_ADDR;
#endif

#if !defined(PLATFORM_POSIX) && !defined(TARGET_SWITCH)
static int (*stdPrintf)(int (*a1)(const char *, ...), const char *a2, int line, const char *fmt, ...) = (void*)0x426D80;
static int (*stdPlatform_Printf)(const char *fmt, ...) = (void*)stdPlatform_Printf_ADDR;
static int (__cdecl *stdPlatform_GetTimeMsec)(void) = (void*)stdPlatform_GetTimeMsec_ADDR;
#else

#ifdef TARGET_SWITCH

    void logToSD(const char* fmt, ...);

#endif
uint64_t Linux_TimeUs();
int stdPrintf(int (*a1)(const char *, ...), const char *a2, int line, const char *fmt, ...);
int stdPlatform_Printf(const char *fmt, ...);
uint32_t stdPlatform_GetTimeMsec();
#endif

int stdConsolePrintf(const char *fmt, ...);

#ifdef TARGET_TWL
extern size_t trackingAllocsA;
extern size_t trackingAllocsB;
extern size_t trackingAllocsBLimit;

void stdPlatform_PrintHeapStats();
#endif

#ifdef __cplusplus
}
#endif

#endif // _STDPLATFORM_H
