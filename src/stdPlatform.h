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

#ifndef PLATFORM_POSIX
void stdPlatform_Assert(const char *msg, const char *file, int line);
void* stdPlatform_AllocHandle(uint32_t size);
void stdPlatform_FreeHandle(void *ptr);
void* stdPlatform_ReallocHandle(void *ptr, uint32_t size);
void* stdPlatform_LockHandle(void *ptr);
void stdPlatform_UnlockHandle(void *ptr);
void stdPlatform_GetDateTime(char *out, uint32_t outLen);
#else
// On POSIX, these are not needed — Linux_* functions handle everything
#ifndef __cplusplus
static void (*stdPlatform_Assert)(const char* a1, const char *a2, int a3) = (void*)stdPlatform_Assert_ADDR;
static void* (*stdPlatform_AllocHandle)(size_t) = (void*)stdPlatform_AllocHandle_ADDR;
static void (*stdPlatform_FreeHandle)(void*) = (void*)stdPlatform_FreeHandle_ADDR;
static void* (*stdPlatform_ReallocHandle)(void*, size_t) = (void*)stdPlatform_ReallocHandle_ADDR;
static uint32_t (*stdPlatform_LockHandle)(uint32_t) = (void*)stdPlatform_LockHandle_ADDR;
static void (*stdPlatform_UnlockHandle)(uint32_t) = (void*)stdPlatform_UnlockHandle_ADDR;
#endif
#endif

#ifndef PLATFORM_POSIX
static int (*stdPrintf)(int (*a1)(const char *, ...), const char *a2, int line, const char *fmt, ...) = (void*)0x426D80;
static int (*stdPlatform_Printf)(const char *fmt, ...) = (void*)stdPlatform_Printf_ADDR;
static int (__cdecl *stdPlatform_GetTimeMsec)(void) = (void*)stdPlatform_GetTimeMsec_ADDR;
#else
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

#ifdef TARGET_DREAMCAST
void stdPlatform_PrintHeapStats();
// Added: current memory pressure for the on-screen debug overlay (see dcDebug).
void DC_GetMemStats(uint32_t* pSysUsedK, uint32_t* pSysFreeK,
                    uint32_t* pVramUsedK, uint32_t* pVramTotalK, uint32_t* pAllocs);
#endif

// Added
void stdPlatform_Memzero32(void* dst, uint32_t len);
int stdPlatform_IsWordAddressableOnly(const void* p);

// Added: TWL-only extram placement hint around an allocation (no-op elsewhere).
// Use for data that is word-safe but too hot for DC's uncached VRAM window.
#ifdef TARGET_TWL
#define TWL_EXTRAM_SUGGEST(hs)  int _twlPrevSuggest = (hs)->suggestHeap(HEAP_WORD_ADDRESSABLE)
#define TWL_EXTRAM_RESTORE(hs)  (hs)->suggestHeap(_twlPrevSuggest)
#else
#define TWL_EXTRAM_SUGGEST(hs)  do {} while (0)
#define TWL_EXTRAM_RESTORE(hs)  do {} while (0)
#endif


// Added: per-file allocation cataloguing (see stdPlatform.c).
// Define STDPLATFORM_ALLOC_TRACKING to route the *_ALLOC/*_FREE macros below
// through a tracker keyed on __FILE__; without it they compile straight to the
// host-services calls (zero overhead). Free/realloc read the allocation size
// back from the platform allocator's own header, so tracked and untracked
// pointers can be mixed safely.
void* stdPlatform_TrackedAlloc(void* (*allocFn)(uint32_t), uint32_t len, const char* pFile);
void  stdPlatform_TrackedFree(void (*freeFn)(void*), void* p, const char* pFile);
void* stdPlatform_TrackedRealloc(void* (*reallocFn)(void*, uint32_t), void* p, uint32_t len, const char* pFile);
void  stdPlatform_PrintAllocStats(void);
uint32_t stdPlatform_AllocSize(void* p);

#ifdef STDPLATFORM_ALLOC_TRACKING
#define STD_ALLOC(len)       stdPlatform_TrackedAlloc(std_g_pHS->alloc, (len), __FILE__)
#define STD_FREE(p)          stdPlatform_TrackedFree(std_g_pHS->free, (p), __FILE__)
#define STD_REALLOC(p, len)  stdPlatform_TrackedRealloc(std_g_pHS->realloc, (p), (len), __FILE__)
#define SITH_ALLOC(len)      stdPlatform_TrackedAlloc(pSithHS->alloc, (len), __FILE__)
#define SITH_FREE(p)         stdPlatform_TrackedFree(pSithHS->free, (p), __FILE__)
#define SITH_REALLOC(p, len) stdPlatform_TrackedRealloc(pSithHS->realloc, (p), (len), __FILE__)
#define RDROID_ALLOC(len)    stdPlatform_TrackedAlloc(rdroid_g_pHS->alloc, (len), __FILE__)
#define RDROID_FREE(p)       stdPlatform_TrackedFree(rdroid_g_pHS->free, (p), __FILE__)
#define RDROID_REALLOC(p, len) stdPlatform_TrackedRealloc(rdroid_g_pHS->realloc, (p), (len), __FILE__)
#define JK_ALLOC(len)        stdPlatform_TrackedAlloc(pHS->alloc, (len), __FILE__)
#define JK_FREE(p)           stdPlatform_TrackedFree(pHS->free, (p), __FILE__)
#else
#define STD_ALLOC(len)       std_g_pHS->alloc(len)
#define STD_FREE(p)          std_g_pHS->free(p)
#define STD_REALLOC(p, len)  std_g_pHS->realloc((p), (len))
#define SITH_ALLOC(len)      pSithHS->alloc(len)
#define SITH_FREE(p)         pSithHS->free(p)
#define SITH_REALLOC(p, len) pSithHS->realloc((p), (len))
#define RDROID_ALLOC(len)    rdroid_g_pHS->alloc(len)
#define RDROID_FREE(p)       rdroid_g_pHS->free(p)
#define RDROID_REALLOC(p, len) rdroid_g_pHS->realloc((p), (len))
#define JK_ALLOC(len)        pHS->alloc(len)
#define JK_FREE(p)           pHS->free(p)
#endif

// Added: OpenJones3D-style logging/assert macros (SITHLOG_*/STDLOG_*/RDLOG_*,
// SITH_ASSERT/STD_ASSERT/RD_ASSERT). They map to the host-services print/assert used
// throughout the original code (stdPrintf(hs->xxxPrint, file, line, fmt, ...) and
// hs->assert(cond, file, line)), so desktop output matches the original engine.
// On TARGET_RETRO_HOMEBREW they compile to nothing — the guard lives here in the header
// (not at each call site) so the debug strings/calls cost zero RAM on DSi/Dreamcast.
#ifdef TARGET_RETRO_HOMEBREW
#define SITHLOG_STATUS(fmt, ...)   ((void)0)
#define SITHLOG_MESSAGE(fmt, ...)  ((void)0)
#define SITHLOG_WARNING(fmt, ...)  ((void)0)
#define SITHLOG_ERROR(fmt, ...)    ((void)0)
#define SITHLOG_DEBUG(fmt, ...)    ((void)0)
#define STDLOG_STATUS(fmt, ...)    ((void)0)
#define STDLOG_MESSAGE(fmt, ...)   ((void)0)
#define STDLOG_WARNING(fmt, ...)   ((void)0)
#define STDLOG_ERROR(fmt, ...)     ((void)0)
#define STDLOG_DEBUG(fmt, ...)     ((void)0)
#define RDLOG_STATUS(fmt, ...)     ((void)0)
#define RDLOG_MESSAGE(fmt, ...)    ((void)0)
#define RDLOG_WARNING(fmt, ...)    ((void)0)
#define RDLOG_ERROR(fmt, ...)      ((void)0)
#define RDLOG_DEBUG(fmt, ...)      ((void)0)
#define SITH_ASSERT(cond)          ((void)0)
#define STD_ASSERT(cond)           ((void)0)
#define RD_ASSERT(cond)            ((void)0)
#define SITH_ASSERTREL(cond)       ((void)0)
#define STD_ASSERTREL(cond)        ((void)0)
#define RD_ASSERTREL(cond)         ((void)0)
#else
#define SITHLOG_STATUS(fmt, ...)   stdPrintf(pSithHS->statusPrint,  __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define SITHLOG_MESSAGE(fmt, ...)  stdPrintf(pSithHS->messagePrint, __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define SITHLOG_WARNING(fmt, ...)  stdPrintf(pSithHS->warningPrint, __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define SITHLOG_ERROR(fmt, ...)    stdPrintf(pSithHS->errorPrint,   __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define SITHLOG_DEBUG(fmt, ...)    stdPrintf(pSithHS->debugPrint,   __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define STDLOG_STATUS(fmt, ...)    stdPrintf(std_g_pHS->statusPrint,  __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define STDLOG_MESSAGE(fmt, ...)   stdPrintf(std_g_pHS->messagePrint, __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define STDLOG_WARNING(fmt, ...)   stdPrintf(std_g_pHS->warningPrint, __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define STDLOG_ERROR(fmt, ...)     stdPrintf(std_g_pHS->errorPrint,   __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define STDLOG_DEBUG(fmt, ...)     stdPrintf(std_g_pHS->debugPrint,   __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define RDLOG_STATUS(fmt, ...)     stdPrintf(rdroid_g_pHS->statusPrint,  __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define RDLOG_MESSAGE(fmt, ...)    stdPrintf(rdroid_g_pHS->messagePrint, __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define RDLOG_WARNING(fmt, ...)    stdPrintf(rdroid_g_pHS->warningPrint, __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define RDLOG_ERROR(fmt, ...)      stdPrintf(rdroid_g_pHS->errorPrint,   __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define RDLOG_DEBUG(fmt, ...)      stdPrintf(rdroid_g_pHS->debugPrint,   __FILE__, __LINE__, (fmt), ##__VA_ARGS__)
#define SITH_ASSERT(cond)          do { if (!(cond)) pSithHS->assert(#cond, __FILE__, __LINE__); } while (0)
#define STD_ASSERT(cond)           do { if (!(cond)) std_g_pHS->assert(#cond, __FILE__, __LINE__); } while (0)
#define RD_ASSERT(cond)            do { if (!(cond)) rdroid_g_pHS->assert(#cond, __FILE__, __LINE__); } while (0)
#define SITH_ASSERTREL(cond)       do { if (!(cond)) pSithHS->assert(#cond, __FILE__, __LINE__); } while (0)
#define STD_ASSERTREL(cond)        do { if (!(cond)) std_g_pHS->assert(#cond, __FILE__, __LINE__); } while (0)
#define RD_ASSERTREL(cond)         do { if (!(cond)) rdroid_g_pHS->assert(#cond, __FILE__, __LINE__); } while (0)
#endif

void stdPlatform_Memcpy32(void* dst, const void* src, uint32_t len);
void stdPlatform_Memset32(void* dst, uint8_t val, uint32_t len);

// Added: single byte store via 16-bit read-modify-write, for word-addressable
// destinations (Dreamcast VRAM / NDS slot-2 RAM drop byte-granular stores).
// Little-endian (SH4/ARM9).
static inline void stdPlatform_WriteByte16(void* p, uint8_t val)
{
    uint16_t* pWord = (uint16_t*)((uintptr_t)p & ~(uintptr_t)1);
    if ((uintptr_t)p & 1)
        *pWord = (*pWord & 0x00FF) | ((uint16_t)val << 8);
    else
        *pWord = (*pWord & 0xFF00) | val;
}


#ifdef __cplusplus
}
#endif

#endif // _STDPLATFORM_H
