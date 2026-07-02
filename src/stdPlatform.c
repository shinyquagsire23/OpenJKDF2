#include "stdPlatform.h"

#include "Win95/std.h"
#include "General/stdMemory.h"
#include "Main/jkQuakeConsole.h"

#ifdef TARGET_TWL
#include <nds.h>
#include <sys/stat.h>
#include "Platform/TWL/dlmalloc.h"
#endif

#ifdef TARGET_DREAMCAST
#include <malloc.h>                  // KOS/newlib memalign for the overflow fallback
#include "Platform/TWL/dlmalloc.h"   // shared dlmalloc (ONLY_MSPACES) for the engine heap
#endif

#ifdef PLATFORM_POSIX
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>

#include "external/fcaseopen/fcaseopen.h"
#endif

#include "SDL2_helper.h"

#ifdef PLATFORM_POSIX
uint32_t Linux_TimeMs()
{
    // TWL has hardware timers we can use for accurate ms timing
#if defined(TARGET_TWL)
    //16756
    //return (uint32_t)(((TIMER1_DATA*(1<<16))+TIMER0_DATA)/32.7285);
    return (uint32_t)(((uint64_t)((TIMER1_DATA*(1<<16))+TIMER0_DATA)<<9)/16757);
#else

    struct timespec _t;

#if defined(_MSC_VER) && !defined(WIN64_MINGW)
    timespec_get(&_t, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &_t);
#endif

    return _t.tv_sec*1000 + lround(_t.tv_nsec/1.0e6);
#endif
}

uint64_t Linux_TimeUs()
{
#if defined(TARGET_TWL)
    //return (uint64_t)((flex64_t)((TIMER1_DATA*(1<<16))+TIMER0_DATA)/0.0327285);
    return (uint64_t)(((uint64_t)((TIMER1_DATA*(1<<16))+TIMER0_DATA)<<19)/17159);
#else
    struct timespec _t;

#if defined(_MSC_VER) && !defined(WIN64_MINGW)
    timespec_get(&_t, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &_t);
#endif

    return _t.tv_sec*1000000 + lround(_t.tv_nsec/1.0e3);
#endif
}

static stdFile_t Linux_stdFileOpen(const char* fpath, const char* mode)
{
    char tmp[512];
    size_t len = strlen(fpath);

    if (len > 512) {
        len = 512;
    }
    _strncpy(tmp, fpath, sizeof(tmp));

#ifndef WIN64_STANDALONE
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif

#ifdef WIN32
for (int i = 0; i < len; i++)
{
    if (tmp[i] == '/') {
        tmp[i] = '\\';
    }
}
#endif

    //printf("open: %s %s\n", fpath, mode);

    stdFile_t ret;
#ifndef TARGET_RETRO_HOMEBREW
    ret = (stdFile_t)fcaseopen(tmp, mode);
#else
    if (mode[0] != 'w') {
        struct stat statstuff;
        int exists = stat(tmp, &statstuff) >= 0;
        if (exists) {
            ret = (stdFile_t)fopen(tmp, mode);
        }
        else {
            return 0;
        }
    }
    else {
        ret = (stdFile_t)fopen(tmp, mode);
    }
#endif
    //printf("File open `%s`->`%s` mode `%s`, ret %x\n", fpath, tmp, mode, ret);
    return ret;
}

static int Linux_stdFileClose(stdFile_t fhand)
{
    int ret = fclose((FILE*)fhand);

#ifdef ARCH_WASM
    EM_ASM(
        FS.syncfs(false, function (err) {
            // Error
        });
    );
#endif // ARCH_WASM

    return ret;
}


static size_t Linux_stdFileRead(stdFile_t fhand, void* dst, size_t len)
{
#ifdef TARGET_TWL
    if (!dst || !len) return 0;
#endif
    size_t val =  fread(dst, 1, len, (FILE*)fhand);

    return val;
}

static size_t Linux_stdFileWrite(stdFile_t fhand, void* dst, size_t len)
{
#ifdef TARGET_TWL
    if (!dst || !len) return 0;
#endif
    return fwrite(dst, 1, len, (FILE*)fhand);
}

static const char* Linux_stdFileGets(stdFile_t fhand, char* dst, size_t len)
{
    // Drops static.jkl animclass parsing from 21.87s to 13.578s due to slow locks on getc
#ifdef TARGET_RETRO_HOMEBREW
    char tmp[128];
    const char* retval = dst;
    if (!dst || !len) return 0;
    while(1) {
        size_t res = fread(tmp, 1, sizeof(tmp), (FILE*)fhand);
        if (!res) break;
        for (size_t i = 0; i < res; i++) {
            char val = tmp[i];
            //if (val == '\r') continue;
            *dst++ = val;
            len--;
            if (val == '\n' || len == 1) {
                fseek((FILE*)fhand, (i+1)-res, SEEK_CUR);
                *dst++ = 0;
                return retval;
            }
            if (!val) {
                fseek((FILE*)fhand, (i+1)-res, SEEK_CUR);
                return retval;
            }
        }
    }
#else
    return fgets(dst, len, (FILE*)fhand);
#endif
}

static const wchar_t* Linux_stdFileGetws(stdFile_t fhand, wchar_t* dst, size_t len)
{
    // Can't use fgetws because -fshort-wchar makes wchar_t 2 bytes
    // but libc fgetws expects native wchar_t (4 bytes on POSIX).
    // Read UTF-16LE characters one at a time instead.
    if (!len) return NULL;
    size_t i = 0;
    while (i < len - 1) {
        wchar_t ch = 0;
        if (fread(&ch, sizeof(wchar_t), 1, (FILE*)fhand) != 1) {
            if (i == 0) return NULL;
            break;
        }
        dst[i++] = ch;
        if (ch == L'\n') break;
    }
    dst[i] = L'\0';
    return dst;
}

static int Linux_stdFseek(stdFile_t fhand, int a, int b)
{
    //printf("fseek? %x %x\n", a, b);
    int ret = fseek((FILE*)fhand, a, b);
    //printf("fseek %x\n", ret);
    return ret;
}

static int Linux_stdFtell(stdFile_t fhand)
{
    return ftell((FILE*)fhand);
}

static void* Linux_alloc(uint32_t len)
{
    void* ret = malloc(len);
    if (ret) {
        memset(ret, 0, len);
    }
    return ret;
}

static void Linux_free(void* ptr)
{
    return free(ptr);
}

static void* Linux_realloc(void* ptr, uint32_t len)
{
    return realloc(ptr, len);
}

#ifdef TARGET_TWL

#define ALLOC_ALIGN (0x4)

//#define MEM_CHECKING
#define MEM_CHECKING_ADD (0x10)
#define MEM_CHECKING_ZERO_VAL (0x00)
#define MEM_CHECKING_VAL (0xAA)
#define MEM_CHECKING_VAL_FREE (0x55)

int heapSuggestion = HEAP_ANY;

size_t trackingAllocsA = 0;
size_t trackingAllocsAReal = 0;
size_t trackingAllocsB = 0;
size_t trackingAllocsBReal = 0;
size_t trackingAllocsBLimit = 0;
size_t trackingAllocsC = 0;
size_t trackingAllocsCReal = 0;
size_t activeAllocs = 0;

mspace openjkdf2_mem_main_mspace = NULL;
mspace openjkdf2_mem_alt_mspace = NULL;
mspace openjkdf2_mem_nwram_mspace = NULL;

intptr_t openjkdf2_mem_alt_mspace_start;
intptr_t openjkdf2_mem_alt_mspace_end;
intptr_t openjkdf2_mem_main_mspace_start;
intptr_t openjkdf2_mem_main_mspace_end;

typedef struct MemTrackingHeader {
    uint32_t memtype_size;
} tMemTrackingHeader;

#define HDR_MEMTYPE_RD(p) (((p)->memtype_size >> 24) & 0xFF)
#define HDR_SIZE_RD(p) ((p)->memtype_size & 0xFFFFFF)
#define HDR_SET(p,t,s) ((p)->memtype_size=(((t&0xFF)<<24) | (s & 0xFFFFFF)))

#ifdef __cplusplus
extern "C" {
#endif

extern void *__real_malloc(size_t size);
extern void __real_free(void *ptr);
extern void* __real_realloc(void *ptr, size_t len);
extern void *__real_calloc(size_t num, size_t size);

#ifdef __cplusplus
}
#endif

static int TWL_suggestHeap(int which) {
    int prev = heapSuggestion;
    heapSuggestion = which;
    return prev;
}


static void* TWL_mspace_alloc(mspace m, uint8_t marker, uint32_t len, uint32_t lenAlign, size_t* pTrackingAllocs, size_t* pTrackingAllocsReal) {
    if (!m) return NULL;

    void* ret = mspace_malloc(m, lenAlign);//malloc(len + sizeof(tMemTrackingHeader));
    if (ret) {
        *pTrackingAllocs += len;
        *pTrackingAllocsReal += lenAlign;
        activeAllocs += 1;
        //printf("%p %x\n", ret, len + sizeof(tMemTrackingHeader));
#ifdef MEM_CHECKING
        memset(ret, MEM_CHECKING_ZERO_VAL, len);
        memset((uint8_t*)ret+len, MEM_CHECKING_VAL, lenAlign-len);
#else
        memset(ret, 0, len);
#endif
        HDR_SET((tMemTrackingHeader*)ret, marker, len);
        return (void*)(((intptr_t)ret) + sizeof(tMemTrackingHeader));
    }
    return NULL;
}

static void TWL_mspace_free(mspace m, tMemTrackingHeader* pHdr, uint32_t size, uint32_t sizeAlign, size_t* pTrackingAllocs, size_t* pTrackingAllocsReal) {
    void* ptr = (void*)(pHdr+1);
    *pTrackingAllocs -= size;
    *pTrackingAllocsReal -= sizeAlign;
    activeAllocs -= 1;
    HDR_SET(pHdr, 0xDE, 0);
#ifdef MEM_CHECKING
    memset(ptr, MEM_CHECKING_VAL_FREE, sizeAlign);
#endif
    mspace_free(m, (void*)pHdr);
}

static void* TWL_mspace_realloc(mspace m, uint8_t marker, tMemTrackingHeader* pHdr, uint32_t oldSize, uint32_t sizeAlign, uint32_t len, uint32_t lenAlign, size_t* pTrackingAllocs, size_t* pTrackingAllocsReal) {
    void* ptr = (void*)(pHdr+1);

    // TODO: force fallback if heapSuggest doesn't match what we have

    void* ret = mspace_realloc(m, (void*)pHdr, lenAlign);
    if (ret) {
        pHdr = (tMemTrackingHeader*)ret;
        *pTrackingAllocs -= oldSize;
        *pTrackingAllocs += len;
        *pTrackingAllocsReal -= sizeAlign;
        *pTrackingAllocsReal += lenAlign;
#ifdef MEM_CHECKING
        if (lenAlign > sizeAlign && len > oldSize) {
            memset((uint8_t*)ret + sizeAlign, MEM_CHECKING_VAL, lenAlign - sizeAlign);
        }
#endif
        HDR_SET(pHdr, marker, len);
        return (void*)((intptr_t)ret + sizeof(tMemTrackingHeader));
    }

    printf("realloc Fallback %x??\n", marker);

    // Fallback option
    ret = Linux_alloc(len);
    if (ret) {
        memcpy(ret, ptr, oldSize);
        Linux_free(ptr);
        return ret;
    }

    printf("aaaaaaa realloc fail\n");
    return NULL;
}

static void* TWL_alloc(uint32_t len)
{
    static BOOL bDontTryAgain = 0;
    if (!len) {
        return NULL;
    }
    // Why?
    uint32_t lenAlign = ((len + sizeof(tMemTrackingHeader)) + (ALLOC_ALIGN-1)) & ~(ALLOC_ALIGN-1);
#ifdef MEM_CHECKING
    lenAlign += MEM_CHECKING_ADD;
#endif
    void* ret = NULL;

    // TODO wrap system init or something for this
    if (!trackingAllocsBLimit) {
        trackingAllocsBLimit = (intptr_t)getHeapLimit() - (intptr_t)getHeapEnd();
        void* mainBase = NULL;
        while (!mainBase) {
            mainBase = __real_malloc(trackingAllocsBLimit);
            if (!mainBase) {
                trackingAllocsBLimit -= 0x1000;
            }
        }
        openjkdf2_mem_main_mspace_start = (intptr_t)mainBase;
        openjkdf2_mem_main_mspace_end = (intptr_t)mainBase + trackingAllocsBLimit;
        //printf("mainBase %p\n", mainBase);
        openjkdf2_mem_main_mspace = create_mspace_with_base(mainBase, trackingAllocsBLimit, 0);

        // Also map NWRAM
        if (isDSiMode()) {
            intptr_t nwramStart = 0x03000000;
            intptr_t nwramEnd = 0x03040000 + 0x40000;
            nwramSetBlockMapping(NWRAM_BLOCK_B, 0x03000000, 256 * 1024,
                         NWRAM_BLOCK_IMAGE_SIZE_256K);
            nwramSetBlockMapping(NWRAM_BLOCK_C, 0x03040000, 256 * 1024,
                         NWRAM_BLOCK_IMAGE_SIZE_256K);
            openjkdf2_mem_nwram_mspace = create_mspace_with_base((void*)nwramStart, nwramEnd-nwramStart, 0);
        }
    }

    // Go to NWRAM for fast heap suggestions
    if (heapSuggestion == HEAP_FAST) {
        if (ret = TWL_mspace_alloc(openjkdf2_mem_nwram_mspace, 0xD5, len, lenAlign, &trackingAllocsC, &trackingAllocsCReal)) {
            return ret;
        }
    }

    if(ret = TWL_mspace_alloc(openjkdf2_mem_alt_mspace, 0xF0, len, lenAlign, &trackingAllocsA, &trackingAllocsAReal)) {
        return ret;
    }

    if (trackingAllocsBReal + lenAlign < trackingAllocsBLimit) {
        if (ret = TWL_mspace_alloc(openjkdf2_mem_main_mspace, 0xDA, len, lenAlign, &trackingAllocsB, &trackingAllocsBReal)) {
            return ret;
        }
    }

    if (heapSuggestion != HEAP_AUDIO) {
        if (ret = TWL_mspace_alloc(openjkdf2_mem_nwram_mspace, 0xD5, len, lenAlign, &trackingAllocsC, &trackingAllocsCReal)) {
            return ret;
        }
    }

    //uint32_t freeEst = (intptr_t)getHeapLimit() - (intptr_t)getHeapEnd();

    printf("already out? %zx %zx %zx\n", trackingAllocsA, trackingAllocsB, trackingAllocsC);

    // Emergency freeing measures
    if (!bDontTryAgain) {
        extern int sithSound_FreeUpMemory(uint32_t);
        extern int rdMaterial_PurgeEntireMaterialCache();
        if (!sithSound_FreeUpMemory(len)) {
            if (!rdMaterial_PurgeMaterialCache()) {
                rdMaterial_PurgeEntireMaterialCache();
            }
        }
        
        bDontTryAgain = 1;
        ret = TWL_alloc(len);
        bDontTryAgain = 0;
    }

    if (!ret) {
        printf("Failed to allocate %x bytes...\n", len);
        //while (1) {}
        return NULL;
    }
    
    return ret;
}

static void TWL_free(void* ptr)
{
    if (!ptr) {
        return;
    }

    tMemTrackingHeader* pHdr = (tMemTrackingHeader*)((intptr_t)ptr - sizeof(tMemTrackingHeader));
    uint32_t sizeAlign = ((HDR_SIZE_RD(pHdr) + sizeof(tMemTrackingHeader)) + (ALLOC_ALIGN-1)) & ~(ALLOC_ALIGN-1);
    uint32_t size = HDR_SIZE_RD(pHdr);
    uint8_t memtype = HDR_MEMTYPE_RD(pHdr);

#ifdef MEM_CHECKING
    sizeAlign += MEM_CHECKING_ADD;
#endif

#ifdef MEM_CHECKING
    for (uint32_t i = size; i < sizeAlign - sizeof(tMemTrackingHeader); i++) {
        if (*((uint8_t*)ptr + i) != MEM_CHECKING_VAL) {
            printf("OOB write!! %p %x %x\n", pHdr, size, sizeAlign - sizeof(tMemTrackingHeader));
            while(1);
        }
    }
#endif

    if (memtype == 0xF0 /*|| ((intptr_t)pHdr >= openjkdf2_mem_alt_mspace_start && (intptr_t)pHdr <= openjkdf2_mem_alt_mspace_end)*/) {
        TWL_mspace_free(openjkdf2_mem_alt_mspace, pHdr, size, sizeAlign, &trackingAllocsA, &trackingAllocsAReal);
        return;
    }
    else if (HDR_MEMTYPE_RD(pHdr) == 0xDA /*|| ((intptr_t)pHdr >= openjkdf2_mem_main_mspace_start && (intptr_t)pHdr <= openjkdf2_mem_main_mspace_end)*/) {
        TWL_mspace_free(openjkdf2_mem_main_mspace, pHdr, size, sizeAlign, &trackingAllocsB, &trackingAllocsBReal);
        return;
    }
    else if (HDR_MEMTYPE_RD(pHdr) == 0xD5 /*|| ((intptr_t)pHdr >= openjkdf2_mem_main_mspace_start && (intptr_t)pHdr <= openjkdf2_mem_main_mspace_end)*/) {
        TWL_mspace_free(openjkdf2_mem_nwram_mspace, pHdr, size, sizeAlign, &trackingAllocsC, &trackingAllocsCReal);
        return;
    }
    else if (memtype == 0xDE) {
        printf("Double free? %p\n", ptr);
        while(1);
    }
    else {
        printf("Where does this go?? %p %x\n", ptr, memtype);
        while(1);
    }
    /*else {
        __real_free(ptr);
    }*/
}

static void* TWL_realloc(void* ptr, uint32_t len)
{
    if (!len) { return NULL; }
    if (!ptr) {
        return Linux_alloc(len);
    }
    extern mspace openjkdf2_mem_alt_mspace;
    tMemTrackingHeader* pHdr = (tMemTrackingHeader*)((intptr_t)ptr - sizeof(tMemTrackingHeader));
    uint32_t oldSize = HDR_SIZE_RD(pHdr);
    uint32_t sizeAlign = ((HDR_SIZE_RD(pHdr) + sizeof(tMemTrackingHeader)) + (ALLOC_ALIGN-1)) & ~(ALLOC_ALIGN-1);
    uint32_t lenAlign = ((len + sizeof(tMemTrackingHeader)) + (ALLOC_ALIGN-1)) & ~(ALLOC_ALIGN-1);

#ifdef MEM_CHECKING
    sizeAlign += MEM_CHECKING_ADD;
    lenAlign += MEM_CHECKING_ADD;
#endif

#ifdef MEM_CHECKING
    for (uint32_t i = HDR_SIZE_RD(pHdr); i < sizeAlign - sizeof(tMemTrackingHeader); i++) {
        if (*((uint8_t*)ptr + i) != MEM_CHECKING_VAL) {
            printf("OOB write!! %p %x %x, %x %x\n", pHdr, HDR_SIZE_RD(pHdr), sizeAlign - sizeof(tMemTrackingHeader), len, lenAlign - sizeof(tMemTrackingHeader));
            while(1);
        }
    }
#endif

    void* ret = NULL;
    if (HDR_MEMTYPE_RD(pHdr) == 0xF0) {
        return TWL_mspace_realloc(openjkdf2_mem_alt_mspace, 0xF0, pHdr, oldSize, sizeAlign, len, lenAlign, &trackingAllocsA, &trackingAllocsAReal);
    }
    else if (HDR_MEMTYPE_RD(pHdr) == 0xDA) {
        return TWL_mspace_realloc(openjkdf2_mem_main_mspace, 0xDA, pHdr, oldSize, sizeAlign, len, lenAlign, &trackingAllocsB, &trackingAllocsBReal);
    }
    else if (HDR_MEMTYPE_RD(pHdr) == 0xD5) {
        return TWL_mspace_realloc(openjkdf2_mem_nwram_mspace, 0xD5, pHdr, oldSize, sizeAlign, len, lenAlign, &trackingAllocsC, &trackingAllocsCReal);
    }
    else if (HDR_MEMTYPE_RD(pHdr) == 0xDE) {
        printf("Double free realloc? %p\n", ptr);
        while(1);
    }
    else {
        printf("Where does this go?? %p %d\n", ptr, len);
        while(1);
        //return __real_realloc(ptr, len);
    }
}



#ifdef __cplusplus
extern "C" {
#endif

void *__wrap_malloc(uint32_t size) {
    return TWL_alloc(size);
}

void __wrap_free(void *ptr) {
    TWL_free(ptr);
}

void* __wrap_realloc(void *ptr, uint32_t len) {
    return TWL_realloc(ptr, len);
}

void *__wrap_calloc(size_t num, size_t size) {
    return TWL_alloc(num*size);
}

extern int64_t __real___muldi3(int32_t a, int32_t b);

__attribute__((naked)) int64_t __wrap___muldi3(int32_t a, int32_t b) {
    __asm__ (
        ".align 4\n"
        ".thumb\n"
        "bx pc\n"
        "nop\n"
        ".arm\n"

        "mul r3, r0, r3\n"
        "mla r3, r2, r1, r3\n"
        "umull   r0, r1, r2, r0\n"
        "add r1, r3\n"
    
        "bx lr\n"
    );
}

__attribute__((naked)) int64_t __wrap___aeabi_lmul(int64_t a, int64_t b) {
    __asm__ (
        ".align 4\n"
        ".thumb\n"
        "mul r3, r0, r3\n"
        "bx pc\n"
        ".arm\n"

        
        "mla r3, r2, r1, r3\n"
        "umull   r0, r1, r2, r0\n"
        "add r1, r3\n"
    
        "bx lr\n"
    );
}

__attribute__((naked)) int64_t __smull_helper(int32_t a, int32_t b) {
    __asm__ (
        ".align 4\n"
        ".thumb\n"
        "mov r3, r0\n"
        "mov r2, r1\n"
        "bx pc\n"
        "nop\n"
        ".arm\n"

        "smull   r0, r1, r2, r3\n"
    
        "bx lr\n"
    );
}

#ifdef __cplusplus
}
#endif

#endif

#ifdef TARGET_DREAMCAST
// ---------------------------------------------------------------------------
// Dreamcast tracked allocator (ported from the DSi/TWL path, kept as its own
// block for now).
//
// The engine churns many small allocations while streaming materials in and out;
// routing them through a dlmalloc mspace gives block coalescing (to fight heap
// fragmentation on the DC's 16 MiB) plus a small tracking header for debugging:
// per-alloc size + pool marker, double-free detection, and optional guard bytes.
//
// Allocation order: SYSTEM RAM FIRST (fast, cached newlib heap), then spill into a
// 4 MiB overflow arena carved out of PVR VRAM (slower, uncached CPU access -- so only
// cold data lands there). If BOTH are exhausted the emergency free-up runs (sound +
// material LRU caches) and we retry once. The VRAM arena is a dlmalloc mspace (block
// coalescing); sysram uses plain newlib malloc.
//
// Deliberately wired only as the engine HostServices alloc/free/realloc, NOT via
// linker --wrap: KOS is preemptively multithreaded and the mspace is not lock-
// guarded, so KOS/newlib's own allocations stay on their heap.
// ---------------------------------------------------------------------------

#include <dc/pvr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void *__real_malloc(size_t size);
extern void __real_free(void *ptr);
extern void* __real_realloc(void *ptr, size_t len);
extern void *__real_calloc(size_t num, size_t size);

#ifdef __cplusplus
}
#endif

#define DC_ALLOC_ALIGN 8   // keep user pointers 8-byte aligned (doubles/pointers)

//#define DC_MEM_CHECKING          // guard bytes after each alloc to catch OOB writes
                                    // (caught a real double-free in the OOM-unwind path once; word-safe fills)
#define DC_MEM_CHECKING_VAL      0xAA
#define DC_MEM_CHECKING_VAL_FREE 0x55

// Tracking-header high byte: which pool the block lives in (and freed sentinel).
#define DC_MARK_MSPACE 0xDC   // VRAM word-addressable arena (opt-in, see DC_alloc)
#define DC_MARK_SYS    0x5A   // system RAM (newlib) -- the primary pool
#define DC_MARK_FREED  0xDE   // sentinel written on free (double-free detection)

// VRAM word-addressable arena sizing. VRAM is 8 MiB total; the PVR keeps framebuffers,
// the vertex buffer and the OPB, and the rest is the texture pool. We carve the arena
// out of that pool, but adaptively: take the smaller of the target below and whatever
// pvr_mem has free beyond a reserve kept for the menu texture (allocated just after
// this) and streamed world textures. This never over-grabs (which used to fail
// pvr_mem_malloc outright, leaving no arena) and self-tunes to the current PVR config.
//
// PVR texture RAM drops byte-granular CPU stores (the controller works in 16-bit
// lanes; a byte write mangles its lane -- see the probe in DC_InitVramOverflow), so
// the arena only serves allocations explicitly flagged HEAP_WORD_ADDRESSABLE by the
// caller via suggestHeap. It is NOT a transparent spill pool for general data.
#define DC_VRAM_OVERFLOW_SIZE   (4 * 1024 * 1024)  // desired max, capped to what's free
#define DC_VRAM_TEXTURE_RESERVE (5 * 512 * 1024)   // ~2.5 MiB left for menuTex + textures
#define DC_VRAM_OVERFLOW_MIN    (256 * 1024)       // don't bother creating a tiny arena

typedef struct DcMemHeader {
    uint32_t mark_size;   // [31:24] pool marker, [23:0] user byte size
    uint32_t _pad;        // keeps the following user pointer 8-byte aligned
} DcMemHeader;
#define DC_HDR_MARK(p)     (((p)->mark_size >> 24) & 0xFF)
#define DC_HDR_SIZE(p)     ((p)->mark_size & 0xFFFFFF)
#define DC_HDR_SET(p,m,s)  ((p)->mark_size = (((m) & 0xFF) << 24) | ((s) & 0xFFFFFF))

static mspace dc_vram_mspace = NULL;
static size_t dc_vram_mspace_size = 0;
static int dc_heapSuggestion = HEAP_ANY;

static int DC_suggestHeap(int which)
{
    int prev = dc_heapSuggestion;
    dc_heapSuggestion = which;
    return prev;
}

// Live-allocation stats (exported for debugging).
size_t dc_trackingAllocs     = 0;  // user bytes live in the VRAM overflow mspace
size_t dc_trackingAllocsReal = 0;  // aligned bytes live in the VRAM overflow mspace
size_t dc_trackingSys        = 0;  // user bytes live in system RAM (the primary pool)
size_t dc_activeAllocs       = 0;

static inline uint32_t DC_BlockSize(uint32_t len)
{
    uint32_t total = (len + (uint32_t)sizeof(DcMemHeader) + (DC_ALLOC_ALIGN - 1)) & ~(DC_ALLOC_ALIGN - 1);
#ifdef DC_MEM_CHECKING
    total += DC_ALLOC_ALIGN; // guard region
#endif
    return total;
}

// Reserve the VRAM overflow arena. Must be called AFTER pvr_init (VRAM is up) and
// EARLY -- before the texture cache fragments VRAM -- so the 4 MiB block is contiguous.
// Called from std3D_Startup. Safe to call more than once (no-op after the first).
void DC_InitVramOverflow(void)
{
    if (dc_vram_mspace) return;

    // Grab the smaller of the target and (free VRAM - texture reserve), so we never fail
    // the alloc by over-asking and always leave headroom for textures.
    size_t avail  = pvr_mem_available();
    size_t budget = (avail > DC_VRAM_TEXTURE_RESERVE) ? (avail - DC_VRAM_TEXTURE_RESERVE) : 0;
    size_t want   = DC_VRAM_OVERFLOW_SIZE;
    if (want > budget) want = budget;
    want &= ~(size_t)31;   // keep the 32-byte alignment pvr_mem hands out

    if (want >= DC_VRAM_OVERFLOW_MIN) {
        // pvr_mem_malloc returns a 32-byte-aligned pointer in the 64-bit texture window
        // (0xa4......, P2 uncached). NOTE: PVR texture RAM does not honor byte-granular
        // CPU stores (the memory controller works in 16-bit lanes) -- see the byte-store
        // probe below. That makes a general-purpose heap here unsafe for any data that
        // gets memcpy'd/byte-written, which is most engine data.
        void* base = pvr_mem_malloc(want);
        if (base) {
            // Byte-store probe: on real hardware byte writes to VRAM mangle the
            // containing 16-bit lane (Flycast emulates VRAM as plain RAM and passes).
            volatile uint8_t* p8 = (volatile uint8_t*)base;
            volatile uint16_t* p16 = (volatile uint16_t*)base;
            p16[0] = 0x1122; p16[1] = 0x3344;
            p8[0] = 0xAA; p8[3] = 0xBB;      // expect 0x11AA / 0xBB44 if bytes work
            stdPlatform_Printf("[DC heap] VRAM byte-store probe: %04x %04x (want 11aa bb44) -> %s\n",
                               p16[0], p16[1],
                               (p16[0] == 0x11AA && p16[1] == 0xBB44) ? "OK" : "BROKEN");
            dc_vram_mspace = create_mspace_with_base(base, want, 0);
            dc_vram_mspace_size = want;
        }
    }
    stdPlatform_Printf("[DC heap] VRAM word-addressable arena: %u KiB (of %u KiB free; %u KiB reserved for textures)\n",
                       (unsigned)(dc_vram_mspace_size / 1024), (unsigned)(avail / 1024),
                       (unsigned)(DC_VRAM_TEXTURE_RESERVE / 1024));
}

static void* DC_alloc(uint32_t len)
{
    static int bDontTryAgain = 0;
    if (!len) return NULL;

    uint32_t total = DC_BlockSize(len);

    // The VRAM arena is word-addressable only, so it's gated behind an explicit
    // HEAP_WORD_ADDRESSABLE suggestion from the caller: those allocations prefer
    // VRAM (relieving sysram) and fall back to sysram; everything else is
    // sysram-only (fast, cached, byte-addressable).
    uint8_t mark = DC_MARK_MSPACE;
    void* raw = NULL;
    if (dc_heapSuggestion == HEAP_WORD_ADDRESSABLE && dc_vram_mspace) {
        raw = mspace_malloc(dc_vram_mspace, total);
    }
    if (!raw) {
        raw = __real_malloc(total);
        mark = DC_MARK_SYS;
    }

    if (!raw) {
        // Emergency freeing measures -- the main reason this override exists.
        // Every pool this allocation may use is exhausted, so reclaim from the sound
        // and material LRU caches (which the plain KOS malloc has no way to reach)
        // and retry once.
        if (!bDontTryAgain) {
            extern int sithSound_FreeUpMemory(uint32_t);
            extern int rdMaterial_PurgeMaterialCache(void);
            extern int rdMaterial_PurgeEntireMaterialCache(void);
            if (!sithSound_FreeUpMemory(len)) {
                if (!rdMaterial_PurgeMaterialCache()) {
                    rdMaterial_PurgeEntireMaterialCache();
                }
            }
            bDontTryAgain = 1;
            void* ret = DC_alloc(len);
            bDontTryAgain = 0;
            return ret;
        }
        stdPlatform_Printf("[DC heap] failed to allocate %u bytes (sys %u KiB live, VRAM %u/%u KiB)\n",
                           (unsigned)len, (unsigned)(dc_trackingSys / 1024),
                           (unsigned)(dc_trackingAllocsReal / 1024), (unsigned)(dc_vram_mspace_size / 1024));
        return NULL;
    }

    if (mark == DC_MARK_MSPACE) {
        dc_trackingAllocs     += len;
        dc_trackingAllocsReal += total;
    } else {
        dc_trackingSys += len;
    }
    dc_activeAllocs++;

    DcMemHeader* hdr = (DcMemHeader*)raw;
    DC_HDR_SET(hdr, mark, len);
    void* user = (void*)((uintptr_t)raw + sizeof(DcMemHeader));
    stdPlatform_Memzero32(user, len); // engine relies on zeroed allocations; word ops for VRAM safety
#ifdef DC_MEM_CHECKING
    stdPlatform_Memset32((uint8_t*)user + len, DC_MEM_CHECKING_VAL,   // word-safe for VRAM blocks
                         total - (uint32_t)sizeof(DcMemHeader) - len);
#endif
    return user;
}

static void DC_free(void* ptr)
{
    if (!ptr) return;
    DcMemHeader* hdr = (DcMemHeader*)((uintptr_t)ptr - sizeof(DcMemHeader));
    uint8_t  mark = DC_HDR_MARK(hdr);
    uint32_t len  = DC_HDR_SIZE(hdr);
    uint32_t total = DC_BlockSize(len);

#ifdef DC_MEM_CHECKING
    for (uint32_t i = len; i < total - (uint32_t)sizeof(DcMemHeader); i++) {
        if (*((uint8_t*)ptr + i) != DC_MEM_CHECKING_VAL) {
            stdPlatform_Printf("[DC heap] OOB write past %p (size %u): %02x at +%u\n",
                               ptr, (unsigned)len, *((uint8_t*)ptr + i), (unsigned)i);
            break;
        }
    }
    stdPlatform_Memset32(ptr, DC_MEM_CHECKING_VAL_FREE, total - (uint32_t)sizeof(DcMemHeader)); // word-safe
#endif

    if (mark == DC_MARK_FREED) {
        stdPlatform_Printf("[DC heap] double free %p\n", ptr);
        return;
    }

    DC_HDR_SET(hdr, DC_MARK_FREED, 0);
    dc_activeAllocs--;

    if (mark == DC_MARK_MSPACE) {
        dc_trackingAllocs     -= len;
        dc_trackingAllocsReal -= total;
        mspace_free(dc_vram_mspace, hdr);
    } else if (mark == DC_MARK_SYS) {
        dc_trackingSys -= len;
        __real_free(hdr);
    } else {
        stdPlatform_Printf("[DC heap] free of unknown block %p (marker %02x)\n", ptr, mark);
        //__real_free(ptr);
        //return;
    }
}

static void* DC_realloc(void* ptr, uint32_t len)
{
    if (!ptr) return DC_alloc(len);
    if (!len) { DC_free(ptr); return NULL; }

    DcMemHeader* hdr = (DcMemHeader*)((uintptr_t)ptr - sizeof(DcMemHeader));
    uint32_t oldLen = DC_HDR_SIZE(hdr);
    if (oldLen == len) return ptr;

    // Simple move-realloc: alloc + copy + free. Keeps the header/pool bookkeeping
    // correct even when a block migrates between pools. Word copy: either side
    // may be in the VRAM arena, where byte-store tails would mangle a 16-bit lane.
    void* nw = DC_alloc(len);
    if (!nw) return NULL;
    stdPlatform_Memcpy32(nw, ptr, oldLen < len ? oldLen : len);
    DC_free(ptr);
    return nw;
}

void *__wrap_malloc(uint32_t size) {
    //return DC_alloc(size);
    return __real_malloc(size);
}

void __wrap_free(void *ptr) {
    //DC_free(ptr);
    __real_free(ptr);
}

void* __wrap_realloc(void *ptr, uint32_t len) {
    //return DC_realloc(ptr, len);
    return __real_realloc(ptr, len);
}

void *__wrap_calloc(size_t num, size_t size) {
    //return DC_alloc(num*size);
    return __real_calloc(num, size);
}
#endif // TARGET_DREAMCAST

static int Linux_stdFeof(stdFile_t fhand)
{
    return feof((FILE*)fhand);
}

uint32_t stdPlatform_GetTimeMsec()
{
    return Linux_TimeMs();
}
#endif

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
static int Dummy_suggestHeap(int which) { return HEAP_ANY; }
#endif

#ifndef PLATFORM_POSIX
void stdPlatform_Assert(const char *msg, const char *file, int line)
{
    char buf[512];
    int lastSlash = 0;
    for (int i = 0; file[i]; i++)
    {
        if ( file[i] == '\\' )
            lastSlash = i;
    }
    _sprintf(buf, "%s\n(%s, %d)\n", msg, &file[lastSlash ? lastSlash + 1 : 0], line);
    jk_printf("ASSERT: %s", buf);
}

void* stdPlatform_AllocHandle(uint32_t size)
{
    return _malloc(size);
}

void stdPlatform_FreeHandle(void *ptr)
{
    _free(ptr);
}

void* stdPlatform_ReallocHandle(void *ptr, uint32_t size)
{
    return _realloc(ptr, size);
}

void* stdPlatform_LockHandle(void *ptr)
{
    return ptr;
}

void stdPlatform_UnlockHandle(void *ptr)
{
}

void stdPlatform_GetDateTime(char *out, uint32_t outLen)
{
    SYSTEMTIME st;
    char tmp[80];
    GetLocalTime(&st);
    const char *ampm = (st.wHour >= 13) ? "pm" : "am";
    uint16_t hour12 = (st.wHour >= 13) ? st.wHour - 12 : st.wHour;
    _sprintf(tmp, "%d/%d/%02d %d:%02d %s", st.wMonth, st.wDay, st.wYear, hour12, st.wMinute, ampm);
    _strncpy(out, tmp, outLen);
}
#endif // !PLATFORM_POSIX

void stdPlatform_InitServices(HostServices *handlers)
{
    handlers->statusPrint = stdPlatform_Printf;
    handlers->messagePrint = stdPlatform_Printf;
    handlers->warningPrint = stdPlatform_Printf;
    handlers->errorPrint = stdPlatform_Printf;
    handlers->some_float = 1000.0;
    handlers->debugPrint = 0;
#ifndef PLATFORM_POSIX
    handlers->assert = stdPlatform_Assert;
#endif
    handlers->unk_0 = 0;
#ifndef PLATFORM_POSIX
    handlers->alloc = daAlloc;
    handlers->free = daFree;
    handlers->realloc =  daRealloc;
    handlers->getTimerTick = stdPlatform_GetTimeMsec;
    handlers->fileOpen = stdFileOpen;
    handlers->fileClose = stdFileClose;
    handlers->fileRead = stdFileRead;
    handlers->fileGets = stdFileGets;
    handlers->fileWrite = stdFileWrite;
    handlers->fileEof = stdFeof;
    handlers->ftell = stdFtell;
    handlers->fseek = stdFseek;
    handlers->fileSize = stdFileSize;
    handlers->filePrintf = stdFilePrintf;
    handlers->fileGetws = stdFileGetws;
    handlers->allocHandle = stdPlatform_AllocHandle;
    handlers->freeHandle = stdPlatform_FreeHandle;
    handlers->reallocHandle = stdPlatform_ReallocHandle;
    handlers->lockHandle = stdPlatform_LockHandle;
    handlers->unlockHandle = stdPlatform_UnlockHandle;
#endif

#ifdef PLATFORM_POSIX
    handlers->alloc = Linux_alloc;
    handlers->free = Linux_free;
    handlers->realloc = Linux_realloc;
    handlers->fileOpen = Linux_stdFileOpen;
    handlers->fileClose = Linux_stdFileClose;
    handlers->fileRead = Linux_stdFileRead;
    handlers->fileGets = Linux_stdFileGets;
    handlers->fileWrite = Linux_stdFileWrite;
    handlers->fileGetws = Linux_stdFileGetws;
    handlers->fseek = Linux_stdFseek;
    handlers->ftell = Linux_stdFtell;
    handlers->getTimerTick = Linux_TimeMs;
    handlers->fileEof = Linux_stdFeof;
#endif

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
   handlers->suggestHeap = Dummy_suggestHeap;
#endif

#ifdef TARGET_TWL
    handlers->alloc = TWL_alloc;
    handlers->free = TWL_free;
    handlers->realloc = TWL_realloc;
    handlers->suggestHeap = TWL_suggestHeap;
#endif

#ifdef TARGET_DREAMCAST
    handlers->alloc = DC_alloc;
    handlers->free = DC_free;
    handlers->realloc = DC_realloc;
    handlers->suggestHeap = DC_suggestHeap;
#endif
}

int stdPlatform_Startup()
{
    return 1;
}

#ifdef PLATFORM_POSIX
int stdPrintf(int (*a1)(const char *, ...), const char *a2, int line, const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    printf("(%p %s:%d) ", a1, a2, line);
    int ret = vprintf(fmt, args);
    va_end (args);
    return ret;
}

#ifdef SDL2_RENDER
static SDL_mutex* stdPlatform_mtxPrintf = NULL;
#endif

int stdPlatform_Printf(const char *fmt, ...)
{
    char tmp[256];
    va_list args;

#ifdef SDL2_RENDER
    if (!stdPlatform_mtxPrintf)
        stdPlatform_mtxPrintf = SDL_CreateMutex();

    SDL_LockMutex(stdPlatform_mtxPrintf);
#endif
    
    va_start (args, fmt);
    int ret = vprintf(fmt, args);
    va_end (args);

#ifdef QUAKE_CONSOLE
    va_start (args, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, args);
    jkQuakeConsole_PrintLine(tmp);
    va_end(args);
#endif

#ifdef TARGET_ANDROID
    LOGI("%s", tmp);
#endif

#ifdef SDL2_RENDER
    SDL_UnlockMutex(stdPlatform_mtxPrintf);
#endif
    return ret;
}
#endif

#ifdef TARGET_TWL
void stdPlatform_PrintHeapStats()
{
    size_t waste = (trackingAllocsAReal - trackingAllocsA) + (trackingAllocsBReal - trackingAllocsB) + (trackingAllocsCReal - trackingAllocsC);
    stdPlatform_Printf("heap ext=0x%zx mn=0x%zx\nnw=0x%zx wst=0x%zx\nnum=%zd\n", trackingAllocsA, trackingAllocsB, trackingAllocsC, waste, activeAllocs);
}
#endif // TARGET_TWL

#ifdef TARGET_DREAMCAST
void stdPlatform_PrintHeapStats()
{
    // TODO
}
#endif // TARGET_DREAMCAST


// Added:
// memcpy/memset that never issue byte stores, for word-addressable-only
// destinations (Dreamcast VRAM, NDS slot-2 RAM -- their buses drop byte enables
// on writes; byte reads are fine). Exact length, any src/dst alignment: unaligned
// edges use 16-bit read-modify-write, bulk uses 32-bit stores (little-endian).
void stdPlatform_Memzero32(void* dst, uint32_t len)
{
    uint8_t* pDst = (uint8_t*)dst;
    if (len && ((uintptr_t)pDst & 1)) {
        stdPlatform_WriteByte16(pDst, 0);
        pDst++; len--;
    }
    if (len >= 2 && ((uintptr_t)pDst & 2)) {
        *(uint16_t*)pDst = 0;
        pDst += 2; len -= 2;
    }
    for (; len >= 4; len -= 4, pDst += 4)
        *(uint32_t*)pDst = 0;
    if (len >= 2) {
        *(uint16_t*)pDst = 0;
        pDst += 2; len -= 2;
    }
    if (len)
        stdPlatform_WriteByte16(pDst, 0);
}

void stdPlatform_Memset32(void* dst, uint8_t val, uint32_t len)
{
    uint8_t* pDst = (uint8_t*)dst;
    uint32_t pattern = val * 0x01010101u;
    if (len && ((uintptr_t)pDst & 1)) {
        stdPlatform_WriteByte16(pDst, val);
        pDst++; len--;
    }
    if (len >= 2 && ((uintptr_t)pDst & 2)) {
        *(uint16_t*)pDst = (uint16_t)pattern;
        pDst += 2; len -= 2;
    }
    for (; len >= 4; len -= 4, pDst += 4)
        *(uint32_t*)pDst = pattern;
    if (len >= 2) {
        *(uint16_t*)pDst = (uint16_t)pattern;
        pDst += 2; len -= 2;
    }
    if (len)
        stdPlatform_WriteByte16(pDst, val);
}

void stdPlatform_Memcpy32(void* dst, const void* src, uint32_t len)
{
    uint8_t* pDst = (uint8_t*)dst;
    const uint8_t* pSrc = (const uint8_t*)src;
    if (len && ((uintptr_t)pDst & 1)) {
        stdPlatform_WriteByte16(pDst, *pSrc);
        pDst++; pSrc++; len--;
    }
    if (len >= 2 && ((uintptr_t)pDst & 2)) {
        *(uint16_t*)pDst = (uint16_t)pSrc[0] | ((uint16_t)pSrc[1] << 8);
        pDst += 2; pSrc += 2; len -= 2;
    }
    if (!((uintptr_t)pSrc & 3)) {
        // Fast path: src co-aligned, straight 32-bit copies
        for (; len >= 4; len -= 4, pDst += 4, pSrc += 4)
            *(uint32_t*)pDst = *(const uint32_t*)pSrc;
    } else {
        // Src misaligned: assemble words from byte reads (always safe)
        for (; len >= 4; len -= 4, pDst += 4, pSrc += 4)
            *(uint32_t*)pDst = (uint32_t)pSrc[0] | ((uint32_t)pSrc[1] << 8) |
                               ((uint32_t)pSrc[2] << 16) | ((uint32_t)pSrc[3] << 24);
    }
    if (len >= 2) {
        *(uint16_t*)pDst = (uint16_t)pSrc[0] | ((uint16_t)pSrc[1] << 8);
        pDst += 2; pSrc += 2; len -= 2;
    }
    if (len)
        stdPlatform_WriteByte16(pDst, *pSrc);
}