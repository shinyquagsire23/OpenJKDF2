/* Asset-free storage tests. Production functions are included unchanged;
 * file lookup, WAV parsing, cache nodes and audio buffers are controlled stubs. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#include "file_type.inc"
#if INTPTR_MAX > INT32_MAX
_Static_assert(sizeof(stdFile_t) >= sizeof(intptr_t), "wide file handles must fit the production type");
static const stdFile_t fixture_file = (stdFile_t)UINT64_C(0x100000001);
#else
static const stdFile_t fixture_file = 1;
#endif
typedef struct stdSound_buffer_t { int playing; } stdSound_buffer_t;
#include "sound_type.inc"
typedef struct SithWorld {
    int numSoundsLoaded, numSounds, level_type_maybe;
    sithSound *sounds;
} SithWorld;
typedef struct Entry { const char *key; void *value; struct Entry *next; } Entry;
typedef struct tHashTable { Entry *buckets[1024]; } tHashTable;
static tHashTable table;
static tHashTable *sithSound_hashtable;
static SithWorld *sithWorld_g_pLastLoadedWorld, *sithWorld_g_pCurrentWorld, *sithWorld_g_pStaticWorld;
static int sithSound_bInit, Main_bMotsCompat, sithSound_var4, sithSound_var5;
static uint32_t sithSound_curDataLoaded, sithSound_maxDataLoaded;
static int fail_after = -1, fail_cache, live_allocations, open_files, pcm_live, pcm_released;
static void *allocate(size_t size) {
    if (!fail_after) return NULL;
    if (fail_after > 0) --fail_after;
    void *ptr = malloc(size); if (ptr) ++live_allocations; return ptr;
}
static void release(void *ptr) {
    if (ptr) { --live_allocations; assert(live_allocations >= 0); free(ptr); }
}
#define SITH_ALLOC allocate
#define SITH_FREE release
#define SITH_ASSERTREL assert
#define _memset memset
#define _strcmp strcmp
#define _atoi atoi
static unsigned bucket(const char *key) {
    unsigned n = 5381; while (*key) n = n * 33 + (unsigned char)*key++; return n % 1024;
}
static tHashTable *stdHashtbl_New(int count) { (void)count; memset(&table, 0, sizeof(table)); return &table; }
static void *stdHashtbl_Find(tHashTable *hash, const char *key) {
    if (!hash) return NULL;
    for (Entry *e = hash->buckets[bucket(key)]; e; e = e->next)
        if (!strcmp(e->key, key)) return e->value;
    return NULL;
}
static int stdHashtbl_Add(tHashTable *hash, const char *key, void *value) {
    if (fail_cache || !hash) return 0;
    assert(!stdHashtbl_Find(hash, key));
    Entry *e = malloc(sizeof(*e)); assert(e); unsigned b = bucket(key);
    e->key = key; e->value = value; e->next = hash->buckets[b]; hash->buckets[b] = e; return 1;
}
static int stdHashtbl_Remove(tHashTable *hash, const char *key) {
    if (!hash) return 0;
    Entry **link = &hash->buckets[bucket(key)];
    while (*link && strcmp((*link)->key, key)) link = &(*link)->next;
    if (!*link) return 0;
    Entry *old = *link; *link = old->next; free(old); return 1;
}
static void stdHashtbl_Free(tHashTable *hash) {
    for (unsigned i = 0; i < 1024; ++i)
        while (hash->buckets[i]) { Entry *old = hash->buckets[i]; hash->buckets[i] = old->next; free(old); }
}
static int stdSound_Startup(void) { return 1; }
static void stdSound_Shutdown(void) { }
static char *stdString_CopyBetweenDelimiter(char *text, char *out, int size, char *delim) {
    char *end = strchr(text, *delim); size_t n = end ? (size_t)(end - text) : strlen(text);
    assert(n < (size_t)size); memcpy(out, text, n); out[n] = 0; return end ? end + 1 : NULL;
}
static void stdString_SafeStrCopy(char *dst, const char *src, size_t size) {
    assert(strlen(src) < size); strcpy(dst, src);
}
static int stdString_snprintf(char *dst, size_t size, const char *format, ...) {
    va_list args; va_start(args, format); int result = vsnprintf(dst, size, format, args); va_end(args); return result;
}
static char opened_name[128];
static stdFile_t file_open(const char *path, const char *mode) {
    (void)mode; assert(!open_files);
    const char *name = strrchr(path, '\\'); assert(name); ++name;
    if (!strcmp(name, "missing.wav")) return 0;
    if (!strcmp(name, "voice.wav") && !strncmp(path, "sound", 5)) return 0;
    strcpy(opened_name, name); ++open_files; return fixture_file;
}
static int file_close(stdFile_t fd) { assert(fd == fixture_file && open_files == 1); --open_files; return 0; }
struct HostServices { stdFile_t (*fileOpen)(const char *, const char *); int (*fileClose)(stdFile_t); };
static struct HostServices host = {file_open, file_close};
static struct HostServices *pSithHS = &host;
static uint32_t stdSound_ParseWav(stdFile_t fd, uint32_t *rate, int32_t *bits, int32_t *stereo, int32_t *offset) {
    assert(fd == fixture_file && open_files == 1); *rate = 44100; *bits = 16; *stereo = 0; *offset = 44;
    return !strcmp(opened_name, "broken.wav") ? 0 : 400;
}
static int stdSound_IsPlaying(stdSound_buffer_t *buffer, int unused) { (void)unused; return buffer->playing; }
static void stdSound_BufferRelease(stdSound_buffer_t *buffer) {
    assert(buffer && pcm_live); --pcm_live; ++pcm_released; release(buffer);
}
static int sithSound_LoadFileData(sithSound *sound) {
    assert(!(sound->isLoaded & 1)); sound->dsoundBuffer2 = allocate(sizeof(*sound->dsoundBuffer2));
    assert(sound->dsoundBuffer2); sound->dsoundBuffer2->playing = 0; sound->isLoaded |= 1;
    sithSound_curDataLoaded += sound->bufferBytes; ++pcm_live; return 1;
}
static void sithWorld_UpdateLoadProgress(double value) { (void)value; }
static struct { struct { char *value; } aArgs[3]; unsigned numArgs; } stdConffile_g_entry;
static char *declaration;
static int read_row;
static int stdConffile_ReadArgs(void) {
    stdConffile_g_entry.numArgs = 3;
    stdConffile_g_entry.aArgs[0].value = read_row++ ? "end" : "world";
    stdConffile_g_entry.aArgs[1].value = "sounds";
    stdConffile_g_entry.aArgs[2].value = declaration;
    return 1;
}
#include "sound_api.inc"
#include "sound_production.inc"
static int sithWorld_bInitted;
static void sithWorld_FreeEntry(SithWorld *world) { sithSound_FreeWorldSounds(world); release(world); }
#include "sound_shutdown.inc"
typedef double flex64_t;
enum { SITHCOG_VALUE_INT = 1, SITHCOG_VALUE_FLOAT = 2 };
typedef struct SithCogSymbolValue { int type; union { int32_t data[4]; float dataAsFloat[4]; }; } SithCogSymbolValue;
typedef struct sithCog { SithCogSymbolValue value; int valid; } sithCog;
static int sithCogExec_PopSymbol(sithCog *cog, SithCogSymbolValue *value) { *value = cog->value; return cog->valid; }
#include "sound_cog.inc"
static size_t sound_memory(SithWorld *pWorld) {
    int aCount[7] = {0}; size_t aMemUsed[7] = {0};
#include "sound_memory.inc"
    assert(aCount[6] == pWorld->numSoundsLoaded); return aMemUsed[6];
}

static sithSound *load(unsigned idx, char prefix) {
    char name[32]; snprintf(name, sizeof(name), "%c%05u.wav", prefix, idx); return sithSound_Load(name, 0);
}
static void set_world(SithWorld *world) { sithWorld_g_pCurrentWorld = sithWorld_g_pLastLoadedWorld = world; }
static void clean(SithWorld *world) {
    sithSound_FreeWorldSounds(world); sithSound_FreeWorldSounds(world);
    assert(!world->sounds && !world->numSounds && !world->numSoundsLoaded);
    assert(!open_files);
}
#ifdef NO_JK_MMAP
static void test_failure_transactions(void) {
    SithWorld world = {0}; set_world(&world);
    assert(!sithSound_New(NULL, 1)); assert(!sithSound_New(&world, -1));
    assert(!sithSound_New(&world, INT_MAX)); assert(!sithSound_New(&world, SITHSOUND_MAX_RECORDS + 1));
    fail_after = 0; assert(!sithSound_New(&world, 1)); assert(!world.sounds && !world.numSounds);
    assert(!load(0, 'f')); assert(!world.sounds && !open_files);
    fail_after = -1; assert(sithSound_New(&world, 1));
    sithSound *first = load(0, 'f'); assert(first); const char *key = first->sound_fname;
    assert(!sithSound_New(&world, 2));
    int allocs = live_allocations;
    fail_after = 0; assert(!load(1, 'f')); fail_after = -1;
    assert(world.numSoundsLoaded == 1 && world.numSounds == 1 && live_allocations == allocs && !open_files);
    fail_cache = 1; assert(!load(1, 'f')); fail_cache = 0;
    assert(world.numSoundsLoaded == 1 && world.numSounds == 1 && live_allocations == allocs && !open_files);
    assert(!sithSound_Load("broken.wav", 0)); assert(!sithSound_Load("missing.wav", 0));
    assert(world.numSoundsLoaded == 1 && world.numSounds == 1 && live_allocations == allocs && !open_files);
    assert(load(1, 'f')); assert(world.numSoundsLoaded == 2);
    int capacity = world.numSounds; allocs = live_allocations;
    fail_cache = 1; assert(!load(2, 'f')); fail_cache = 0;
    assert(world.numSoundsLoaded == 2 && world.numSounds == capacity && live_allocations == allocs);
    assert(!sithSound_Load("broken.wav", 0)); assert(!world.sounds[0].isLoaded);
    assert(load(2, 'f')); assert(sithSound_Load("voice.wav", 0));
    assert(key == first->sound_fname && stdHashtbl_Find(sithSound_hashtable, key) == first);
    clean(&world); assert(!live_allocations && !sithSound_pages);
    sithWorld_g_pLastLoadedWorld = NULL; assert(!load(0, 'z')); assert(!open_files);
}
static void test_growth_and_eviction(void) {
    SithWorld world = {0}; set_world(&world); assert(sithSound_New(&world, 1));
    sithSound *first = load(0, 'g'); assert(first); sithSound *class_reference = first;
    sithSound *mixer_reference = first, *ambient_reference = first;
    for (unsigned i = 1; i < 770; ++i) assert(load(i, 'g'));
    assert(world.sounds == first && world.numSoundsLoaded == 770 && world.numSounds >= 770);
    int cap = world.numSounds, allocs = live_allocations;
    for (unsigned i = 0; i < 770; ++i) {
        sithSound *sound = load(i, 'g'); assert(sound == sithSound_GetWorldSoundByIndex(&world, i));
        assert(sound == sithSound_GetFromIdx(i) && sound->id == (int)i);
    }
    assert(world.numSounds == cap && live_allocations == allocs);
    assert(sound_memory(&world) == 770 * (400 + sizeof(sithSound)));
    sithCog cog = {.value = {.type = SITHCOG_VALUE_INT, .data = {769}}, .valid = 1};
    assert(sithCogExec_PopSound(&cog) == load(769, 'g'));
    cog.value.data[0] = 0; Main_bMotsCompat = 1; assert(!sithCogExec_PopSound(&cog));
    cog.value.type = SITHCOG_VALUE_FLOAT; cog.value.dataAsFloat[0] = 0.0f; assert(sithCogExec_PopSound(&cog) == first);
    Main_bMotsCompat = 0; cog.valid = 0; assert(!sithCogExec_PopSound(&cog));
    assert(class_reference == first && mixer_reference == first && ambient_reference == first);
    assert(!sithSound_GetWorldSoundByIndex(NULL, 0)); assert(!sithSound_GetWorldSoundByIndex(&world, -1));
    assert(!sithSound_GetWorldSoundByIndex(&world, 770)); assert(!sithSound_GetFromIdx(65536));
    assert(!sithSound_GetFromIdx(-1));
    sithSound *overflow = sithSound_GetWorldSoundByIndex(&world, 769);
    sithSound *protected_overflow = sithSound_GetWorldSoundByIndex(&world, 768);
    sithSound_LoadFileData(first); sithSound_LoadFileData(overflow); sithSound_LoadFileData(protected_overflow);
    protected_overflow->field_40 = 1;
    assert(sithSound_Load(first->sound_fname, 1) == first);
    first->dsoundBuffer2->playing = 1; overflow->infoLoaded = 1;
    sithSound_var4 = sithSound_var5 = 0; int released = pcm_released;
    assert(sithSound_FreeUpMemory(400) == 400);
    assert(pcm_released == released + 1 && (first->isLoaded & 1) && !(overflow->isLoaded & 1));
    assert((protected_overflow->isLoaded & 1) && !protected_overflow->dsoundBuffer2->playing);
    assert(overflow == load(769, 'g') && overflow->id == 769 && !overflow->dsoundBuffer2);
    assert(sithSound_curDataLoaded == 800); clean(&world);
    assert(!live_allocations && !pcm_live && !sithSound_curDataLoaded && !sithSound_pages);
}
static void test_declarations_and_zero(void) {
    char *bad[] = {"-1", "32768", "2147483648", "99999999999999999999999", "1x", ""};
    SithWorld world = {0}; set_world(&world);
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        declaration = bad[i]; read_row = 0; assert(!sithSound_ReadSoundsListText(&world, 0)); assert(!world.sounds);
    }
    declaration = "1"; read_row = 0; fail_after = 0;
    assert(!sithSound_ReadSoundsListText(&world, 0)); assert(!world.sounds); fail_after = -1;
    declaration = "0"; read_row = 0; assert(sithSound_ReadSoundsListText(&world, 0)); assert(!world.sounds);
    assert(!sithSound_Load("broken.wav", 0));
    assert(world.sounds && world.numSounds == 1 && !world.numSoundsLoaded && !open_files);
    clean(&world);
    fail_cache = 1; assert(!load(0, 'e')); fail_cache = 0;
    assert(world.sounds && world.numSounds == 1 && !world.numSoundsLoaded && !open_files);
    assert(!stdHashtbl_Find(sithSound_hashtable, "e00000.wav")); clean(&world);
    assert(load(0, 'e') && load(1, 'e')); clean(&world);
    Main_bMotsCompat = 1; assert(!sithSound_New(&world, SITHSOUND_MAX_RECORDS));
    assert(sithSound_New(&world, SITHSOUND_MAX_RECORDS - 1));
    assert(world.numSounds == SITHSOUND_MAX_RECORDS); clean(&world);
    assert(sithSound_New(&world, 0)); assert(world.numSounds == 1); clean(&world); Main_bMotsCompat = 0;
}
static void test_static_current_and_ceiling(void) {
    SithWorld current = {0}, statik = {0}; statik.level_type_maybe = 1;
    sithWorld_g_pStaticWorld = &statik; set_world(&statik); assert(sithSound_New(&statik, 1));
    for (unsigned i = 0; i < SITHSOUND_MAX_RECORDS; ++i) assert(load(i, 's'));
    assert(statik.numSounds == SITHSOUND_MAX_RECORDS && statik.numSoundsLoaded == SITHSOUND_MAX_RECORDS);
    sithSound *last = sithSound_GetWorldSoundByIndex(&statik, SITHSOUND_MAX_RECORDS - 1);
    assert(last->id == 0xfffe && sithSound_GetFromIdx(0xfffe) == last);
    sithCog cog = {.value = {.type = SITHCOG_VALUE_INT, .data = {0xfffe}}, .valid = 1};
    assert(sithCogExec_PopSound(&cog) == last); cog.value.data[0] = -1; assert(!sithCogExec_PopSound(&cog));
    assert(!sithSound_GetFromIdx(0xffff) && !sithSound_GetFromIdx(-1));
    // Preserve and characterize the pre-existing signed-wire behavior separately.
    assert(!sithSound_GetFromIdx((int16_t)0x8001));
    assert(!sithSound_GetFromIdx(0x18001)); assert(!load(SITHSOUND_MAX_RECORDS, 's'));
    set_world(&current); assert(sithSound_New(&current, 1));
    int before = current.numSoundsLoaded; assert(load(0, 's') == statik.sounds);
    assert(current.numSoundsLoaded == before);
    for (unsigned i = 0; i < SITHSOUND_MAX_RECORDS; ++i) assert(load(i, 'c'));
    assert(current.numSounds == SITHSOUND_MAX_RECORDS && current.numSoundsLoaded == SITHSOUND_MAX_RECORDS);
    assert(sithSound_GetFromIdx(32766)->id == 32766); assert(!sithSound_GetFromIdx(32767));
    assert(!load(SITHSOUND_MAX_RECORDS, 'c'));
    clean(&current); assert(load(0, 's') == statik.sounds);
    clean(&statik); sithWorld_g_pStaticWorld = NULL; assert(!sithSound_pages && !live_allocations);
    set_world(&current); assert(load(0, 'c') && load(1, 'c')); clean(&current);
}
static void test_shutdown_order(void) {
    SithWorld *current = allocate(sizeof(*current)), *statik = allocate(sizeof(*statik));
    assert(current && statik); memset(current, 0, sizeof(*current)); memset(statik, 0, sizeof(*statik));
    statik->level_type_maybe = 1; sithWorld_g_pStaticWorld = statik;
    set_world(statik); assert(load(0, 't') && load(1, 't'));
    set_world(current); assert(load(0, 'u') && load(1, 'u'));
    assert(sithSound_Shutdown()); assert(!sithSound_hashtable);
    sithWorld_Shutdown(); assert(!sithSound_pages && !live_allocations);
    assert(!sithWorld_g_pCurrentWorld && !sithWorld_g_pStaticWorld && !sithWorld_g_pLastLoadedWorld);
}
#else
static void test_legacy_fixed_storage(void) {
    SithWorld world = {0}; set_world(&world); assert(sithSound_New(&world, 1));
    sithSound *first = load(0, 'l'); assert(first == world.sounds);
    assert(!load(1, 'l')); assert(world.numSounds == 1 && world.numSoundsLoaded == 1);
    assert(first == sithSound_GetFromIdx(0) && load(0, 'l') == first);
    clean(&world); assert(!live_allocations); assert(sithSound_Shutdown());
}
#endif
int main(void) {
    assert(sithSound_Startup());
#ifdef NO_JK_MMAP
    test_failure_transactions(); test_growth_and_eviction(); test_declarations_and_zero();
    test_static_current_and_ceiling(); test_shutdown_order();
#else
    test_legacy_fixed_storage();
#endif
    assert(!open_files && !live_allocations && !pcm_live);
    puts("sound storage invariants passed"); return 0;
}
