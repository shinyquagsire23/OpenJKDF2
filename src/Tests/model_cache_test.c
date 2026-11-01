/* Asset-free storage test; model parsing is stubbed, storage code is extracted
 * unchanged from production. This does not certify malformed 3DO parsing. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef struct rdModel3 { char filename[32]; int id; void *geometry; } rdModel3;
typedef struct SithWorld {
    uint32_t numModels, sizeModels;
    rdModel3 *aModels;
    void *sounds; /* Opaque counterpart: only its shutdown ownership is modeled. */
    int level_type_maybe;
} SithWorld;
typedef struct Entry { const char *key; void *value; struct Entry *next; } Entry;
typedef struct tHashTable { Entry *buckets[1024]; } tHashTable;
static tHashTable table;
static SithWorld *sithWorld_g_pLastLoadedWorld, *sithWorld_g_pCurrentWorld, *sithWorld_g_pStaticWorld;
static int fail_after = -1, fail_cache, live_allocations;
static SithWorld *counterpart_world;
static unsigned counterpart_frees;
static void *allocate(size_t size) {
    if (fail_after == 0) return NULL;
    if (fail_after > 0) --fail_after;
    void *ptr = malloc(size);
    if (ptr) ++live_allocations;
    return ptr;
}
static void release(void *ptr) {
    assert(!counterpart_world || ptr != counterpart_world || !counterpart_world->sounds);
    if (ptr) { --live_allocations; assert(live_allocations >= 0); free(ptr); } }
#define SITH_ALLOC allocate
#define SITH_FREE release
#define SITH_ASSERTREL assert
#define _memset memset
#define _memcmp memcmp
#define _strlen strlen
#define _sprintf sprintf
typedef double flex_t;
typedef double flex_d_t;
static unsigned bucket(const char *key) { unsigned n = 5381; while (*key) n = n * 33 + (unsigned char)*key++; return n % 1024; }
static tHashTable *stdHashtbl_New(int size) { (void)size; memset(&table, 0, sizeof(table)); return &table; }
static void *stdHashtbl_Find(tHashTable *hash, const char *key) {
    if (!hash) return NULL;
    for (Entry *e = hash->buckets[bucket(key)]; e; e = e->next)
        if (!strcmp(e->key, key)) return e->value;
    return NULL;
}
static int stdHashtbl_Add(tHashTable *hash, const char *key, void *value) {
    if (fail_cache) return 0;
    assert(!stdHashtbl_Find(hash, key));
    Entry *e = malloc(sizeof(*e)); assert(e);
    unsigned b = bucket(key);
    e->key = key; e->value = value; e->next = hash->buckets[b]; hash->buckets[b] = e;
    return 1;
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
        while (hash->buckets[i]) { Entry *e = hash->buckets[i]; hash->buckets[i] = e->next; free(e); }
}
static int rdModel3_LoadEntry(char *path, rdModel3 *model) {
    memset(model, 0, sizeof(*model));
    const char *name = strrchr(path, '\\'); assert(name); ++name;
    if (!strcmp(name, "missing.3do")) return 0;
    assert(strlen(name) < sizeof(model->filename)); strcpy(model->filename, name);
    model->geometry = allocate(16);
    return model->geometry != NULL;
}
static void rdModel3_FreeEntryGeometryOnly(rdModel3 *model) { release(model->geometry); model->geometry = NULL; }
static int stdPlatform_Printf(const char *format, ...) { (void)format; return 0; }
static void sithWorld_UpdateLoadProgress(double value) { (void)value; }
static struct { struct { const char *value; } aArgs[3]; } stdConffile_g_entry;
static int stdConffile_linenum, read_row;
static const char *declared_count;
static int stdConffile_ReadArgs(void) {
    stdConffile_g_entry.aArgs[0].value = read_row++ ? "end" : "world";
    stdConffile_g_entry.aArgs[1].value = "models";
    stdConffile_g_entry.aArgs[2].value = declared_count;
    return 1;
}
static struct { void *errorPrint; } host;
static void *pSithHS_unused;
#define pSithHS (&host)
static void stdPrintf(void *target, const char *file, int line, const char *format, ...) {
    (void)target; (void)file; (void)line; (void)format;
}

#include "model_api.inc"
#include "model_production.inc"
static int sithWorld_bInitted;
static void sithWorld_FreeEntry(SithWorld *world) {
    sithModel_FreeWorldModels(world);
    release(world);
    sithWorld_g_pCurrentWorld = NULL;
}
/* External linkage avoids unused-static warnings on the independent topic. */
void sithSound_FreeWorldSounds(SithWorld *world) {
    assert(world == counterpart_world && world->sounds && !counterpart_frees);
    release(world->sounds); world->sounds = NULL; ++counterpart_frees;
}
#include "model_shutdown.inc"

static rdModel3 *load(unsigned index, char prefix) {
    char name[32]; snprintf(name, sizeof(name), "%c%05u.3do", prefix, index);
    return sithModel_Load(name, 1);
}
#ifdef NO_JK_MMAP
static void test_failures(void) {
    SithWorld world = {0};
    assert(!sithModel_AllocWorldModels(&world, -1));
    assert(!sithModel_AllocWorldModels(&world, 32769));
    for (int fail = 0; fail < 2; ++fail) {
        fail_after = fail;
        assert(!sithModel_AllocWorldModels(&world, 1));
        assert(!world.aModels && !world.sizeModels && !world.numModels && !live_allocations);
    }
    fail_after = -1;
    assert(sithModel_AllocWorldModels(&world, 1));
    sithWorld_g_pLastLoadedWorld = sithWorld_g_pCurrentWorld = &world;
    rdModel3 *first = load(0, 'f'); assert(first);
    const char *key = first->filename; int before = live_allocations;
    for (int fail = 0; fail < 2; ++fail) {
        fail_after = fail; assert(!load(1, 'f'));
        assert(world.numModels == 1 && world.sizeModels == 1 && live_allocations == before);
        assert(first->filename == key && stdHashtbl_Find(sithModel_hashtable, key) == first);
    }
    fail_after = -1; fail_cache = 1; assert(!load(1, 'f')); fail_cache = 0;
    assert(world.numModels == 1 && world.sizeModels == 1 && live_allocations == before);
    assert(!sithModel_Load("missing.3do", 1));
    assert(world.numModels == 1 && world.sizeModels == 1 && live_allocations == before);
    assert(load(1, 'f'));
    assert(sithModel_GetModelByIndex(0) == first && first->filename == key);
    sithModel_FreeWorldModels(&world); assert(!live_allocations && !sithModel_stores);
    const char *bad[] = {"-1", "32769", "nonsense", "1junk", "99999999999999999999999999999"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        declared_count = bad[i]; read_row = 0;
        assert(!sithModel_ReadStaticModelsListText(&world, 0));
        assert(!world.aModels && !world.sizeModels);
    }
}
static void test_growth(void) {
    SithWorld current = {0}, shared = {0}; shared.level_type_maybe = 1;
    assert(sithModel_AllocWorldModels(&shared, 1));
    assert(sithModel_AllocWorldModels(&current, 1));
    sithWorld_g_pCurrentWorld = &current; sithWorld_g_pStaticWorld = &shared;
    sithWorld_g_pLastLoadedWorld = &shared;
    rdModel3 *static_first = load(0, 's'); assert(static_first && static_first->id == 0x8000);
    sithWorld_g_pLastLoadedWorld = &current;
    rdModel3 *saved[1024]; const char *keys[1024];
    for (unsigned i = 0; i < 1024; ++i) {
        saved[i] = load(i, 'm'); assert(saved[i] && saved[i]->id == (int)i); keys[i] = saved[i]->filename;
    }
    unsigned capacity = current.sizeModels; int allocated = live_allocations;
    for (unsigned i = 1024; i-- > 0;) {
        assert(load(i, 'm') == saved[i]);
        assert(sithModel_GetWorldModelByIndex(&current, i) == saved[i]);
        assert(sithModel_GetModelByIndex(i) == saved[i]);
        assert(saved[i]->filename == keys[i]);
    }
    assert(load(0, 's') == static_first && sithModel_GetModelByIndex(0x8000) == static_first);
    assert(current.numModels == 1024 && current.sizeModels == capacity && live_allocations == allocated);
    assert(!sithModel_GetModelByIndex(-1) && !sithModel_GetModelByIndex(-32768));
    assert(!sithModel_GetModelByIndex(0x10000) && !sithModel_GetModelByIndex(0x18000));
    assert(!sithModel_GetWorldModelByIndex(&current, 1024));
    sithModel_FreeWorldModels(&current);
    assert(sithModel_GetModelByIndex(0x8000) == static_first && load(0, 's') == static_first);
    sithModel_FreeWorldModels(&shared); assert(!live_allocations && !sithModel_stores);
}
static void test_limit(void) {
    SithWorld world = {0}; sithWorld_g_pCurrentWorld = sithWorld_g_pStaticWorld = sithWorld_g_pLastLoadedWorld = &world;
    assert(sithModel_AllocWorldModels(&world, 0));
    for (unsigned i = 0; i < SITHMODEL_MAX_MODELS; ++i) assert(load(i, 'b'));
    assert(world.sizeModels == SITHMODEL_MAX_MODELS && world.numModels == SITHMODEL_MAX_MODELS);
    rdModel3 *last = sithModel_GetModelByIndex(0x7fff); assert(last && last->id == 0x7fff);
    assert(!load(SITHMODEL_MAX_MODELS, 'b'));
    assert(!sithModel_GetModelByIndex(-1) && !sithModel_GetModelByIndex(0x17fff));
    assert(sithModel_GetModelByIndex(0xffff) == last);
    sithModel_FreeWorldModels(&world); assert(!live_allocations && !sithModel_stores);
    world.level_type_maybe = 1; assert(sithModel_AllocWorldModels(&world, 32768));
    for (unsigned i = 0; i < SITHMODEL_MAX_MODELS; ++i) assert(load(i, 't'));
    assert(sithModel_GetModelByIndex(0xffff)->id == 0xffff);
    assert(!sithModel_GetModelByIndex(-1));
    /* Hash shutdown precedes world destruction on the production shutdown path. */
    sithModel_Shutdown(); sithModel_FreeWorldModels(&world); assert(!live_allocations && !sithModel_stores);
}
static void test_shutdown_fallback(void) {
    assert(sithModel_Startup());
    SithWorld *world = allocate(sizeof(*world)), *shared = allocate(sizeof(*shared));
    assert(world && shared); memset(world, 0, sizeof(*world)); memset(shared, 0, sizeof(*shared));
    shared->level_type_maybe = 1;
    sithWorld_g_pCurrentWorld = sithWorld_g_pLastLoadedWorld = world;
    sithWorld_g_pStaticWorld = shared;
    assert(sithModel_AllocWorldModels(world, 1) && sithModel_AllocWorldModels(shared, 1));
    for (unsigned i = 0; i < 65; ++i) assert(load(i, 'q'));
    sithWorld_g_pLastLoadedWorld = shared;
    for (unsigned i = 0; i < 34; ++i) assert(load(i, 'r'));
#ifdef TEST_COMPOSED_SHUTDOWN
    counterpart_world = world; world->sounds = allocate(1); assert(world->sounds);
#endif
    sithModel_Shutdown(); sithWorld_Shutdown();
#ifdef TEST_COMPOSED_SHUTDOWN
    assert(counterpart_frees == 1);
#endif
    assert(!live_allocations && !sithModel_stores);
    assert(!sithWorld_g_pCurrentWorld && !sithWorld_g_pStaticWorld && !sithWorld_g_pLastLoadedWorld);
}
int main(void) {
    (void)pSithHS_unused;
    assert(sithModel_Startup()); test_failures();
    for (int i = 0; i < 20; ++i) test_growth();
    test_limit();
    test_shutdown_fallback();
    puts("PASS stable pages, borrowed cache keys, allocation/cache failure rollback, repeated growth/free, static/current IDs, 32768 limit");
    return 0;
}
#else
int main(void) {
    (void)pSithHS_unused;
    SithWorld world = {0};
    assert(sithModel_Startup());
    assert(sithModel_AllocWorldModels(&world, 1));
    sithWorld_g_pCurrentWorld = sithWorld_g_pLastLoadedWorld = &world;
    rdModel3 *first = load(0, 'l'); assert(first == &world.aModels[0]);
    assert(!load(1, 'l') && world.sizeModels == 1 && world.numModels == 1);
    assert(sithModel_GetModelByIndex(0) == first);
    sithModel_FreeWorldModels(&world); sithModel_Shutdown(); assert(!live_allocations);
    puts("PASS injected-executable mode retains fixed contiguous model layout");
    return 0;
}
#endif
