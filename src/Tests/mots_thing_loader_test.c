/* Actual placed-thing loader, reset/template-copy, position assignment and
 * argument tokenizer with original synthetic text. The thingflags case is an
 * exact production block; unrelated parameter dispatch, resource/network calls,
 * line IO, world postprocessing and rotation math are explicit fixture stubs.
 * Minimal world/thing records do not assert the full engine ABI. Both conditional
 * struct layouts are compiled, including a JK build without an ARCH field.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "actual_constants.inc"
#include "actual_thing_types.inc"

/* The minimal fixture represents a free thing by the production enum's zero. */
enum { SITH_THING_FREE = 0 };

#define _atoi atoi
#define _atof atof
#define _strcmp strcmp
#define _strtok strtok
#define _strchr strchr
#define _sscanf sscanf
#define _memcpy memcpy
#define SITH_ASSERTREL assert
#define TWL_EXTRAM_SUGGEST(x) ((void)0)
#define TWL_EXTRAM_RESTORE(x) ((void)0)
#define SITH_ALLOC(n) calloc(1, (n)) /* Deterministic initial object bytes. */
#define SITH_FREE free
#define stdPlatform_Memzero32(p,n) memset((p), 0, (n))
#define stdPlatform_Memcpy32 memcpy
#define rdVector_Copy3(d,s) (*(d) = *(s))
#define rdMatrix_Copy34(d,s) (*(d) = *(s))
#define rdVector_Zero3(v) memset((v), 0, sizeof(*(v)))

typedef float flex_t;
typedef struct { flex_t x,y,z; } rdVector3;
typedef struct { rdVector3 rvec,lvec,uvec,scale; } rdMatrix34;
typedef struct SithThing SithThing;
typedef struct { int id; } SithSector;
typedef struct { int unused; } SithPathFrame;
typedef struct {
    int type;
    void *model3, *particlecloud;
    SithThing* pThing;
} rdThing;
struct SithThing {
    int32_t idx, guid, signature, type, moveType;
    uint32_t flags;
    rdThing renderData;
    rdVector3 position;
    rdMatrix34 orient;
    SithThing* pTemplate;
    void* pPuppetClass;
    struct { int sizeFrames; SithPathFrame* aFrames; } trackParams;
    SithSector* sector;
#ifdef JKM_LIGHTING
    int32_t archlightIdx;
#endif
};
typedef struct {
    SithThing* aThings;
    int numThingsLoaded, numThings, numSectors;
    SithSector* aSectors;
} SithWorld;

static unsigned checks;
static void check(int ok, const char* expr, int line) {
    ++checks;
    if (!ok) {
        fprintf(stderr, "FAIL thing-loader line %d: %s\n", line, expr);
        exit(1);
    }
}
#define CHECK(x) check(!!(x), #x, __LINE__)

static SithWorld world;
static SithWorld* sithWorld_g_pCurrentWorld = &world;
static rdMatrix34 rdroid_identMatrix34 = {{1,0,0}, {0,1,0}, {0,0,1}, {0,0,0}};
static SithThing baseTemplate, childTemplate, freeTemplate;
static int sithThing_bInitted2, sithNet_isMulti, sithNet_isServer;
static int sithNet_things[32], sithNet_thingsIdx, jkPlayer_setDiff, g_submodeFlags;
static int initializations, frees, overrides, parameters, postprocesses;
static int sector_entries, diagnostic_count;
static char diagnostics[2][160];

static int jk_printf(const char* format, ...) {
    CHECK(diagnostic_count < (int)(sizeof(diagnostics) / sizeof(diagnostics[0])));
    va_list args;
    va_start(args, format);
    int length = vsnprintf(diagnostics[diagnostic_count], sizeof(diagnostics[0]), format, args);
    va_end(args);
    CHECK(length >= 0 && (size_t)length < sizeof(diagnostics[0]));
    ++diagnostic_count;
    return length;
}

static int rdThing_NewEntry(rdThing* data, SithThing* thing) {
    data->pThing = thing;
    return 1;
}
static void rdThing_SetModel3(rdThing* data, void* model) { data->model3 = model; }
static void rdThing_SetParticleCloud(rdThing* data, void* particles) { data->particlecloud = particles; }
static void rdPuppet_New(rdThing* data) { (void)data; }
static void sithThing_FreeThingIndex(int index) { (void)index; }
static void sithMulti_RemoveStaticThing(int guid) { (void)guid; }
static void sithThing_FreeThing(SithThing* thing) { ++frees; thing->type = 0; }
static void sithThing_Initialize(SithThing* thing) { ++initializations; (void)thing; }
static void sithThing_LoadPostProcess(void) { ++postprocesses; }
static void sithThing_EnterSector(SithThing* thing, SithSector* sector, int a, int b) {
    (void)a; (void)b; thing->sector = sector; ++sector_entries;
}
static void rdMatrix_BuildRotate34(rdMatrix34* out, const rdVector3* angles) {
    *out = rdroid_identMatrix34;
    out->rvec = *angles; /* An observable marker, not production trigonometry. */
}
static SithThing* sithTemplate_GetTemplate(const char* name) {
    if (!strcmp(name, "base")) return &baseTemplate;
    if (!strcmp(name, "child")) return &childTemplate;
    if (!strcmp(name, "free")) return &freeTemplate;
    return NULL;
}

enum { THINGPARAM_THINGFLAGS = 0 };
static int sithThing_ParseArg(StdConffileArg* arg, SithThing* pThing) {
    int result = 0;
    uint32_t thingFlags;
    ++parameters;
    if (strcmp(arg->key, "thingflags")) return 0;
    ++overrides;
    switch (THINGPARAM_THINGFLAGS) {
#include "actual_thing_flags.inc"
    }
    return result;
LABEL_59:
    return 0;
}

static const char* const* inputLines;
static unsigned inputPosition;
static char lineBuffer[512];
static char* stdConffile_g_aLine = lineBuffer;
static StdConffileEntry stdConffile_g_entry;
static int stdConffile_ReadLine(void) {
    const char* line = inputLines[inputPosition];
    if (!line) return 0;
    ++inputPosition;
    CHECK(strlen(line) < sizeof(lineBuffer));
    strcpy(lineBuffer, line);
    return 1;
}
#include "actual_thing_args.inc"
#include "actual_thing_helpers.inc"
#ifdef OLD_THING_LOADER
#include "old_thing_loader.inc"
#else
#include "actual_thing_loader.inc"
#endif

static const char* const placedThings[] = {
    "world things 10",
    "0: base positive 1 2 3 10 20 30 0 7 thingflags=48",
    "1: base zero 4 5 6 0 0 0 0 0",
    "2: base negative 0 0 0 0 0 0 0 -1",
    "3: base othernegative 0 0 0 0 0 0 0 -2",
    "4: base absent 0 0 0 0 0 0 0",
    "5: base jkoverride 0 0 0 0 0 0 0 thingflags=40",
    "6: base zerooverride 0 0 0 0 0 0 0 0 thingflags=40",
    "7: child inherited 0 0 0 0 0 0 0 0",
    "8: base invalidsector 0 0 0 0 0 0 -1 6 thingflags=40",
    "9: child emptyparameter 0 0 0 0 0 0 0 thingflags=",
    "end",
    NULL
};

static void run_placement(int skip) {
    inputLines = placedThings;
    inputPosition = 0;
    initializations = parameters = overrides = frees = 0;
    sector_entries = diagnostic_count = 0;
    CHECK(sithThing_ReadStaticThingsListText(&world, skip) == 1);
    CHECK(world.numThingsLoaded == 10);
    CHECK(initializations == 9);
    CHECK(sector_entries == 9);
    CHECK(diagnostic_count == 0);
    CHECK(parameters == 10);
    CHECK(overrides == 4);
    CHECK(frees == (skip ? 9 : 0));
    CHECK(world.aThings[0].flags == 0x48);
    CHECK(world.aThings[1].flags == 0x8);
    CHECK(world.aThings[4].flags == 0x8);
    CHECK(world.aThings[5].flags == 0x40);
    CHECK(world.aThings[6].flags == 0x40);
    CHECK(world.aThings[7].flags == 0x48);
    CHECK(world.aThings[8].type == 0);
    CHECK(world.aThings[9].flags == 0x48); /* Failed override keeps inheritance. */
    CHECK(world.aThings[0].position.x == 1);
    CHECK(world.aThings[0].position.y == 2);
    CHECK(world.aThings[0].position.z == 3);
    CHECK(world.aThings[0].orient.rvec.x == 10);
    CHECK(world.aThings[0].orient.rvec.y == 20);
    CHECK(world.aThings[0].orient.rvec.z == 30);
    CHECK(world.aThings[0].orient.scale.x == 0);
    for (int i = 0; i < 10; ++i) {
        SithThing* thing = &world.aThings[i];
        CHECK(thing->idx == i);
        CHECK(thing->renderData.pThing == thing);
        if (i == 8) continue;
        CHECK(thing->guid == i);
        CHECK(thing->sector == world.aSectors);
        CHECK(thing->pTemplate == ((i == 7 || i == 9) ? &childTemplate : &baseTemplate));
    }
#ifdef JKM_LIGHTING
    CHECK(world.aThings[0].archlightIdx == 7);
    CHECK(world.aThings[1].archlightIdx == 0);
    CHECK(world.aThings[2].archlightIdx == -1);
    CHECK(world.aThings[3].archlightIdx == -2);
    CHECK(world.aThings[4].archlightIdx == -1);
    CHECK(world.aThings[5].archlightIdx == -1);
    CHECK(world.aThings[6].archlightIdx == 0);
    CHECK(world.aThings[7].archlightIdx == 0);
    CHECK(world.aThings[8].archlightIdx == -1);
    CHECK(world.aThings[9].archlightIdx == -1);
    CHECK(baseTemplate.archlightIdx == -1);
    CHECK(childTemplate.archlightIdx == -1);
#endif
    CHECK(baseTemplate.flags == 0x8);
    CHECK(childTemplate.flags == 0x48);
}

static const char* const invalidTemplateThings[] = {
    "world things 3",
    "0: missing absenttemplate 1 2 3 0 0 0 0 7 thingflags=48",
    "1: free invalidtemplate 4 5 6 0 0 0 0 9 thingflags=48",
    "2: base validafterinvalid 9 8 7 0 0 0 0 3 thingflags=48",
    "end",
    NULL
};

static void run_invalid_templates(int skip) {
    inputLines = invalidTemplateThings;
    inputPosition = 0;
    initializations = parameters = overrides = frees = 0;
    sector_entries = diagnostic_count = 0;
    CHECK(sithThing_ReadStaticThingsListText(&world, skip) == 1);
    CHECK(world.numThingsLoaded == 3);
    CHECK(initializations == 1);
    CHECK(sector_entries == 1);
    CHECK(parameters == 2);
    CHECK(overrides == 1);
    CHECK(frees == (skip ? 1 : 0));
    CHECK(sithThing_bInitted2 == 2);
    CHECK(diagnostic_count == 2);
    CHECK(strstr(diagnostics[0], "static thing 0:") != NULL);
    CHECK(strstr(diagnostics[0], "'missing'") != NULL);
    CHECK(strstr(diagnostics[1], "static thing 1:") != NULL);
    CHECK(strstr(diagnostics[1], "'free'") != NULL);
    for (int i = 0; i < 2; ++i) {
        SithThing* thing = &world.aThings[i];
        CHECK(thing->idx == i);
        CHECK(thing->type == SITH_THING_FREE);
        CHECK(thing->guid == -1);
        CHECK(thing->signature == 0);
        CHECK(thing->flags == 0);
        CHECK(thing->sector == NULL);
        CHECK(thing->pTemplate == NULL);
        CHECK(thing->renderData.pThing == thing);
        CHECK(thing->position.x == 0 && thing->position.y == 0 && thing->position.z == 0);
#ifdef JKM_LIGHTING
        CHECK(thing->archlightIdx == -1);
#endif
    }
    SithThing* valid = &world.aThings[2];
    CHECK(valid->idx == 2 && valid->guid == 2);
    CHECK(valid->type == baseTemplate.type);
    CHECK(valid->sector == world.aSectors);
    CHECK(valid->pTemplate == &baseTemplate);
    CHECK(valid->flags == 0x48);
    CHECK(valid->position.x == 9 && valid->position.y == 8 && valid->position.z == 7);
#ifdef JKM_LIGHTING
    CHECK(valid->archlightIdx == 3);
    CHECK(baseTemplate.archlightIdx == -1);
    CHECK(freeTemplate.archlightIdx == -1);
#endif
    CHECK(baseTemplate.flags == 0x8);
    CHECK(freeTemplate.type == SITH_THING_FREE);
    CHECK(freeTemplate.flags == 0x8);
}

int main(void) {
    SithSector sector = {0};
    world.aSectors = &sector;
    world.numSectors = 1;
    world.numThings = -1;
    CHECK(sithThing_Reset(&baseTemplate) == 1);
    baseTemplate.type = 1;
    baseTemplate.flags = 0x8;
    baseTemplate.renderData.type = RD_THING_MODEL3;
    CHECK(sithThing_Reset(&childTemplate) == 1);
    sithThing_SetThingBasedOn(&childTemplate, &baseTemplate);
    StdConffileArg override = {"thingflags", "48"};
    CHECK(sithThing_ParseArg(&override, &childTemplate) == 1);
    CHECK(childTemplate.flags == 0x48);
    run_placement(0);
    run_placement(1);
    CHECK(postprocesses == 2);
    SITH_FREE(world.aThings);
    world.aThings = NULL;
    CHECK(sithThing_Reset(&freeTemplate) == 1);
    freeTemplate.type = SITH_THING_FREE;
    freeTemplate.flags = 0x8;
    run_invalid_templates(0);
    run_invalid_templates(1);
    CHECK(postprocesses == 4);
    SITH_FREE(world.aThings);
    world.aThings = NULL;
#ifdef JKM_LIGHTING
    printf("PASS actual placed-thing loader JKM_LIGHTING: %u checks\n", checks);
#else
    printf("PASS actual placed-thing loader without JKM_LIGHTING: %u checks\n", checks);
#endif
    return 0;
}
