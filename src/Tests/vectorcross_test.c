/*
 * The runner extracts complete production VectorCross, rdVector_Cross3,
 * PopSymbol/PopVector and PushStack/PushVector functions into the includes.
 * This exercises real vector stack conversion and return placement, rather
 * than a hand-written cross or a mock that supplies preordered operands.
 * Surrounding structs and symbol lookup are deliberately minimal test doubles.
 * Desktop float, uncompressed fixed-stack behavior is tested. Parsing, complete
 * game ABI, compressed/dynamic stacks, and stack overflow are outside scope.
 */
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SITH_ASSERTREL assert
#define _memset memset
#define SITHCOGVM_MAX_STACKSIZE 64
typedef float flex_t;
typedef float cog_flex_t;
typedef struct { flex_t x, y, z; } rdVector3;
typedef struct {
    uint32_t type;
    union { int32_t data[3]; cog_flex_t dataAsFloat[3]; intptr_t dataAsPtrs[3]; };
} SithCogSymbolValue;
typedef struct { SithCogSymbolValue val; } SithCogSymbol;
typedef struct { SithCogSymbol symbols[2]; } SithCogSymbolTable;
typedef struct {
    SithCogSymbolTable *pSymbolTable;
    SithCogSymbolValue stack[SITHCOGVM_MAX_STACKSIZE];
    uint32_t stackPos;
} sithCog;

static SithCogSymbol *sithCogParse_GetSymbolByID(SithCogSymbolTable *table, int32_t id)
{
    return table && id >= 0 && id < 2 ? &table->symbols[id] : NULL;
}

static void stdPlatform_Memcpy32(void *dst, const void *src, size_t size)
{
    (void)dst; (void)src; (void)size;
    fprintf(stderr, "FAIL unexpected stack overflow path\n");
    exit(1);
}

#include "production.inc"
#include "wrapper.inc"

static unsigned assertions;
static const char *case_name;
static const char *binding_name;

static void check(int condition, const char *what)
{
    ++assertions;
    if (!condition) {
        fprintf(stderr, "FAIL %s [%s]: %s\n", case_name, binding_name, what);
        exit(1);
    }
}

static void check_vector(rdVector3 actual, rdVector3 expected, const char *prefix)
{
    char message[128];
    const float a[] = {actual.x, actual.y, actual.z};
    const float e[] = {expected.x, expected.y, expected.z};
    const char component[] = "xyz";
    for (unsigned i = 0; i < 3; ++i) {
        snprintf(message, sizeof(message), "%s.%c expected %.9g, got %.9g", prefix, component[i], e[i], a[i]);
        check(isfinite(a[i]) && fabsf(a[i] - e[i]) <= 0.000001f, message);
    }
}

static void push_argument(sithCog *cog, const rdVector3 *v, int symbol_id, int use_symbol)
{
    sithCogExec_PushVector(cog, v);
    if (use_symbol) {
        check(sithCogExec_PopSymbol(cog, &cog->pSymbolTable->symbols[symbol_id].val), "prepare symbol vector");
        SithCogSymbolValue ref = {0};
        ref.type = SITHCOG_VALUE_SYMBOLID;
        ref.data[0] = symbol_id;
        sithCogExec_PushStack(cog, &ref);
    }
}

int main(void)
{
    static const struct { const char *name; rdVector3 a, b, expected; } cases[] = {
        {"x-cross-y", {1,0,0}, {0,1,0}, {0,0,1}},
        {"y-cross-x", {0,1,0}, {1,0,0}, {0,0,-1}},
        {"y-cross-z", {0,1,0}, {0,0,1}, {1,0,0}},
        {"z-cross-x", {0,0,1}, {1,0,0}, {0,1,0}},
        {"nontrivial-integers", {1,2,3}, {4,-5,6}, {27,6,-13}},
        {"nontrivial-fractions", {.5f,-1.25f,2}, {-3,4,.25f}, {-8.3125f,-6.125f,-1.75f}},
        {"negative-and-zero", {-2,0,5}, {7,3,-1}, {-15,33,-6}},
        {"parallel", {1,-2,3}, {2,-4,6}, {0,0,0}},
        {"zero-left", {0,0,0}, {2,-4,6}, {0,0,0}},
        {"zero-right", {2,-4,6}, {0,0,0}, {0,0,0}},
    };
    static const char *bindings[] = {"literal/literal", "symbol/literal", "literal/symbol", "symbol/symbol"};
    const rdVector3 sentinel = {17.25f, -31.5f, 8.125f};
    unsigned runs = 0;
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        for (unsigned mode = 0; mode < 4; ++mode) {
            SithCogSymbolTable symbols = {0};
            sithCog cog = {0};
            rdVector3 result;
            cog.pSymbolTable = &symbols;
            case_name = cases[i].name;
            binding_name = bindings[mode];
            sithCogExec_PushVector(&cog, &sentinel);
            /* A then B is the source argument order; the VM stack is LIFO. */
            push_argument(&cog, &cases[i].a, 0, mode & 1);
            push_argument(&cog, &cases[i].b, 1, mode & 2);
            check(cog.stackPos == 3, "two arguments above sentinel");
            sithCogFunction_VectorCross(&cog);
            check(cog.stackPos == 2, "consume two arguments and return one value");
            check(cog.stack[1].type == SITHCOG_VALUE_VECTOR, "returned value is a vector");
            check(sithCogExec_PopVector(&cog, &result), "pop returned vector");
            check_vector(result, cases[i].expected, "result");
            check(sithCogExec_PopVector(&cog, &result), "pop underlying sentinel");
            check_vector(result, sentinel, "sentinel");
            check(cog.stackPos == 0, "no leaked stack values");
            ++runs;
        }
    }
    printf("PASS VectorCross: %u cases/bindings, %u assertions; actual wrapper/math/stack helpers\n", runs, assertions);
    return 0;
}
