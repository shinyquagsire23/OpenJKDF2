/* Compile with the production headers and complete source translation units.
 * Covers the desktop float VM stack and symbol lookup. No script parser, game
 * initialization, compressed stacks or overflow path is exercised here.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Cog/sithCogExec.h"
#include "Cog/sithCogFunction.h"
#include "Cog/sithCogParse.h"
#include "stdPlatform.h"

/* This verb is registered by sithCogFunction_Startup, but has no public header
 * declaration. Keep its real signature here, without copying its body. */
extern void sithCogFunction_VectorCross(sithCog *pCog);

#ifdef OPENJKDF2_FOCUSED_TEST
HostServices *pSithHS;
SithCogSymbolTable *sithCog_g_pSymbolTable;
#endif

static void assertion_failed(const char *expression, const char *file, int line)
{
    fprintf(stderr, "engine assertion: %s (%s:%d)\n", expression, file, line);
    exit(1);
}

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
        check(sithCogExec_PopSymbol(cog, &cog->pSymbolTable->aSymbols[symbol_id].val), "prepare symbol vector");
        SithCogSymbolValue ref = {0};
        ref.type = SITHCOG_VALUE_SYMBOLID;
        ref.data[0] = symbol_id;
        sithCogExec_PushStack(cog, &ref);
    }
}

int main(void)
{
    HostServices services = {0};
    services.assert = assertion_failed;
    pSithHS = &services;
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
            SithCogSymbol values[2] = {0};
            SithCogSymbolTable symbols = {0};
            symbols.aSymbols = values;
            symbols.numUsedSymbols = 2;
            symbols.tableSize = 2;
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
