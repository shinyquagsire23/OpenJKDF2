/* Bounded, asset-free tests of extracted production stack operations.
 * The fixture uses eight slots and valid integer symbols. Its copy observer
 * checks the complete request before forwarding to the production word copy.
 * No old implementation, COG bytecode, or malformed input is executed.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SITHCOGVM_MAX_STACKSIZE 8
#define COG_DYNAMIC_STACKS_INCREMENT 4
#include "stack_types.inc"

static unsigned checks, shifts, growCopies;
static sithCog* pActiveCog;

#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "FAIL cog stack line %d: %s\n", __LINE__, #condition); \
    exit(1); } } while (0)
#define SITH_ASSERTREL(condition) CHECK(condition)

_Static_assert(sizeof(((sithCog*)0)->stack[0]) == sizeof(SithCogSymbolValue),
               "stack storage must contain complete symbol values");
_Static_assert(sizeof(SithCogSymbolValue) % sizeof(uint32_t) == 0,
               "symbol rows must remain word aligned");
_Static_assert((SITHCOGVM_MAX_STACKSIZE - 1) * sizeof(SithCogSymbolValue) <= UINT32_MAX,
               "the word-copy byte count must be representable");

#include "word_copy.inc"

#ifdef COG_DYNAMIC_STACKS
static int bFailAllocation;
static unsigned allocations, frees;
static size_t lastAllocationBytes;
#ifdef TARGET_TWL
static void* pLastAllocation;
static void* testAllocate(size_t bytes)
{
    ++allocations;
    lastAllocationBytes = bytes;
    CHECK(bytes <= (SITHCOGVM_MAX_STACKSIZE + COG_DYNAMIC_STACKS_INCREMENT) * sizeof(SithCogSymbolValue));
    pLastAllocation = bFailAllocation ? NULL : malloc(bytes);
    if (!bFailAllocation) CHECK(pLastAllocation != NULL);
    return pLastAllocation;
}
#define SITH_ALLOC(bytes) testAllocate(bytes)
#define TWL_EXTRAM_SUGGEST(unused) ((void)0)
#define TWL_EXTRAM_RESTORE(unused) ((void)0)
#else
static void* testReallocate(void* pOld, size_t bytes)
{
    ++allocations;
    lastAllocationBytes = bytes;
    CHECK(bytes <= (SITHCOGVM_MAX_STACKSIZE + COG_DYNAMIC_STACKS_INCREMENT) * sizeof(SithCogSymbolValue));
    if (bFailAllocation) return NULL;
    void* pNew = realloc(pOld, bytes);
    CHECK(pNew != NULL);
    return pNew;
}
#define SITH_REALLOC(p, bytes) testReallocate(p, bytes)
#endif
static void testFree(void* pOld)
{
    if (pOld) ++frees;
    free(pOld);
}
#define SITH_FREE(p) testFree(p)
void sithCogExec_GrowStack(sithCog* pCtx, uint32_t sz);
#endif

static void stdPlatform_Memcpy32(void* pDst, const void* pSrc, uint32_t bytes)
{
    CHECK(pActiveCog != NULL);
    if (pDst == pActiveCog->stack && pSrc == &pActiveCog->stack[1]) {
        CHECK(pActiveCog->stackPos == SITHCOGVM_MAX_STACKSIZE);
#ifdef COG_DYNAMIC_STACKS
        CHECK(pActiveCog->stackSize >= SITHCOGVM_MAX_STACKSIZE);
#endif
        CHECK(bytes == (SITHCOGVM_MAX_STACKSIZE - 1) * sizeof(SithCogSymbolValue));
        ++shifts;
    }
#ifdef TARGET_TWL
    else {
        CHECK(pDst == pLastAllocation && pSrc == pActiveCog->stack);
        CHECK(bytes == pActiveCog->stackSize * sizeof(SithCogSymbolValue));
        CHECK(bytes <= lastAllocationBytes);
        ++growCopies;
    }
#else
    else CHECK(0);
#endif
    /* Only a checked, bounded request reaches the actual word-copy routine. */
    testWordCopy(pDst, pSrc, bytes);
}

#include "stack_operations.inc"

static SithCogSymbolValue makeValue(unsigned id)
{
    SithCogSymbolValue value;
    memset(&value, 0, sizeof(value));
    value.type = SITHCOG_VALUE_INT;
    for (size_t i = 0; i < sizeof(value.dataAsPtrs) / sizeof(value.dataAsPtrs[0]); ++i)
        value.dataAsPtrs[i] = (intptr_t)(100 + id * 4 + i);
    return value;
}

static void checkValue(const SithCogSymbolValue* pValue, unsigned id)
{
    SithCogSymbolValue expected = makeValue(id);
    CHECK(pValue->type == expected.type);
    for (size_t i = 0; i < sizeof(expected.dataAsPtrs) / sizeof(expected.dataAsPtrs[0]); ++i)
        CHECK(pValue->dataAsPtrs[i] == expected.dataAsPtrs[i]);
}

static void push(sithCog* pCog, unsigned id)
{
    SithCogSymbolValue value = makeValue(id);
    sithCogExec_PushStack(pCog, &value);
    checkValue(&value, id);
}

static void testPushPop(void)
{
    sithCog cog = {0};
    SithCogSymbolValue out = makeValue(99);
    pActiveCog = &cog;
    CHECK(sithCogExec_PopStack(&cog, &out) == 0);
    checkValue(&out, 99);
    for (unsigned i = 0; i < 3; ++i) push(&cog, i);
    CHECK(cog.stackPos == 3);
    for (unsigned i = 3; i > 0; --i) {
        CHECK(sithCogExec_PopStack(&cog, &out) == 1);
        checkValue(&out, i - 1);
    }
    CHECK(cog.stackPos == 0 && shifts == 0);
    sithCogExec_ResetStack(&cog);
}

static void testRetainedOrder(void)
{
    sithCog cog = {0};
    pActiveCog = &cog;
    for (unsigned i = 0; i < SITHCOGVM_MAX_STACKSIZE; ++i) push(&cog, i);
    for (unsigned i = 0; i < SITHCOGVM_MAX_STACKSIZE; ++i) checkValue(&cog.stack[i], i);
    for (unsigned next = SITHCOGVM_MAX_STACKSIZE; next < SITHCOGVM_MAX_STACKSIZE + 2; ++next) {
        push(&cog, next);
        CHECK(cog.stackPos == SITHCOGVM_MAX_STACKSIZE);
        for (unsigned i = 0; i < SITHCOGVM_MAX_STACKSIZE; ++i)
            checkValue(&cog.stack[i], next - SITHCOGVM_MAX_STACKSIZE + 1 + i);
    }
    CHECK(shifts == 2);
    sithCogExec_ResetStack(&cog);
    CHECK(cog.stackPos == 0);
#ifdef COG_DYNAMIC_STACKS
    CHECK(cog.stack == NULL && cog.stackSize == 0);
#endif
}

#ifdef COG_DYNAMIC_STACKS
static void testAllocationFailure(void)
{
    sithCog cog = {0};
    pActiveCog = &cog;
    bFailAllocation = 1;
    push(&cog, 0);
    CHECK(cog.stack == NULL && cog.stackSize == 0 && cog.stackPos == 0);
    bFailAllocation = 0;
    for (unsigned i = 0; i < SITHCOGVM_MAX_STACKSIZE; ++i) push(&cog, i);
    SithCogSymbolValue* pOld = cog.stack;
    const unsigned oldAllocations = allocations, oldFrees = frees, oldShifts = shifts;
    sithCogExec_GrowStack(&cog, cog.stackSize);
    CHECK(allocations == oldAllocations);
    bFailAllocation = 1;
    push(&cog, SITHCOGVM_MAX_STACKSIZE);
    CHECK(allocations == oldAllocations + 1 && frees == oldFrees && shifts == oldShifts);
    CHECK(cog.stack == pOld && cog.stackSize == SITHCOGVM_MAX_STACKSIZE);
    CHECK(cog.stackPos == SITHCOGVM_MAX_STACKSIZE);
    CHECK(lastAllocationBytes == (SITHCOGVM_MAX_STACKSIZE + COG_DYNAMIC_STACKS_INCREMENT) * sizeof(*cog.stack));
    for (unsigned i = 0; i < SITHCOGVM_MAX_STACKSIZE; ++i) checkValue(&cog.stack[i], i);
    bFailAllocation = 0;
    push(&cog, SITHCOGVM_MAX_STACKSIZE);
    CHECK(cog.stackSize == SITHCOGVM_MAX_STACKSIZE + COG_DYNAMIC_STACKS_INCREMENT);
    CHECK(cog.stackPos == SITHCOGVM_MAX_STACKSIZE && shifts == oldShifts + 1);
    for (unsigned i = 0; i < SITHCOGVM_MAX_STACKSIZE; ++i) checkValue(&cog.stack[i], i + 1);
    sithCogExec_ResetStack(&cog);
    CHECK(cog.stack == NULL && cog.stackSize == 0 && cog.stackPos == 0);
}
#endif

int main(void)
{
    testPushPop();
    testRetainedOrder();
#ifdef COG_DYNAMIC_STACKS
    testAllocationFailure();
#endif
#ifdef TARGET_TWL
    CHECK(growCopies > 0);
#else
    CHECK(growCopies == 0);
#endif
    printf("PASS COG stack: %u checks, symbol bytes %zu, stack field bytes %zu, shifts %u, growth copies %u\n",
           checks, sizeof(SithCogSymbolValue), sizeof(((sithCog*)0)->stack), shifts, growCopies);
    return 0;
}
