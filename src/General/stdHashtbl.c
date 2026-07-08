#include "stdHashtbl.h"

#include "jk.h"

#include "stdPlatform.h"
#include "General/stdLinkList.h"
#include "General/stdSingleLinklist.h"
#include <math.h>
#include <stdlib.h>

#ifdef STDHASHTABLE_NODE_POOL
// Added: slab-pooled link aCurKfNodeEntryNums (see engine_config.h). Nodes are recycled via a
// freelist threaded through ->next; slabs are never returned (population is
// steady-state across level loads). All node writes are word-width.
#define STDHASHTABLE_POOL_CHUNK_NODES 340 // ~4KB slabs
typedef struct stdHashPoolChunk { struct stdHashPoolChunk* pNext; } stdHashPoolChunk;
static stdHashPoolChunk* stdHashtbl_pPoolChunks = NULL;
static tHashLink* stdHashtbl_pFreeNodes = NULL;

static tHashLink* stdHashtbl_NodeAlloc(void)
{
    if (!stdHashtbl_pFreeNodes)
    {
        stdHashPoolChunk* pChunk;
        { TWL_EXTRAM_SUGGEST(std_g_pHS);
        pChunk = (stdHashPoolChunk*)STD_ALLOC(sizeof(stdHashPoolChunk) + sizeof(tHashLink) * STDHASHTABLE_POOL_CHUNK_NODES);
        TWL_EXTRAM_RESTORE(std_g_pHS); }
        if (!pChunk)
            return NULL;
        pChunk->pNext = stdHashtbl_pPoolChunks;
        stdHashtbl_pPoolChunks = pChunk;
        tHashLink* aNodes = (tHashLink*)(pChunk + 1);
        for (int i = 0; i < STDHASHTABLE_POOL_CHUNK_NODES; i++)
        {
            aNodes[i].next = stdHashtbl_pFreeNodes;
            stdHashtbl_pFreeNodes = &aNodes[i];
        }
    }
    tHashLink* pNode = stdHashtbl_pFreeNodes;
    stdHashtbl_pFreeNodes = pNode->next;
    return pNode;
}

static void stdHashtbl_NodeFree(tHashLink* pNode)
{
    pNode->next = stdHashtbl_pFreeNodes;
    stdHashtbl_pFreeNodes = pNode;
}
#define STDHASHTABLE_NODE_FREE(p) stdHashtbl_NodeFree(p)
#else
#define STDHASHTABLE_NODE_FREE(p) STD_FREE(p)
#endif

#define hashmapBucketSizes_MAX (32)

int hashmapBucketSizes[hashmapBucketSizes_MAX] = 
{
    23,
    53,
    79,
    101,
    151,
    211,
    251,
    307,
    353,
    401,
    457,
    503,
    557,
    601,
    653,
    701,
    751,
    809,
    853,
    907,
    953,
    1009,
    1103,
    1201,
    1301,
    1409,
    1511,
    1601,
    1709,
    1801,
    1901,
    1999
};

uint32_t stdHashtbl_HashStringToIdx(const char *data, uint32_t numNodes)
{
    uint32_t hash;
    uint8_t i;
    
    if (!data || !data[0]) return 0; // Added

#ifdef STDHASHTABLE_CRC32_KEYS
    // TODO: check performance on this
    hash = stdCrc32(data, strlen(data));
#else
    hash = 0;
    for ( i = *data; i; ++data )
    {
        hash = (65599 * hash) + i;
        i = (uint8_t)data[1];
    }
#endif
    return hash % numNodes;
}

tHashTable* stdHashtbl_New(int size)
{
    tHashTable *pHashtbl;
    int sizeIterIdx;
    signed int calcedPrime;
    int *sizeIter;
    int actualNumBuckets = 1999;
    signed int v7;

    pHashtbl = (tHashTable *)STD_ALLOC(sizeof(tHashTable));
    if (!pHashtbl)
        return NULL;

    // Added: memset
    _memset(pHashtbl, 0, sizeof(*pHashtbl));

    // Basically every usage of stdHashtbl_New assumes maxEntries is
    // exactly what it says, the maximum anticipated number of entries.
    //
    // But this constructor seems to interpret that as maxBuckets, which
    // means everything is an O(1) lookup but also that the linked lists
    // never actually get uh, linked. lol
    //
    // So this just log2's the argument to make tHashTable smaller in RAM
    // and O(log2(n)) lookups
#ifdef STDHASHTABLE_LOG2_BUCKETS
    size = (int)log2(size) / 2;
#endif

    sizeIterIdx = 0;
    calcedPrime = size;
    sizeIter = hashmapBucketSizes;
    pHashtbl->numNodes = 0;
    pHashtbl->aSymbols = 0;
    pHashtbl->pfHashFunc = 0;
    while ( size >= *sizeIter )
    {
        ++sizeIter;
        ++sizeIterIdx;
        if ( sizeIter >= &hashmapBucketSizes[hashmapBucketSizes_MAX] )
        {
            actualNumBuckets = size;
            sizeIterIdx = hashmapBucketSizes_MAX-1;
            break;
        }
    }
    actualNumBuckets = hashmapBucketSizes[sizeIterIdx];

    // Calculate a prime number?
    if ( size > 1999 )
    {
        while ( 1 )
        {
            v7 = 2;
            if ( calcedPrime - 1 <= 2 )
            break;
            while ( calcedPrime % v7 )
            {
                if ( ++v7 >= calcedPrime - 1 )
                    goto loop_escape;
            }
            ++calcedPrime;
        }
loop_escape:
        actualNumBuckets = calcedPrime;
    }

    pHashtbl->numNodes = actualNumBuckets;
    { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: CRC-keyed links are word-safe
    pHashtbl->aSymbols = (tHashLink *)STD_ALLOC(sizeof(tHashLink) * actualNumBuckets);
    TWL_EXTRAM_RESTORE(std_g_pHS); }
    if ( pHashtbl->aSymbols )
    {
      stdPlatform_Memzero32(pHashtbl->aSymbols, sizeof(tHashLink) * pHashtbl->numNodes); // Added: word-safe
      pHashtbl->pfHashFunc = stdHashtbl_HashStringToIdx;
    }
    else {
        // Added: fail more gracefully and without memleaks
        STD_FREE(pHashtbl);
        return NULL;
    }
    return pHashtbl;
}

tHashLink* stdHashtbl_GetTailNode(tHashLink *pCur)
{
#ifdef STDHASHTABLE_SINGLE_LINKLIST
    return stdSingleLinklist_GetTail(pCur);
#else
    return stdLinklist_GetLastNode(pCur);
#endif
}

void stdHashtbl_FreeListNodes(tHashLink *pNode)
{
    tHashLink *iter;
    
    // Added: nullptr check
    if (!pNode) return;

    iter = pNode->next;
    while ( iter )
    {
        // TODO verify possible regression, prevent double free?
        tHashLink* next_iter = iter->next;
        iter->next = NULL; // added

        //printf("Free from %p: %p\n", a1, iter);
        STDHASHTABLE_NODE_FREE(iter); // Added
        
        iter = next_iter;
    }
}

void stdHashtbl_Free(tHashTable *pTable)
{
    int bucketIdx;
    int bucketIdx2;
    tHashLink *iter;
    tHashLink *iter_child;
    
    // Added: nullptr check
    if (!pTable) return;

    bucketIdx = 0;
    if ( pTable->numNodes > 0 )
    {
        bucketIdx2 = 0;
        do
        {
            stdHashtbl_FreeListNodes(&pTable->aSymbols[bucketIdx2]);
            pTable->aSymbols[bucketIdx2].next = NULL; // added
            ++bucketIdx;
            ++bucketIdx2;
        }
        while ( bucketIdx < pTable->numNodes );
    }
    STD_FREE(pTable->aSymbols);
    pTable->aSymbols = NULL; // added
    
    STD_FREE(pTable);
}

int stdHashtbl_Add(tHashTable *pTable, const char *pName, void *pData)
{
    tHashLink *new_child; // eax
    tHashLink *v9; // ecx
    tHashLink *v10; // esi

    // ADDED
    if (!pTable || !pName)
        return 0;

    if (stdHashtbl_Find(pTable, pName)) {
#ifndef SITH_DEBUG_STRUCT_NAMES
        stdHashtbl_Remove(pTable, pName);
#else
        return 0;
#endif
    }

    v9 = &pTable->aSymbols[pTable->pfHashFunc(pName, pTable->numNodes)];
    v10 = stdHashtbl_GetTailNode(v9);

    if ( v10->key )
    {
#ifdef STDHASHTABLE_NODE_POOL
        new_child = stdHashtbl_NodeAlloc(); // Added: slab pool
#else
        tHashLink *new_child_alloc; // Added: see below
        { TWL_EXTRAM_SUGGEST(std_g_pHS);
        new_child_alloc = (tHashLink *)STD_ALLOC(sizeof(tHashLink));
        TWL_EXTRAM_RESTORE(std_g_pHS); }
        new_child = new_child_alloc;
#endif
        if (!new_child)
            return 0;
        //printf("Alloc to %p: %p %s\n", v9, new_child, key);

        stdPlatform_Memzero32(new_child, sizeof(*new_child)); // Added: word-safe
#ifdef STDHASHTABLE_CRC32_KEYS
        new_child->keyCrc32 = stdCrc32(pName, strlen(pName));
#else
        new_child->key = pName;
#endif
        new_child->value = pData;
#ifdef STDHASHTABLE_SINGLE_LINKLIST
        stdSingleLinklist_InsertAfter(v10, new_child);
#else
        stdLinkList_AddNode(v10, new_child);
#endif
    }
    else
    {
        stdPlatform_Memzero32(v9, sizeof(*v9)); // Added: word-safe
#ifdef STDHASHTABLE_CRC32_KEYS
        v9->keyCrc32 = stdCrc32(pName, strlen(pName));
#else
        v9->key = pName;
#endif
        v9->value = pData;

        //printf("Bin to %p: %p %s\n", v9, new_child, key);
    }
    return 1;
}

void* stdHashtbl_Find(tHashTable *pTable, const char *pName)
{
    tHashLink *i;
    tHashLink *foundKey;

    if (!pTable || !pName) // Added: key nullptr check
        return NULL;

#ifdef STDHASHTABLE_CRC32_KEYS
    uint32_t keyCrc32 = stdCrc32(pName, strlen(pName));
#endif

    foundKey = 0;
    for ( i = &pTable->aSymbols[pTable->pfHashFunc(pName, pTable->numNodes)]; i; i = i->next )
    {
#ifdef STDHASHTABLE_CRC32_KEYS
        if (!i->keyCrc32) {
            foundKey = 0;
            break;
        }
        if (i->keyCrc32 == keyCrc32) {
            foundKey = i;
            break;
        }
#else
        const char* key_iter = (const char *)i->key;
        if ( !key_iter )
        {
            foundKey = 0;
            break;
        }
        if ( !_strcmp(key_iter, pName) )
        {
            foundKey = i;
            break;
        }
#endif
    }

    if (foundKey) {
        return foundKey->value;
    }

    return 0;
}

int stdHashtbl_Remove(tHashTable *pTable, const char *pName)
{
    int v2;
    tHashLink *foundKey;
    tHashLink *i;
    tHashLink *bucketTopKey;

    if (!pTable || !pName) // Added: key nullptr
        return 0;

#ifdef STDHASHTABLE_CRC32_KEYS
    uint32_t keyCrc32 = stdCrc32(pName, strlen(pName));
#endif

    tHashLink* beforeFoundKey = NULL; // added
    foundKey = 0;
    v2 = pTable->pfHashFunc(pName, pTable->numNodes);
    for ( i = &pTable->aSymbols[v2]; i; i = i->next )
    {
#ifdef STDHASHTABLE_CRC32_KEYS
        if (!i->keyCrc32) {
            break;
        }
        if (i->keyCrc32 == keyCrc32)
        {
            foundKey = i;
            break;
        }
#else
        const char* key_iter = i->key;
        if ( !key_iter )
            break;
        if ( !_strcmp(key_iter, pName) )
        {
            foundKey = i;
            break;
        }
#endif
        beforeFoundKey = i;
    }

    if ( !foundKey )
        return 0;

    //stdLinkList_RemoveNode(foundKey); // Added: Moved to prevent freeing issues
    bucketTopKey = &pTable->aSymbols[v2];
    if ( bucketTopKey == foundKey )
    {
        tHashLink* pNext = foundKey->next;
        if ( pNext )
        {
#ifdef STDHASHTABLE_CRC32_KEYS
            bucketTopKey->keyCrc32 = pNext->keyCrc32;
#else
            bucketTopKey->key = pNext->key;
#endif
            bucketTopKey->value = pNext->value;

#ifdef STDHASHTABLE_SINGLE_LINKLIST
            stdSingleLinklist_InsertReplace(pNext, bucketTopKey);
#else
            stdLinklist_InsertReplace(pNext, bucketTopKey);
#endif
            STDHASHTABLE_NODE_FREE(pNext); // Added
        }
        else
        {
#ifndef STDHASHTABLE_SINGLE_LINKLIST
            bucketTopKey->prev = NULL;
#endif
            bucketTopKey->next = NULL;
#ifdef STDHASHTABLE_CRC32_KEYS
            bucketTopKey->keyCrc32 = 0;
#else
            bucketTopKey->key = NULL;
#endif
            bucketTopKey->value = 0;
        }
    }
    else
    {
#ifdef STDHASHTABLE_SINGLE_LINKLIST
        stdSingleLinklist_UnlinkChild(foundKey, beforeFoundKey); // Added: Moved to prevent freeing issues
#else
        stdLinkList_RemoveNode(foundKey); // Added: Moved to prevent freeing issues
#endif
        STDHASHTABLE_NODE_FREE(foundKey); // Added
    }
    return 1;
}

#ifdef STDHASHTABLE_CRC32_KEYS
int stdHashtbl_FreeKeyCrc32(tHashTable *pHashtbl, uint32_t keyCrc32)
{
    int v2;
    tHashLink *foundKey;
    tHashLink *i;
    tHashLink *bucketTopKey;

    if (!pHashtbl)
        return 0;

    tHashLink* beforeFoundKey = NULL; // added
    foundKey = 0;
    //v2 = pHashtbl->pfHashFunc(key, pHashtbl->numNodes);
    v2 = keyCrc32 % pHashtbl->numNodes;
    for ( i = &pHashtbl->aSymbols[v2]; i; i = i->next )
    {
        if (!i->keyCrc32) {
            break;
        }
        if (i->keyCrc32 == keyCrc32)
        {
            foundKey = i;
            break;
        }
        beforeFoundKey = i;
    }

    if ( !foundKey )
        return 0;

    //stdLinkList_RemoveNode(foundKey); // Added: Moved to prevent freeing issues
    bucketTopKey = &pHashtbl->aSymbols[v2];
    if ( bucketTopKey == foundKey )
    {
        tHashLink* pNext = foundKey->next;
        if ( pNext )
        {
            bucketTopKey->keyCrc32 = pNext->keyCrc32;
            bucketTopKey->value = pNext->value;

#ifdef STDHASHTABLE_SINGLE_LINKLIST
            stdSingleLinklist_InsertReplace(pNext, bucketTopKey);
#else
            stdLinklist_InsertReplace(pNext, bucketTopKey);
#endif
            STDHASHTABLE_NODE_FREE(pNext); // Added
        }
        else
        {
#ifndef STDHASHTABLE_SINGLE_LINKLIST
            bucketTopKey->prev = NULL;
#endif
            bucketTopKey->next = NULL;
            bucketTopKey->keyCrc32 = 0;
            bucketTopKey->value = 0;
        }
    }
    else
    {
#ifdef STDHASHTABLE_SINGLE_LINKLIST
        stdSingleLinklist_UnlinkChild(foundKey, beforeFoundKey); // Added: Moved to prevent freeing issues
#else
        stdLinkList_RemoveNode(foundKey); // Added: Moved to prevent freeing issues
#endif
        STDHASHTABLE_NODE_FREE(foundKey); // Added
    }
    return 1;
}
#endif

void stdHashtbl_PrintTableDiagnostics(tHashTable *pTable)
{
    int maxLookups; // edi
    int bucketIdx2; // ebp
    int bucketIdx; // ebx
    int numChildren; // eax
    signed int numFilled; // [esp+14h] [ebp-Ch]
    signed int totalChildren; // [esp+18h] [ebp-8h]

    std_g_pHS->debugPrint("HASHTABLE Diagnostics\n");
    std_g_pHS->debugPrint("---------------------\n");
    maxLookups = 0;
    bucketIdx2 = 0;
    numFilled = 0;
    totalChildren = 0;
    if ( pTable->numNodes > 0 )
    {
        bucketIdx = 0;
        do
        {
            if ( pTable->aSymbols[bucketIdx].key )
            {
                ++numFilled;
#ifdef STDHASHTABLE_SINGLE_LINKLIST
                numChildren = stdSingleLinklist_NumChildren(&pTable->aSymbols[bucketIdx]);
#else
                numChildren = stdLinklist_GetCount(&pTable->aSymbols[bucketIdx]);
#endif
                totalChildren += numChildren;
                if ( numChildren > maxLookups )
                    maxLookups = numChildren;
            }
            ++bucketIdx2;
            ++bucketIdx;
        }
        while ( bucketIdx2 < pTable->numNodes );
    }
    std_g_pHS->debugPrint(" Maximum Lookups = %d\n", maxLookups);
    std_g_pHS->debugPrint(" Filled Indices = %d/%d (%2.2f%%)\n", numFilled, pTable->numNodes, (flex_t)numFilled * 100.0 / (flex_t)pTable->numNodes); // FLEXTODO
    std_g_pHS->debugPrint(" Average Lookup = %2.2f\n", (flex_t)totalChildren / (flex_t)numFilled); // FLEXTODO
    std_g_pHS->debugPrint(" Weighted Lookup = %2.2f\n", (flex_t)totalChildren / (flex_t)pTable->numNodes); // FLEXTODO
    std_g_pHS->debugPrint("---------------------\n");
}

void stdHashtbl_DumpTable(tHashTable *pTable)
{
    int index;
    tHashLink *key_iter;

    std_g_pHS->debugPrint("HASHTABLE\n---------\n");
    index = 0;
    if ( pTable->numNodes > 0 )
    {
        do
        {
            std_g_pHS->debugPrint("Index: %d\t", index);
            key_iter = &pTable->aSymbols[index];
            std_g_pHS->debugPrint("Strings:", index);
            for ( ; key_iter; key_iter = key_iter->next )
                std_g_pHS->debugPrint(" '%s'", key_iter->key);
            std_g_pHS->debugPrint("\n");
            ++index;
        }
        while ( index < pTable->numNodes );
    }
}
