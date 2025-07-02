#include "stdHashTable.h"

#include "jk.h"

#include "stdPlatform.h"
#include "General/stdLinklist.h"
#include <math.h>
#include <stdlib.h>

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

uint32_t stdHashTable_HashStringToIdx(const char *data, uint32_t numBuckets)
{
    uint32_t hash;
    uint8_t i;
    
    if (!data || !data[0]) return 0; // Added

    hash = 0;
    for ( i = *data; i; ++data )
    {
        hash = (65599 * hash) + i;
        i = (uint8_t)data[1];
    }
    return hash % numBuckets;
}

stdHashTable* stdHashTable_New(int maxEntries)
{
    stdHashTable *hashtable;
    int sizeIterIdx;
    signed int calcedPrime;
    int *sizeIter;
    int actualNumBuckets = 1999;
    signed int v7;

    hashtable = (stdHashTable *)std_pHS->alloc(sizeof(stdLinklist));
    if (!hashtable)
        return NULL;
    
    // Added: memset
    _memset(hashtable, 0, sizeof(*hashtable));

    sizeIterIdx = 0;
    calcedPrime = maxEntries;
    sizeIter = hashmapBucketSizes;
    hashtable->numBuckets = 0;
    hashtable->buckets = 0;
    hashtable->keyHashToIndex = 0;
    while ( maxEntries >= *sizeIter )
    {
        ++sizeIter;
        ++sizeIterIdx;
        if ( sizeIter >= &hashmapBucketSizes[hashmapBucketSizes_MAX] )
        {
            actualNumBuckets = maxEntries;
            sizeIterIdx = hashmapBucketSizes_MAX-1;
            break;
        }
    }
    actualNumBuckets = hashmapBucketSizes[sizeIterIdx];

    // Calculate a prime number?
    if ( maxEntries > 1999 )
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

    hashtable->numBuckets = actualNumBuckets;
    hashtable->buckets = (stdLinklist *)std_pHS->alloc(sizeof(stdLinklist) * actualNumBuckets);
    if ( hashtable->buckets )
    {
      _memset(hashtable->buckets, 0, sizeof(stdLinklist) * hashtable->numBuckets);
      hashtable->keyHashToIndex = stdHashTable_HashStringToIdx;
    }
    return hashtable;
}

stdLinklist* stdHashTable_GetBucketTail(stdLinklist *pLL)
{
    return stdLinklist_GetTail(pLL);
}

void stdHashTable_FreeBuckets(stdLinklist *a1)
{
    stdLinklist *iter;
    
    // Added: nullptr check
    if (!a1) return;

    iter = a1->next;
    while ( iter )
    {
        // TODO verify possible regression, prevent double free?
        stdLinklist* next_iter = iter->next;
        iter->next = NULL; // added

        //printf("Free from %p: %p\n", a1, iter);
        std_pHS->free(iter);
        
        iter = next_iter;
    }
}

void stdHashTable_Free(stdHashTable *table)
{
    int bucketIdx;
    int bucketIdx2;
    stdLinklist *iter;
    stdLinklist *iter_child;
    
    // Added: nullptr check
    if (!table) return;

    bucketIdx = 0;
    if ( table->numBuckets > 0 )
    {
        bucketIdx2 = 0;
        do
        {
            stdHashTable_FreeBuckets(&table->buckets[bucketIdx2]);
            table->buckets[bucketIdx2].next = NULL; // added
            ++bucketIdx;
            ++bucketIdx2;
        }
        while ( bucketIdx < table->numBuckets );
    }
    std_pHS->free(table->buckets);
    table->buckets = NULL; // added
    
    std_pHS->free(table);
}

int stdHashTable_SetKeyVal(stdHashTable *hashmap, const char *key, void *value)
{
    stdLinklist *new_child; // eax
    stdLinklist *v9; // ecx
    stdLinklist *v10; // esi

    // ADDED
    if (!hashmap)
        return 0;

    if (stdHashTable_GetKeyVal(hashmap, key))
        return 0;

    v9 = &hashmap->buckets[hashmap->keyHashToIndex(key, hashmap->numBuckets)];
    v10 = stdLinklist_GetTail(v9);

    if ( v10->key )
    {
        new_child = (stdLinklist *)std_pHS->alloc(sizeof(stdLinklist));
        if (!new_child)
            return 0;
        //printf("Alloc to %p: %p\n", v9, new_child);

        _memset(new_child, 0, sizeof(*new_child));
        new_child->key = key;
        new_child->value = value;
        stdLinklist_InsertAfter(v10, new_child);
    }
    else
    {
        _memset(v9, 0, sizeof(*v9));
        v9->key = key;
        v9->value = value;
    }
    return 1;
}

void* stdHashTable_GetKeyVal(stdHashTable *hashmap, const char *key)
{
    stdLinklist *i;
    const char *key_iter;
    stdLinklist *foundKey;

    if (!hashmap)
        return 0;

    foundKey = 0;
    for ( i = &hashmap->buckets[hashmap->keyHashToIndex(key, hashmap->numBuckets)]; i; i = i->next )
    {
      key_iter = (const char *)i->key;
      if ( !key_iter )
      {
        foundKey = 0;
        break;
      }
      if ( !_strcmp(key_iter, key) )
      {
        foundKey = i;
        break;
      }
    }

    if (foundKey)
        return foundKey->value;

    return 0;
}

int stdHashTable_FreeKey(stdHashTable *hashtable, char *key)
{
    int v2;
    stdLinklist *foundKey;
    stdLinklist *i;
    const char *key_iter;
    stdLinklist *bucketTopKey;

    if (!hashtable)
        return 0;

    foundKey = 0;
    v2 = hashtable->keyHashToIndex(key, hashtable->numBuckets);
    for ( i = &hashtable->buckets[v2]; i; i = i->next )
    {
        key_iter = i->key;
        if ( !key_iter )
            break;
        if ( !_strcmp(key_iter, key) )
        {
            foundKey = i;
            break;
        }
    }

    if ( !foundKey )
        return 0;

    //stdLinklist_UnlinkChild(foundKey); // Added: Moved to prevent freeing issues
    bucketTopKey = &hashtable->buckets[v2];
    if ( bucketTopKey == foundKey )
    {
        stdLinklist* pNext = foundKey->next;
        if ( pNext )
        {
            bucketTopKey->key = pNext->key;
            bucketTopKey->value = pNext->value;

            stdLinklist_InsertReplace(pNext, bucketTopKey);
            std_pHS->free(pNext);
        }
        else
        {
            bucketTopKey->prev = NULL;
            bucketTopKey->next = NULL;
            bucketTopKey->key = NULL;
            bucketTopKey->value = 0;
        }
    }
    else
    {
        stdLinklist_UnlinkChild(foundKey); // Added: Moved to prevent freeing issues
        std_pHS->free(foundKey);
    }
    return 1;
}

void stdHashTable_PrintDiagnostics(stdHashTable *hashtable)
{
    int maxLookups; // edi
    int bucketIdx2; // ebp
    int bucketIdx; // ebx
    int numChildren; // eax
    signed int numFilled; // [esp+14h] [ebp-Ch]
    signed int totalChildren; // [esp+18h] [ebp-8h]

    std_pHS->debugPrint("HASHTABLE Diagnostics\n");
    std_pHS->debugPrint("---------------------\n");
    maxLookups = 0;
    bucketIdx2 = 0;
    numFilled = 0;
    totalChildren = 0;
    if ( hashtable->numBuckets > 0 )
    {
        bucketIdx = 0;
        do
        {
            if ( hashtable->buckets[bucketIdx].key )
            {
                ++numFilled;
                numChildren = stdLinklist_NumChildren(&hashtable->buckets[bucketIdx]);
                totalChildren += numChildren;
                if ( numChildren > maxLookups )
                    maxLookups = numChildren;
            }
            ++bucketIdx2;
            ++bucketIdx;
        }
        while ( bucketIdx2 < hashtable->numBuckets );
    }
    std_pHS->debugPrint(" Maximum Lookups = %d\n", maxLookups);
    std_pHS->debugPrint(" Filled Indices = %d/%d (%2.2f%%)\n", numFilled, hashtable->numBuckets, (flex_t)numFilled * 100.0 / (flex_t)hashtable->numBuckets); // FLEXTODO
    std_pHS->debugPrint(" Average Lookup = %2.2f\n", (flex_t)totalChildren / (flex_t)numFilled); // FLEXTODO
    std_pHS->debugPrint(" Weighted Lookup = %2.2f\n", (flex_t)totalChildren / (flex_t)hashtable->numBuckets); // FLEXTODO
    std_pHS->debugPrint("---------------------\n");
}

void stdHashTable_Dump(stdHashTable *hashtable)
{
    int index;
    stdLinklist *key_iter;

    std_pHS->debugPrint("HASHTABLE\n---------\n");
    index = 0;
    if ( hashtable->numBuckets > 0 )
    {
        do
        {
            std_pHS->debugPrint("Index: %d\t", index);
            key_iter = &hashtable->buckets[index];
            std_pHS->debugPrint("Strings:", index);
            for ( ; key_iter; key_iter = key_iter->next )
                std_pHS->debugPrint(" '%s'", key_iter->key);
            std_pHS->debugPrint("\n");
            ++index;
        }
        while ( index < hashtable->numBuckets );
    }
}
