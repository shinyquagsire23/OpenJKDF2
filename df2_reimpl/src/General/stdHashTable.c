#include "stdHashTable.h"

#include "jk.h"

#include "stdPlatform.h"
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

int stdHashTable_HashStringToIdx(const char *data, int numBuckets)
{
    int hash;
    uint8_t i;

    hash = 0;
    for ( i = *data; i; ++data )
    {
        hash = (65599 * hash) + i;
        i = (uint8_t)data[1];
    }
    return abs(hash % numBuckets);
}

stdHashTable* stdHashTable_New(int maxEntries)
{
    stdHashTable *hashtable;
    int sizeIterIdx;
    signed int calcedPrime;
    int *sizeIter;
    int actualNumBuckets = 1999;
    signed int v7;

    hashtable = (stdHashTable *)std_pHS->alloc(sizeof(stdHashKey));
    if (!hashtable)
        return NULL;

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
    hashtable->buckets = (stdHashKey *)std_pHS->alloc(sizeof(stdHashKey) * actualNumBuckets);
    if ( hashtable->buckets )
    {
      _memset(hashtable->buckets, 0, sizeof(stdHashKey) * hashtable->numBuckets);
      hashtable->keyHashToIndex = stdHashTable_HashStringToIdx;
    }
    return hashtable;
}

stdHashKey* stdHashTable_GetBucketTail(stdHashKey *a1)
{
    stdHashKey *result; // eax
    stdHashKey *i; // ecx

    result = a1;
    for ( i = a1->child; i; i = i->child )
        result = i;
    return result;
}

void stdHashTable_FreeBuckets(stdHashKey *a1)
{
    stdHashKey *iter;

    iter = a1->child;
    if ( iter )
    {
        do
        {
            // TODO verify possible regression, prevent double free?
            stdHashKey* next_iter = iter->child;
            iter->child = NULL; // added

            std_pHS->free(iter);
            
            iter = next_iter;
        }
        while (iter);
    }
}

void stdHashTable_Free(stdHashTable *table)
{
    int bucketIdx;
    int bucketIdx2;
    stdHashKey *iter;
    stdHashKey *iter_child;

    bucketIdx = 0;
    if ( table->numBuckets > 0 )
    {
        bucketIdx2 = 0;
        do
        {
            stdHashTable_FreeBuckets(&table->buckets[bucketIdx2]);
            table->buckets[bucketIdx2].child = NULL; // added
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
    stdHashKey *new_child; // eax
    stdHashKey *v9; // ecx
    stdHashKey *v10; // esi
    stdHashKey *j; // eax

    // ADDED
    if (!hashmap)
        return 0;

    if (stdHashTable_GetKeyVal(hashmap, key))
        return 0;

    v9 = &hashmap->buckets[hashmap->keyHashToIndex(key, hashmap->numBuckets)];
    v10 = stdHashKey_GetLastChild(v9);

    if ( v10->key )
    {
        new_child = (stdHashKey *)std_pHS->alloc(sizeof(stdHashKey));
        if (!new_child)
            return 0;

        new_child->parent = 0;
        new_child->child = 0;
        new_child->key = 0;
        new_child->value = 0;
        new_child->key = key;
        new_child->value = value;
        stdHashKey_AddLink(v10, new_child);
    }
    else
    {
        v9->parent = 0;
        v9->child = 0;
        v9->key = 0;
        v9->value = 0;
        v9->key = key;
        v9->value = value;
    }
    return 1;
}

void* stdHashTable_GetKeyVal(stdHashTable *hashmap, const char *key)
{
    stdHashKey *i;
    const char *key_iter;
    stdHashKey *foundKey;

    if (!hashmap)
        return 0;

    foundKey = 0;
    for ( i = &hashmap->buckets[hashmap->keyHashToIndex(key, hashmap->numBuckets)]; i; i = i->child )
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
    stdHashKey *foundKey;
    stdHashKey *i;
    const char *key_iter;
    stdHashKey *bucketTopKey;

    if (!hashtable)
        return 0;

    foundKey = 0;
    v2 = hashtable->keyHashToIndex(key, hashtable->numBuckets);
    for ( i = &hashtable->buckets[v2]; i; i = i->child )
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

    stdHashKey_UnlinkChild(foundKey);
    bucketTopKey = &hashtable->buckets[v2];
    if ( bucketTopKey == foundKey )
    {
        if ( foundKey->child )
        {
            bucketTopKey->parent = foundKey->child->parent;
            bucketTopKey->child = foundKey->child->child;
            bucketTopKey->key = foundKey->child->key;
            bucketTopKey->value = foundKey->child->value;
            if ( bucketTopKey->child )
                bucketTopKey->child->parent = bucketTopKey;
            std_pHS->free(foundKey->child);
        }
        else
        {
            bucketTopKey->parent = 0;
            bucketTopKey->child = 0;
            bucketTopKey->key = 0;
            bucketTopKey->value = 0;
        }
    }
    else
    {
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
                numChildren = stdHashKey_NumChildren(&hashtable->buckets[bucketIdx]);
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
    std_pHS->debugPrint(" Filled Indices = %d/%d (%2.2f%%)\n", numFilled, hashtable->numBuckets, (float)numFilled * 100.0 / (float)hashtable->numBuckets);
    std_pHS->debugPrint(" Average Lookup = %2.2f\n", (float)totalChildren / (float)numFilled);
    std_pHS->debugPrint(" Weighted Lookup = %2.2f\n", (float)totalChildren / (float)hashtable->numBuckets);
    std_pHS->debugPrint("---------------------\n");
}

void stdHashTable_Dump(stdHashTable *hashtable)
{
    int index;
    stdHashKey *key_iter;

    std_pHS->debugPrint("HASHTABLE\n---------\n");
    index = 0;
    if ( hashtable->numBuckets > 0 )
    {
        do
        {
            std_pHS->debugPrint("Index: %d\t", index);
            key_iter = &hashtable->buckets[index];
            std_pHS->debugPrint("Strings:", index);
            for ( ; key_iter; key_iter = key_iter->child )
                std_pHS->debugPrint(" '%s'", key_iter->key);
            std_pHS->debugPrint("\n");
            ++index;
        }
        while ( index < hashtable->numBuckets );
    }
}

stdHashKey* stdHashKey_AddLink(stdHashKey *parent, stdHashKey *child)
{
    stdHashKey *child_;

    child_ = parent->child;
    child->parent = parent;
    child->child = child_;
    parent->child = child;
    if ( child_ )
        child_->parent = child;
    return child_;
}

stdHashKey* stdHashKey_InsertAtTop(stdHashKey *a1, stdHashKey *a2)
{
    stdHashKey *result; // eax

    result = a1->parent;
    a2->child = a1;
    a2->parent = result;
    a1->parent = a2;
    if ( result )
        result->child = a2;
    return result;
}

stdHashKey* stdHashKey_InsertAtEnd(stdHashKey *a1, stdHashKey *a2)
{
    stdHashKey *v2; // ecx
    stdHashKey *i; // eax
    stdHashKey *result; // eax

    v2 = a1;
    for ( i = a1->child; i; i = i->child )
        v2 = i;
    result = a2;
    v2->child = a2;
    a2->parent = v2;
    a2->child = 0;
    return result;
}

void stdHashKey_DisownMaybe(stdHashKey *a1)
{
    if ( a1->parent )
        a1->parent->child = 0;
    a1->parent = 0;
}

stdHashKey* stdHashKey_OrphanAndDisown(stdHashKey *a1)
{
    stdHashKey *result; // eax

    result = a1;
    a1->parent = 0;
    a1->child = 0;
    return result;
}

stdHashKey* stdHashKey_UnlinkChild(stdHashKey *hashkey)
{
    stdHashKey *result;
    stdHashKey *hashkey_parent;
    stdHashKey *hashkey_child;

    result = hashkey;
    hashkey_parent = hashkey->parent;
    if ( hashkey->parent )
        hashkey_parent->child = hashkey->child;

    hashkey_child = hashkey->child;
    if ( hashkey_child )
        hashkey_child->parent = hashkey_parent;

    hashkey->child = 0;
    hashkey->parent = 0;
    return result;
}

int stdHashKey_NumChildren(stdHashKey *hashkey)
{
    stdHashKey *hashkey_iter;
    int result;

    hashkey_iter = hashkey;
    for ( result = 0; hashkey_iter; ++result )
        hashkey_iter = hashkey_iter->child;
    return result;
}

stdHashKey* stdHashKey_GetNthChild(stdHashKey *key, int n)
{
    stdHashKey *result; // eax
    int v3; // ecx

    result = key;
    if ( key )
    {
        v3 = n;
        do
        {
            if ( v3 <= 0 )
                break;
            result = result->child;
            --v3;
        }
        while ( result );
    }
    return result;
}

stdHashKey* stdHashKey_GetLastChild(stdHashKey *hashkey)
{
    stdHashKey *result; // eax
    stdHashKey *i; // ecx

    result = hashkey;
    if ( hashkey )
    {
        for ( i = hashkey->child; i; i = i->child )
            result = i;
    }
    return result;
}

stdHashKey* stdHashKey_GetFirstParent(stdHashKey *a1)
{
    stdHashKey *result; // eax
    stdHashKey *v2; // ecx

    result = a1;
    if ( a1 )
    {
        v2 = a1->parent;
        if ( a1->parent )
        {
            do
            {
                result = v2;
                v2 = v2->parent;
            }
            while ( v2 );
        }
    }
    return result;
}
