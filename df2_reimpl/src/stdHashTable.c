#include "stdHashTable.h"

#include "jk.h"

#include "stdPlatform.h"
#include <math.h>

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

int stdHashTable_HashStringToIdx(uint8_t *data, int numBuckets)
{
    int hash;
    uint8_t i;

    hash = 0;
    for ( i = *data; i; ++data )
    {
        hash = (65599 * hash) + i;
        i = data[1];
    }
    return abs(hash % numBuckets);
}

stdHashTable* stdHashTable_New(int maxEntries)
{
    stdHashTable *hashtable;
    int sizeIterIdx;
    signed int calcedPrime;
    int *sizeIter;
    int actualNumBuckets;
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
        }
        else
        {
            actualNumBuckets = hashmapBucketSizes[sizeIterIdx];
        }
    }

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
    hashtable->buckets = (stdHashKey *)std_pHS->alloc(16 * actualNumBuckets);
    if ( hashtable->buckets )
    {
      _memset(hashtable->buckets, 0, sizeof(stdHashKey) * hashtable->numBuckets);
      hashtable->keyHashToIndex = stdHashTable_HashStringToIdx;
    }
    return hashtable;
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
            iter = table->buckets[bucketIdx2].child;
            if ( iter )
            {
                do
                {
                    iter_child = iter->child;
                    std_pHS->free(iter);
                    iter = iter_child;
                }
                while ( iter_child );
            }
            ++bucketIdx;
            ++bucketIdx2;
        }
        while ( bucketIdx < table->numBuckets );
    }
    std_pHS->free(table->buckets);
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

    // TODO this is an inlined func
    v10 = v9;
    for ( j = v10->child; j; j = j->child )
        v10 = j;

    if ( v10->key )
    {
        new_child = (stdHashKey *)std_pHS->alloc(sizeof(stdHashKey));
        if (!new_child)
            return 0;

        new_child->parent = 0;
        new_child->child = 0;
        new_child->key = 0;
        new_child->value = 0;
        new_child->key = (int)key;
        new_child->value = (int)value;
        stdHashKey_AddLink(v10, new_child);
    }
    else
    {
        v9->parent = 0;
        v9->child = 0;
        v9->key = 0;
        v9->value = 0;
        v9->key = (int)key;
        v9->value = (int)value;
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
        if ( !strcmp(key_iter, key) )
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

void stdHashtable_PrintDiagnostics(stdHashTable *hashtable)
{
    stdHashTable *hashtable_; // esi
    int maxLookups; // edi
    int bucketIdx2; // ebp
    int bucketIdx; // ebx
    int numChildren; // eax
    signed int numFilled; // [esp+14h] [ebp-Ch]
    signed int totalChildren; // [esp+18h] [ebp-8h]

    std_pHS->debugPrint("HASHTABLE Diagnostics\n");
    std_pHS->debugPrint("---------------------\n");
    hashtable_ = hashtable;
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

void stdHashtable_Dump(stdHashTable *hashtable)
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
  stdHashKey *child_; // eax

  child_ = parent->child;
  child->parent = parent;
  child->child = child_;
  parent->child = child;
  if ( child_ )
    child_->parent = child;
  return child_;
}

stdHashKey* stdHashKey_UnlinkChild(stdHashKey *hashkey)
{
  stdHashKey *result; // eax
  stdHashKey *hashkey_parent; // ecx
  stdHashKey *hashkey_child; // edx

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
