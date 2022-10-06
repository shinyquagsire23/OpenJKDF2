#ifndef _STDHASHTABLE_H
#define _STDHASHTABLE_H

#include "types.h"

#define stdHashTable_HashStringToIdx_ADDR (0x00437AB0)
#define stdHashTable_New_ADDR (0x00437AF0)
#define stdHashTable_GetBucketTail_ADDR (0x00437BB0)
#define stdHashTable_FreeBuckets_ADDR (0x00437BD0) // unused
#define stdHashTable_Free_ADDR (0x00437C00)
#define stdHashTable_SetKeyVal_ADDR (0x00437C60)
#define stdHashTable_GetKeyVal_ADDR (0x00437D80)
#define stdHashTable_FreeKey_ADDR (0x00437E00)
#define stdHashTable_PrintDiagnostics_ADDR (0x00437F20) // unused but interesting
#define stdHashTable_Dump_ADDR (0x00438040) // unused but interesting

typedef struct stdLinklist stdLinklist;

typedef struct stdHashTable
{
    int numBuckets;
    stdLinklist* buckets;
    uint32_t (*keyHashToIndex)(const char *data, uint32_t numBuckets);
} stdHashTable;

uint32_t stdHashTable_HashStringToIdx(const char *data, uint32_t numBuckets);
stdHashTable* stdHashTable_New(int maxEntries);
stdLinklist* stdHashTable_GetBucketTail(stdLinklist *pLL);
void stdHashTable_FreeBuckets(stdLinklist *a1);
void stdHashTable_Free(stdHashTable *table);
void* stdHashTable_GetKeyVal(stdHashTable *table, const char *key);
int stdHashTable_SetKeyVal(stdHashTable *hashmap, const char *key, void *value);
int stdHashTable_FreeKey(stdHashTable *hashtable, char *key);
void stdHashTable_PrintDiagnostics(stdHashTable *hashtable);
void stdHashTable_Dump(stdHashTable *hashtable);

#endif // _STDHASHTABLE_H
