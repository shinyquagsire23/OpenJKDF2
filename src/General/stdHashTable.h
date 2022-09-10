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

#define stdHashKey_AddLink_ADDR (0x0043A7F0)
#define stdHashKey_InsertAtTop_ADDR (0x0043A810) // unused
#define stdHashKey_InsertAtEnd_ADDR (0x0043A830) // unused
#define stdHashKey_UnlinkChild_ADDR (0x0043A860)
#define stdHashKey_DisownMaybe_ADDR (0x0043A890) // unused
#define stdHashKey_OrphanAndDisown_ADDR (0x0043A8B0) // unused
#define stdHashKey_NumChildren_ADDR (0x0043A8D0) // used by stdHashtable_PrintDiagnostics
#define stdHashKey_GetNthChild_ADDR (0x0043A8F0) // unused
#define stdHashKey_GetLastChild_ADDR (0x0043A910) // unused
#define stdHashKey_GetFirstParent_ADDR (0x0043A930) // unused

typedef struct stdHashKey stdHashKey;

typedef struct stdHashKey
{
    stdHashKey* parent;
    stdHashKey* child;
    const char* key;
    void* value;
} stdHashKey;

typedef struct stdHashTable
{
    int numBuckets;
    stdHashKey* buckets;
    uint32_t (*keyHashToIndex)(const char *data, uint32_t numBuckets);
} stdHashTable;

uint32_t stdHashTable_HashStringToIdx(const char *data, uint32_t numBuckets);
stdHashTable* stdHashTable_New(int maxEntries);
stdHashKey* stdHashTable_GetBucketTail(stdHashKey *a1);
void stdHashTable_FreeBuckets(stdHashKey *a1);
void stdHashTable_Free(stdHashTable *table);
void* stdHashTable_GetKeyVal(stdHashTable *table, const char *key);
int stdHashTable_SetKeyVal(stdHashTable *hashmap, const char *key, void *value);
int stdHashTable_FreeKey(stdHashTable *hashtable, char *key);
void stdHashTable_PrintDiagnostics(stdHashTable *hashtable);
void stdHashTable_Dump(stdHashTable *hashtable);

stdHashKey* stdHashKey_AddLink(stdHashKey *parent, stdHashKey *child);
stdHashKey* stdHashKey_InsertAtTop(stdHashKey *a1, stdHashKey *a2);
stdHashKey* stdHashKey_InsertAtEnd(stdHashKey *a1, stdHashKey *a2);
stdHashKey* stdHashKey_UnlinkChild(stdHashKey *hashkey);
void stdHashKey_DisownMaybe(stdHashKey *a1);
stdHashKey* stdHashKey_OrphanAndDisown(stdHashKey *a1);
int stdHashKey_NumChildren(stdHashKey *hashkey);
stdHashKey* stdHashKey_GetNthChild(stdHashKey *key, int n);
stdHashKey* stdHashKey_GetLastChild(stdHashKey *hashkey);
stdHashKey* stdHashKey_GetFirstParent(stdHashKey *a1);

#endif // _STDHASHTABLE_H
