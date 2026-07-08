#ifndef _STDHASHTABLE_H
#define _STDHASHTABLE_H

#include "types.h"

#include "General/crc32.h"

#define stdHashtbl_HashStringToIdx_ADDR (0x00437AB0)
#define stdHashtbl_New_ADDR (0x00437AF0)
#define stdHashtbl_GetTailNode_ADDR (0x00437BB0)
#define stdHashtbl_FreeListNodes_ADDR (0x00437BD0) // unused
#define stdHashtbl_Free_ADDR (0x00437C00)
#define stdHashtbl_Add_ADDR (0x00437C60)
#define stdHashtbl_Find_ADDR (0x00437D80)
#define stdHashtbl_Remove_ADDR (0x00437E00)
#define stdHashtbl_PrintTableDiagnostics_ADDR (0x00437F20) // unused but interesting
#define stdHashtbl_DumpTable_ADDR (0x00438040) // unused but interesting

typedef struct tLinkListNode tLinkListNode;
typedef struct stdSingleLinklist stdSingleLinklist;

#ifdef STDHASHTABLE_SINGLE_LINKLIST
typedef stdSingleLinklist tHashLink;
#else
typedef tLinkListNode tHashLink;
#endif

typedef struct tHashTable
{
    int numNodes;
    tHashLink* aSymbols;
    uint32_t (*pfHashFunc)(const char *data, uint32_t numNodes);
} tHashTable;

uint32_t stdHashtbl_HashStringToIdx(const char *data, uint32_t numNodes);
tHashTable* stdHashtbl_New(int size);
tHashLink* stdHashtbl_GetTailNode(tHashLink *pCur);
void stdHashtbl_FreeListNodes(tHashLink *pNode);
void stdHashtbl_Free(tHashTable *pTable);
#ifdef STDHASHTABLE_CRC32_KEYS
int stdHashtbl_FreeKeyCrc32(tHashTable *pHashtbl, uint32_t keyCrc32);
#endif
void* stdHashtbl_Find(tHashTable *table, const char *pName);
int stdHashtbl_Add(tHashTable *pTable, const char *pName, void *pData);
int stdHashtbl_Remove(tHashTable *pTable, const char *pName);
void stdHashtbl_PrintTableDiagnostics(tHashTable *pTable);
void stdHashtbl_DumpTable(tHashTable *pTable);

#endif // _STDHASHTABLE_H
