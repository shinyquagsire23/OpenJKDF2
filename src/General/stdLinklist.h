#ifndef _LEC_STD_LINKLIST
#define _LEC_STD_LINKLIST

#include "types.h"

#define stdLinklist_InsertAfter_ADDR (0x0043A7F0)
#define stdLinklist_InsertBefore_ADDR (0x0043A810) // unused
#define stdLinklist_InsertAtEnd_ADDR (0x0043A830) // unused
#define stdLinklist_UnlinkChild_ADDR (0x0043A860)
#define stdLinklist_RemoveParent_ADDR (0x0043A890) // unused
#define stdLinklist_UnlinkNode_ADDR (0x0043A8B0) // unused
#define stdLinklist_NumChildren_ADDR (0x0043A8D0) // used by stdHashtable_PrintDiagnostics
#define stdLinklist_GetNthChild_ADDR (0x0043A8F0) // unused
#define stdLinklist_GetTail_ADDR (0x0043A910) // unused
#define stdLinklist_GetHead_ADDR (0x0043A930) // unused

typedef struct stdLinklist stdLinklist;

typedef struct stdLinklist
{
    stdLinklist* prev;
    stdLinklist* next;
    union {
        const char* key;
#ifdef STDHASHTABLE_CRC32_KEYS
        uint32_t keyCrc32;
#endif
    };
    void* value;
} stdLinklist;

stdLinklist* stdLinklist_InsertReplace(stdLinklist *pCur, stdLinklist *pNodeToAdd); // Added
stdLinklist* stdLinklist_InsertAfter(stdLinklist *pCur, stdLinklist *pNodeToAdd);
stdLinklist* stdLinklist_InsertBefore(stdLinklist *pCur, stdLinklist *pNodeToAdd);
stdLinklist* stdLinklist_InsertAtEnd(stdLinklist *pCur, stdLinklist *pNodeToAdd);
stdLinklist* stdLinklist_UnlinkChild(stdLinklist *pCur);
void stdLinklist_RemoveParent(stdLinklist *pCur);
stdLinklist* stdLinklist_UnlinkNode(stdLinklist *pCur);
int stdLinklist_NumChildren(stdLinklist *pCur);
stdLinklist* stdLinklist_GetNthChild(stdLinklist *pLL, int n);
stdLinklist* stdLinklist_GetTail(stdLinklist *pLL);
stdLinklist* stdLinklist_GetHead(stdLinklist *a1);

#endif // _LEC_STD_LINKLST