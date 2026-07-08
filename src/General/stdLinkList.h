#ifndef _LEC_STD_LINKLIST
#define _LEC_STD_LINKLIST

#include "types.h"

#define stdLinkList_AddNode_ADDR (0x0043A7F0)
#define stdLinklist_InsertNode_ADDR (0x0043A810) // unused
#define stdLinklist_AppendNode_ADDR (0x0043A830) // unused
#define stdLinkList_RemoveNode_ADDR (0x0043A860)
#define stdLinklist_NewList_ADDR (0x0043A890) // unused
#define stdLinklist_DetachNode_ADDR (0x0043A8B0) // unused
#define stdLinklist_GetCount_ADDR (0x0043A8D0) // used by stdHashtable_PrintDiagnostics
#define stdLinklist_GetNode_ADDR (0x0043A8F0) // unused
#define stdLinklist_GetLastNode_ADDR (0x0043A910) // unused
#define stdLinklist_GetFirstNode_ADDR (0x0043A930) // unused

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
stdLinklist* stdLinkList_AddNode(stdLinklist *pCur, stdLinklist *pNodeToAdd);
stdLinklist* stdLinklist_InsertNode(stdLinklist *pCur, stdLinklist *pNodeToAdd);
stdLinklist* stdLinklist_AppendNode(stdLinklist *pCur, stdLinklist *pNodeToAdd);
stdLinklist* stdLinkList_RemoveNode(stdLinklist *pCur);
void stdLinklist_NewList(stdLinklist *pCur);
stdLinklist* stdLinklist_DetachNode(stdLinklist *pCur);
int stdLinklist_GetCount(stdLinklist *pCur);
stdLinklist* stdLinklist_GetNode(stdLinklist *pLL, int n);
stdLinklist* stdLinklist_GetLastNode(stdLinklist *pLL);
stdLinklist* stdLinklist_GetFirstNode(stdLinklist *a1);

#endif // _LEC_STD_LINKLST