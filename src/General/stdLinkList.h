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

typedef struct tLinkListNode tLinkListNode;

typedef struct tLinkListNode
{
    tLinkListNode* prev;
    tLinkListNode* next;
    union {
        const char* key;
#ifdef STDHASHTABLE_CRC32_KEYS
        uint32_t keyCrc32;
#endif
    };
    void* value;
} tLinkListNode;

tLinkListNode* stdLinklist_InsertReplace(tLinkListNode *pCur, tLinkListNode *pNodeToAdd); // Added
tLinkListNode* stdLinkList_AddNode(tLinkListNode *pCur, tLinkListNode *pNodeToAdd);
tLinkListNode* stdLinklist_InsertNode(tLinkListNode *pCur, tLinkListNode *pNodeToAdd);
tLinkListNode* stdLinklist_AppendNode(tLinkListNode *pCur, tLinkListNode *pNodeToAdd);
tLinkListNode* stdLinkList_RemoveNode(tLinkListNode *pCur);
void stdLinklist_NewList(tLinkListNode *pCur);
tLinkListNode* stdLinklist_DetachNode(tLinkListNode *pCur);
int stdLinklist_GetCount(tLinkListNode *pCur);
tLinkListNode* stdLinklist_GetNode(tLinkListNode *pLL, int n);
tLinkListNode* stdLinklist_GetLastNode(tLinkListNode *pLL);
tLinkListNode* stdLinklist_GetFirstNode(tLinkListNode *a1);

#endif // _LEC_STD_LINKLST