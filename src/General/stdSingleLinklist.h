#ifndef _LEC_STD_SINGLELINKLIST
#define _LEC_STD_SINGLELINKLIST

#include "types.h"

typedef struct stdSingleLinklist stdSingleLinklist;

typedef struct stdSingleLinklist
{
    stdSingleLinklist* next;
    union {
        const char* key;
#ifdef STDHASHTABLE_CRC32_KEYS
        uint32_t keyCrc32;
#endif
    };
    void* value;
} stdSingleLinklist;

stdSingleLinklist* stdSingleLinklist_InsertReplace(stdSingleLinklist *pCur, stdSingleLinklist *pNodeToAdd); // Added
stdSingleLinklist* stdSingleLinklist_InsertAfter(stdSingleLinklist *pCur, stdSingleLinklist *pNodeToAdd);
stdSingleLinklist* stdSingleLinklist_InsertAtEnd(stdSingleLinklist *pCur, stdSingleLinklist *pNodeToAdd);
stdSingleLinklist* stdSingleLinklist_UnlinkChild(stdSingleLinklist *pCur, stdSingleLinklist *pPrev);
stdSingleLinklist* stdSingleLinklist_UnlinkNode(stdSingleLinklist *pCur);
int stdSingleLinklist_NumChildren(stdSingleLinklist *pCur);
stdSingleLinklist* stdSingleLinklist_GetNthChild(stdSingleLinklist *pLL, int n);
stdSingleLinklist* stdSingleLinklist_GetTail(stdSingleLinklist *pLL);

#endif // _LEC_STD_SINGLELINKLST