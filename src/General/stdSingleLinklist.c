#include "stdSingleLinklist.h"

// Added
stdSingleLinklist* stdSingleLinklist_InsertReplace(stdSingleLinklist *pCur, stdSingleLinklist *pNodeToAdd)
{
    stdSingleLinklist* pNext = pCur->next;

    pNodeToAdd->next = pNext;

    return pNext;
}

stdSingleLinklist* stdSingleLinklist_InsertAfter(stdSingleLinklist *pCur, stdSingleLinklist *pNodeToAdd)
{
    stdSingleLinklist* pNext = pCur->next;

    pNodeToAdd->next = pNext;
    pCur->next = pNodeToAdd;

    return pNext;
}

stdSingleLinklist* stdSingleLinklist_InsertAtEnd(stdSingleLinklist *pCur, stdSingleLinklist *pNodeToAdd)
{
    stdSingleLinklist* pEnd = stdSingleLinklist_GetTail(pCur);

    pEnd->next = pNodeToAdd;
    pNodeToAdd->next = NULL;

    return pNodeToAdd;
}

stdSingleLinklist* stdSingleLinklist_UnlinkChild(stdSingleLinklist *pCur, stdSingleLinklist *pCurPrev)
{
    if ( pCurPrev )
        pCurPrev->next = pCur->next;

    stdSingleLinklist* pCurNext = pCur->next;

    stdSingleLinklist_UnlinkNode(pCur);
    return pCur;
}

stdSingleLinklist* stdSingleLinklist_UnlinkNode(stdSingleLinklist *pCur)
{
    pCur->next = NULL;
    return pCur;
}

int stdSingleLinklist_NumChildren(stdSingleLinklist *pCur)
{
    int result;

    stdSingleLinklist* pIter = pCur;
    for ( result = 0; pIter; ++result )
        pIter = pIter->next;

    return result;
}

stdSingleLinklist* stdSingleLinklist_GetNthChild(stdSingleLinklist *pCur, int n)
{
    stdSingleLinklist* pOut = pCur;

    while ( pOut )
    {
        if ( n <= 0 )
            break;
        pOut = pOut->next;
        --n;
    }

    return pOut;
}

stdSingleLinklist* stdSingleLinklist_GetTail(stdSingleLinklist *pCur)
{
    stdSingleLinklist *result; // eax
    stdSingleLinklist *i; // ecx

    result = pCur;
    if ( pCur )
    {
        for ( i = pCur->next; i; i = i->next )
            result = i;
    }
    return result;
}