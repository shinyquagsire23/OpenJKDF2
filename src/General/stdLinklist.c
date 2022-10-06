#include "stdLinklist.h"

// Added
stdLinklist* stdLinklist_InsertReplace(stdLinklist *pCur, stdLinklist *pNodeToAdd)
{
    stdLinklist* pPrev = pCur->prev;
    stdLinklist* pNext = pCur->next;

    pNodeToAdd->prev = pPrev;
    pNodeToAdd->next = pNext;

    if ( pNext )
        pNext->prev = pNodeToAdd;

    return pNext;
}

stdLinklist* stdLinklist_InsertAfter(stdLinklist *pCur, stdLinklist *pNodeToAdd)
{
    stdLinklist* pNext = pCur->next;

    pNodeToAdd->prev = pCur;
    pNodeToAdd->next = pNext;
    pCur->next = pNodeToAdd;

    if ( pNext )
        pNext->prev = pNodeToAdd;

    return pNext;
}

stdLinklist* stdLinklist_InsertBefore(stdLinklist *pCur, stdLinklist *pNodeToAdd)
{
    stdLinklist *pPrev = pCur->prev;

    pNodeToAdd->prev = pPrev;
    pNodeToAdd->next = pCur;
    pCur->prev = pNodeToAdd;

    if ( pPrev )
        pPrev->next = pNodeToAdd;

    return pPrev;
}

stdLinklist* stdLinklist_InsertAtEnd(stdLinklist *pCur, stdLinklist *pNodeToAdd)
{
    stdLinklist* pEnd = stdLinklist_GetTail(pCur);

    pEnd->next = pNodeToAdd;
    pNodeToAdd->prev = pEnd;
    pNodeToAdd->next = NULL;

    return pNodeToAdd;
}

stdLinklist* stdLinklist_UnlinkChild(stdLinklist *pCur)
{
    stdLinklist* pCurPrev = pCur->prev;
    if ( pCur->prev )
        pCurPrev->next = pCur->next;

    stdLinklist* pCurNext = pCur->next;
    if ( pCurNext )
        pCurNext->prev = pCurPrev;

    stdLinklist_UnlinkNode(pCur);
    return pCur;
}

void stdLinklist_RemoveParent(stdLinklist *pCur)
{
    if ( pCur->prev )
        pCur->prev->next = NULL;
    pCur->prev = NULL;
}

stdLinklist* stdLinklist_UnlinkNode(stdLinklist *pCur)
{
    pCur->prev = NULL;
    pCur->next = NULL;
    return pCur;
}

int stdLinklist_NumChildren(stdLinklist *pCur)
{
    int result;

    stdLinklist* pIter = pCur;
    for ( result = 0; pIter; ++result )
        pIter = pIter->next;

    return result;
}

stdLinklist* stdLinklist_GetNthChild(stdLinklist *pCur, int n)
{
    stdLinklist* pOut = pCur;

    while ( pOut )
    {
        if ( n <= 0 )
            break;
        pOut = pOut->next;
        --n;
    }

    return pOut;
}

stdLinklist* stdLinklist_GetTail(stdLinklist *pCur)
{
    stdLinklist *result; // eax
    stdLinklist *i; // ecx

    result = pCur;
    if ( pCur )
    {
        for ( i = pCur->next; i; i = i->next )
            result = i;
    }
    return result;
}

stdLinklist* stdLinklist_GetHead(stdLinklist *pCur)
{
    stdLinklist *result; // eax
    stdLinklist *v2; // ecx

    result = pCur;
    if ( pCur )
    {
        v2 = pCur->prev;
        if ( pCur->prev )
        {
            do
            {
                result = v2;
                v2 = v2->prev;
            }
            while ( v2 );
        }
    }
    return result;
}