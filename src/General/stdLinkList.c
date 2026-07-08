#include "stdLinkList.h"

// Added
tLinkListNode* stdLinklist_InsertReplace(tLinkListNode *pCur, tLinkListNode *pNodeToAdd)
{
    tLinkListNode* pPrev = pCur->prev;
    tLinkListNode* pNext = pCur->next;

    pNodeToAdd->prev = pPrev;
    pNodeToAdd->next = pNext;

    if ( pNext )
        pNext->prev = pNodeToAdd;

    return pNext;
}

tLinkListNode* stdLinkList_AddNode(tLinkListNode *pCur, tLinkListNode *pNodeToAdd)
{
    tLinkListNode* pNext = pCur->next;

    pNodeToAdd->prev = pCur;
    pNodeToAdd->next = pNext;
    pCur->next = pNodeToAdd;

    if ( pNext )
        pNext->prev = pNodeToAdd;

    return pNext;
}

tLinkListNode* stdLinklist_InsertNode(tLinkListNode *pCur, tLinkListNode *pNodeToAdd)
{
    tLinkListNode *pPrev = pCur->prev;

    pNodeToAdd->prev = pPrev;
    pNodeToAdd->next = pCur;
    pCur->prev = pNodeToAdd;

    if ( pPrev )
        pPrev->next = pNodeToAdd;

    return pPrev;
}

tLinkListNode* stdLinklist_AppendNode(tLinkListNode *pCur, tLinkListNode *pNodeToAdd)
{
    tLinkListNode* pEnd = stdLinklist_GetLastNode(pCur);

    pEnd->next = pNodeToAdd;
    pNodeToAdd->prev = pEnd;
    pNodeToAdd->next = NULL;

    return pNodeToAdd;
}

tLinkListNode* stdLinkList_RemoveNode(tLinkListNode *pCur)
{
    tLinkListNode* pCurPrev = pCur->prev;
    if ( pCur->prev )
        pCurPrev->next = pCur->next;

    tLinkListNode* pCurNext = pCur->next;
    if ( pCurNext )
        pCurNext->prev = pCurPrev;

    stdLinklist_DetachNode(pCur);
    return pCur;
}

void stdLinklist_NewList(tLinkListNode *pCur)
{
    if ( pCur->prev )
        pCur->prev->next = NULL;
    pCur->prev = NULL;
}

tLinkListNode* stdLinklist_DetachNode(tLinkListNode *pCur)
{
    pCur->prev = NULL;
    pCur->next = NULL;
    return pCur;
}

int stdLinklist_GetCount(tLinkListNode *pCur)
{
    int result;

    tLinkListNode* pIter = pCur;
    for ( result = 0; pIter; ++result )
        pIter = pIter->next;

    return result;
}

tLinkListNode* stdLinklist_GetNode(tLinkListNode *pCur, int n)
{
    tLinkListNode* pOut = pCur;

    while ( pOut )
    {
        if ( n <= 0 )
            break;
        pOut = pOut->next;
        --n;
    }

    return pOut;
}

tLinkListNode* stdLinklist_GetLastNode(tLinkListNode *pCur)
{
    tLinkListNode *result; // eax
    tLinkListNode *i; // ecx

    result = pCur;
    if ( pCur )
    {
        for ( i = pCur->next; i; i = i->next )
            result = i;
    }
    return result;
}

tLinkListNode* stdLinklist_GetFirstNode(tLinkListNode *pCur)
{
    tLinkListNode *result; // eax
    tLinkListNode *v2; // ecx

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