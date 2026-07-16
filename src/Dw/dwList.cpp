// dwList — circular doubly-linked list (sentinel node), C++ template COMDATs
// scattered through DroidWorks.exe:
//   dwList::dwList        @0x40b940 (dwList_Ctor)
//   dwList::Free          @0x436d20
//   dwList::InsertAfter   @0x43c170
//   dwList::FreeOwnedNodes@0x402780
//   dwList::UnlinkFreeNode@0x403710
//   dwList::UnlinkNode    @0x403750
//   dwList::FreeNodeRange @0x40ab10
//
// Allocation: original used operator new / HostServices FreeHandle; this
// layer is desktop-only, so plain malloc/free are used (kept — the node
// alloc/free strategy must stay uniform with owners that free nodes raw).

#include "Dw/dwList.h"

#include <stdlib.h>

// No module statics — no dwList_Startup needed (soft-reset rule).

// MSVC virtual scalar-deleting-destructor shape: vtable slot 0,
// called as (this, bFreeMemory).
typedef void (*dwList_DtorDeleteFn)(void* pThis, int bFreeMemory);

// @40b940
dwList::dwList()
{
    dwListNode* pNewSentinel;

    this->pSentinel = NULL;
    pNewSentinel = (dwListNode*)malloc(sizeof(dwListNode));
    this->pSentinel = pNewSentinel;
    // Note: the original did not null-check the allocation either, and left
    // the sentinel's pData uninitialized.
    pNewSentinel->pNext = pNewSentinel;
    pNewSentinel->pPrev = pNewSentinel;
}

// @436d20
void dwList::Free()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;

    pSent = this->pSentinel;
    pNode = pSent->pNext;
    while (pNode != pSent) {
        pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        pNode->pNext = NULL;
        pNode->pPrev = NULL;
        free(pNode);
        pNode = pNext;
    }
    free(this->pSentinel);
    // Note: this->pSentinel is left dangling, as in the original dtor — the
    // object is expected to be dead (or re-constructed) after this. This is
    // also why dwList has no implicit destructor (see dwList.h).
}

// @43c170 — pData is taken by value; the old C translation's void** was a
// const-ref artifact (see dwList.h).
dwList* dwList::InsertAfter(dwListNode* pAfter, void* pData)
{
    dwListNode* pNew;

    pNew = (dwListNode*)malloc(sizeof(dwListNode));
    // Note: the null-check guards only the payload store (MSVC operator-new
    // check artifact); the link-in below was unconditional in the original.
    if (pNew != NULL)
        pNew->pData = pData;
    pNew->pPrev = pAfter;
    pNew->pNext = pAfter->pNext;
    pAfter->pNext = pNew;
    pNew->pNext->pPrev = pNew;
    return this;
}

// @402780
void dwList::FreeOwnedNodes()
{
    dwListNode* pNode;
    dwListNode* pNext;
    void* pData;
    dwList_DtorDeleteFn* paVtbl;

    // Note: the original wrapped this loop in an SEH/C++-EH frame (unwind
    // continues freeing on exception); dropped in the translation.
    pNode = this->pSentinel->pNext;
    while (pNode != this->pSentinel) {
        pData = pNode->pData;
        pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        pNode->pNext = NULL;
        pNode->pPrev = NULL;
        free(pNode);
        if (pData != NULL) {
            // virtual scalar-deleting dtor: vtbl slot 0, flag 1 = free object
            paVtbl = *(dwList_DtorDeleteFn**)pData;
            paVtbl[0](pData, 1);
        }
        pNode = pNext;
    }
    // Trailing base-dtor part (the original inlined the list dtor here):
    // frees any remaining nodes — none by now — plus the sentinel.
    this->Free();
}

// @403710
dwList* dwList::UnlinkFreeNode(dwListNode* pNode)
{
    pNode->pPrev->pNext = pNode->pNext;
    pNode->pNext->pPrev = pNode->pPrev;
    pNode->pNext = NULL;
    pNode->pPrev = NULL;
    free(pNode);
    return this;
}

// @403750
void dwList::UnlinkNode(dwListNode** ppNode)
{
    dwListNode* pNode;

    pNode = *ppNode;
    pNode->pPrev->pNext = pNode->pNext;
    pNode->pNext->pPrev = pNode->pPrev;
    pNode->pNext = NULL;
    pNode->pPrev = NULL;
}

// @40ab10
dwList* dwList::FreeNodeRange(dwListNode* pNode, dwListNode* pEnd)
{
    dwListNode* pNext;

    while (pNode != pEnd) {
        pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        pNode->pNext = NULL;
        pNode->pPrev = NULL;
        free(pNode);
        pNode = pNext;
    }
    return this;
}
