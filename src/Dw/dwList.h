#ifndef _DWLIST_H
#define _DWLIST_H

#include "Dw/dwTypes.h"

// dwList — circular doubly-linked list with a heap-allocated sentinel node
// (C++ list<void*>-style template instantiation, COMDAT-scattered in the
// binary; see dwList.cpp for the per-function addresses).
//
// C++-ONLY header: dwList is a verifiably-C++ unit and has no C consumers.
// C code that needs to pass a list around uses an opaque
// `typedef struct dwList dwList;` forward declaration (see dwGob.h/dwInits.h).
//
// Layout note: the Ghidra "/DW/dwList" struct (0xc: pNext/pPrev/pData) is the
// NODE. The list handle owners embed is a single pointer to the sentinel;
// that handle is `dwList` here, the 0xc node is `dwListNode`.
//
// Empty list: sentinel->pNext == sentinel->pPrev == sentinel. Iteration:
// for (n = list.pSentinel->pNext; n != list.pSentinel; n = n->pNext).

#ifndef __cplusplus
#error "Dw/dwList.h is C++-only; C consumers forward-declare `typedef struct dwList dwList;`"
#endif

struct dwListNode
{
    dwListNode* pNext; // 0x00
    dwListNode* pPrev; // 0x04
    void* pData;       // 0x08: payload (never freed by Free/UnlinkFreeNode)
}; // sizeof 0x0c

struct dwList
{
    dwListNode* pSentinel; // head sentinel of the circular ring
    // sizeof 0x04

    // Allocate + self-link the sentinel. @40b940 (dwList_Ctor)
    dwList();

    // Note: NO destructor on purpose. The original class's dtor is Free(),
    // but node/payload ownership is manual everywhere in DW (owners call
    // Free/FreeOwnedNodes explicitly, then may keep or re-Ctor the handle);
    // an implicit dtor would double-free the sentinel behind those callers.
    // Free every node AND the sentinel (payloads untouched; pSentinel left
    // dangling, as in the original dtor). @436d20 (dwList_Free)
    void Free();

    // Insert a new node holding pData after pAfter (pass pSentinel to
    // push-front, pSentinel->pPrev to push-back). Returns this.
    // Note: the payload is now taken by value — the old C translation's
    // `void**` parameter was an artifact of the original C++ const-ref
    // (`const T&` with T = void*). @43c170 (dwList_InsertAfter)
    dwList* InsertAfter(dwListNode* pAfter, void* pData);

    // Free every node + sentinel, and virtually DELETE each non-NULL payload
    // via its vtable slot 0 scalar-deleting dtor (pData->vtbl[0](pData, 1)).
    // @402780 (dwList_FreeOwnedNodes)
    void FreeOwnedNodes();

    // Unlink pNode from its ring and free it (payload untouched). Returns
    // this. @403710 (dwList_UnlinkFreeNode)
    dwList* UnlinkFreeNode(dwListNode* pNode);

    // Unlink *ppNode from its ring, zero its links, do NOT free it.
    // @403750 (dwList_UnlinkNode)
    static void UnlinkNode(dwListNode** ppNode);

    // Unlink + free every node in [pNode, pEnd) (payloads untouched). Returns
    // this. Shared COMDAT used by ~6 units. @40ab10 (dwList_FreeNodeRange)
    dwList* FreeNodeRange(dwListNode* pNode, dwListNode* pEnd);
};

#endif // _DWLIST_H
