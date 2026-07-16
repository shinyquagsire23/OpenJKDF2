// dwWidgetGroup — the DroidWorks container widget base (child list + input/
// tick/paint forwarding).
//
// Decompiled from DroidWorks.exe, unit range 0x444320-0x44481x + the dtor
// pair @0x402870/0x402890 (mis-binned in the dwAnim range) + the FreeImages
// broadcast @0x43c040. vtable @0x51e0c0. See dwWidgetGroup.h for the
// forwarding-quirk summary.
//
// Iteration pattern (everywhere below): the children dwList is a circular
// ring around a sentinel; walk pSentinel->pNext until back at the sentinel.
// Faithfulness detail: the INPUT/TICK/MESSAGE loops (OnMouse*/OnKey/Update/
// OnHover/OnMessage) cache pNext BEFORE the child callback, while the
// Move/HitTest/EnsureImages/FreeImages/Draw loops read the next link AFTER
// the callback — both mirrored exactly from the binary.
//
// No module statics — no dwWidgetGroup_Startup needed (soft-reset rule).

#include "Dw/dwWidgetGroup.h"

#include "Dw/dwImage.h" // dwImageBits (plain-C struct)

#include <stdlib.h>

// ---- ctors/dtor ---------------------------------------------------------------

// @444320 (Ghidra: dwWidgetGroup_CtorDefault) — the binary built the
// (0, 0, mode width, mode height) rect inline and called the dwWidget rect
// ctor; that is exactly what the dwWidget default ctor does, so delegate.
// The children dwList member ctor allocates the empty (self-linked) sentinel.
dwWidgetGroup::dwWidgetGroup()
    : dwWidget()
{
}

// @4443b0 (Ghidra: dwWidgetGroup_Ctor)
dwWidgetGroup::dwWidgetGroup(dwRect* pRect)
    : dwWidget(pRect)
{
}

// @402890 (Ghidra: dwWidgetGroup_Dtor; scalar-deleting wrapper @402870).
// Binary order: re-point vptr at the group vtable (compiler does this),
// FreeChildImages (direct, non-virtual call), then the inlined
// children.FreeOwnedNodes(): unlink+free each node THEN delete its child,
// then free the remaining nodes + sentinel, then the dwWidget base dtor.
// Note: the child delete is a real C++ `delete` here instead of dwList's
// raw MSVC vtbl-slot-0 call (identical behavior: virtual dtor + free); the
// original's C++ EH unwind frame around the loop is dropped.
dwWidgetGroup::~dwWidgetGroup()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;

    dwWidgetGroup::FreeImages(); // @43c040, called directly in the binary

    pSent = this->children.pSentinel;
    pNode = pSent->pNext;
    while (pNode != pSent)
    {
        pChild = (dwWidget*)pNode->pData;
        pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        pNode->pNext = NULL;
        pNode->pPrev = NULL;
        free(pNode);
        if (pChild != NULL)
            delete pChild; // binary: child vtbl slot 0 (scalar-deleting dtor, flag 1)
        pNode = pNext;
    }
    // Trailing inlined list-dtor part: frees any remaining nodes — none by
    // now — plus the sentinel (children.pSentinel left dangling, as in the
    // binary; the object is dead after this).
    this->children.Free();

    // dwWidget base dtor runs automatically (binary: explicit tail call).
}

// ---- input forwarding ------------------------------------------------------------

// @444450 — first ENABLED child whose rect contains (x, y), until handled.
int dwWidgetGroup::OnMouseMove(int16_t x, int16_t y)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;
    dwPoint pt;
    int handled;

    pt.x = x;
    pt.y = y;
    handled = 0;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && handled == 0)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->bEnabled != 0 && pChild->ContainsPoint(&pt) != 0)
            handled = pChild->OnMouseMove(x, y); // vtbl +0x04
        pNode = pNext;
    }
    return handled;
}

// @4444d0 — same walk as OnMouseMove, forwarding OnMouseDown.
int dwWidgetGroup::OnMouseDown(int16_t x, int16_t y)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;
    dwPoint pt;
    int handled;

    pt.x = x;
    pt.y = y;
    handled = 0;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && handled == 0)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->bEnabled != 0 && pChild->ContainsPoint(&pt) != 0)
            handled = pChild->OnMouseDown(x, y); // vtbl +0x08
        pNode = pNext;
    }
    return handled;
}

// @444550 — same walk as OnMouseMove, forwarding OnMouseUp.
int dwWidgetGroup::OnMouseUp(int16_t x, int16_t y)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;
    dwPoint pt;
    int handled;

    pt.x = x;
    pt.y = y;
    handled = 0;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && handled == 0)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->bEnabled != 0 && pChild->ContainsPoint(&pt) != 0)
            handled = pChild->OnMouseUp(x, y); // vtbl +0x0c
        pNode = pNext;
    }
    return handled;
}

// @4445d0 — every ENABLED child (no containment test), until handled.
int dwWidgetGroup::OnKey(int key, int repeat)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;
    int handled;

    handled = 0;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && handled == 0)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->bEnabled != 0)
            handled = pChild->OnKey(key, repeat); // vtbl +0x10
        pNode = pNext;
    }
    return handled;
}

// @444620 — per-frame tick broadcast to every ENABLED child (no early out).
void dwWidgetGroup::Update(float dt)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;

    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->bEnabled != 0)
            pChild->Update(dt); // vtbl +0x14
        pNode = pNext;
    }
}

// @444670 — first child whose rect contains (x, y), until handled. Binary
// quirk kept: NO bEnabled check on this path (unlike the mouse buttons).
int dwWidgetGroup::OnHover(int16_t x, int16_t y)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;
    dwPoint pt;
    int handled;

    pt.x = x;
    pt.y = y;
    handled = 0;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && handled == 0)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->ContainsPoint(&pt) != 0)
            handled = pChild->OnHover(x, y); // vtbl +0x18
        pNode = pNext;
    }
    return handled;
}

// @4446e0 — every ENABLED child, until one handles the message; returns the
// last handler result (0 when nobody handled it).
int dwWidgetGroup::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;
    int handled;

    handled = 0;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && handled == 0)
    {
        pNext = pNode->pNext;
        pChild = (dwWidget*)pNode->pData;
        if (pChild->bEnabled != 0)
            handled = pChild->OnMessage(pMsg); // vtbl +0x1c
        pNode = pNext;
    }
    return handled;
}

// ---- geometry / hit testing --------------------------------------------------------

// @444780 — translate the group's own rect, then every child (no checks).
void dwWidgetGroup::Move(int16_t dx, int16_t dy)
{
    dwListNode* pNode;

    this->left += dx;
    this->top += dy;
    this->right += dx;
    this->bottom += dy;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel)
    {
        ((dwWidget*)pNode->pData)->Move(dx, dy); // vtbl +0x28
        pNode = pNode->pNext; // binary reads the link AFTER the call
    }
}

// @444410 — first child HitTest hit (no enabled/containment pre-checks; the
// group never returns itself).
dwWidget* dwWidgetGroup::HitTest(dwPoint* pPt)
{
    dwListNode* pNode;
    dwWidget* pHit;

    pHit = NULL;
    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel && pHit == NULL)
    {
        pHit = ((dwWidget*)pNode->pData)->HitTest(pPt); // vtbl +0x38
        pNode = pNode->pNext; // binary reads the link AFTER the call
    }
    return pHit;
}

// ---- image lifetime / paint ----------------------------------------------------------

// @4447e0 — broadcast to ALL children (no enabled check).
void dwWidgetGroup::EnsureImages()
{
    dwListNode* pNode;

    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel)
    {
        ((dwWidget*)pNode->pData)->EnsureImages(); // vtbl +0x3c
        pNode = pNode->pNext; // binary reads the link AFTER the call
    }
}

// @43c040 (Ghidra: dwWidgetGroup_FreeChildImages) — broadcast to ALL
// children (no enabled check). Sits at vtbl +0x40 (FreeImages) and is also
// called directly by the dtor.
void dwWidgetGroup::FreeImages()
{
    dwListNode* pNode;

    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel)
    {
        ((dwWidget*)pNode->pData)->FreeImages(); // vtbl +0x40
        pNode = pNode->pNext; // binary reads the link AFTER the call
    }
}

// @444730 — DrawChild on ALL children (enabled or not — visibility is the
// dirty-rect/clip machinery's problem): each child clips itself against the
// destination bounds ∩ pClipRect ∩ its own rect and paints via its Draw.
void dwWidgetGroup::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwListNode* pNode;

    pNode = this->children.pSentinel->pNext;
    while (pNode != this->children.pSentinel)
    {
        ((dwWidget*)pNode->pData)->DrawChild(pDestBits, pClipRect); // @4424b0
        pNode = pNode->pNext; // binary reads the link AFTER the call
    }
}
