#ifndef _DWWIDGETGROUP_H
#define _DWWIDGETGROUP_H

// dwWidgetGroup — the DroidWorks container widget base: a dwWidget owning a
// list of child widgets, with every input/tick/paint virtual forwarding to
// the children. Screens, panels and every composite control derive from it.
//
// Decompiled from DroidWorks.exe, unit range 0x444320-0x44481x, plus the
// dtor pair @0x402870/0x402890 (mis-binned in the dwAnim range) and the
// FreeImages broadcast @0x43c040 (shared with the dwList COMDAT cluster).
// vtable @0x51e0c0 (dwWidgetGroup_vtbl).
//
// Binary layout: { dwWidget base @0x00 (0xe); dwListNode* pChildren @0x10 }
// — sizeof 0x14. pChildren is the sentinel pointer of a circular dwList
// whose node payloads (node->pData) are child dwWidget*. Here that is the
// dwList class by value (layout-identical: one pointer).
//
// Child ownership: the group dtor DELETES every child (virtual dtor) and
// frees the list nodes + sentinel. Insertion is done by the derived classes
// directly on the list (children.InsertAfter). Forwarding quirks worth
// knowing (all faithful to the binary):
//  - OnMouseMove/Down/Up forward only to ENABLED children whose rect
//    contains the point; OnHover forwards on containment WITHOUT the
//    enabled check; OnKey/Update/OnMessage forward on enabled alone;
//    HitTest/Draw/Move/EnsureImages/FreeImages forward to ALL children.
//  - every "until handled" loop walks the list in insertion order and stops
//    at the first child returning nonzero.

#include "Dw/dwWidget.h"

// C++-ONLY header (container base; every consumer is a C++ control/screen).
// C code passes groups around as `typedef struct dwWidgetGroup dwWidgetGroup;`
// opaque forward decls.
#ifndef __cplusplus
#error "Dw/dwWidgetGroup.h is C++-only; C consumers forward-declare `typedef struct dwWidgetGroup dwWidgetGroup;`"
#endif

#include "Dw/dwList.h"

struct dwWidgetGroup : dwWidget
{
    dwList children; // 0x10 (Ghidra: pChildren — the dwList sentinel pointer);
                     // node->pData = child dwWidget*

    // Full-screen group (the binary built the mode-sized rect inline and
    // called the rect ctor — identical to the dwWidget default ctor). @444320
    dwWidgetGroup();
    // Group covering *pRect. @4443b0
    dwWidgetGroup(dwRect* pRect);

    // FreeImages on every child, then DELETE every child (virtual dtor) and
    // free the list nodes + sentinel. @402870 (DtorDelete) / @402890 (body;
    // both mis-binned in the dwAnim range)
    virtual ~dwWidgetGroup();

    virtual int OnMouseMove(int16_t x, int16_t y);    // vtbl +0x04 @444450 — enabled + containing child, until handled
    virtual int OnMouseDown(int16_t x, int16_t y);    // vtbl +0x08 @4444d0 — enabled + containing child, until handled
    virtual int OnMouseUp(int16_t x, int16_t y);      // vtbl +0x0c @444550 — enabled + containing child, until handled
    virtual int OnKey(int key, int repeat);           // vtbl +0x10 @4445d0 — enabled children, until handled
    virtual void Update(float dt);                    // vtbl +0x14 @444620 — tick broadcast to enabled children
    virtual int OnHover(int16_t x, int16_t y);        // vtbl +0x18 @444670 — containing child (NO enabled check), until handled
    virtual int OnMessage(dwWidgetMsg* pMsg);         // vtbl +0x1c @4446e0 — enabled children, until handled
    virtual void Move(int16_t dx, int16_t dy);        // vtbl +0x28 @444780 — translate own rect + all children
    virtual dwWidget* HitTest(dwPoint* pPt);          // vtbl +0x38 @444410 — first child HitTest hit (no checks, no self)
    virtual void EnsureImages();                      // vtbl +0x3c @4447e0 — broadcast to ALL children
    virtual void FreeImages();                        // vtbl +0x40 @43c040 (Ghidra: dwWidgetGroup_FreeChildImages) — broadcast to ALL children
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // vtbl +0x44 @444730 — DrawChild on ALL children (clip handling per child)

    // Inherited from dwWidget (not overridden in the binary vtable):
    // Enable/Disable/ContainsPoint/GetRect/Invalidate.
};

#endif // _DWWIDGETGROUP_H
