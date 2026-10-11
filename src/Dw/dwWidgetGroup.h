#ifndef _DWWIDGETGROUP_H
#define _DWWIDGETGROUP_H

// dwWidgetGroup — the DroidWorks container widget base: a dwWidget owning a
// list of child widgets, with every input/tick/paint virtual forwarding to
// the children. Screens, panels and every composite control derive from it.
//
// Decompiled from DroidWorks.exe, plus the
// dtor pair dwWidgetGroup_DtorDelete/dwWidgetGroup_Dtor (mis-binned in the dwAnim range) and the
// FreeImages broadcast dwWidgetGroup_FreeChildImages (shared with the dwList COMDAT cluster).
// dwWidgetGroup_vtbl.
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
    // called the rect ctor — identical to the dwWidget default ctor).
    dwWidgetGroup();
    // Group covering *pRect.
    dwWidgetGroup(dwRect* pRect);

    // FreeImages on every child, then DELETE every child (virtual dtor) and
    // free the list nodes + sentinel. (DtorDelete and the body are
    // both mis-binned in the dwAnim range)
    virtual ~dwWidgetGroup();

    virtual int OnMouseMove(int16_t x, int16_t y);    // vtbl +0x04 dwWidgetGroup_OnMouseMove — enabled + containing child, until handled
    virtual int OnMouseDown(int16_t x, int16_t y);    // vtbl +0x08 dwWidgetGroup_OnMouseDown — enabled + containing child, until handled
    virtual int OnMouseUp(int16_t x, int16_t y);      // vtbl +0x0c dwWidgetGroup_OnMouseUp — enabled + containing child, until handled
    virtual int OnKey(int key, int repeat);           // vtbl +0x10 dwWidgetGroup_OnKey — enabled children, until handled
    virtual void Update(float dt);                    // vtbl +0x14 dwWidgetGroup_Update — tick broadcast to enabled children
    virtual int OnHover(int16_t x, int16_t y);        // vtbl +0x18 dwWidgetGroup_OnHover — containing child (NO enabled check), until handled
    virtual int OnMessage(dwWidgetMsg* pMsg);         // vtbl +0x1c dwWidgetGroup_OnMessage — enabled children, until handled
    virtual void Move(int16_t dx, int16_t dy);        // vtbl +0x28 dwWidgetGroup_Move — translate own rect + all children
    virtual dwWidget* HitTest(dwPoint* pPt);          // vtbl +0x38 dwWidgetGroup_HitTest — first child HitTest hit (no checks, no self)
    virtual void EnsureImages();                      // vtbl +0x3c dwWidgetGroup_EnsureImages — broadcast to ALL children
    virtual void FreeImages();                        // vtbl +0x40 (Ghidra: dwWidgetGroup_FreeChildImages) — broadcast to ALL children
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // vtbl +0x44 dwWidgetGroup_Draw — DrawChild on ALL children (clip handling per child)

    // Inherited from dwWidget (not overridden in the binary vtable):
    // Enable/Disable/ContainsPoint/GetRect/Invalidate.
};

#endif // _DWWIDGETGROUP_H
