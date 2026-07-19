// dwControlPanel — conf-driven container of hotspot controls (+ the inner
// dwControlPanelHelpRect help-hotspot widget) and the shared
// dw_aPartSlotColors table init.
//
// Decompiled from DroidWorks.exe, unit range 0x4096c0-0x409faf (9 functions;
// vtables dwControlPanel_vtbl @0x51e708 / dwControlPanelHelpRect_vtbl
// @0x51e750). Built only by dwGuiReference_CreateControl (keyword
// CONTROLPANEL); dwGuiScreen_CreateControl's HELPRECT branch builds the
// help-rect class too (wire-up once this file lands).
//
// Module statics: only dw_aPartSlotColors — (re)filled by
// dwControlPanel_Startup (the binary's whole Startup body; dw_Startup calls
// it, the orchestrator wires dwMain_Startup).

#include "Dw/dwControlPanel.h"

#include "Dw/dwWorkshopCtrl.h" // dwWorkshopCtrl (BUTTON keyword)
#include "Dw/dwGuiReference.h" // dwGuiRefTile (RECT) + dwGuiRefRadioGroup/AddCategory (CP_RADIOGROUP)
#include "Dw/dwGuiScreen.h"    // dwGuiScreen_LocalizeString
#include "Dw/dwList.h"

#include "jk.h"
#include "stdPlatform.h" // stdPlatform_Printf (stub reporter)

#include <stdlib.h> // atoi (binary: CRT atoi @0x507d10), free
#include <string.h> // memcpy

// ---- module globals ------------------------------------------------------------

// Part connector-type -> DW palette color index for the 3D slot markers.
// Binary: uchar[10] @0x53d6b8 (.data, but the binary re-writes it in Startup
// anyway — see below).
extern "C" uint8_t dw_aPartSlotColors[10];
uint8_t dw_aPartSlotColors[10];

// ---- module init ----------------------------------------------------------------

// @4096c0 (dwControlPanel_Startup, called from dw_Startup @419d40) — the
// function's ONLY job: fill the shared dw_aPartSlotColors table (binary:
// builtin_memcpy of the 10-byte constant). Not control-panel state — the
// table merely lives in this compile unit. Doubles as this module's
// soft-reset hook (no other statics).
extern "C" void dwControlPanel_Startup(void)
{
    static const uint8_t aInitColors[10] = {
        0x1f, 0x05, 0x2c, 0x05, 0x2c, 0x53, 0x12, 0x05, 0x05, 0x39
    };
    memcpy(dw_aPartSlotColors, aInitColors, sizeof(dw_aPartSlotColors));
}

// ---- dwControlPanel ---------------------------------------------------------------

// @409710 (dwControlPanel_Ctor) — caller (dwGuiReference_CreateControl
// CONTROLPANEL branch): ParseRect -> rect, ParseULong -> code,
// LocalizeString(conf cursor) -> filename (skips the build entirely on a
// sentinel filename), new(0x28). Note: the binary passed the 8-byte rect BY
// VALUE; a pointer here like every other control ctor (same semantics — the
// base ctor copies it). pStringTable is pre-zeroed and only assigned when
// pTable is non-NULL (faithful, though the net effect is identical).
// EnsureLoaded() at the end means the .cp file is parsed AT CONSTRUCTION.
dwControlPanel::dwControlPanel(dwRect* pRect, uint32_t code, char* pConfName, dwStringTable* pTable)
    : dwWidgetGroup(pRect)
    , confName(pConfName, 0)
    , pStringTable(NULL)
    , helpCode((int32_t)code)
{
    if (pTable != NULL)
        this->pStringTable = pTable;
    this->EnsureLoaded();
}

// @4097b0 (dwControlPanel_Dtor; scalar-deleting wrapper @409790, vtbl +0x00).
// Binary order: delete every child + unlink/free its node (the same
// unlink-zero-free-then-delete shape as the group dtor), then the confName
// dwString dtor (implicit member dtor here), then the inlined ~dwWidgetGroup
// (whose FreeImages broadcast + child loop run over the now-empty list and
// free the sentinel) and the dwWidget base dtor — all of which C++ dtor
// sequencing reproduces exactly.
dwControlPanel::~dwControlPanel()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidget* pChild;

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
        free(pNode); // binary: stdPlatform_FreeHandle, freed BEFORE the child delete
        if (pChild != NULL)
            delete pChild; // binary: child vtbl slot 0 (scalar-deleting dtor, flag 1)
        pNode = pNext;
    }
}

// @409920 (dwControlPanel_OnHover, vtbl +0x18) — forward hover to the FIRST
// child whose rect contains the point (left/top inclusive, right/bottom
// exclusive; the binary reads the rect fields directly — no enabled check,
// no virtual ContainsPoint) and return its result. When nothing is under the
// cursor, notify the panel-default help code ({ 0x7531, helpCode, 0, NULL }
// to dwWidget_pDefault) and return 1. Children iterate in reverse conf order
// (see LoadFromConf).
int dwControlPanel::OnHover(int16_t x, int16_t y)
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwWidget* pChild;

    pSent = this->children.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pChild = (dwWidget*)pNode->pData;
        if (x >= pChild->left && x < pChild->right && y >= pChild->top && y < pChild->bottom)
        {
            return pChild->OnHover(x, y); // virtual, vtbl +0x18
        }
    }
    return this->OnHoverNotify((void*)(intptr_t)this->helpCode); // dispatches + returns 1
}

// @409f70 (dwControlPanel_Draw, vtbl +0x44) — verbatim pass-through to the
// group paint; kept as a real override to mirror the binary vtable.
void dwControlPanel::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwWidgetGroup::Draw(pDestBits, pClipRect);
}

// @409ab0 (dwControlPanel_EnsureLoaded) — parse guard: only while the child
// list is still empty. Only binary caller: the ctor.
void dwControlPanel::EnsureLoaded()
{
    if (this->children.pSentinel->pNext == this->children.pSentinel)
        this->LoadFromConf(this->confName.pBuffer);
}

// @4099d0 (dwControlPanel_LoadFromConf) — open the .cp conf (the WHOLE body,
// open through close, is skipped when pFilename is NULL), then per line:
// ReadLine + NextToken -> ParseControl; every control built is PREPENDED to
// the child list (InsertAfter(pSentinel) — so children sit in REVERSE conf
// order, faithful). Ends with a virtual Invalidate() and Close.
// Quirk (faithful): the loop tests bEof BEFORE ReadLine, so the read that
// hits EOF still runs its (empty) line through ParseControl.
void dwControlPanel::LoadFromConf(char* pFilename)
{
    dwConfFile conf;
    char* pKeyword;
    dwWidget* pControl;

    if (pFilename == NULL)
        return;

    dwConfFile_Open(&conf, pFilename);
    while (!conf.bEof)
    {
        dwConfFile_ReadLine(&conf);
        pKeyword = dwConfFile_NextToken(&conf);
        pControl = this->ParseControl(pKeyword, &conf);
        if (pControl != NULL)
        {
            this->children.InsertAfter(this->children.pSentinel, pControl);
        }
    }
    this->Invalidate(); // virtual, vtbl +0x34
    dwConfFile_Close(&conf);
}

// @409ad0 (dwControlPanel_ParseControl) — the keyword factory for one conf
// line. Token layouts (every "localized" token goes through
// dwGuiScreen_LocalizeString(tok, this->pStringTable) first; atoi = CRT atoi
// @507d10):
//   CP_RADIOGROUP l t r b nItems, then nItems item LINES (see below)
//   BUTTON        l t r b cmdId imgNormal sndOff imgPressed sndClick
//                 (l/t/r/b/cmdId/imgNormal/imgPressed localized; the two
//                 sound tokens raw) -> dwWorkshopCtrl(..., bToggle=0)
//   RECT          rect(ParseRect) a(ParseULong) b(ParseULong) -> dwGuiRefTile
//   HELPRECT      rect(ParseRect) code(ParseULong) -> dwControlPanelHelpRect
// Unknown keywords return NULL silently (no log in the binary).
dwWidget* dwControlPanel::ParseControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect;

    rect.left = 0;
    rect.top = 0;
    rect.right = 0;
    rect.bottom = 0;

    if (dwString_Equals(pKeyword, "CP_RADIOGROUP"))
    {
        uint32_t nItems;

        rect.left = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.top = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.right = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        nItems = 0;
        dwConfFile_ParseULong(pConf, &nItems);

        // binary: new(0x18) dwGuiRefRadioGroup_Ctor @42a540(&rect), then one
        // dwGuiRefRadioGroup_AddCategory @42a6f0 per item line (@409c1c-409d19;
        // same localized/raw token pattern as the BUTTON branch).
        dwGuiRefRadioGroup* pGroup = new dwGuiRefRadioGroup(&rect);

        while (nItems != 0)
        {
            nItems--;
            if (pConf->bEof) // faithful: tested after the decrement, before the read
                break;
            dwConfFile_ReadLine(pConf);

            dwRect itemRect;
            itemRect.left   = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
            itemRect.top    = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
            itemRect.right  = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
            itemRect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
            int cmdId = atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
            char* pImgNormal  = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
            char* pSndOff     = dwConfFile_NextToken(pConf); // raw (NOT localized)
            char* pImgPressed = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
            char* pSndClick   = dwConfFile_NextToken(pConf); // raw (NOT localized)
            dwGuiRefRadioGroup_AddCategory(pGroup, &itemRect, pImgNormal, pSndOff, pImgPressed,
                                           pSndClick, cmdId);
        }
        return pGroup;
    }

    if (dwString_Equals(pKeyword, "BUTTON"))
    {
        int cmdId;
        char* pImgNormal;
        char* pSndOff;
        char* pImgPressed;
        char* pSndClick;

        rect.left = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.top = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.right = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        cmdId = atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        pImgNormal = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
        pSndOff = dwConfFile_NextToken(pConf); // raw (NOT localized)
        pImgPressed = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
        pSndClick = dwConfFile_NextToken(pConf); // raw (NOT localized)

        // binary: new(0x50) dwWorkshopCtrl_Ctor @4071a0, momentary (bToggle=0)
        return new dwWorkshopCtrl(&rect, pImgNormal, pSndOff, pImgPressed, pSndClick, cmdId, 0);
    }

    if (dwString_Equals(pKeyword, "RECT"))
    {
        uint32_t a;
        uint32_t b;

        dwConfFile_ParseRect(pConf, &rect);
        a = 0;
        b = 0;
        dwConfFile_ParseULong(pConf, &a);
        dwConfFile_ParseULong(pConf, &b);
        // binary: new(0x14) dwGuiRefTile_Ctor @42a890(&rect, a, b) — nested-frame
        // decoration (color, count).
        return new dwGuiRefTile(&rect, (uint8_t)a, (uint8_t)b);
    }

    if (dwString_Equals(pKeyword, "HELPRECT"))
    {
        uint32_t code;

        dwConfFile_ParseRect(pConf, &rect);
        code = 0;
        dwConfFile_ParseULong(pConf, &code);
        // binary: new(0x14) built INLINE — dwWidget(&rect), helpCode = code,
        // vptr = dwControlPanelHelpRect_vtbl @0x51e750
        return new dwControlPanelHelpRect(&rect, (int32_t)code);
    }

    return NULL;
}

// ---- dwControlPanelHelpRect ---------------------------------------------------

// No standalone binary ctor — both factories (ParseControl above @409ef5 and
// dwGuiScreen_CreateControl's HELPRECT branch) build the object inline with
// exactly this shape.
dwControlPanelHelpRect::dwControlPanelHelpRect(dwRect* pRect, int32_t code)
    : dwWidget(pRect)
    , helpCode(code)
{
}

// @409f90 (dwControlPanelHelpRect_DtorDelete, vtbl +0x00) — the dtor body is
// the plain dwWidget dtor (COMDAT thunk j_dwWidgetDtor @409fb0); nothing of
// our own to destroy.
dwControlPanelHelpRect::~dwControlPanelHelpRect()
{
}

// vtbl +0x18 @419780 — the shared dwWidget_OnHoverNotify COMDAT body (it
// reads binary +0x10 — this class's helpCode — as the msg sender): dispatch
// { 0x7531, helpCode, 0, NULL } to dwWidget_pDefault and return 1.
int dwControlPanelHelpRect::OnHover(int16_t x, int16_t y)
{
    (void)x;
    (void)y;
    return this->OnHoverNotify((void*)(intptr_t)this->helpCode);
}
