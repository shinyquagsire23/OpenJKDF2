// dwGuiScreen — the foundational DroidWorks SCREEN base class (screen-as-
// widget + screen-as-app-flow-segment MI), the shared control factories, THE
// game-wide string-table lookup (dwGuiScreen_LocalizeString), the tooltip
// machinery and the base cheat-code matcher.
//
// Decompiled from DroidWorks.exe, unit range 0x42f930-0x43214f, plus:
//   - EnsureImages @0x432150 / FreeImages @0x432170 (base defaults physically
//     just past the unit end, mis-binned into the dwGuiWidgets range)
//   - Update(dt) slot body @0x41c510 (shared COMDAT, Ghidra: mis-attributed
//     dwGuiMission_ForwardUpdate) and OnHover slot body @0x40ba70 (undetected
//     fn in the dwGuiCredits range) — both trivial forwards into `controls`
// See dwGuiScreen.h for the class/vtable/layout documentation.
//
// Adaptations (each marked with a Note at its site):
//  - display bpp reads (binary global DAT_006b17e4, bits) map to
//    stdDisplay_pCurVideoMode->format.format.bpp with a NULL guard.
//  - the 8bpp screen-sized background/snapshot copies go through
//    stdBitmapRle2_InstantiateCopy (P8 stub in dwAnim.cpp until the RLE unit
//    lands — returns NULL, all uses are NULL-guarded like the binary).
//  - BACKGROUND image loads go through dwImage_LoadFile (the translated
//    dispatcher; the binary's first-load path used its 0x444c50 sibling).
//  - not-yet-translated control classes are stubbed: the branch parses its
//    tokens faithfully, logs a TODO(dw-decomp) line and returns NULL.
//
// Cross-unit symbols still owned elsewhere are declared extern below — see
// the TODO(dw-decomp) block.

#include "Dw/dwGuiScreen.h"

#include "Dw/dwAnim.h"        // dwAnim (tutorial FLC widget) + dwAnim_Open
#include "Dw/dwImage.h"       // dwImage/dwImageBits + dwImage_LoadFile
#include "Dw/dwImageVBuf.h"   // dwImageVBuf (16bpp background copy, screen image)
#include "Dw/dwImageDraw.h"   // dwImageDraw_FillRect/ShadeRect
#include "Dw/dwDisplay.h"     // dwDisplay_pScreenImage/pDirtyList/AddDirtyRect/Present
#include "Dw/dwCursor.h"      // dwCursor_SetCursor, dwCursor_pos
#include "Dw/dwSound.h"       // dwSound_pManager (FreeAllSamples), dwSound_SetMusic
#include "Dw/dwColormap.h"    // dwColormap_Load
#include "Dw/dwConfFile.h"    // conf parsing
#include "Dw/dwStringTable.h" // dwStringTable (STRINGTABLE keyword + lookups)
#include "Dw/dwGuiHypText.h"  // dwGuiHypText (TEXT keyword)
#include "Dw/dwWorkshopCtrl.h" // dwWorkshopCtrl/dwWcButtonBlink (BUTTON/TOGGLE/BUTTON_BLINK)
#include "Dw/dwGuiButton.h"   // dwGuiTextButton/dwGuiClock (BUTTON_TEXT[_LEFT]/CLOCK)
#include "Dw/dwControlPanel.h" // dwControlPanelHelpRect (HELPRECT)
#include "Dw/dwGuiViewBox.h"  // dwGuiImage (IMAGE)
#include "Dw/dwGuiTextMisc.h" // dwGuiTextPopup/dwGuiTimer (TEXTPOPUP/TIMER)
#include "Dw/dwGuiWidgets.h"  // dwGuiScrollBar (SCROLLBAR)
#include "Dw/dwGuiWidgetBar.h" // dwGuiWidgetBar (WIDGETBAR)
#include "Dw/dwMission.h"     // dwMissionSequence (msg 0x66)
#include "Dw/dwGuiOptions.h"  // dwGuiRanking (STATS_JOB) + dwGuiOptions_NewEnterSeg (msg 0x65)
#include "Dw/dwGuiQuickView.h" // dwGuiQuickView (QUICKVIEW)
#include "Dw/dwGuiStatsPart.h"  // dwGuiStatsPart (STATS_PART)
#include "Dw/dwGuiStatsDroid.h" // dwGuiStatsDroid (STATS_DROID)
#include "Dw/dwGuiInGame.h"    // dwGuiInGame_New/CheckDroidValid (msg 0x67 deploy)

#include "jk.h"
#include "stdPlatform.h" // stdPlatform_Printf

#include <ctype.h>  // isspace (binary: CRT isspace @0x507d80)
#include <stdlib.h> // malloc/free (binary: dwHS alloc/free) for the POD records

// These engine headers have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/stdDisplay.h" // stdDisplay_pCurVideoMode (binary 0x6478f8; bpp = DAT_006b17e4)
}

// ---- cross-unit externs (TODO(dw-decomp): provided by other units) ----------

// The GLOBAL string table (Global.str) loaded by dw_Startup; the localization
// fallback in dwGuiScreen_LocalizeString.
// TODO(dw-decomp): provided by the dw core unit (dw part2, P7). Binary global
// @0x53d958 (dwCore_pGlobalStrings).
extern "C" dwStringTable* dwCore_pGlobalStrings;

// Nonzero when the recorded-input cue playlist is empty (binary: the direct
// global read `dwSegment_pCueList == dwSegment_pCueList->pNext` @0x53e858 —
// the sentinel is a static inside dwSegment.cpp here, so an accessor is
// needed). Used by the tutorial auto-exit in Update(void).
// TODO(dw-decomp): provided by dwSegment (one-line accessor over its static
// playlist sentinel).
extern "C" int dwSegment_IsPlaylistEmpty(void);

// Forces RenderActive to repaint the whole screen instead of walking the
// dirty-rect list. TODO(dw-decomp): provided by the dwMain unit (P7). Binary
// global @0x53e854 (dwMain_bFullRedraw).
extern "C" uint8_t dwMain_bFullRedraw;

// 8bpp screen-sized image copy (background/snapshot). Currently a loud P8
// stub returning NULL, defined in dwAnim.cpp.
// TODO(dw-decomp): provided by the stdBitmapRle2 engine-side unit (P8).
extern "C" dwImage* stdBitmapRle2_InstantiateCopy(dwImage* pSrc, int16_t width, int16_t height); // @442ec0
extern "C" dwImage* stdBitmapRle2_LoadFile16(char* pFilePath); // @444c50 (BACKGROUND: forces a lockable buffer)

// ---- module init -------------------------------------------------------------

// Note: no binary counterpart — the unit owns no module statics; kept for the
// soft-reset convention. @-
extern "C" void dwGuiScreen_Startup(void)
{
}

// ---- local helpers -----------------------------------------------------------

// Shared stub reporter for not-yet-translated control classes.
static dwWidget* dwGuiScreen_StubControl(const char* pKeyword, const char* pClass, const char* pUnit)
{
    stdPlatform_Printf("TODO(dw-decomp): dwGuiScreen control '%s' -> %s (unit %s) not translated yet\n",
                       pKeyword, pClass, pUnit);
    return NULL;
}

// Capture the current screen into a new image and darken it to 60% — the
// dimmed backdrop handed to sub-screens spawned by the 0x66/0x68 commands.
// Note: the binary inlines this twice in OnMessage; factored here verbatim.
// The screen-image NULL guard is added (the binary assumes an open display).
static dwImage* dwGuiScreen_CaptureShadedScreen()
{
    dwImage* pSnap;
    dwRect rect;
    dwImageBits bits;
    void* pPixels;
    int stride;

    if (!stdDisplay_pCurVideoMode || !dwDisplay_pScreenImage) // Note: guard added
        return NULL;

    rect.left = 0;
    rect.top = 0;
    rect.right = (int16_t)stdDisplay_pCurVideoMode->format.width;
    rect.bottom = (int16_t)stdDisplay_pCurVideoMode->format.height;

    // Note: binary @0x442ec0 ctor takes (pSrcImage, pRect) with rect always
    // {0,0,w,h}; the P8 placeholder signature takes width/height directly.
    pSnap = stdBitmapRle2_InstantiateCopy((dwImage*)dwDisplay_pScreenImage, rect.right, rect.bottom);
    if (pSnap)
    {
        pPixels = NULL;
        stride = 0;
        pSnap->Lock(&pPixels, &stride); // vtbl +0x0c
        bits.pDesc = &pSnap->desc;      // binary: obj-as-desc alias
        bits.pPixels = pPixels;
        bits.stride = stride;
        dwImageDraw_ShadeRect(&bits, &rect, 0x3c); // 60%
        pSnap->Unlock(); // vtbl +0x10
    }
    return pSnap;
}

// Find pWidget's node in pList and unlink+free it (widget kept). Mirrors the
// binary's inline sentinel walks in the dtor / 0x792a / 0x7932 handlers.
static void dwGuiScreen_UnlinkWidgetNode(dwList* pList, dwWidget* pWidget)
{
    dwListNode* pNode;

    for (pNode = pList->pSentinel->pNext; pNode != pList->pSentinel; pNode = pNode->pNext)
    {
        if ((dwWidget*)pNode->pData == pWidget)
        {
            pList->UnlinkFreeNode(pNode);
            return;
        }
    }
}

// ---- ctor / dtor ---------------------------------------------------------------

// @42f930 (dwGuiScreen_Ctor)
dwGuiScreen::dwGuiScreen(const char* pName, dwImage* pBgSrc)
    : dwWidget()  // full-screen widget rect
    , dwSegment() // pausable segment clock
    , scriptName(pName, 0)
    , colormapName()
    , musicName()
    , pBgImage(NULL)
    , pSnapshotImage(NULL)
    , controls() // full-screen group
    , pTooltipFont(NULL)
    , tooltipBgColor(0)   // Note: zero-init added (binary leaves the two color
    , tooltipTextColor(0) // bytes uninitialized; only read once LABEL_INFO set them)
    , pTooltipTarget(NULL)
    , bTooltipVisible(0)
    , hoverStartSec(0.0f)
    , labels()
    , pStringTable(NULL)
    , lastTickSec(0.0f) // Note: zero-init added (binary leaves it uninitialized until Activate)
    , bActive(0)
    , pPickedWidget(NULL) // Note: zero-init added (binary leaves it uninitialized until pick-mode OnMouseDown)
    , bModal(0)
    , bTutorialHold(0)
    , tutorialMusicName()
    , tutorialRecName()
    , pTutorialAnim(NULL)
    , cheatIndex(0)
{
    this->tooltipRect.left = 0;
    this->tooltipRect.top = 0;
    this->tooltipRect.right = 0;
    this->tooltipRect.bottom = 0;
    this->cheatBuffer[0] = '\0';

    if (pBgSrc)
    {
        // Note: display bpp read adapted (binary: DAT_006b17e4 bits) + NULL
        // guard on the video mode.
        if (stdDisplay_pCurVideoMode && stdDisplay_pCurVideoMode->format.format.bpp < 9)
        {
            // 8bpp: screen-sized stdBitmapRle2 COPY of the source image
            this->pBgImage = stdBitmapRle2_InstantiateCopy(
                pBgSrc,
                (int16_t)stdDisplay_pCurVideoMode->format.width,
                (int16_t)stdDisplay_pCurVideoMode->format.height);
        }
        else if (stdDisplay_pCurVideoMode)
        {
            // 16bpp: owned dwImageVBuf copy at the display depth
            this->pBgImage = new dwImageVBuf(pBgSrc, (uint8_t)stdDisplay_pCurVideoMode->format.format.bpp);
        }
    }

    if (this->scriptName.length != 0)
        this->scriptName.Append(".ifc", 4); // binary: DAT_00528b94 = ".ifc" (interface
                                            // script; NOT ".cmp", which is a colormap file)
}

// @42fb30 (dwGuiScreen_Dtor; scalar-deleting wrapper @42fb10)
dwGuiScreen::~dwGuiScreen()
{
    dwListNode* pNode;
    dwListNode* pNext;
    void* pData;

    dwGuiScreen::FreeImages(); // binary: vptr already re-pointed here — non-virtual

    if (this->pTutorialAnim)
    {
        // unlink its node from the controls list if it is currently a child
        // (0x792a appends it), then destroy the widget itself
        dwGuiScreen_UnlinkWidgetNode(&this->controls.children, this->pTutorialAnim);
        delete this->pTutorialAnim; // virtual dtor (vtbl +0x00, flags 1)
        this->pTutorialAnim = NULL;
    }

    if (this->pBgImage)
        delete this->pBgImage;
    if (this->pSnapshotImage)
        delete this->pSnapshotImage;

    if (this->pStringTable)
        delete this->pStringTable; // dwStringTable_Dtor + free

    if (this->pTooltipFont)
    {
        // Note: fonts are cache-owned (dwFont.c); the binary pairs an ICF'd
        // no-op with stdPlatform_FreeHandle on the heap handle — only the
        // handle is freed.
        free(this->pTooltipFont);
    }

    // labels: free every record payload, then the nodes + sentinel
    for (pNode = this->labels.pSentinel->pNext; pNode != this->labels.pSentinel; pNode = pNext)
    {
        pNext = pNode->pNext;
        pData = pNode->pData;
        this->labels.UnlinkFreeNode(pNode);
        if (pData)
            free(pData);
    }
    this->labels.Free();

    // `controls` member dtor (child widgets deleted) + dwString members +
    // dwSegment/dwWidget base dtors run implicitly after this body.
}

// ---- controls script -----------------------------------------------------------

// @42fdf0 (dwGuiScreen_LoadControls)
void dwGuiScreen::LoadControls(char* pScriptPath)
{
    dwConfFile conf;
    char* pKeyword;
    dwWidget* pCtrl;

    if (!pScriptPath)
        return;

    dwConfFile_Open(&conf, pScriptPath);
    while (!conf.bEof)
    {
        dwConfFile_ReadLine(&conf);
        pKeyword = dwConfFile_NextToken(&conf);
        pCtrl = this->CreateControl(pKeyword, &conf); // virtual +0x48
        if (pCtrl)
            this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, pCtrl); // append
    }
    this->Invalidate(); // virtual +0x34
    dwConfFile_Close(&conf);
}

// @42fed0 (dwGuiScreen_LocalizeString) — THE game-wide string-table lookup.
extern "C" char* dwGuiScreen_LocalizeString(char* pStr, dwStringTable* pTable)
{
    dwString* pVal;

    while (*pStr != '\0' && isspace((unsigned char)*pStr)) // binary: CRT isspace @0x507d80
        pStr++;

    if (pStr != NULL && *pStr != '\0') // Note: vestigial NULL check preserved (already dereferenced above)
    {
        pVal = NULL;
        if (pTable)
            pVal = pTable->Find(pStr);
        if (!pVal)
        {
            if (dwCore_pGlobalStrings)
                pVal = dwCore_pGlobalStrings->Find(pStr);
            if (!pVal)
                return pStr; // not found: the trimmed key itself
        }
        return pVal->pBuffer;
    }
    return pStr;
}

// ---- tooltip -------------------------------------------------------------------

// @42ff30 (dwGuiScreen_FlushTooltipDirty)
void dwGuiScreen::FlushTooltipDirty()
{
    if (this->pTooltipTarget)
    {
        dwDisplay_AddDirtyRect(&this->tooltipRect);
        this->pTooltipTarget = NULL;
        this->bTooltipVisible = 0;
    }
}

// ---- factories -------------------------------------------------------------------

// @42ff60 (Ghidra: dwGuiScreen_CreateControl) — the COMMON free-function
// factory (screen-state-less keywords). Fallback of the virtual factory;
// also called directly by dwEnding_OnActivate.
extern "C" dwWidget* dwGuiScreen_CreateControl(char* pKeyword, dwConfFile* pConf, dwStringTable* pStringTable)
{
    dwRect rect;
    uint32_t param;
    char* pTok1;
    char* pTok2;
    char* pTok3;
    char* pTok4;
    dwAnim* pAnim;

    rect.left = 0;
    rect.top = 0;
    rect.right = 0;
    rect.bottom = 0;
    param = 0;

    if (dwString_Equals(pKeyword, "ANIMATION"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param); // msgCode
        pTok1 = dwConfFile_NextToken(pConf);  // FLC filename
        return dwAnim_Open(&rect, pTok1, (int)param, 1);
    }
    if (dwString_Equals(pKeyword, "ANIM_PLAY"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param);
        pTok1 = dwConfFile_NextToken(pConf);
        pAnim = dwAnim_Open(&rect, pTok1, (int)param, 1);
        if (!pAnim)
            return NULL;
        pAnim->Play((uint8_t)1); // the non-virtual overload (Ghidra: dwAnim_Play)
        return pAnim;
    }
    if (dwString_Equals(pKeyword, "BUTTON"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param); // command id
        pTok1 = dwConfFile_NextToken(pConf);
        pTok2 = dwConfFile_NextToken(pConf);
        pTok3 = dwConfFile_NextToken(pConf);
        pTok4 = dwConfFile_NextToken(pConf);
        // binary: new(0x50) dwWorkshopCtrl_Ctor(&rect, tok1, tok2, tok3, tok4, param, 0)
        return new dwWorkshopCtrl(&rect, pTok1, pTok2, pTok3, pTok4, (int)param, 0);
    }
    if (dwString_Equals(pKeyword, "BUTTON_BLINK"))
    {
        uint32_t blinkParam = 0;
        char* pTok5;
        char* pTok6;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &blinkParam);
        pTok1 = dwConfFile_NextToken(pConf);
        pTok2 = dwConfFile_NextToken(pConf);
        pTok3 = dwConfFile_NextToken(pConf);
        pTok4 = dwConfFile_NextToken(pConf);
        pTok5 = dwConfFile_NextToken(pConf);
        pTok6 = dwConfFile_NextToken(pConf);
        // binary: new(0x74) dwWcButtonBlink_Ctor(&rect, tok1..tok6, blinkParam)
        return new dwWcButtonBlink(&rect, pTok1, pTok2, pTok3, pTok4, pTok5, pTok6, (int)blinkParam);
    }
    if (dwString_Equals(pKeyword, "BUTTON_TEXT") || dwString_Equals(pKeyword, "BUTTON_TEXT_LEFT"))
    {
        // Shared parse (binary: two near-identical branches; BUTTON_TEXT sets
        // bAltDraw=1 and colors (colorA, colorB); BUTTON_TEXT_LEFT sets
        // bAltDraw=0 with the two color bytes SWAPPED (colorB, colorA)).
        uint32_t colorA = 0;
        uint32_t colorB = 0;
        char* pText;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param);   // command id
        pTok1 = dwConfFile_NextToken(pConf);    // font name
        dwConfFile_ParseULong(pConf, &colorA);
        pTok2 = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &colorB);
        pTok3 = dwConfFile_NextToken(pConf);
        pTok4 = dwConfFile_NextToken(pConf);
        pText = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pStringTable);
        // binary: new(0x78) dwGuiTextButton_Ctor(&rect, pText, fontName,
        //   colorNormal, tok2, colorHot, tok3, tok4, param, bAltDraw);
        // BUTTON_TEXT: bAltDraw=1, (colorA, colorB); _LEFT: bAltDraw=0, swapped.
        if (dwString_Equals(pKeyword, "BUTTON_TEXT"))
            return new dwGuiTextButton(&rect, pText, pTok1, (uint8_t)colorA, pTok2,
                                       (uint8_t)colorB, pTok3, pTok4, (int)param, 1);
        return new dwGuiTextButton(&rect, pText, pTok1, (uint8_t)colorB, pTok2,
                                   (uint8_t)colorA, pTok3, pTok4, (int)param, 0);
    }
    if (dwString_Equals(pKeyword, "HELPRECT"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param);
        // binary builds it INLINE: new(0x14) { dwWidget(&rect); helpCode@+0x10 =
        // param; vptr = dwControlPanelHelpRect_vtbl@0x51e750 } (hover hotspot
        // that notifies the help control).
        return new dwControlPanelHelpRect(&rect, (int32_t)param);
    }
    if (dwString_Equals(pKeyword, "IMAGE"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        pTok1 = dwConfFile_NextToken(pConf); // image name
        // binary: new(0x20) dwGuiImage_Ctor(&rect, imageName)
        return new dwGuiImage(&rect, pTok1);
    }
    if (dwString_Equals(pKeyword, "INDICATOR"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        pTok1 = dwConfFile_NextToken(pConf);
        pTok2 = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &param);
        (void)pTok1; (void)pTok2;
        // TODO(dw-decomp): INDICATOR -> dwGuiIndicator (unit dwHelp) —
        // binary: new(0x48) dwGuiIndicator_Ctor(&rect, tok1, tok2, param, 1.0f)
        return dwGuiScreen_StubControl("INDICATOR", "dwGuiIndicator", "dwHelp");
    }
    if (dwString_Equals(pKeyword, "QUICKVIEW"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        // binary: new(0x574) dwGuiQuickView_Ctor(&rect)
        return new dwGuiQuickView(&rect);
    }
    if (dwString_Equals(pKeyword, "RADIOGROUP"))
    {
        uint32_t count = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &count);
        // TODO(dw-decomp): RADIOGROUP -> dwGuiRefRadioGroup (unit dwGuiReference) —
        // binary: new(0x18) dwGuiRefRadioGroup_Ctor(&rect), then per line:
        // ParseRect + ParseULong + 4 tokens -> dwGuiRefRadioGroup_AddCategory.
        dwGuiScreen_StubControl("RADIOGROUP", "dwGuiRefRadioGroup", "dwGuiReference");
        // Note: consume the category lines so the rest of the script still
        // parses (mirrors the binary's alloc-failure path, which also
        // ReadLine-drains them without token parsing).
        for (; count != 0; count--)
        {
            if (pConf->bEof)
                break;
            dwConfFile_ReadLine(pConf);
        }
        return NULL;
    }
    if (dwString_Equals(pKeyword, "RECT"))
    {
        uint32_t param2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param);
        dwConfFile_ParseULong(pConf, &param2);
        // TODO(dw-decomp): RECT -> dwGuiRefTile (unit dwGuiReference) —
        // binary: new(0x14) dwGuiRefTile_Ctor(&rect, param, param2)
        return dwGuiScreen_StubControl("RECT", "dwGuiRefTile", "dwGuiReference");
    }
    if (dwString_Equals(pKeyword, "SCROLLBAR"))
    {
        uint32_t u1 = 0, u2 = 0, u3 = 0;
        int32_t l1 = 0, l2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &u1);
        dwConfFile_ParseULong(pConf, &u2);
        dwConfFile_ParseULong(pConf, &u3);
        dwConfFile_ParseLong(pConf, &l1);
        dwConfFile_ParseLong(pConf, &l2);
        pTok1 = dwConfFile_NextToken(pConf);
        pTok2 = dwConfFile_NextToken(pConf);
        // binary: new(0x5c) dwGuiScrollBar_Ctor(&rect, u1, u2, u3, l1, l2, tok1, tok2)
        return new dwGuiScrollBar(&rect, (int)u1, (int)u2, (int)u3, l1, l2, pTok1, pTok2);
    }
    if (dwString_Equals(pKeyword, "STATS_DROID"))
    {
        uint32_t v1 = 0, v2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pTok1 = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &v1);
        pTok2 = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &v2);
        // binary: new(0xf8) dwGuiStatsDroid_Ctor(&rect, tok1, v1, tok2, v2)
        return new dwGuiStatsDroid(&rect, pTok1, (uint8_t)v1, pTok2, (uint8_t)v2);
    }
    if (dwString_Equals(pKeyword, "STATS_JOB"))
    {
        uint32_t v1 = 0, v2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pTok1 = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &v1);
        pTok2 = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &v2);
        // dwGuiRanking (unit dwGuiOptions, landed) — binary new(0x38)
        // dwGuiRanking_Ctor(&rect, tok1, v1, tok2, v2).
        return new dwGuiRanking(&rect, pTok1, (uint8_t)v1, pTok2, (uint8_t)v2);
    }
    if (dwString_Equals(pKeyword, "STATS_PART"))
    {
        uint32_t c1 = 0, c2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pTok1 = dwConfFile_NextToken(pConf); // label font
        dwConfFile_ParseULong(pConf, &c1);
        pTok2 = dwConfFile_NextToken(pConf); // value font
        dwConfFile_ParseULong(pConf, &c2);
        // binary: new(0x50) dwGuiStatsPart_Ctor(&rect, labelFont, (byte)c1, valueFont, (byte)c2)
        return new dwGuiStatsPart(&rect, pTok1, (uint8_t)c1, pTok2, (uint8_t)c2);
    }
    if (dwString_Equals(pKeyword, "TEXT")) // binary: DAT_005292f4
    {
        uint32_t color = 0;
        char* pText;
        pTok1 = dwConfFile_NextToken(pConf); // leading token BEFORE the rect (binary quirk)
        dwConfFile_ParseRect(pConf, &rect);
        pTok2 = dwConfFile_NextToken(pConf); // font name
        dwConfFile_ParseULong(pConf, &color);
        pText = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pStringTable);
        // binary: new(0x48) dwGuiHypText_Ctor(&rect, 0, fontName, color, tok1),
        // then frees the ctor's dwString and calls vtbl+0x48 SetText(pText)
        // (SetText APPENDS — the Free keeps it a plain assign).
        {
            dwGuiHypText* pCtrl = new dwGuiHypText(&rect, NULL, pTok2, (uint8_t)color, pTok1);
            pCtrl->text.Free();
            pCtrl->SetText(pText);
            return pCtrl;
        }
    }
    if (dwString_Equals(pKeyword, "TOGGLE"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param);
        pTok1 = dwConfFile_NextToken(pConf);
        pTok2 = dwConfFile_NextToken(pConf);
        pTok3 = dwConfFile_NextToken(pConf);
        pTok4 = dwConfFile_NextToken(pConf);
        // binary: new(0x50) dwWorkshopCtrl_Ctor(&rect, tok1, tok2, tok3, tok4, param, 1)
        // (same ctor as BUTTON with bToggle = 1)
        return new dwWorkshopCtrl(&rect, pTok1, pTok2, pTok3, pTok4, (int)param, 1);
    }

    if (pKeyword == NULL || *pKeyword == '\0')
        return NULL;
    stdPlatform_Printf("Unrecognized UI control %s\n", pKeyword); // Note: binary calls jk_logtofile (compiled-out stub)
    return NULL;
}

// vtbl +0x48 @430a10 (Ghidra: dwGuiScreen_CreateControl2) — the VIRTUAL
// factory: screen-level keywords, falling back to the common factory above.
dwWidget* dwGuiScreen::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect;
    char* pName;

    rect.left = 0;
    rect.top = 0;
    rect.right = 0;
    rect.bottom = 0;

    if (dwString_Equals(pKeyword, "BACKGROUND"))
    {
        pName = dwConfFile_NextToken(pConf);
        if (!pName || *pName == '\0')
            return NULL;
        if (!this->pBgImage)
        {
            // binary: the display-format loader @0x444c50 (LoadFile16), NOT the
            // bpp dispatcher — LoadFile16 passes bIdk=1 to loads_bmp, forcing
            // the decode-into-buffer path (LoadFormat0/ToVBuffer) so a compressed
            // .rle background is a LOCKABLE stdBitmapRle2, not a lazy stdBitmapRle.
            // The composite branch below Locks pBgImage, so it MUST be lockable.
            this->pBgImage = stdBitmapRle2_LoadFile16(pName);
        }
        else
        {
            // subsequent BACKGROUND lines composite onto the existing image
            dwImage* pOverlay = stdBitmapRle2_LoadFile16(pName);
            if (pOverlay)
            {
                void* pPixels = NULL;
                int stride = 0;
                dwImageBits bits;
                this->pBgImage->Lock(&pPixels, &stride); // vtbl +0x0c
                bits.pDesc = &this->pBgImage->desc;      // binary: obj-as-desc alias
                bits.pPixels = pPixels;
                bits.stride = stride;
                pOverlay->Blit(&bits, 0, 0, NULL); // vtbl +0x04 (this = SOURCE)
                delete pOverlay;
                this->pBgImage->Unlock(); // vtbl +0x10
            }
        }
        return NULL;
    }
    if (dwString_Equals(pKeyword, "AMBIENT"))
    {
        this->musicName.AssignCStr(dwConfFile_NextToken(pConf));
        return NULL;
    }
    if (dwString_Equals(pKeyword, "CLOCK"))
    {
        uint32_t param = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pName = dwConfFile_NextToken(pConf); // font name
        dwConfFile_ParseULong(pConf, &param);
        // binary: new(0x20) dwGuiClock_Ctor(rect, fontName, param,
        //   &this-dwSegment-subobject, 0). Note: the binary's 4th arg (the
        //   screen's segment subobject) is stored but only ever NULL-CHECKED
        //   (dwGuiClock_Draw@4086c0 gates on it, then reads the global ms
        //   counter directly) — here it is the plain bRunning flag, and the
        //   member-factory screen is never NULL, so pass 1.
        return new dwGuiClock(rect, pName, (uint8_t)param, 1, 0);
    }
    if (dwString_Equals(pKeyword, "COLORMAP"))
    {
        pName = dwConfFile_NextToken(pConf);
        if (pName && *pName != '\0')
            this->colormapName.AssignCStr(pName);
        // 16bpp displays convert immediately; 8bpp waits for Activate.
        // Note: bpp read adapted (binary: videomode+0x20 == 0x10).
        if (stdDisplay_pCurVideoMode && stdDisplay_pCurVideoMode->format.format.bpp == 0x10
            && this->colormapName.length != 0)
        {
            dwColormap_Load(this->colormapName.pBuffer);
        }
        return NULL;
    }
    if (dwString_Equals(pKeyword, "LABEL_INFO"))
    {
        uint32_t v = 0;
        pName = dwConfFile_NextToken(pConf);
        if (pName && *pName != '\0')
        {
            // Note: binary leaks any previous font handle here — preserved.
            dwFont* pFont = (dwFont*)malloc(sizeof(dwFont));
            this->pTooltipFont = pFont ? dwFont_Load(pFont, pName) : NULL;
        }
        dwConfFile_ParseULong(pConf, &v);
        this->tooltipBgColor = (uint8_t)v;
        dwConfFile_ParseULong(pConf, &v);
        this->tooltipTextColor = (uint8_t)v;
        return NULL;
    }
    if (dwString_Equals(pKeyword, "LABEL"))
    {
        char* pRaw;
        char* pText;
        char* pChildKeyword;
        dwWidget* pCtrl;
        dwGuiScreenLabel* pLabel;

        pRaw = dwConfFile_NextToken(pConf);
        pText = dwGuiScreen_LocalizeString(pRaw, this->pStringTable);
        if (pText == pRaw)
            pText = NULL; // only keys with a localization get a tooltip
        pChildKeyword = dwConfFile_NextToken(pConf);
        pCtrl = this->CreateControl(pChildKeyword, pConf); // virtual recurse
        if (!pCtrl)
            return NULL;
        if (pText)
        {
            pLabel = (dwGuiScreenLabel*)malloc(sizeof(dwGuiScreenLabel));
            if (pLabel)
            {
                pLabel->left = pCtrl->left; // tooltip zone = the wrapped control's rect
                pLabel->top = pCtrl->top;
                pLabel->right = pCtrl->right;
                pLabel->bottom = pCtrl->bottom;
                pLabel->pText = pText;
                this->labels.InsertAfter(this->labels.pSentinel->pPrev, pLabel); // append
            }
        }
        return pCtrl;
    }
    if (dwString_Equals(pKeyword, "LABEL_RECT"))
    {
        char* pRaw;
        char* pText;
        dwGuiScreenLabel* pLabel;

        pRaw = dwConfFile_NextToken(pConf);
        pText = dwGuiScreen_LocalizeString(pRaw, this->pStringTable);
        dwConfFile_ParseRect(pConf, &rect);
        if (pRaw == pText)
            return NULL;
        pLabel = (dwGuiScreenLabel*)malloc(sizeof(dwGuiScreenLabel));
        if (pLabel)
        {
            pLabel->left = rect.left;
            pLabel->top = rect.top;
            pLabel->right = rect.right;
            pLabel->bottom = rect.bottom;
            pLabel->pText = pText;
            this->labels.InsertAfter(this->labels.pSentinel->pPrev, pLabel); // append
        }
        return NULL;
    }
    if (dwString_Equals(pKeyword, "STRINGTABLE"))
    {
        pName = dwConfFile_NextToken(pConf);
        if (!pName || *pName == '\0')
            return NULL;
        if (this->pStringTable)
            return NULL; // only the first STRINGTABLE line wins
        this->pStringTable = new dwStringTable(pName);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "TEXTPOPUP"))
    {
        uint32_t cmdId = 0, colorA = 0, colorB = 0;
        char* pFontName;
        char* pText1;
        char* pText2;
        char* pTokMid;
        char* pText3;
        char* pTokEnd;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &cmdId);
        pFontName = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &colorA);
        dwConfFile_ParseULong(pConf, &colorB);
        pText1 = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
        pText2 = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
        pTokMid = dwConfFile_NextToken(pConf);
        pText3 = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
        pTokEnd = dwConfFile_NextToken(pConf);
        // binary: new(0x78) dwGuiTextPopup_Ctor(&rect, pText1, fontName, colorA,
        //   colorB, cmdId, pText2, pTokMid, pText3, pTokEnd, 1)
        return new dwGuiTextPopup(&rect, pText1, pFontName, (uint8_t)colorA,
                                  (uint8_t)colorB, (int)cmdId, pText2, pTokMid,
                                  pText3, pTokEnd, 1);
    }
    if (dwString_Equals(pKeyword, "TIMER"))
    {
        float t0 = 0.0f, t1 = 0.0f;
        char* pChildKeyword;
        dwWidget* pChild;
        dwConfFile_ParseFloat(pConf, &t0);
        dwConfFile_ParseFloat(pConf, &t1);
        pChildKeyword = dwConfFile_NextToken(pConf);
        pChild = this->CreateControl(pChildKeyword, pConf); // virtual recurse
        if (!pChild)
            return NULL;
        // binary: new(0x20) dwGuiTimer_Ctor(pChild, t0, t1) — timed show/hide
        // decorator; the timer OWNS (and deletes) the wrapped child.
        return new dwGuiTimer(pChild, t0, t1);
    }
    if (dwString_Equals(pKeyword, "TUTORIAL"))
    {
        char* pFlicName;
        dwRect animRect;
        this->tutorialRecName.AssignCStr(dwConfFile_NextToken(pConf));   // .rec input-cue file
        this->tutorialMusicName.AssignCStr(dwConfFile_NextToken(pConf)); // tutorial music
        pFlicName = dwConfFile_NextToken(pConf);
        animRect.left = 0;
        animRect.top = 0;
        animRect.right = 0;
        animRect.bottom = 0;
        dwConfFile_ParseRect(pConf, &animRect);
        if (pFlicName && *pFlicName != '\0')
            this->pTutorialAnim = dwAnim_Open(&animRect, pFlicName, -1, 1);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "WIDGETBAR"))
    {
        uint32_t count = 0;
        dwGuiWidgetBar* pBar;
        dwConfFile_ParseRect(pConf, &rect);
        // binary: new(0x18) dwGuiWidgetBar_Ctor(&rect), then per item line:
        // name token + localized text + token + 3 ulongs + a recursive child
        // control -> dwGuiWidgetBar_AddItem(bar, child, name, text, tok,
        // (byte)u1, u2, u3).
        pBar = new dwGuiWidgetBar(&rect);
        dwConfFile_ParseULong(pConf, &count);
        for (; count != 0; count--)
        {
            char* pItemName;
            char* pItemText;
            char* pTok;
            uint32_t u1 = 0, u2 = 0, u3 = 0;
            char* pChildKeyword;
            dwWidget* pChild;
            if (pConf->bEof)
                break;
            dwConfFile_ReadLine(pConf);
            pItemName = dwConfFile_NextToken(pConf);
            pItemText = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
            pTok = dwConfFile_NextToken(pConf);
            dwConfFile_ParseULong(pConf, &u1);
            dwConfFile_ParseULong(pConf, &u2);
            dwConfFile_ParseULong(pConf, &u3);
            pChildKeyword = dwConfFile_NextToken(pConf);
            pChild = this->CreateControl(pChildKeyword, pConf);
            pBar->AddItem(pChild, pItemName, pItemText, pTok, (uint8_t)u1, (int)u2, (int)u3);
        }
        return pBar;
    }

    // everything else: the common screen-state-less factory
    return dwGuiScreen_CreateControl(pKeyword, pConf, this->pStringTable);
}

// ---- widget-side virtuals -------------------------------------------------------

// vtbl +0x44 @431240 (dwGuiScreen_Draw)
void dwGuiScreen::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->EnsureImages(); // virtual +0x3c
    if (this->pBgImage)
        this->pBgImage->Blit(pDestBits, 0, 0, pClipRect); // vtbl +0x04 (this = SOURCE)
    this->controls.DrawChild(pDestBits, pClipRect);
    if (this->bTooltipVisible && this->pTooltipTarget && this->pTooltipFont && !this->bModal)
    {
        dwImageDraw_FillRect(pDestBits, &this->tooltipRect, this->tooltipBgColor, pClipRect);
        dwFont_DrawTextCentered(pDestBits, this->pTooltipFont, &this->tooltipRect,
                                this->pTooltipTarget->pText, this->tooltipTextColor, pClipRect);
    }
}

// vtbl +0x04 @4318a0 (dwGuiScreen_OnMouseMove) — tooltip hover tracking.
int dwGuiScreen::OnMouseMove(int16_t x, int16_t y)
{
    dwListNode* pNode;
    dwGuiScreenLabel* pLabel;

    if (this->pTooltipFont)
    {
        pLabel = this->pTooltipTarget;
        if (!pLabel
            || x < pLabel->left || pLabel->right <= x
            || y < pLabel->top || pLabel->bottom <= y)
        {
            // left the current label zone (or none latched): flush, rescan
            this->FlushTooltipDirty();
            for (pNode = this->labels.pSentinel->pNext; pNode != this->labels.pSentinel; pNode = pNode->pNext)
            {
                pLabel = (dwGuiScreenLabel*)pNode->pData;
                if (x >= pLabel->left && x < pLabel->right && y >= pLabel->top && y < pLabel->bottom)
                {
                    this->pTooltipTarget = pLabel;
                    this->hoverStartSec = this->GetElapsed();
                    break;
                }
            }
        }
    }

    if (!this->bActive && this->controls.bEnabled)
        return this->controls.OnMouseMove(x, y);
    return 1;
}

// vtbl +0x08 @431980 (dwGuiScreen_OnMouseDown)
int dwGuiScreen::OnMouseDown(int16_t x, int16_t y)
{
    dwPoint pt;

    this->FlushTooltipDirty();
    if (this->bActive)
    {
        // pick mode (armed by msg 0x7530): capture the hit widget
        pt.x = x;
        pt.y = y;
        this->pPickedWidget = this->controls.HitTest(&pt); // vtbl +0x38
        dwWidget_pMouseTarget = this;
    }
    else if (this->controls.bEnabled)
    {
        return this->controls.OnMouseDown(x, y);
    }
    return 1;
}

// vtbl +0x0c @4319f0 (dwGuiScreen_OnMouseUp)
int dwGuiScreen::OnMouseUp(int16_t x, int16_t y)
{
    if (this->bActive)
    {
        if (this->pPickedWidget)
            this->pPickedWidget->OnHover(x, y); // vtbl +0x18 — notify the picked control
        if (dwWidget_pMouseTarget == (dwWidget*)this)
            dwWidget_pMouseTarget = NULL;
        dwCursor_SetCursor(1);
        this->bActive = 0;
    }
    else if (this->controls.bEnabled)
    {
        return this->controls.OnMouseUp(x, y);
    }
    return 1;
}

// vtbl +0x10 @431ad0 (dwGuiScreen_OnKey) — cheat-code entry.
int dwGuiScreen::OnKey(int key, int repeat)
{
    char c;
    dwWidgetMsg msg;

    c = (char)key;
    if (c == '\x1b' && this->bModal)
    {
        // Esc during a tutorial: dispatch the tutorial-exit message
        msg.code = 0x7932;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    if (c == '\x03' || c == '\r')
    {
        // Ctrl-C or Enter submits the typed ring buffer
        this->CheckCheatCodes(this->cheatBuffer); // virtual +0x4c
        this->cheatBuffer[0] = '\0';
        this->cheatIndex = 0;
        this->Invalidate(); // virtual +0x34
    }
    else
    {
        this->cheatBuffer[this->cheatIndex] = c;
        this->cheatIndex = (uint8_t)((this->cheatIndex + 1) % 0xf);
        this->cheatBuffer[this->cheatIndex] = '\0';
    }

    if (this->controls.bEnabled)
        return this->controls.OnKey(key, repeat);
    return 0;
}

// vtbl +0x14 @41c510 (shared COMDAT; Ghidra: dwGuiMission_ForwardUpdate) —
// forward the per-frame widget tick into the controls group.
void dwGuiScreen::Update(float dt)
{
    this->controls.Update(dt);
}

// vtbl +0x18 @40ba70 (undetected COMDAT in the dwGuiCredits range) — forward
// hover into the controls group (no bEnabled gate; the group's own OnHover
// does the containment checks).
int dwGuiScreen::OnHover(int16_t x, int16_t y)
{
    return this->controls.OnHover(x, y);
}

// vtbl +0x3c @432150 (dwGuiScreen_EnsureImages — mis-binned past the unit end)
void dwGuiScreen::EnsureImages()
{
    if (this->pTutorialAnim)
        this->pTutorialAnim->EnsureImages(); // vtbl +0x3c
    this->controls.EnsureImages();           // vtbl +0x3c
}

// vtbl +0x40 @432170 (dwGuiScreen_FreeImages — mis-binned past the unit end)
void dwGuiScreen::FreeImages()
{
    if (this->pTutorialAnim)
        this->pTutorialAnim->FreeImages(); // vtbl +0x40
    this->controls.FreeImages();           // vtbl +0x40
}

// vtbl +0x1c @4312d0 (dwGuiScreen_OnMessage)
int dwGuiScreen::OnMessage(dwWidgetMsg* pMsg)
{
    uint32_t code;
    dwWidgetMsg msg;

    code = (uint32_t)pMsg->code;
    if (code >= 0x65 && code <= 0x6c)
    {
        // screen-switch commands: capture/interrupt into a new segment
        dwSegment* pSeg = NULL;
        dwCursor_SetCursor(0);
        this->RenderActive();
        switch (code)
        {
        case 0x65:
            // dwGuiOptions enter segment (unit dwGuiOptions, landed): plays
            // OStart.san then pushes the options screen.
            pSeg = dwGuiOptions_NewEnterSeg(0);
            break;
        case 0x66:
            this->pSnapshotImage = dwGuiScreen_CaptureShadedScreen();
            // dwMissionSequence (unit dwGuiMission, landed): the
            // workshop<->mission sequencer — binary new(0x1c) + vtbl 0x51f7d8.
            pSeg = static_cast<dwSegment*>(new dwMissionSequence(this->pSnapshotImage));
            break;
        case 0x67:
            // dwGuiInGame final-mission deploy. binary: if the assembled droid
            // is valid, find the rank/category-4 mission in dwCore_pMissionList
            // and new(0x284) dwGuiInGame(pMissionInfo); pSeg = its dwSegment
            // subobject. TODO(dw-decomp): the rank-4 mission lookup needs the
            // populated dwCore_pMissionList (P7 boot flow) — until then deploy
            // the current mission.
            if (dwGuiInGame_CheckDroidValid())
                pSeg = dwGuiInGame_New(dwCore_pCurrentMission);
            break;
        case 0x68:
            this->pSnapshotImage = dwGuiScreen_CaptureShadedScreen();
            // TODO(dw-decomp): 0x68 -> dwGuiLoadSave screen (unit
            // dwGuiLoadSave) — binary: new(0xfc) dwGuiLoadSave_Ctor(
            // pSnapshotImage); pSeg = its dwSegment subobject (obj+0x10).
            stdPlatform_Printf("TODO(dw-decomp): dwGuiScreen msg 0x68 -> dwGuiLoadSave screen (unit dwGuiLoadSave) not translated yet\n");
            break;
        case 0x6a:
            // TODO(dw-decomp): 0x6a -> reference intro-video segment (unit
            // dwGuiReference) — binary: new(0x18) { dwSegment_Ctor; +0x14 = 0;
            // vptr = 0x51f238 (Activate = dwGuiReference_PlayIntroVideo) }.
            stdPlatform_Printf("TODO(dw-decomp): dwGuiScreen msg 0x6a -> dwGuiReference intro-video segment (unit dwGuiReference) not translated yet\n");
            break;
        default: // 0x69/0x6b/0x6c: cursor + render only
            break;
        }
        if (pSeg)
        {
            msg.code = 0x7532; // "screen switching" broadcast
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
            // Note: the binary's InterruptWith reads the active segment
            // itself; the translated API takes it explicitly.
            dwSegment_InterruptWith(dwSegment_pActive, pSeg);
        }
        return 1;
    }

    if (code == 30000) // 0x7530: arm one-shot pick mode
    {
        dwCursor_SetCursor(3);
        this->bActive = 1;
    }
    else if (code == 0x96) // 150: advance the app flow
    {
        dwSegment_RequestAdvance();
    }
    else if (code == 0x792a) // tutorial ENTER
    {
        if (this->tutorialRecName.length != 0)
        {
            this->bModal = 1;
            if (this->pTutorialAnim)
            {
                // move the tutorial FLC to the BACK of the controls list
                // (drawn last = on top), then start it
                dwGuiScreen_UnlinkWidgetNode(&this->controls.children, this->pTutorialAnim);
                this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, this->pTutorialAnim);
                this->pTutorialAnim->Play(); // virtual +0x48
            }
            dwSegment_Play(this->tutorialRecName.pBuffer); // replay the recorded input cues
            if (this->tutorialMusicName.length != 0)
                dwSound_SetMusic(this->tutorialMusicName.pBuffer, 0);
        }
    }
    else if (code == 0x7932) // tutorial EXIT (Esc / hidden hotspots / cue drain)
    {
        if (this->bModal)
        {
            this->bTutorialHold = 0;
            this->bModal = 0;
            dwSegment_EndPlayback();
            if (this->pTutorialAnim)
            {
                this->pTutorialAnim->Stop(); // virtual +0x4c
                dwGuiScreen_UnlinkWidgetNode(&this->controls.children, this->pTutorialAnim);
            }
            dwSound_SetMusic(this->musicName.pBuffer, 1); // restore the screen music
        }
    }

    if (this->controls.bEnabled)
        return this->controls.OnMessage(pMsg);
    return 0; // Note: the binary returns an undefined AL on this path
}

// ---- cheats ----------------------------------------------------------------------

// vtbl +0x4c @431f50 (dwGuiScreen_CheckCheatCodes) — the base cheat table.
// The game-data pokes need the P5 units' structs; each branch documents the
// exact binary semantics and is stubbed until its owner lands.
void dwGuiScreen::CheckCheatCodes(char* pCode)
{
    if (dwString_Equals(pCode, "SOMONEY"))
    {
        // TODO(dw-decomp): SOMONEY -> unlock all missions (unit dwMission) —
        // binary: for every record in dwCore_pMissionList (@0x53d990) whose
        // rank/category int @+4 is 0/1/2/3: set the unlocked byte @+0 to 1.
        stdPlatform_Printf("TODO(dw-decomp): cheat SOMONEY -> dwMission record pokes (unit dwMission) not translated yet\n");
    }
    else if (dwString_Equals(pCode, "FITTO"))
    {
        // TODO(dw-decomp): FITTO -> unlock all part blueprints (unit dwPart) —
        // binary: for every record in dwCore_pBlueprintList (@0x53d97c): set
        // the byte @+5 to 1.
        stdPlatform_Printf("TODO(dw-decomp): cheat FITTO -> dwPart blueprint pokes (unit dwPart) not translated yet\n");
    }
    else if (dwString_Equals(pCode, "BEEFCAKE"))
    {
        // TODO(dw-decomp): BEEFCAKE -> max the assembled droid's stats (unit
        // dwPart) — binary: for every dwPartNode in dwCore_pWorkspaceNodes
        // (@0x53d984) whose part's type int @pPart+8 != 9: set the node's
        // current-stat short @node+0x84 to the part's max-stat short
        // @pPart+0x5f0.
        stdPlatform_Printf("TODO(dw-decomp): cheat BEEFCAKE -> dwPartNode stat pokes (unit dwPart) not translated yet\n");
    }
    else if (dwString_Equals(pCode, "DEFCON0") || dwString_Equals(pCode, "DEFCON1")
             || dwString_Equals(pCode, "DEFCON2") || dwString_Equals(pCode, "DEFCON3"))
    {
        // TODO(dw-decomp): DEFCONn -> set the current mission's defcon (unit
        // dwMission) — binary: if dwCore_pCurrentMission (@0x53d9x8) is set,
        // write n (the trailing digit) to its int @+8.
        stdPlatform_Printf("TODO(dw-decomp): cheat %s -> dwMission defcon poke (unit dwMission) not translated yet\n", pCode);
    }
    else if (dwString_Equals(pCode, "MST3K"))
    {
        // TODO(dw-decomp): MST3K -> set the low 5 bits of the shared player
        // progress/stats bitmask (unit dwPlayer) — binary: the unnamed global
        // @0x53d9f8 (loaded from the .plr STATS key by dwPlayer_LoadPlr; read
        // by dwHelp/dwGuiStatus/dwGuiReference/dwWorkshop/dwGuiOptions)
        // |= 0x1f.
        stdPlatform_Printf("TODO(dw-decomp): cheat MST3K -> dwPlayer stats-flag poke (unit dwPlayer) not translated yet\n");
    }
}

// ---- segment-side virtuals ---------------------------------------------------------

// scn vtbl +0x00 @431b90 (Ghidra: dwGuiScreen_OnActivate)
int dwGuiScreen::Activate()
{
    // lazy-build the controls from "<name>.cmp" on first activation
    if (this->controls.children.pSentinel->pNext == this->controls.children.pSentinel)
        this->LoadControls(this->scriptName.pBuffer);

    if (this->pSnapshotImage)
        delete this->pSnapshotImage; // virtual delete (vtbl +0x00, flags 1)
    this->pSnapshotImage = NULL;

    if (this->colormapName.length != 0)
        dwColormap_Load(this->colormapName.pBuffer);

    dwWidget_pDefault = this; // this screen now receives keyboard/messages
    dwCursor_SetCursor(1);
    this->bActive = 0;

    if (this->musicName.length != 0)
        dwSound_SetMusic(this->musicName.pBuffer, 1);

    this->Invalidate(); // virtual +0x34 (full-screen dirty rect)
    this->lastTickSec = 0.0f;
    return 1;
}

// scn vtbl +0x04 @431c30 (Ghidra: dwGuiScreen_OnHide)
void dwGuiScreen::Deactivate()
{
    this->FlushTooltipDirty();
    if (dwWidget_pDefault == (dwWidget*)this)
        dwWidget_pDefault = NULL;
    // free every cached (non-playing) sound sample
    // Note: guard added; the binary's dwSound_FreeAllSamples reads the
    // manager global unconditionally.
    if (dwSound_pManager)
        dwSound_pManager->FreeAllSamples();
}

// scn vtbl +0x08 @431a70 (Ghidra: dwGuiScreen_SegSuspend)
void dwGuiScreen::Suspend()
{
    dwWidgetMsg msg;

    // exit a live tutorial before this screen gets stacked away
    msg.code = 0x7932;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);

    this->Disable(); // virtual +0x24 (widget side)
    dwSegment::Suspend();
}

// scn vtbl +0x0c @431ab0 (Ghidra: dwGuiScreen_SegResume)
void dwGuiScreen::Resume()
{
    this->Enable(); // virtual +0x20 (widget side)
    dwSegment::Resume();
    dwWidget_pDefault = this;
}

// scn vtbl +0x10 @431c60 (Ghidra: dwGuiScreen_SegUpdate) — the per-frame tick.
void dwGuiScreen::Update()
{
    float elapsedSec;
    float deltaSec;
    float magSec;
    float effSec;
    dwWidgetMsg msg;

    // tutorial auto-exit once the recorded cue playlist drains
    if (this->bModal && dwSegment_IsPlaylistEmpty() && !this->bTutorialHold)
    {
        msg.code = 0x7932;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }

    // ~45Hz widget Update broadcast (>= 0.022s between ticks)
    elapsedSec = this->GetElapsed();
    deltaSec = elapsedSec - this->lastTickSec;
    magSec = (deltaSec < 0.0f) ? -deltaSec : deltaSec;
    effSec = (magSec <= 1e-05f) ? 0.0f : deltaSec;
    if (effSec >= 0.022f)
    {
        this->lastTickSec = elapsedSec;
        this->Update(deltaSec); // virtual +0x14 (widget tick; raw delta, as in the binary)
    }

    // tooltip idle: latch visible after 0.75s of hover (mouse not captured)
    if (!dwWidget_bCaptured && this->pTooltipTarget && !this->bTooltipVisible
        && (elapsedSec - this->hoverStartSec) >= 0.75f)
    {
        int16_t textW;
        int16_t left;
        int16_t dx;
        int16_t dy;
        int bOverlap;

        this->bTooltipVisible = 1;
        textW = (int16_t)dwFont_MeasureString(this->pTooltipFont, this->pTooltipTarget->pText, 0);

        // centered under the label zone; box height = font header dword @+8
        // (the .laf "bpp"/top-inset dword) + 4
        left = (int16_t)((this->pTooltipTarget->right + this->pTooltipTarget->left) / 2)
             - (int16_t)(textW + 4) / 2;
        this->tooltipRect.left = left;
        this->tooltipRect.right = (int16_t)(textW + 4 + left);
        this->tooltipRect.top = this->pTooltipTarget->bottom;
        this->tooltipRect.bottom = (int16_t)(this->pTooltipFont->pHeader->bpp + 4 + this->pTooltipTarget->bottom);

        // clamp into this screen's widget rect
        dx = 0;
        if (this->tooltipRect.left < this->left)
            dx = (int16_t)(this->left - this->tooltipRect.left);
        else if (this->right <= this->tooltipRect.right)
            dx = (int16_t)(this->right - this->tooltipRect.right - 1);
        dy = 0;
        if (this->tooltipRect.top < this->top)
            dy = (int16_t)(this->top - this->tooltipRect.top);
        else if (this->bottom <= this->tooltipRect.bottom)
            dy = (int16_t)(this->bottom - this->tooltipRect.bottom - 1);
        this->tooltipRect.left = (int16_t)(this->tooltipRect.left + dx);
        this->tooltipRect.top = (int16_t)(this->tooltipRect.top + dy);
        this->tooltipRect.right = (int16_t)(this->tooltipRect.right + dx);
        this->tooltipRect.bottom = (int16_t)(this->tooltipRect.bottom + dy);

        // dodge the cursor: test the cursor point and the point 10px below
        bOverlap = (dwCursor_pos.x >= this->tooltipRect.left && dwCursor_pos.x < this->tooltipRect.right
                    && dwCursor_pos.y >= this->tooltipRect.top && dwCursor_pos.y < this->tooltipRect.bottom);
        if (!bOverlap)
        {
            bOverlap = (dwCursor_pos.x >= this->tooltipRect.left && dwCursor_pos.x < this->tooltipRect.right
                        && (int16_t)(dwCursor_pos.y + 10) >= this->tooltipRect.top
                        && (int16_t)(dwCursor_pos.y + 10) < this->tooltipRect.bottom);
        }
        if (bOverlap)
        {
            int16_t dy2 = (int16_t)(dwCursor_pos.y - this->tooltipRect.bottom);
            // binary quirk: the horizontal clamp shift is applied a SECOND time here
            this->tooltipRect.left = (int16_t)(this->tooltipRect.left + dx);
            this->tooltipRect.right = (int16_t)(this->tooltipRect.right + dx);
            this->tooltipRect.top = (int16_t)(this->tooltipRect.top + dy2);
            this->tooltipRect.bottom = (int16_t)(this->tooltipRect.bottom + dy2);
        }
        dwDisplay_AddDirtyRect(&this->tooltipRect);
    }

    // repaint + present when anything is dirty
    if (dwDisplay_pDirtyList->pNext != dwDisplay_pDirtyList)
    {
        this->RenderActive();
        dwDisplay_Present();
    }
}

// @431e90 (dwGuiScreen_RenderActive) — repaint this screen into the locked
// display surface, per dirty rect (or one full pass when dwMain_bFullRedraw).
void dwGuiScreen::RenderActive()
{
    void* pPixels;
    int stride;
    dwImageBits bits;
    dwDirtyRect* pDirty;

    if (!dwDisplay_pScreenImage) // Note: guard added (binary assumes an open display)
        return;

    pPixels = NULL;
    stride = 0;
    dwDisplay_pScreenImage->Lock(&pPixels, &stride); // vtbl +0x0c
    bits.pDesc = &dwDisplay_pScreenImage->desc;      // binary: obj-as-desc alias
    bits.pPixels = pPixels;
    bits.stride = stride;

    if (dwMain_bFullRedraw == 0)
    {
        for (pDirty = dwDisplay_pDirtyList->pNext; pDirty != dwDisplay_pDirtyList; pDirty = pDirty->pNext)
            this->DrawChild(&bits, (dwRect*)&pDirty->left);
    }
    else
    {
        this->DrawChild(&bits, NULL);
    }

    dwDisplay_pScreenImage->Unlock(); // vtbl +0x10
}
