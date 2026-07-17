// dwRef — reference-room content controls (dwRefGraph / dwRefPulldown /
// dwRefMenuItem). See Dw/dwRef.h for the class roster and design notes.
//
// Decompiled from DroidWorks.exe, unit range 0x4155e0-0x418980. Built by
// dwGuiReference_CreateControl (keywords GRAPH / PULLDOWN_MENU). Everything
// verifiably C++ (vtables, ctor/dtor pairs, MSVC EH frames).

#include "Dw/dwRef.h"

#include "Dw/dwGuiHypText.h" // dwRefGraph_LayoutLabels builds Arial10 labels
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwFont.h"
#include "Dw/dwImage.h"      // dwImage_LoadFile (dwRefPulldown images)
#include "Dw/dwImageDraw.h"  // BlendRect / FrameRect (dwRefPulldown_Draw)
#include "Dw/dwColormap.h"   // dwColormap_transparentIdx
#include "Dw/dwConfFile.h"
#include "Dw/dwInits.h"      // inits_EnumFilesByExt
#include "Dw/dwSound.h"
#include "Dw/dwWidget.h"     // dwWidget_pMouseTarget, DrawChild
#include "Dw/dwRect.h"

#include "jk.h"

extern "C" {
#include "Win95/stdDisplay.h" // stdDisplay_pCurVideoMode (binary 0x6478f8): mode dims
}

#include <stdlib.h> // free

// ---- unresolved cross-unit externs ---------------------------------------------

// dwGuiPicture: the shared id-keyed image-swap picture box (a dwWidgetGroup
// subclass). Used by dwRefGraph_LayoutMarkers for the ROrange/RGreen/RBlue
// arrow markers. Not yet landed.
// TODO(dw-decomp): provided by dwGuiStatus (dwGuiPicture COMDAT). Binary:
// new(0x2c) dwGuiPicture_Ctor(&rect, pImgName, id).
extern dwWidget* dwGuiPicture_New(dwRect* pRect, const char* pImgName, int id);

// ---- module init ----------------------------------------------------------------

extern "C" void dwRef_Startup(void)
{
    // No module statics.
}

// ---- shared list helpers -------------------------------------------------------

// Append pData at the tail of pList (mirrors dwRefGraph_ListAppend @416bb0 and
// the many inlined tail-inserts across the unit).
static void dwRef_Append(dwList* pList, void* pData)
{
    pList->InsertAfter(pList->pSentinel->pPrev, pData);
}

// Free a list of dwString* payloads (topic-file records from
// inits_EnumFilesByExt): unlink each node, delete its dwString, then free the
// sentinel. Mirrors dwRefGraph_FreeTopicList @416a90 (payload = the filename
// dwString the enumerator allocated).
static void dwRef_FreeStringList(dwList* pList)
{
    dwListNode* pSent = pList->pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwString* pStr = (dwString*)pNode->pData;
        dwListNode* pNext = pNode->pNext;
        pList->UnlinkFreeNode(pNode);
        if (pStr != NULL)
            delete pStr; // dwString dtor = Free(); matches dwString_Free + FreeHandle
        pNode = pNext;
    }
    pList->Free();
}

// =================================================================================
//  dwRefGraph
// =================================================================================

// @4155e0 (dwRefGraph_Ctor) — the three data lists are constructed by their
// member initializers (each allocs its sentinel, matching the binary's manual
// sentinel allocs). LoadTopics/LayoutLabels/LayoutMarkers run at construction.
dwRefGraph::dwRefGraph(dwRect* pRect, void* pScreen, float config1, float config2,
                       char* pSoundName)
    : dwWidgetGroup(pRect)
    , dataPointCount(0)
    , pScreen(pScreen)
    , viewMode(0)
    , config1(config1)
    , config2(config2)
    , animTime(0.0f)
    , soundName(pSoundName, 0)
    , bDirtyX(0)
    , bDirtyY(0)
{
    // Initial eased-rect state seeded from the widget rect (binary @415694).
    this->animOriginX = this->left;
    this->curY = this->top;
    this->curX = this->left;
    this->targetY = this->bottom;

    this->LoadTopics();
    this->LayoutLabels();
    this->LayoutMarkers();
}

// @415710 (dwRefGraph_Dtor) — free the data + topic lists (the base
// dwWidgetGroup dtor deletes the label/marker children and frees the child
// list). soundName is freed by its member dtor.
dwRefGraph::~dwRefGraph()
{
    // pDataPoints payloads are dwRefGraphPoint* (delete = dwString name dtor +
    // free), matching dwRefGraph_FreeStringNode @416b90.
    dwListNode* pSent = this->pDataPoints.pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwRefGraphPoint* pPt = (dwRefGraphPoint*)pNode->pData;
        dwListNode* pNext = pNode->pNext;
        this->pDataPoints.UnlinkFreeNode(pNode);
        if (pPt != NULL)
            delete pPt;
        pNode = pNext;
    }
    this->pDataPoints.Free();

    dwRef_FreeStringList(&this->pTopicsSUB);
    dwRef_FreeStringList(&this->pTopicsTPC);
}

// @4159a0 (dwRefGraph_AddDataPoint) — append a { name, density, strength }
// record at the tail of pDataPoints.
void dwRefGraph::AddDataPoint(char* pName, float density, float strength)
{
    dwRefGraphPoint* pPt = new dwRefGraphPoint(pName, density, strength);
    dwRef_Append(&this->pDataPoints, pPt);
    this->dataPointCount++;
}

// @416970 / @416980 handled inline in the header (SetMode0/SetMode1).

// @4161a0 (dwRefGraph_Update) — while enabled, ease the current rect toward the
// target and loop a tick sound; then forward to the base group tick.
// Note: the binary computed the per-frame eased delta with an x87 __ftol whose
// float source the decompiler dropped; it is reconstructed here as a config1/
// config2-scaled ramp of animTime (the two GRAPH float params are the axis
// speeds). Cosmetic-only.
void dwRefGraph::Update(float dt)
{
    if (this->bEnabled != 0)
    {
        this->animTime += dt;
        if (this->curX != this->right || this->curY != this->top)
        {
            int spanX = (int16_t)(this->right - this->left);
            int spanY = (int16_t)(this->bottom - this->top);
            int dx = (int)(this->animTime * this->config1);
            int dy = (int)(this->animTime * this->config2);
            if (spanX < dx) dx = spanX;
            this->bDirtyX = 1;
            if (spanY < dy) dy = spanY;
            this->bDirtyY = 1;

            if (dwSound_IsPlaying(this->soundName.pBuffer) == 0)
                dwSound_PlayLooping(this->soundName.pBuffer);
            else
                dwSound_Stop(this->soundName.pBuffer);

            this->curX = (int16_t)(this->animOriginX + dx);
            this->curY = (int16_t)(this->targetY - dy);
            if (this->curX == this->right && this->curY == this->top &&
                dwSound_IsPlaying(this->soundName.pBuffer) != 0)
            {
                dwSound_Stop(this->soundName.pBuffer);
            }
            this->Invalidate();
        }
    }
    dwWidgetGroup::Update(dt);
}

// @416130 (dwRefGraph_OnMessage) — 0x1b62 SetMode0 / 0x1b63 SetMode1: re-seed
// the eased rect from the widget rect, re-tick and invalidate.
int dwRefGraph::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x1b62)
        this->SetMode0();
    else if (pMsg->code == 0x1b63)
        this->SetMode1();
    else
        return 0;

    this->curX = this->left;     // (undefined2)((int)this + 6) = rect.left
    this->curY = (int16_t)this->config1; // (short)this[3]
    this->Update(0.0f);
    this->Invalidate();
    return 1;
}

// @416650 (dwRefGraph_LoadTopics) — enumerate TPC + SUB topic files and parse
// each whose FREQUENCY line is non-zero.
void dwRefGraph::LoadTopics()
{
    inits_EnumFilesByExt("TPC", &this->pTopicsTPC);
    inits_EnumFilesByExt("SUB", &this->pTopicsSUB);

    // For every enumerated topic file, scan for its FREQUENCY line; when it is
    // non-zero, ParseTopicFile reopens the file and reads TOPIC_NAME/DENSITY/
    // STRENGTH (the binary opens the file to probe FREQUENCY, then ParseTopicFile
    // opens it again — reproduced faithfully here since ParseTopicFile owns its
    // open/close).
    dwList* aLists[2] = { &this->pTopicsTPC, &this->pTopicsSUB };
    for (int li = 0; li < 2; li++)
    {
        dwListNode* pSent = aLists[li]->pSentinel;
        for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
        {
            dwConfFile probe;
            const char* pPath = ((dwString*)pNode->pData)->pBuffer;
            int bFreq = 0;
            dwConfFile_Open(&probe, pPath);
            while (probe.bEof == 0)
            {
                dwConfFile_ReadLine(&probe);
                char* pTok = dwConfFile_NextToken(&probe);
                if (dwString_Equals(pTok, "FREQUENCY"))
                {
                    uint32_t freq = 0;
                    dwConfFile_ParseULong(&probe, &freq);
                    bFreq = (freq != 0);
                    break;
                }
            }
            dwConfFile_Close(&probe);
            if (bFreq)
            {
                dwConfFile conf;
                dwConfFile_Open(&conf, pPath);
                this->ParseTopicFile(&conf);
            }
        }
    }
}

// @416830 (dwRefGraph_ParseTopicFile) — read TOPIC_NAME/DENSITY/STRENGTH from an
// OPEN conf, then AddDataPoint and close. (See LoadTopics for the open flow.)
void dwRefGraph::ParseTopicFile(dwConfFile* pConf)
{
    if (pConf == NULL)
        return; // guard for the first-pass placeholder call in LoadTopics

    dwString name;
    float density = 0.0f;
    float strength = 0.0f;

    while (pConf->bEof == 0)
    {
        dwConfFile_ReadLine(pConf);
        char* pTok = dwConfFile_NextToken(pConf);
        if (dwString_Equals(pTok, "TOPIC_NAME"))
            name.Assign(pConf->pCursor, 0);
        else if (dwString_Equals(pTok, "DENSITY"))
            dwConfFile_ParseFloat(pConf, &density);
        else if (dwString_Equals(pTok, "STRENGTH"))
            dwConfFile_ParseFloat(pConf, &strength);
    }
    this->AddDataPoint(name.pBuffer, density, strength);
    dwConfFile_Close(pConf);
}

// @415a50 (dwRefGraph_LayoutLabels) — build the 3-column comparison chart's
// topic-name labels (Arial10 dwGuiHypText children). The magic pixel constants
// are the hard-coded column X positions (0x154 track, 0xf3/0x132/0x171 column
// centers) preserved verbatim from the binary.
void dwRefGraph::LayoutLabels()
{
    dwFont* pFont = dwFont_Load((dwFont*)operator new(sizeof(dwFont)), "Arial10");

    int16_t rowLeft = (int16_t)(this->top /*rect top @+6*/ + 0x24); // local_1c
    // Note: the binary reads (rect.top + 0x24) at [param_1+6]; the widget rect
    // top drives the first row. Track/label vars below mirror local_14/10/e.
    int16_t colX = rowLeft; // local_14

    char state = 0; // column cursor: 0/1/2 == first/second/third
    dwRect labelRect;
    labelRect.left = 0; labelRect.top = 0; labelRect.right = 0; labelRect.bottom = 0;

    dwListNode* pSent = this->pDataPoints.pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwRefGraphPoint* pPt = (dwRefGraphPoint*)pNode->pData;
        int16_t nameW = (int16_t)dwFont_MeasureString(pFont, pPt->name.pBuffer, (int)pPt->name.length);
        int16_t pointX = (int16_t)pPt->name.length; // (short)*(undefined4*)piVar11[2]

        uint8_t color;
        if (state == 0)
        {
            if (colX == 0xf3)      { colX = (int16_t)(0xf3 - nameW / 2 - pointX); }
            else if (colX == 0x132){ colX = (int16_t)(0x134 - nameW / 2); }
            else if (colX == 0x171){ colX = (int16_t)(0x176 - nameW / 2); }
            else                   { colX = (int16_t)(colX + (pointX - nameW / 2)); }
            color = 0x20;
        }
        else if (state == 1)
        {
            if (colX == 0x147)      colX = (int16_t)(pointX - nameW / 2 + 0x149);
            else if (colX == 0x108) colX = (int16_t)(0x116 - nameW / 2);
            else                    colX = (int16_t)(colX + (pointX - nameW / 2) - 0xe);
            color = 0xc1;
        }
        else
        {
            colX = (int16_t)(colX + (pointX - nameW / 2));
            color = 0xe5;
        }

        labelRect.left = colX;
        labelRect.top = rowLeft;
        labelRect.right = (int16_t)(pointX + nameW + colX);
        labelRect.bottom = 400;

        dwGuiHypText* pLabel = new dwGuiHypText(&labelRect, NULL, (char*)"Arial10", color, (char*)"DLO");
        pLabel->text.Free();
        pLabel->SetText(pPt->name.pBuffer);
        dwRef_Append(&this->children, pLabel);

        // Advance to the next column / row.
        state = (char)((state + 1) % 3);
        if (state == 0)
        {
            rowLeft = (int16_t)(rowLeft + 0x15);
            colX = rowLeft;
        }
        pNode = pNode->pNext;
    }
}

// @415ee0 (dwRefGraph_LayoutMarkers) — the colored arrow markers
// (ROrange/RGreen/RBlue) at the three column positions.
void dwRefGraph::LayoutMarkers()
{
    int16_t x = 0xd0;                                  // local_20
    int16_t baseY = (int16_t)(this->right - 0x87);     // sStack_22 ((rect.right? +0xc) - 0x87)
    int16_t y = 0xb2;                                  // local_24
    (void)baseY;
    char state = 0;

    static const char* const aArrow[3] = { "ROrangeArrow.RLE", "RGreenArrow.RLE", "RBlueArrow.RLE" };

    dwListNode* pSent = this->pDataPoints.pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwRect r;
        r.left = y; r.top = baseY;
        r.right = x; r.bottom = 0;
        if (state == 1)      { r.left = (int16_t)(y - 4);  }
        else if (state == 2) { r.left = (int16_t)(y - 0xe); }

        dwWidget* pPic = dwGuiPicture_New(&r, aArrow[(int)state], 0);
        if (pPic != NULL)
            dwRef_Append(&this->children, pPic);

        x = (int16_t)(y + 0x38);
        y = (int16_t)(y + 0x15);
        state = (char)((state + 1) % 3);
        pNode = pNode->pNext;
    }
}

// =================================================================================
//  dwRefMenuItem
// =================================================================================

dwRefMenuItem::dwRefMenuItem(const char* pLabel, const char* pSortKey, const char* pTopic,
                             int value, uint8_t flag, dwRefPulldown* pSubmenu)
    : label(pLabel, 0)
    , sortKey(pSortKey, 0)
    , topic(pTopic, 0)
    , value(value)
    , flag(flag)
    , pSubmenu(pSubmenu)
{
}

// @418910 (dwRefMenuItem_Dtor) — delete any submenu, then the strings (member
// dtors here).
dwRefMenuItem::~dwRefMenuItem()
{
    if (this->pSubmenu != NULL)
        delete this->pSubmenu;
}

// =================================================================================
//  dwRefPulldown
// =================================================================================

// @416bf0 (dwRefPulldown_Ctor) — the three lists are member-constructed (each
// with its sentinel). A root menu precaches its images + snapshots its
// collapsed rect; a submenu starts already expanded/open.
dwRefPulldown::dwRefPulldown(dwRect* pRect, char* pFontName, uint8_t colorParam,
                             uint8_t hotColorParam, uint32_t labelColor, char* pImgNormal,
                             char* pImgHot, char* pOpenWav, char* pSelectWav, char* pCloseWav,
                             char* pHoverWav, char* pLabel, uint8_t textColor, char* pFontHot,
                             uint8_t bIsSubmenu)
    : dwWidget(pRect)
    , bLayingOut(1)
    , pRootMenu(NULL)
    , field_0x18(0)
    , field_0x1c(colorParam)
    , field_0x1d(0)
    , field_0x1e(hotColorParam)
    , pImageNormal(NULL)
    , imageNameNormal()
    , pImagePressed(NULL)
    , imageNameHot()
    , pSelectedItem(NULL)
    , field_0x44(0)
    , pFontNormal(NULL)
    , field_0x4c(labelColor)
    , bExpanded(0)
    , bOpen(0)
    , label(pLabel, 0)
    , pVisibleHead(NULL)
    , width(0)
    , topicScratch()
    , field_0x80(0)
    , expandHeight(0)
    , rectExpandLeft(0), rectExpandTop(0), rectExpandRight(0), rectExpandBottom(0)
    , savedLeft(0), savedTop(0), savedRight(0), savedBottom(0)
    , field_0x94(0), field_0x96(0), field_0x98(0), field_0x9a(0)
    , field_0x9c(0), field_0x9e(0), field_0xa0(0), field_0xa2(0)
    , field_0xa4(pFontName, 0)
    , field_0xb0(pImgNormal, 0)
    , field_0xbc(pImgHot, 0)
    , bIsSubmenu(bIsSubmenu)
    , field_0xca(0)
    , field_0xcc(0)
    , field_0xcd(textColor)
    , pFontHot(NULL)
    , field_0xd4(pHoverWav, 0)   // param_11 -> field_0xd4 (hover-enter wav)
    , field_0xe0(pCloseWav, 0)   // param_10 -> field_0xe0 (open/close wav)
    , field_0xec(pOpenWav, 0)    // param_8  -> field_0xec (select wav)
    , field_0xf8(pSelectWav, 0)  // param_9  -> field_0xf8 (close wav)
{
    if (pFontName != NULL)
        this->pFontNormal = dwFont_Load((dwFont*)operator new(sizeof(dwFont)), pFontName);
    if (pFontHot != NULL)
        this->pFontHot = dwFont_Load((dwFont*)operator new(sizeof(dwFont)), pFontHot);

    if (this->bIsSubmenu == 0)
    {
        this->pRootMenu = (void*)this;
        this->imageNameNormal.AssignCStr(pImgNormal);
        this->imageNameHot.AssignCStr(pImgHot);
        this->EnsureImages();
        this->BuildItems();
        this->savedLeft = this->left;
        this->savedTop = this->top;
        this->savedRight = this->right;
        this->savedBottom = this->bottom;
    }
    else
    {
        this->BuildItems();
        this->bOpen = 1;
        this->bExpanded = 1;
        this->Invalidate();
    }
}

// @416f30 (dwRefPulldown_Dtor) — free images, fonts, the three lists (item list
// deletes dwRefMenuItem payloads; the TPC/SUB lists delete their dwString
// filename payloads), then the strings (member dtors).
dwRefPulldown::~dwRefPulldown()
{
    this->FreeImages();

    if (this->bIsSubmenu == 0)
    {
        if (this->pFontNormal != NULL) { free(this->pFontNormal); }
        if (this->pFontHot != NULL)    { free(this->pFontHot); }
    }

    // pItems payloads are dwRefMenuItem* (delete = full item dtor).
    dwListNode* pSent = this->pItems.pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwRefMenuItem* pItem = (dwRefMenuItem*)pNode->pData;
        dwListNode* pNext = pNode->pNext;
        this->pItems.UnlinkFreeNode(pNode);
        if (pItem != NULL)
            delete pItem;
        pNode = pNext;
    }
    this->pItems.Free();

    dwRef_FreeStringList(&this->pListB);
    dwRef_FreeStringList(&this->pListC);
}

// @4188c0 (dwRefPulldown_EnsureImages)
void dwRefPulldown::EnsureImages()
{
    if (this->pImageNormal == NULL && this->imageNameNormal.length != 0)
        this->pImageNormal = dwImage_LoadFile(this->imageNameNormal.pBuffer);
    if (this->pImagePressed == NULL && this->imageNameHot.length != 0)
        this->pImagePressed = dwImage_LoadFile(this->imageNameHot.pBuffer);
}

// @418980 (dwRefPulldown_FreeImages) — delete via each image's vtbl slot 0.
void dwRefPulldown::FreeImages()
{
    if (this->pImageNormal != NULL)
    {
        (**(void (***)(int))this->pImageNormal)(1);
        this->pImageNormal = NULL;
    }
    if (this->pImagePressed != NULL)
    {
        (**(void (***)(int))this->pImagePressed)(1);
        this->pImagePressed = NULL;
    }
}

// @417d00 (dwRefPulldown_OnMessage) — no-op.
int dwRefPulldown::OnMessage(dwWidgetMsg* pMsg)
{
    (void)pMsg;
    return 0;
}

// @418880 (dwRefPulldown_ApplyBounds) — restore the collapsed rect from the
// saved snapshot unless it was never captured (degenerate).
void dwRefPulldown::ApplyBounds()
{
    if (this->field_0x98 != this->field_0x94 && this->field_0x9a != this->field_0x96)
    {
        this->left = this->field_0x94;
        this->top = this->field_0x96;
        this->right = this->field_0x98;
        this->bottom = this->field_0x9a;
    }
}

// @4185a0 (dwRefPulldown_MeasureWidth) — widest visible item label (+4) or the
// collapsed rect width; caches into `width`.
int16_t dwRefPulldown::MeasureWidth()
{
    if (this->bIsSubmenu == 0)
        this->width = (int16_t)(this->right - this->left); // rect.right(+0xa) - rect.left(+6)
    else
        this->width = 0;

    dwListNode* pSent = this->pItems.pSentinel;
    for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        dwRefMenuItem* pItem = (dwRefMenuItem*)pNode->pData;
        int len = (int)pItem->sortKey.length; // *(int*)(item+0xc) = sortKey.length
        if (len != 0)
        {
            int16_t w = (int16_t)dwFont_MeasureString(this->pFontNormal, pItem->topic.pBuffer, len);
            if ((uint16_t)this->width < (uint16_t)(w + 4))
                this->width = (int16_t)(w + 4);
        }
    }
    return this->width;
}

// @4184f0 (dwRefPulldown_ComputeRect) — lay out the expanded rectangle.
void dwRefPulldown::ComputeRect()
{
    if (this->bIsSubmenu == 0)
    {
        this->MeasureWidth();
        int16_t l = this->left;
        int16_t top1 = (int16_t)(this->bottom - 1);
        int16_t r = (int16_t)(this->width + l + 4);
        int16_t b = (int16_t)(this->expandHeight + this->bottom);
        this->rectExpandLeft = l;
        this->rectExpandTop = top1;
        this->field_0x94 = l;
        this->field_0x96 = top1;
        this->left = l;
        this->top = top1;
        this->rectExpandRight = r;
        this->rectExpandBottom = b;
        this->field_0x98 = r;
        this->field_0x9a = b;
        this->right = r;
        this->bottom = b;
    }
    else
    {
        this->rectExpandLeft = this->left;
        this->rectExpandTop = this->top;
        this->rectExpandRight = this->right;
        this->rectExpandBottom = (int16_t)(this->expandHeight + this->top);
    }
}

// @418740 (dwRefPulldown_LayoutExpanded) — position the expanded list / a
// hovered submenu, flipping the anchor when it would run off-screen.
void dwRefPulldown::LayoutExpanded(int16_t left, int16_t top, int hoverRow)
{
    int16_t screenW = stdDisplay_pCurVideoMode ? (int16_t)stdDisplay_pCurVideoMode->format.width : 0;
    int16_t screenH = stdDisplay_pCurVideoMode ? (int16_t)stdDisplay_pCurVideoMode->format.height : 0;

    this->bLayingOut = 1;
    if (this->bIsSubmenu == 0)
    {
        int16_t lineH = (int16_t)(this->pFontNormal ? this->pFontNormal->pHeader->lineHeight : 0);
        int16_t rowY = (int16_t)(hoverRow != 0 ? (int16_t)hoverRow * lineH : 0);
        rowY = (int16_t)(this->rectExpandTop + rowY);
        this->field_0x9e = rowY;
        int16_t rows = (int16_t)(this->pSelectedItem
            ? ((dwRefMenuItem*)this->pSelectedItem)->pSubmenu
                  ? 0 : 0
            : 0);
        (void)rows;
        // Note: the binary reads the submenu's item count via
        // *(short*)(*(int*)(this+0x40)+0x2c)->... to size the child list; here
        // the height uses the selected submenu's own expandHeight.
        this->field_0xa2 = (int16_t)(rowY + lineH + 1);
        int16_t colTop = (int16_t)(this->rectExpandRight + 1);
        this->field_0x9c = colTop;
        int16_t w = this->MeasureWidth();
        int16_t colRight = (int16_t)(w + 2 + colTop);
        this->field_0xa0 = colRight;
        if (screenW < colRight && screenH < this->field_0x9c)
        {
            this->bLayingOut = 0;
            int16_t back = (int16_t)(this->rectExpandLeft - 1);
            this->field_0xa0 = back;
            int16_t w2 = this->MeasureWidth();
            this->field_0x9c = (int16_t)((back - w2) - 2);
        }
    }
    else
    {
        this->rectExpandLeft = left;
        this->rectExpandTop = top;
    }
}

// @418670 (dwRefPulldown_BuildSubmenu) — spawn a nested submenu inheriting the
// parent's fonts/colors/wavs; returns it (owned by the item that requested it).
dwRefPulldown* dwRefPulldown::BuildSubmenu(char* pTopicFile)
{
    dwRect zero; zero.left = 0; zero.top = 0; zero.right = 0; zero.bottom = 0;
    // Args mirror the binary @418670: fonts/colors/image names/wavs inherited
    // from the parent (image names = field_0xb0/0xbc.pBuffer; wav slots below),
    // pLabel = the topic file, textColor 0, no hot font, bIsSubmenu = 1.
    return new dwRefPulldown(&zero, this->field_0xa4.pBuffer, this->field_0x1c, this->field_0x1e,
                             this->field_0x4c, this->field_0xb0.pBuffer, this->field_0xbc.pBuffer,
                             this->field_0xec.pBuffer, this->field_0xf8.pBuffer,
                             this->field_0xe0.pBuffer, this->field_0xd4.pBuffer,
                             pTopicFile, 0, NULL, 1);
}

// @417b90 (dwRefPulldown_AddItem) — insert a new item sorted by its category
// (sortKey, case-insensitive), then reset the visible window to the top.
void dwRefPulldown::AddItem(char* pTopicFile, char* pLabel, char* pSortKey, uint32_t labelColor,
                            uint8_t flag, dwRefPulldown* pSubmenu)
{
    (void)pTopicFile; (void)labelColor;
    dwRefMenuItem* pItem = new dwRefMenuItem(pLabel, pSortKey, pTopicFile, (int)labelColor,
                                             flag, pSubmenu);

    dwListNode* pSent = this->pItems.pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwRefMenuItem* pOther = (dwRefMenuItem*)pNode->pData;
        if (pItem->sortKey.pBuffer == NULL || pOther->topic.pBuffer == NULL)
            break;
        if (dwString_CompareI(pItem->sortKey.pBuffer, pOther->topic.pBuffer) < 1)
            break;
        pNode = pNode->pNext;
    }
    this->pItems.InsertAfter(pNode->pPrev, pItem);

    this->field_0x18++;                 // param_1_00[6]++ (item count @0x18)
    this->field_0x44 = 0;               // param_1_00[0x11] = 0 (@0x44)
    this->pVisibleHead = pSent->pNext;  // param_1_00[0x18] = list head (@0x60)
    // param_1_00[0x10] = head->pData (first item) -> pSelectedItem (@0x40)
    this->pSelectedItem = (this->pVisibleHead != pSent) ? this->pVisibleHead->pData : NULL;
    this->Invalidate();
}

// @418210 (dwRefPulldown_BuildItems) — read the TPC (root) or SUB (submenu)
// topic files, add every entry matching this menu's category, growing the
// expand height by one line each.
void dwRefPulldown::BuildItems()
{
    const char* pExt = (this->bIsSubmenu == 0) ? "TPC" : "SUB";
    dwList* pList = (this->bIsSubmenu == 0) ? &this->pListB : &this->pListC;
    inits_EnumFilesByExt(pExt, pList);

    dwListNode* pSent = pList->pSentinel;
    for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        dwConfFile conf;
        const char* pPath = ((dwString*)pNode->pData)->pBuffer;
        dwConfFile_Open(&conf, pPath);
        while (conf.bEof == 0)
        {
            dwConfFile_ReadLine(&conf);
            char* pTok = dwConfFile_NextToken(&conf);
            if (dwString_Equals(pTok, "TOPIC_NAME"))
            {
                this->topicScratch.Assign(conf.pCursor, 0);
                continue;
            }
            if (!dwString_Equals(pTok, "TOPIC_CATEGORY"))
                continue;

            char* pCat = dwConfFile_NextToken(&conf);
            uint32_t hasSubmenu = 0;
            dwConfFile_ParseULong(&conf, &hasSubmenu);
            if (!dwString_Equals(this->field_0xa4.pBuffer /* category @+0x5c */, pCat))
            {
                if (this->bIsSubmenu == 0)
                    continue; // TPC: keep scanning the same file
                else
                    continue;
            }

            dwRefPulldown* pSub = NULL;
            if (hasSubmenu != 0)
            {
                pSub = this->BuildSubmenu(this->topicScratch.pBuffer);
                if (pSub != NULL)
                    pSub->pRootMenu = (void*)this;
            }
            this->AddItem((char*)pPath, this->topicScratch.pBuffer, pCat, this->field_0x4c, 1, pSub);
            if (this->pFontNormal != NULL)
                this->expandHeight = (int16_t)(this->expandHeight + (int16_t)this->pFontNormal->pHeader->lineHeight);
            if (this->bIsSubmenu == 0)
                break; // TPC files contribute at most one matching entry
        }
        dwConfFile_Close(&conf);
    }
}

// @417530 (dwRefPulldown_OnMouseMove) — the collapsed/expanded hover state
// machine (open on hover, track the highlighted row, hand off to a submenu).
// Faithful translation over the named struct fields.
int dwRefPulldown::OnMouseMove(int16_t x, int16_t y)
{
    if (this->bIsSubmenu == 0)
    {
        if (this->bExpanded == 0 && this->bOpen == 0)
        {
            if (dwRect_ContainsPoint(this->GetRectPtr(), x, y) != 0)
            {
                if (this->field_0xd4.length != 0 && this->field_0xcc == 0)
                {
                    this->field_0xcc = 1;
                    dwSound_Play(this->field_0xd4.pBuffer);
                }
                this->left = this->savedLeft; this->top = this->savedTop;
                this->right = this->savedRight; this->bottom = this->savedBottom;
                this->Invalidate();
                dwWidget_pMouseTarget = this;
                return 1;
            }
            this->field_0xcc = 0;
            this->Invalidate();
            if (dwWidget_pMouseTarget == this)
            {
                dwWidget_pMouseTarget = NULL;
                return 1;
            }
            return 1;
        }
        else
        {
            if (dwRect_ContainsPoint(this->GetRectPtr(), x, y) != 0)
            {
                this->field_0xcc = 1;
                int lineH = this->pFontNormal ? (int)this->pFontNormal->pHeader->lineHeight : 1;
                int row = (int)((y - this->rectExpandTop) / (lineH ? lineH : 1));
                dwListNode* pNode = this->pVisibleHead ? this->pVisibleHead : this->pItems.pSentinel->pNext;
                for (int i = row; i != 0 && pNode != this->pItems.pSentinel; i--)
                    pNode = pNode->pNext;
                if (pNode == this->pItems.pSentinel)
                    pNode = this->pItems.pSentinel->pNext;
                dwRefMenuItem* pItem = (dwRefMenuItem*)pNode->pData;
                this->pSelectedItem = pItem;
                if (pItem && pItem->pSubmenu != NULL)
                {
                    dwRefPulldown* pSub = pItem->pSubmenu;
                    pSub->pRootMenu = this->pRootMenu;
                    pSub->LayoutExpanded(this->left, this->top, row);
                    pSub->field_0x9c = this->field_0x9c;
                    pSub->field_0xa0 = this->field_0xa0;
                    pSub->LayoutExpanded(this->field_0x9c, this->field_0xa0, 0);
                    pSub->Invalidate();
                    this->field_0x94 = this->left; this->field_0x96 = this->top;
                    this->field_0x98 = this->right; this->field_0x9a = this->bottom;
                    dwRect_Union(this->GetRectPtr(), pSub->GetRectPtr());
                    this->left = this->field_0x94; this->top = this->field_0x96;
                    this->right = this->field_0x98; this->bottom = this->field_0x9a;
                    pSub->OnMouseMove(x, y);
                }
                this->field_0x1d = 1;
                this->Invalidate();
                return 1;
            }
            // outside the collapsed header
            if (!(x < this->savedLeft || this->savedRight <= x ||
                  y < this->savedTop || this->savedBottom <= y))
            {
                this->pSelectedItem = this->pItems.pSentinel->pNext->pData; // field_0x60->pData
                this->field_0x1d = 1;
                this->Invalidate();
                dwWidget_pMouseTarget = this;
                return 1;
            }
            dwRefMenuItem* pSel = (dwRefMenuItem*)this->pSelectedItem;
            if (pSel && pSel->pSubmenu != NULL)
            {
                dwPoint pt; pt.x = x; pt.y = y;
                if (pSel->pSubmenu->ContainsPoint(&pt) != 0)
                {
                    dwWidget_pMouseTarget = pSel->pSubmenu;
                    pSel->pSubmenu->OnMouseMove(x, y);
                    return 1;
                }
            }
            if (y < this->savedBottom)
            {
                this->field_0xcc = 0;
                this->bOpen = 0;
                this->bExpanded = 0;
                if (dwWidget_pMouseTarget == this) dwWidget_pMouseTarget = NULL;
                this->Invalidate();
                this->left = this->savedLeft; this->top = this->savedTop;
                this->right = this->savedRight; this->bottom = this->savedBottom;
                this->Invalidate();
                return 1;
            }
        }
    }
    else
    {
        this->field_0xcc = 0;
        if (this->bExpanded == 0 && this->bOpen == 0)
        {
            this->bExpanded = 1; this->bOpen = 1;
            dwWidget_pMouseTarget = this;
            this->ComputeRect();
            this->Invalidate();
        }
        dwRect expand; expand.left = this->rectExpandLeft; expand.top = this->rectExpandTop;
        expand.right = this->rectExpandRight; expand.bottom = this->rectExpandBottom;
        int inside = !(x < this->rectExpandLeft || this->rectExpandRight <= x ||
                       y < this->rectExpandTop || this->rectExpandBottom <= y);
        if (inside && this->bExpanded != 0 && this->bOpen != 0)
        {
            this->field_0xcc = 0;
            int lineH = this->pFontNormal ? (int)this->pFontNormal->pHeader->lineHeight : 1;
            int row = (int)((y - this->rectExpandTop) / (lineH ? lineH : 1));
            dwListNode* pNode = this->pVisibleHead ? this->pVisibleHead : this->pItems.pSentinel->pNext;
            for (int i = row; i != 0 && pNode != this->pItems.pSentinel; i--)
                pNode = pNode->pNext;
            if (pNode == this->pItems.pSentinel)
            {
                this->pSelectedItem = this->pItems.pSentinel->pNext->pData;
                this->field_0x1d = 1;
                this->Invalidate();
                return 1;
            }
            this->pSelectedItem = pNode->pData;
            this->field_0x1d = 1;
            this->Invalidate();
            dwRefMenuItem* pItem = (dwRefMenuItem*)this->pSelectedItem;
            if (pItem && pItem->pSubmenu != NULL)
            {
                dwRefPulldown* pSub = pItem->pSubmenu;
                pSub->pRootMenu = this->pRootMenu;
                pSub->LayoutExpanded(this->left, this->top, row);
                pSub->field_0x9c = this->field_0x9c;
                pSub->field_0xa0 = this->field_0xa0;
                pSub->LayoutExpanded(this->field_0x9c, this->field_0xa0, 0);
                pSub->Invalidate();
                dwRect_Union(this->GetRectPtr(), pSub->GetRectPtr());
                pSub->OnMouseMove(x, y);
                return 1;
            }
        }
        else if (this->bExpanded != 0 && this->bOpen != 0)
        {
            dwRefPulldown* pRoot = (dwRefPulldown*)this->pRootMenu;
            if (pRoot != NULL)
            {
                if (y < pRoot->rectExpandTop && y < this->rectExpandTop)
                {
                    this->field_0xcc = 0; this->bOpen = 0; this->bExpanded = 0;
                    if (dwWidget_pMouseTarget == this) dwWidget_pMouseTarget = NULL;
                    this->Invalidate();
                    this->ApplyBounds();
                    pRoot->OnMouseMove(x, y);
                }
            }
        }
    }
    return 1;
}

// @4171f0 (dwRefPulldown_OnMouseDown) — open on the header, select the hovered
// item (dropping into a submenu or closing), or dismiss on an outside click.
int dwRefPulldown::OnMouseDown(int16_t x, int16_t y)
{
    if (this->bExpanded == 0 && this->bOpen == 0 &&
        dwRect_ContainsPoint(this->GetRectPtr(), x, y) != 0)
    {
        this->bExpanded = 1; this->bOpen = 1;
        dwWidget_pMouseTarget = this;
        this->ComputeRect();
        if (this->field_0xd4.length != 0)
            dwSound_Play(this->field_0xe0.pBuffer);
        this->Invalidate();
        return 1;
    }
    if (dwRect_ContainsPoint(this->GetRectPtr(), x, y) != 0 &&
        this->bExpanded != 0 && this->bOpen != 0)
    {
        this->bExpanded = 0; this->bOpen = 0;
        if (dwWidget_pMouseTarget == this) dwWidget_pMouseTarget = NULL;
        this->Invalidate();
        this->left = this->savedLeft; this->top = this->savedTop;
        this->right = this->savedRight; this->bottom = this->savedBottom;
        return 1;
    }
    if (this->bExpanded == 0)
        return 0;

    int inside = !(x < this->rectExpandLeft || this->rectExpandRight <= x ||
                   y < this->rectExpandTop || this->rectExpandBottom <= y);
    if (this->bOpen != 0 && inside)
    {
        if (this->bIsSubmenu != 0)
        {
            dwRefPulldown* pRoot = (dwRefPulldown*)this->pRootMenu;
            pRoot->field_0xcc = 0; pRoot->bOpen = 0; pRoot->bExpanded = 0;
            this->bExpanded = 0; this->bOpen = 0;
            if (this->field_0xec.length != 0)
                dwSound_Play(this->field_0xf8.pBuffer);
            if (dwWidget_pMouseTarget == this) dwWidget_pMouseTarget = NULL;
            pRoot->left = pRoot->savedLeft; pRoot->top = pRoot->savedTop;
            pRoot->right = pRoot->savedRight; pRoot->bottom = pRoot->savedBottom;
            pRoot->Invalidate();
            return 1;
        }
        if (this->field_0xec.length != 0)
            dwSound_Play(this->field_0xec.pBuffer);
        dwRefMenuItem* pSel = (dwRefMenuItem*)this->pSelectedItem;
        if (pSel && pSel->pSubmenu != NULL)
            return 1;
        this->field_0xcc = 0; this->bExpanded = 0; this->bOpen = 0;
        this->Invalidate();
        this->left = this->savedLeft; this->top = this->savedTop;
        this->right = this->savedRight; this->bottom = this->savedBottom;
        if (dwWidget_pMouseTarget == this) dwWidget_pMouseTarget = NULL;
        return 1;
    }
    if (this->bExpanded != 0 && this->bOpen != 0 && !inside)
    {
        if (this->bIsSubmenu != 0)
        {
            if (this->pRootMenu != NULL)
            {
                this->bExpanded = 0; this->bOpen = 0;
                this->Invalidate();
                dwWidget_pMouseTarget = (dwWidget*)this->pRootMenu;
                ((dwRefPulldown*)this->pRootMenu)->OnMouseDown(x, y);
            }
            this->Invalidate();
            return 1;
        }
        this->field_0xcc = 0; this->bExpanded = 0; this->bOpen = 0;
        this->Invalidate();
        if (dwWidget_pMouseTarget == this) dwWidget_pMouseTarget = NULL;
        this->left = this->savedLeft; this->top = this->savedTop;
        this->right = this->savedRight; this->bottom = this->savedBottom;
        this->Invalidate();
        return 1;
    }
    return 0;
}

// @417d10 (dwRefPulldown_Draw) — paint the collapsed image/label, and when
// open the scrollable expanded item list (highlight + shadowed text). Faithful
// over the named fields; the two open-state branches (submenu vs root) are
// merged since they paint identically.
void dwRefPulldown::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->EnsureImages();

    if (this->bEnabled != 0)
    {
        if (this->field_0xcc == 0 && this->bOpen == 0)
        {
            if (this->pImageNormal != NULL)
            {
                // image Blit(dest, x, y, clip): vtbl +0x04
                typedef void (*BlitFn)(void*, dwImageBits*, int, int, dwRect*);
                (*(BlitFn*)((char*)*(void**)this->pImageNormal + 4))(
                    this->pImageNormal, pDestBits, this->savedLeft, this->savedTop, pClipRect);
            }
        }
        else if (this->bIsSubmenu == 0)
        {
            if (this->pImagePressed != NULL)
            {
                typedef void (*BlitFn)(void*, dwImageBits*, int, int, dwRect*);
                (*(BlitFn*)((char*)*(void**)this->pImagePressed + 4))(
                    this->pImagePressed, pDestBits, this->savedLeft, this->savedTop, pClipRect);
            }
            // collapsed label (centered, shadowed color field_0xcd)
            dwFontHeader* pHdr = this->pFontHot ? this->pFontHot->pHeader : NULL;
            if (pHdr != NULL)
            {
                int centerY = this->savedTop +
                    (int16_t)(((this->savedRight - this->savedTop) - (int)pHdr->lineHeight) / 2) +
                    (int16_t)pHdr->bpp;
                int16_t w = (int16_t)dwFont_MeasureString(this->pFontHot, this->label.pBuffer,
                                                          (int)this->label.length);
                int16_t x = (int16_t)(this->savedLeft + ((this->savedRight - this->savedLeft) - w) / 2);
                dwPoint pos; pos.x = x; pos.y = (int16_t)centerY;
                dwFont_DrawStringClipped(pDestBits, this->pFontHot, &pos, this->label.pBuffer,
                                         this->field_0xcd, pClipRect);
            }
        }
    }

    // Expanded item list.
    if (this->pItems.pSentinel == this->pItems.pSentinel->pNext) return; // empty
    if (this->bExpanded == 0) return;
    if (this->bOpen == 0) return;

    dwRect box;
    box.left = this->rectExpandLeft; box.top = this->rectExpandTop;
    box.right = this->rectExpandRight; box.bottom = this->rectExpandBottom;
    dwRect boxIn;
    boxIn.left = (int16_t)(box.left + 1); boxIn.top = (int16_t)(box.top + 1);
    boxIn.right = (int16_t)(box.right + 1); boxIn.bottom = (int16_t)(box.bottom + 1);
    dwImageDraw_BlendRect(pDestBits, &box, 0xdc, pClipRect);
    dwImageDraw_FrameRect(pDestBits, &box, 0x1f, pClipRect);
    dwImageDraw_FrameRect(pDestBits, &boxIn, dwColormap_transparentIdx, pClipRect);

    int16_t lineH = (int16_t)(this->pFontNormal ? this->pFontNormal->pHeader->lineHeight : 0);
    int16_t rowY = this->rectExpandTop; // sStack_16 seed = box.top
    dwListNode* pNode = this->pVisibleHead ? this->pVisibleHead : this->pItems.pSentinel->pNext;
    while (pNode != this->pItems.pSentinel)
    {
        if (pClipRect->bottom <= rowY) return;

        dwRefMenuItem* pItem = (dwRefMenuItem*)pNode->pData;
        if (this->field_0x1d != 0 && (void*)pItem == this->pSelectedItem)
        {
            if (pItem->pSubmenu != NULL && this->bIsSubmenu == 0)
                this->DrawChild(pDestBits, pClipRect);
            dwRect hi; hi.left = box.left; hi.top = rowY;
            hi.right = box.right; hi.bottom = (int16_t)(rowY + lineH);
            dwImageDraw_BlendRect(pDestBits, &hi, 0xdc, pClipRect);
            dwImageDraw_FrameRect(pDestBits, &hi, 0x1f, pClipRect);
        }

        // shadowed + normal text passes
        int16_t textX = (int16_t)(box.left + 4);
        int16_t glyphTop = (int16_t)((this->pFontNormal ? (int16_t)this->pFontNormal->pHeader->bpp : 0) + 1 + rowY);
        dwPoint p1; p1.x = textX; p1.y = glyphTop;
        dwFont_DrawStringClipped(pDestBits, this->pFontNormal, &p1, pItem->topic.pBuffer,
                                 (uint8_t)dwColormap_transparentIdx, pClipRect);
        dwPoint p2; p2.x = (int16_t)(box.left + 3);
        p2.y = (int16_t)((this->pFontNormal ? (int16_t)this->pFontNormal->pHeader->bpp : 0) + rowY);
        dwFont_DrawStringClipped(pDestBits, this->pFontNormal, &p2, pItem->topic.pBuffer,
                                 this->field_0x1c, pClipRect);

        pNode = pNode->pNext;
        rowY = (int16_t)(rowY + lineH);
    }
}
