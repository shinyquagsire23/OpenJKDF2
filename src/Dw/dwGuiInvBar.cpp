// dwGuiInvBar — the in-game INVENTORY item-bar popup (dwWidget subclass). See
// Dw/dwGuiInvBar.h for the role summary and the vtable/struct maps.
//
// Decompiled from DroidWorks.exe unit range 0x41a9f0-0x41b240. Per-function
// @addresses below. Compiled as C++ (vtable + ctor/dtor + MSVC EH frames).
//
// Engine-name mapping (Ghidra DW name -> OpenJKDF2 repo name):
//   sithWorld_pCurrentWorld -> sithWorld_g_pCurrentWorld
//   ->playerThing           -> ->pLocalPlayer
// The inventory descriptor table is the repo's sithInventory_g_aTypes
// (SithInventoryType). ⚠ The DW build repurposes SithInventoryType::hudBitmap
// as a dwImage* (its dwImageDesc gives the icon dims). The two
// sithInventory_FUN_* helpers are DW-engine internals (owner: P8 diff audit).

#include "Dw/dwGuiInvBar.h"

#include "Dw/dwGuiInGame.h" // dwGuiInGame_pActive + dwGuiInGame_PlayVoiceLineEx
#include "Dw/dwCog.h"       // dwCog_UseItem
#include "Dw/dwFont.h"
#include "Dw/dwImage.h"     // dwImage_CallBlit / dwImage_CallBlitColorMap + dwImageBits
#include "Dw/dwImageDraw.h" // dwImageDraw_FillTriBlend
#include "Dw/dwDisplay.h"   // dwDisplay_AddDirtyRect
#include "Dw/dwString.h"    // dwString_Equals (unused here but keeps the surface consistent)

#include "jk.h"
#include "globals.h" // SithThing / SithWorld / sithWorld_g_pCurrentWorld / sithInventory_g_aTypes
// Unguarded C engine header — wrap for correct C++<->C linkage.
extern "C" {
#include "Gameplay/sithInventory.h" // SithInventoryType / sithInventory_GetInventory
}

#define DWINV_COUNT 0x32
#define DWINV_FLAG_SELECTABLE 2

// The icon dwImage the DW build stores in SithInventoryType::hudBitmap.
static inline dwImage* dwInv_Icon(int i) { return (dwImage*)sithInventory_g_aTypes[i].hudBitmap; }

// A descriptor slot is "usable" when selectable, available, and owned.
static bool dwGuiInvBar_IsUsable(SithThing* pThing, int i)
{
    if ((sithInventory_g_aTypes[i].flags & DWINV_FLAG_SELECTABLE) == 0)
        return false;
    if (sithInventory_IsInventoryAvailable(pThing, i) == 0)
        return false;
    return sithInventory_GetInventory(pThing, i) != 0.0f;
}

// ---- module init ------------------------------------------------------------

extern "C" void dwGuiInvBar_Startup(void)
{
}

// ---- ctor / dtor ------------------------------------------------------------

// @41a9f0
dwGuiInvBar::dwGuiInvBar(dwRect* pRect, int16_t cellSpacing, const char* pFontName, uint8_t textColorIdx)
    : dwWidget(pRect)
{
    this->cellSpacing = cellSpacing;
    this->gridLeft = 0;
    this->gridTop = 0;
    this->gridRight = 0;
    this->gridBottom = 0;
    this->bShown = 0;
    this->selectedBin = 0;
    this->selRectL = 0;
    this->selRectT = 0;
    this->selRectR = 0;
    this->selRectB = 0;
    this->pFont = NULL;
    this->textColorIdx = textColorIdx;
    this->bgColorIdx = 0x46;
    if (pFontName != NULL && *pFontName != '\0')
    {
        this->pFont = dwFont_Load(new dwFont, pFontName);
    }
}

// @41aad0 (scalar-deleting wrapper @41aab0)
dwGuiInvBar::~dwGuiInvBar()
{
    if (this->bShown != 0)
        Hide();
    if (this->pFont != NULL)
    {
        // Note: the binary calls the mislabeled empty-COMDAT "sithRender_Open"
        // (= rdCanvas_FreeEntry no-op) here before freeing; dropped.
        delete this->pFont;
    }
}

// ---- layout / visibility ----------------------------------------------------

// @41ab40
void dwGuiInvBar::Layout()
{
    this->cellWidth = 0;
    this->cellHeight = 0;
    if (dwGuiInGame_pActive == NULL || sithWorld_g_pCurrentWorld == NULL)
        return;

    SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
    uint16_t numUsable = 0;
    for (int i = 0; i < DWINV_COUNT; i++)
    {
        if (!dwGuiInvBar_IsUsable(pThing, i))
            continue;
        // The icon dwImage begins with its dwImageDesc (vptr aliases
        // desc.format; width@4/height@6 — see the dwImage.h layout note).
        dwImageDesc* pIconDesc = (dwImageDesc*)dwInv_Icon(i);
        if ((uint16_t)this->cellWidth < pIconDesc->width)
            this->cellWidth = pIconDesc->width;
        if ((uint16_t)this->cellHeight < pIconDesc->height)
            this->cellHeight = pIconDesc->height;
        numUsable++;
    }

    if (numUsable == 0)
    {
        // Binary: dwGuiInGame_PlayVoiceLineEx on the running mission (a
        // __thiscall on dwGuiInGame_pActive; guarded by the pActive check above).
        dwGuiInGame_pActive->PlayVoiceLineEx(0, (char*)"GHCA037.wav", 0, 0);
        if (this->bShown != 0)
            Hide();
        return;
    }

    uint16_t cols = (uint16_t)(((this->right - this->left) - this->cellSpacing) / (int)(uint16_t)this->cellWidth);
    this->columns = cols;
    if (numUsable < cols)
        this->columns = numUsable;

    this->gridLeft = this->cellSpacing + this->left;
    // rows = ceil(numUsable / columns); columns re-derived as ceil(numUsable / rows)
    uint32_t rows = (uint32_t)((numUsable - 1) + (uint16_t)this->columns) / (uint32_t)(uint16_t)this->columns;
    this->columns = (int16_t)(((rows - 1) + numUsable) / rows);
    this->gridTop = (int16_t)((this->bottom + this->top) / 2) - (int16_t)((int)(rows * (uint16_t)this->cellHeight) / 2);
    this->gridRight = this->cellWidth * this->columns + this->gridLeft;
    this->gridBottom = (int16_t)rows * this->cellHeight + this->gridTop;
    if (this->bShown == 0)
    {
        this->selectedBin = 0;
        this->bShown = 1;
    }
    Invalidate();
}

// @41acd0
void dwGuiInvBar::Hide()
{
    this->bShown = 0;
    Invalidate();
}

// ---- input ------------------------------------------------------------------

// @41ace0
int dwGuiInvBar::OnMouseMove(int16_t x, int16_t y)
{
    int newSel = 0;
    if (this->bShown != 0)
    {
        bool bInGrid = !(x < this->gridLeft || this->gridRight <= x || y < this->gridTop || this->gridBottom <= y);
        if (bInGrid)
        {
            newSel = this->selectedBin;
            bool bInSel = false;
            if (newSel != 0)
                bInSel = !(x < this->selRectL || this->selRectR <= x || y < this->selRectT || this->selRectB <= y);
            if (!bInSel)
            {
                int col = (x - this->gridLeft) / (int)(uint16_t)this->cellWidth;
                int16_t row = (int16_t)((y - this->gridTop) / (int)(uint16_t)this->cellHeight);
                int remaining = (uint16_t)(this->columns * row) + 1 + col;
                SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
                int i = 0;
                for (; i < DWINV_COUNT; i++)
                {
                    if (dwGuiInvBar_IsUsable(pThing, i))
                    {
                        remaining = (int16_t)(remaining - 1);
                        newSel = i;
                    }
                    if ((int16_t)remaining == 0)
                        break;
                }
                if ((int16_t)remaining == 0)
                {
                    dwDisplay_AddDirtyRect((dwRect*)&this->selRectL);
                    int16_t cellX = (int16_t)col * this->cellWidth + this->gridLeft;
                    int16_t cellY = row * this->cellHeight + this->gridTop;
                    this->selRectL = cellX;
                    this->selRectT = cellY;
                    this->selRectR = cellX + this->cellWidth;
                    this->selRectB = cellY + this->cellHeight;
                }
                else
                {
                    newSel = 0;
                }
            }
        }
    }
    if (this->selectedBin != newSel)
    {
        dwDisplay_AddDirtyRect((dwRect*)&this->selRectL);
        this->selectedBin = newSel;
    }
    return 0;
}

// @41aeb0
int dwGuiInvBar::OnMouseDown(int16_t x, int16_t y)
{
    if (this->bShown != 0)
    {
        Hide();
        if (this->selectedBin != 0)
        {
            bool bInSel = !(x < this->selRectL || this->selRectR <= x || y < this->selRectT || this->selRectB <= y);
            if (bInSel)
            {
                SithThing* pSource = sithWorld_g_pCurrentWorld->pLocalPlayer;
                sithInventory_BinSendActivate(pSource, this->selectedBin);
                uint32_t flags = sithInventory_g_aTypes[this->selectedBin].flags;
                if ((flags & 2) != 0 && (flags & 8) == 0)
                    dwCog_UseItem(pSource, this->selectedBin);
            }
        }
    }
    return 0;
}

// @41af40
int dwGuiInvBar::OnMessage(dwWidgetMsg* pMsg)
{
    switch (pMsg->code)
    {
    case 0x1f41: // toggle
        if (this->bShown != 0)
            Hide();
        else
            Layout();
        break;
    case 0x1f49: // hide if shown
        if (this->bShown != 0)
            Hide();
        break;
    case 0x1f4a: // show if hidden
        if (this->bShown == 0)
            Layout();
        break;
    case 0x1f4b: // relayout if shown
        if (this->bShown != 0)
            Layout();
        break;
    }
    return 0;
}

// @41b240
int dwGuiInvBar::ContainsPoint(dwPoint* pPt)
{
    return 1; // modal: grabs every click
}

// ---- draw -------------------------------------------------------------------

// @41afd0
void dwGuiInvBar::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (this->bShown == 0)
        return;

    // Background triangle: apex at (left, grid vertical center), base = grid rect.
    dwPoint apex;
    apex.x = this->left;
    apex.y = (int16_t)((this->gridBottom - this->gridTop) / 2) + this->gridTop;
    dwImageDraw_FillTriBlend(pDestBits, this->bgColorIdx, &apex, (dwPoint*)&this->gridLeft, pClipRect);

    int16_t cellX = this->left + this->cellSpacing;
    int16_t xRight = cellX + this->cellWidth;
    int16_t rowTop = this->gridTop;
    int16_t rowBottom = rowTop + this->cellHeight;
    int16_t col = 0;
    SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;

    for (int i = 0; i < DWINV_COUNT; i++)
    {
        if (!dwGuiInvBar_IsUsable(pThing, i))
            continue;

        dwImage* pIcon = dwInv_Icon(i);
        if (i == this->selectedBin)
            dwImage_CallBlit(pIcon, pDestBits, cellX, rowTop, pClipRect);
        else
            dwImage_CallBlitColorMap(pIcon, pDestBits, cellX, rowTop, pClipRect);

        if (this->pFont != NULL)
        {
            int16_t fontLineHeight = (int16_t)this->pFont->pHeader->field_C;
            uint32_t count = (uint32_t)sithInventory_GetInventory(pThing, i);
            if (count > 1 && count < 99)
            {
                dwPoint pt;
                pt.x = cellX + 5;
                pt.y = (rowBottom - fontLineHeight) - 3;
                char digits[3];
                digits[0] = (char)(count / 10) + '0';
                digits[1] = (char)(count % 10) + '0';
                digits[2] = '\0';
                dwFont_DrawStringClipped(pDestBits, this->pFont, &pt, digits, this->textColorIdx, pClipRect);
            }
            dwRect nameRect;
            nameRect.left = cellX + 6;
            nameRect.top = rowTop + 4;
            nameRect.right = xRight;
            nameRect.bottom = rowBottom;
            dwFont_DrawText(pDestBits, this->pFont, &nameRect, sithInventory_g_aTypes[i].fpath, this->textColorIdx, pClipRect);
        }

        col++;
        if (col == this->columns)
        {
            col = 0;
            cellX = this->left + this->cellSpacing;
            xRight = cellX + this->cellWidth;
            rowTop += this->cellHeight;
            rowBottom += this->cellHeight;
        }
        else
        {
            cellX += this->cellWidth;
            xRight += this->cellWidth;
        }
    }
}
