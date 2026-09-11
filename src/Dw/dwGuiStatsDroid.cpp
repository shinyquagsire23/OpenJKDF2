// dwGuiStatsDroid — the STATS_DROID assembled-droid stat-sheet widget.
//
// Decompiled from DroidWorks.exe @0x40fe00-0x410a2f (vtbl @0x51ea90).
// See dwGuiStatsDroid.h for the layout / slot map.
//
// No module statics — no dwGuiStatsDroid_Startup needed (soft-reset rule).

#include "Dw/dwGuiStatsDroid.h"

#include "Dw/dwImageDraw.h" // FrameRect / FillRect / Line
#include "Dw/dwGuiScreen.h" // dwGuiScreen_LocalizeString
#include "Dw/dwList.h"      // dwListNode iteration
#include "Dw/dwString.h"    // dwCore_workspaceName
#include "Dw/dwPart.h"      // dwPartNode (workspace payloads)

#include "globals.h" // SithThing / SithWorld / sithWorld_g_pCurrentWorld
#include "jk.h"      // _sprintf

extern "C" {
// Real repo sithInventory_GetInventory (returns the item's owned amount).
flex_t sithInventory_GetInventory(SithThing* pThing, int typeId);
}

// ---- cross-unit symbols -----------------------------------------------------

// Workspace droid part list + display name (owned by dwPart/dwInits/dwPlayer).
extern "C" dwListNode* dwCore_pWorkspaceNodes; // @0x53d984
extern "C" dwString dwCore_workspaceName;      // @0x53d978

// The running-mission HUD (NULL outside a mission). Owned by dwGuiInGame (P6w2).
struct dwGuiInGame;
extern "C" dwGuiInGame* dwGuiInGame_pActive; // @0x53e800

// ---- localized-string-key tables (binary: the PTR_s_NONE tables inside
// dwWorkshopDroidEditor_vtbl at +0x18 / +0x1c / +0x22) -----------------------
static const char* const dwGuiStatsDroid_aArm[4] =
    { "NONE", "LOW", "MEDIUM", "HIGH" };
static const char* const dwGuiStatsDroid_aPowerUse[5] =
    { "NONE", "VERY_LOW", "LOW", "MEDIUM", "HIGH" };
static const char* const dwGuiStatsDroid_aDurability[6] =
    { "NONE", "LOW", "MEDIUM_LOW", "MEDIUM", "MEDIUM_HIGH", "HIGH" };

// ===============================================================================

// @40fe00
dwGuiStatsDroid::dwGuiStatsDroid(dwRect* pRect, char* pFont1Name, uint8_t colorLabel,
                                 char* pFont2Name, uint8_t colorValue)
    : dwWidget(pRect)
{
    this->totals.ClearTotals();
    this->pFont1 = NULL;
    this->colorLabel = colorLabel;
    this->pFont2 = NULL;
    this->colorValue = colorValue;
    this->powerCur = 0;
    this->powerTarget = 0;
    if (pFont1Name != NULL)
        this->pFont1 = dwFont_Load(new dwFont, pFont1Name);
    if (pFont2Name != NULL)
        this->pFont2 = dwFont_Load(new dwFont, pFont2Name);
    this->labelDroidName = dwGuiScreen_LocalizeString((char*)"DROID_NAME:", NULL);
    this->labelTotalMass = dwGuiScreen_LocalizeString((char*)"TOTAL_MASS:", NULL);
    this->massValue[0] = '\0';
    this->labelMagnetic = dwGuiScreen_LocalizeString((char*)"MAGNETIC:", NULL);
    this->magneticValue = NULL;
    this->labelDurability = dwGuiScreen_LocalizeString((char*)"DURABILITY:", NULL);
    this->durabilityValue = NULL;
    this->labelLArm = dwGuiScreen_LocalizeString((char*)"L_ARM_STRENGTH:", NULL);
    this->lArmValue = NULL;
    this->labelRArm = dwGuiScreen_LocalizeString((char*)"R_ARM_STRENGTH:", NULL);
    this->rArmValue = NULL;
    this->labelSpeed = dwGuiScreen_LocalizeString((char*)"SPEED:", NULL);
    this->speedValue[0] = '\0';
    this->labelPowerUsage = dwGuiScreen_LocalizeString((char*)"POWER_USAGE:", NULL);
    this->powerUsageValue = NULL;
    this->labelPower = dwGuiScreen_LocalizeString((char*)"POWER:", NULL);
    this->powerValue[0] = '\0';
    this->Refresh();
}

// @40fff0 (DtorDelete @40ffd0)
dwGuiStatsDroid::~dwGuiStatsDroid()
{
    if (this->pFont1 != NULL)
        delete this->pFont1;
    if (this->pFont2 != NULL)
        delete this->pFont2;
}

// @410070 — hover-help notification.
int dwGuiStatsDroid::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    dwWidgetMsg msg = { 0x7531, (void*)0x791a, 0, NULL };
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// @4100a0
int dwGuiStatsDroid::OnMessage(dwWidgetMsg* pMsg)
{
    uint32_t code = (uint32_t)pMsg->code;
    if (code > 0x7db)
    {
        if (code < 0x7de) // 0x7dc / 0x7dd
        {
            this->Refresh();
            this->Invalidate();
        }
        else if (code == 0x7ec)
        {
            this->Invalidate();
        }
    }
    return 0;
}

// @4100e0 — recompute the stat totals from the workspace and format the value
// strings.
void dwGuiStatsDroid::Refresh()
{
    // Accumulate into a stack local, then copy into the widget's totals
    // (faithful to the binary — avoids showing partial state during a draw).
    dwDroidStatsTotals local;
    local.ClearTotals();
    for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext;
         pNode != dwCore_pWorkspaceNodes; pNode = pNode->pNext)
    {
        local.AccumulatePart((dwPartNode*)pNode->pData, 0);
    }
    this->totals = local;

    // Total mass. Binary: sprintf(massValue, MASS_FMT, 1, (double)mass).
    char* pMassFmt = dwGuiScreen_LocalizeString((char*)"MASS_FMT", NULL);
    _sprintf(this->massValue, pMassFmt, 1, (double)this->totals.mass);

    // Magnetic yes/no.
    this->magneticValue = dwGuiScreen_LocalizeString(
        (this->totals.capFlags & 0x10) ? (char*)"YES" : (char*)"NO", NULL);

    // Durability. Binary: __ftol(durability - (-0.5)) & 0xff -> 6-entry table.
    int durIdx = (int)(this->totals.durability + 0.5f) & 0xff;
    this->durabilityValue = dwGuiScreen_LocalizeString(
        (char*)dwGuiStatsDroid_aDurability[durIdx], NULL);

    // L/R arm strength: (maxLoad + 2) / 3, clamped to 3 -> 4-entry table.
    int lIdx = (this->totals.maxLoadLeft + 2) / 3;
    if (lIdx > 3) lIdx = 3;
    this->lArmValue = dwGuiScreen_LocalizeString((char*)dwGuiStatsDroid_aArm[lIdx], NULL);

    int rIdx = (this->totals.maxLoadRight + 2) / 3;
    if (rIdx > 3) rIdx = 3;
    this->rArmValue = dwGuiScreen_LocalizeString((char*)dwGuiStatsDroid_aArm[rIdx], NULL);

    // Speed value. speed = (power/mass) * 10 / drag; then round(speed * 3.6).
    char* pSpeedFmt = dwGuiScreen_LocalizeString((char*)"SPEED_FMT", NULL);
    float speed;
    if (this->totals.drag == 0.0f)
        speed = 0.0f;
    else
        speed = (this->totals.power / this->totals.mass) * 10.0f / this->totals.drag;
    int speedInt = (int)(speed * 3.6f + 0.5f);
    // Note: SPEED_FMT comes from the string table; the binary passes a 32-bit int.
    _sprintf(this->speedValue, pSpeedFmt, speedInt);

    // Power usage from the drain rate -> 5-entry table.
    int puIdx = 0;
    float drain = this->totals.drain;
    if (drain > 0.0f)
    {
        if (drain < 10.0f)
            puIdx = 1;
        else if (drain < 15.0f)
            puIdx = 2;
        else if (drain <= 20.0f)
            puIdx = 3;
        else
            puIdx = 4;
    }
    this->powerUsageValue = dwGuiScreen_LocalizeString((char*)dwGuiStatsDroid_aPowerUse[puIdx], NULL);

    // Power %.
    int cap = (int)(uint16_t)this->totals.batteryCapacity;
    if (this->totals.batteryCapacity != 0)
    {
        int pct = ((int)this->powerCur * 100) / cap;
        if (pct > 100)
            pct = 100;
        // Note: "%lu%%" expects unsigned long on LP64 — pass one explicitly.
        _sprintf(this->powerValue, "%lu%%", (unsigned long)pct);
    }
    else
    {
        _sprintf(this->powerValue, "0%%");
    }

    // Clamp the shown charge, then arm the gauge tween toward the real charge.
    if ((int)this->powerCur > cap)
        this->powerCur = (int16_t)this->totals.batteryCapacity;
    this->powerStart = this->powerCur;
    this->powerTarget = this->totals.batteryCharge;
    this->animTimeAccum = 0.0f;
}

// @4103b0
void dwGuiStatsDroid::Update(float dt)
{
    if (dwGuiInGame_pActive == NULL)
    {
        // Off-mission: tween the gauge toward its target charge at 2000/sec.
        if (this->powerCur != this->powerTarget)
        {
            int start = (int)this->powerStart;
            int target = (int)this->powerTarget;
            this->animTimeAccum += dt;
            int delta = target - start;
            float mag = this->animTimeAccum * 2000.0f;
            if (delta < 0)
                mag = -mag;
            int cur = (int)(mag + 0.5f) + start;
            if (cur < 0)
                cur = 0;
            if ((delta > 0 && cur > target) || (delta < 0 && cur < target))
                cur = target;
            this->powerCur = (int16_t)cur;

            int cap = (int)(uint16_t)this->totals.batteryCapacity;
            if (this->totals.batteryCapacity != 0)
                _sprintf(this->powerValue, "%lu%%", (unsigned long)((cur * 100) / cap));
            else
                _sprintf(this->powerValue, "0%%");
            this->Invalidate();
        }
    }
    else
    {
        // In a mission: snap the gauge to the live player energy (bin 0x14).
        // Note: defensive world null-guard (dwGuiInvBar does the same); the
        // binary assumes a live world whenever the HUD is active.
        SithThing* pPlayer = sithWorld_g_pCurrentWorld ? sithWorld_g_pCurrentWorld->pLocalPlayer : NULL;
        if (pPlayer != NULL)
        {
            int16_t energy = (int16_t)(int)((float)sithInventory_GetInventory(pPlayer, 0x14) + 0.5f);
            if (energy != this->powerCur)
            {
                this->powerCur = energy;
                this->powerTarget = energy;
                int cap = (int)(uint16_t)this->totals.batteryCapacity;
                _sprintf(this->powerValue, "%lu%%", (unsigned long)(((int)energy * 100) / cap));
                this->Invalidate();
            }
        }
    }
}

// @410500 — draw the power gauge + the stat rows.
void dwGuiStatsDroid::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (this->pFont1 == NULL || this->pFont2 == NULL)
        return;

    int16_t L = this->left, T = this->top, R = this->right, B = this->bottom;
    int lineHeight = (int)this->pFont1->pHeader->lineHeight;

    // Power gauge frame (bottom strip).
    dwRect gauge;
    gauge.left = (int16_t)(L + 2);
    gauge.right = (int16_t)(R - 2);
    gauge.top = (int16_t)((B - lineHeight) - 4);
    gauge.bottom = (int16_t)(B - 4);
    dwImageDraw_FrameRect(pDestBits, &gauge, this->colorLabel, pClipRect);

    // Filled portion (inset by 2 on every side).
    int16_t fillL = (int16_t)(L + 4);
    int16_t fillT = (int16_t)((B - lineHeight) - 2);
    int16_t fillR = (int16_t)(R - 4);
    int16_t fillB = (int16_t)(B - 6);
    if (this->totals.batteryCapacity != 0)
    {
        dwRect fill;
        fill.left = fillL;
        fill.top = fillT;
        fill.right = (int16_t)(((int)(int16_t)(fillR - fillL) * (int)this->powerCur) /
                               (int)(uint16_t)this->totals.batteryCapacity + fillL);
        fill.bottom = fillB;
        dwRect_Clip(&fill, pClipRect);
        dwImageDraw_FillRect(pDestBits, &fill, this->colorValue, NULL);
    }

    // Separator line above the gauge.
    int16_t sepY = (int16_t)(B - lineHeight - 7);
    {
        dwPoint p0 = { (int16_t)(L + 2), sepY };
        dwPoint p1 = { (int16_t)(R - 2), sepY };
        dwImageDraw_Line(pDestBits, &p0, &p1, this->colorLabel, pClipRect);
    }

    // Droid name row.
    dwRect row;
    row.left = (int16_t)(L + 2);
    row.top = (int16_t)(T + 2);
    row.right = (int16_t)(R - 2);
    row.bottom = (int16_t)((T + 2) + lineHeight);
    dwFont_DrawText(pDestBits, this->pFont1, &row, this->labelDroidName, this->colorLabel, pClipRect);
    dwFont_DrawTextAligned(pDestBits, this->pFont2, &row, dwCore_workspaceName.pBuffer,
                           this->colorValue, pClipRect, 2);

    // Separator line under the name.
    int16_t nameSepY = (int16_t)(T + 3 + lineHeight);
    {
        dwPoint p0 = { (int16_t)(L + 2), nameSepY };
        dwPoint p1 = { (int16_t)(R - 2), nameSepY };
        dwImageDraw_Line(pDestBits, &p0, &p1, this->colorLabel, pClipRect);
    }

    // Eight evenly-spaced stat rows between yTop and the gauge separator.
    int16_t yTop = (int16_t)(T + 4 + lineHeight);
    int span = (int)(int16_t)((B - lineHeight - 8) - yTop);

    struct { char* pLabel; char* pValue; } aRows[8] = {
        { this->labelTotalMass,  this->massValue },
        { this->labelMagnetic,   this->magneticValue },
        { this->labelDurability, this->durabilityValue },
        { this->labelLArm,       this->lArmValue },
        { this->labelRArm,       this->rArmValue },
        { this->labelSpeed,      this->speedValue },
        { this->labelPowerUsage, this->powerUsageValue },
        { this->labelPower,      this->powerValue },
    };
    for (int k = 0; k < 8; ++k)
    {
        row.left = (int16_t)(L + 2);
        row.top = (int16_t)(yTop + (span * k) / 8);
        row.right = (int16_t)(R - 2);
        row.bottom = B;
        dwFont_DrawText(pDestBits, this->pFont1, &row, aRows[k].pLabel, this->colorLabel, pClipRect);
        dwFont_DrawTextAligned(pDestBits, this->pFont2, &row, aRows[k].pValue,
                               this->colorValue, pClipRect, 2);
    }
}
