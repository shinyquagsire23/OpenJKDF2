// dwHelp — animated HELP-droid speech control (keyword "HELP") + dwGuiIndicator
// blinking status widget (keyword "INDICATOR"). DroidWorks.exe 0x418af0-0x419ba0,
// vtbls @0x51ed50 (dwHelp) / @0x51edc8 (dwGuiIndicator). See Dw/dwHelp.h.
//
// This unit owns the dwGuiIndicator_*/dwHelp_Ctor shims (ex-dwMain.c
// placeholders — the orchestrator deletes those copies now that these are real).

#include "Dw/dwHelp.h"

#include "Dw/dwSound.h"      // dwSound_Play / _Stop
#include "Dw/dwCursor.h"     // dwCursor_Precache
#include "Dw/dwPlayer.h"     // dwPlayer_statsFlags
#include "Dw/dwGuiInGame.h"  // dwGuiInGame_pActive (player-speaker routing)
#include "Dw/dwString.h"
#include "Dw/dwImage.h"
#include "Dw/dwRect.h"

#include "jk.h"          // _sprintf
#include "stdPlatform.h" // stdPlatform_Printf (binary: jk_logtofile)

#include <stdlib.h> // rand
#include <new>      // placement new (C shims)

// =====================================================================
// dwHelp
// =====================================================================

// @418af0 (dwHelp_Ctor)
dwHelp::dwHelp(dwRect* pRect, char* pAnimName, int speakerCode)
    : dwAnim(pRect, pAnimName, /*msgCode*/0, /*bLoop*/1, /*fps*/15.0f)
{
    this->bAutoAdvance = 0;
    this->speechDelay = -1.0f;
    // currentWav default-constructed by its member ctor.
    this->speakerCode = speakerCode;
    this->savedAnimFrame = 0;
}

// @418b90 (dwHelp_Dtor; scalar-deleting wrapper @418b70)
dwHelp::~dwHelp()
{
    this->StopSpeech();
    // currentWav dtor frees its buffer; dwAnim base dtor tears the rest down.
}

// vtbl +0x10 @418bf0 (dwHelp_OnKey)
int dwHelp::OnKey(int key, int repeat)
{
    (void)repeat;
    if ((char)key == '\x1b')
        this->StopSpeech();
    return 0;
}

// vtbl +0x14 @418c10 (dwHelp_Update)
void dwHelp::Update(float dt)
{
    if (this->currentWav.length == 0 && this->speechDelay > 0.0f)
    {
        this->speechDelay -= dt;
        if (this->speechDelay <= 0.0f)
            this->PlaySpeech(0, 1);
    }
    this->dwAnim::Update(dt); // tick the mouth-flap frames
}

// vtbl +0x18 @4196d0 (dwHelp_OnHover)
int dwHelp::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    // Hover-notify (the binary's DispatchMsg the decompiler rendered with a
    // lost ECX message): dispatch { 0x7531, msgCode } and return 1. dwHelp's
    // inherited dwAnimBase msgCode is 0.
    return this->OnHoverNotify((void*)(intptr_t)this->msgCode);
}

// vtbl +0x1c @419700 (dwHelp_OnMessage)
int dwHelp::OnMessage(dwWidgetMsg* pMsg)
{
    char handled = 0;
    uint32_t code = (uint32_t)pMsg->code;

    if (code < 0x7531)
    {
        if (code != 30000) // 0x7530
        {
            if (code == 0x2329)
            {
                this->StopSpeech();
                handled = 1;
            }
        }
        else if (this->currentWav.length == 0) // 0x7530: idle line while idle
        {
            handled = this->PlaySpeech(0, 0);
        }
    }
    else if (code == 0x7531) // play(msgCode, var)
    {
        handled = this->PlaySpeech((uint32_t)(intptr_t)pMsg->pSender, pMsg->param);
    }
    else if (code == 0x7532)
    {
        this->StopSpeech();
    }

    if (handled == 0)
        handled = (char)this->dwAnimBase::OnMessage(pMsg);
    return handled;
}

// @419610 (dwHelp_StopSpeech)
void dwHelp::StopSpeech()
{
    if (this->currentWav.length != 0)
    {
        this->savedAnimFrame = (int32_t)this->curFrame;
        this->Stop();       // virtual dwAnimBase::Stop
        this->Invalidate(); // virtual dwWidget::Invalidate
        if (this->speakerCode == 0x6b)
        {
            if (dwGuiInGame_pActive != NULL)
                dwGuiInGame_pActive->ClearCammyText();
        }
        else
        {
            dwString tmp(this->currentWav); // copy the name before freeing
            this->currentWav.Free();
            dwSound_Stop(tmp.pBuffer);
            tmp.Free();
        }
        this->currentWav.Free();
        this->Invalidate();
    }
}

// @418c70 (dwHelp_PlaySpeech) — the giant (speakerCode, msgCode) -> wav table.
char dwHelp::PlaySpeech(unsigned int msgCode, int var)
{
    const char* pWav = NULL;
    char local_25 = 0;
    char aWavName[20];

    this->speechDelay = -1.0f;

    if (this->speakerCode == 100) // HPCP (help droid)
    {
        if (msgCode < 0x66)
        {
            if (msgCode == 0x65) pWav = "HPCP010";
            else if (msgCode == 0) { pWav = "HPCP001L"; this->bAutoAdvance = 1; }
        }
        else if (msgCode < 0x3eb)
        {
            if (msgCode == 0x3ea) pWav = "HPCP023";
            else switch (msgCode) {
                case 0x66: pWav = "HPCP009"; break;
                case 0x67: pWav = "HPCP007L"; break;
                case 0x68: pWav = "LSCP008"; break;
                case 0x6a: pWav = "HPCP005L"; break;
            }
        }
        else if (msgCode < 0x7d5)
        {
            if (msgCode == 0x7d4) pWav = "HPCP019";
            else if (msgCode == 0x3eb) pWav = "HPCP022";
        }
        else if (msgCode < 0x7df)
        {
            if (msgCode == 0x7de) pWav = "HPCP011L";
            else if (msgCode == 0x7d5) pWav = "HPCP037";
        }
        else if (msgCode < 0xfa9)
        {
            if (msgCode == 0xfa8) pWav = "HPCP036";
            else switch (msgCode) {
                case 0x7e3: pWav = "HPCP021"; break;
                case 0x7e4: pWav = "HPCP025"; break;
                case 0x7e5:
                    switch (var) {
                        case 1: pWav = "HPCP031"; break;
                        case 2: pWav = "HPCP032L"; break;
                        case 3: pWav = "HPCP030"; break;
                        case 4: pWav = "HPCP034"; break;
                        case 5: pWav = "HPCP028L"; break;
                        case 6: pWav = "HPCP026L"; break;
                    }
                    break;
                case 0x7e7: pWav = "HPCP014"; break;
                case 0x7e8: pWav = "HPCP013"; break;
                case 0x7eb: pWav = "HPCP038L"; break;
            }
        }
        else if (msgCode < 0x7919)
        {
            if (msgCode == 31000) pWav = "HPCP015";
            else if (msgCode == 30000)
            {
                this->StopSpeech();
                dwCursor_Precache(1);
                dwCursor_Precache(2);
                dwCursor_Precache(7);
                dwCursor_Precache(6);
                dwCursor_Precache(8);
                dwCursor_Precache(0xb);
                dwCursor_Precache(0xc);
                dwPlayer_statsFlags |= 0x80000000;
                // Note: binary dispatches a lost widget message here.
            }
        }
        else switch (msgCode) {
            case 0x7919: pWav = "HPCP016"; break;
            case 0x791a: pWav = "HPCP017"; break;
            case 0x791b: pWav = "HPCP018"; break;
            case 0x791c: pWav = "HPCP024"; break;
            case 0x791d: pWav = "HPCP035"; break;
            case 0x7929:
                if (this->currentWav.length == 0)
                {
                    // Note: MSVC scaled rand() to 0..3 (RAND_MAX 0x7fff). Added: macOS rand() is
                    // 0x7fffffff, so the old scale gave r>>3 (no case matched, speech never played).
                    int r = rand() % 4;
                    switch (r) {
                        case 0: pWav = "GCCP001"; break;
                        case 1: pWav = "GCCP002"; break;
                        case 2: pWav = "GCCP003"; break;
                        case 3: pWav = "GCCP004"; break;
                    }
                }
                break;
        }
    }
    if (this->speakerCode == 0x66) // MMCP
    {
        if (msgCode < 0xbb9)
        {
            if (msgCode == 3000) pWav = "MMCP013";
            else if (msgCode == 0)
            {
                if (var == 0)
                {
                    if (this->bAutoAdvance == 0)
                    { pWav = "MMCP001"; this->speechDelay = 1.0f; this->bAutoAdvance = 1; }
                    else
                    { pWav = "MMCP004"; this->speechDelay = 5.0f; this->bAutoAdvance = 1; }
                }
                else { pWav = "MMCP002L"; this->bAutoAdvance = 1; }
            }
        }
        else if (msgCode < 0x7532)
        {
            if (msgCode == 0x7531)
            {
                this->StopSpeech();
                dwPlayer_statsFlags |= 0x20000000;
                // Note: binary dispatches a lost widget message here.
            }
            else if (msgCode == 0xbb9) pWav = "MMCP017";
            else if (msgCode == 0xbba) pWav = "MMCP014L";
        }
        else switch (msgCode) {
            case 0x791a: pWav = "MMCP009"; break;
            case 0x791b: pWav = "MMCP010"; break;
            case 0x791f: pWav = "MMCP006L"; break;
            case 0x7920: pWav = "MMCP011L"; break;
            case 0x7921: pWav = "MMCP016"; break;
        }
    }
    if (this->speakerCode == 0x68) // LSCP
    {
        if (msgCode < 0xfa3)
        {
            if (msgCode < 4000)
            {
                if (msgCode == 0)
                {
                    if (var == 0)
                    {
                        if (this->bAutoAdvance == 0)
                        { pWav = "LSCP001L"; this->bAutoAdvance = 1; }
                        else
                        { pWav = "LSCP003"; this->speechDelay = 5.0f; this->bAutoAdvance = 1; }
                    }
                    else { pWav = "LSCP004"; this->bAutoAdvance = 1; }
                }
            }
            else pWav = "LSCP014";
        }
        else if (msgCode < 0x7923)
        {
            if (msgCode == 0x7922) pWav = "LSCP011";
            else switch (msgCode) {
                case 0xfa3: pWav = "LSCP009L"; break;
                case 0xfa4: pWav = "LSCP006"; break;
                case 0xfa5:
                case 0xfa6: pWav = "LSCP008"; break;
                case 0xfa7: pWav = "LSCP005"; break;
                case 0xfa8: pWav = "LSCP012L"; break;
            }
        }
        else if (msgCode == 0x7928) pWav = "LSCP007";
    }
    if (this->speakerCode == 0x6a) // RHCP
    {
        if (msgCode < 0x97)
        {
            if (msgCode == 0x96) pWav = "RHCP015";
            else if (msgCode == 0)
            {
                if (var == 0)
                {
                    pWav = "RHCP001";
                    if (this->bAutoAdvance == 0)
                    { this->speechDelay = 1.0f; this->bAutoAdvance = 1; }
                    else
                    { this->speechDelay = 7.0f; this->bAutoAdvance = 1; }
                }
                else { pWav = "RHCP003L"; this->bAutoAdvance = 1; }
            }
        }
        else if (msgCode < 0x1b5c)
        {
            if (msgCode == 0x1b5b) pWav = "RHCP018";
            else if (msgCode == 7000) pWav = "RHCP008";
        }
        else if (msgCode < 0x7531)
        {
            if (msgCode == 30000)
            {
                this->StopSpeech();
                dwPlayer_statsFlags |= 0x40000000;
                // Note: binary dispatches a lost widget message here.
            }
            else switch (msgCode) {
                case 0x1b5d: pWav = "RHCP009"; break;
                case 0x1b5e: pWav = "RHCP013"; break;
                case 0x1b5f: pWav = "RHCP014"; break;
                case 0x1b61: pWav = "RHCP016"; break;
            }
        }
        else switch (msgCode) {
            case 0x792b: pWav = "RHCP007"; break;
            case 0x792c: pWav = "RHCP010"; break;
            case 0x792d: pWav = "RHCP011"; break;
            case 0x792e: pWav = "RHCP005L"; break;
            case 0x792f: pWav = "RHCP009"; break;
            case 0x7930: pWav = "RHCP014"; break;
            case 0x7931: pWav = "RHCP013"; break;
        }
    }
    if (this->speakerCode == 0x6c) // SSCA
    {
        if (msgCode < 0x97)
        {
            if (msgCode == 0x96) pWav = "SSCA010";
            else if (msgCode == 0)
            {
                if (var == 0)
                {
                    if (this->bAutoAdvance == 0)
                    { pWav = "SSCA001"; this->speechDelay = 1.0f; this->bAutoAdvance = 1; }
                    else
                    { pWav = "SSCA003"; this->speechDelay = 5.0f; this->bAutoAdvance = 1; }
                }
                else { pWav = "SSCA002"; this->bAutoAdvance = 1; }
            }
        }
        else switch (msgCode) {
            case 0x7920: pWav = "SSCA008"; break;
            case 0x7922: pWav = "SSCA005"; break;
            case 0x7925: pWav = "SSCA004"; break;
            case 0x7926: pWav = "SSCA006"; break;
            case 0x7927: pWav = "SSCA007"; break;
        }
    }
    // Player speaker (0x6b), and the 0x6c/SSCA fall-through when SSCA had no
    // match, both consult the HPCA table (binary: shared LAB_004192e2 block).
    if (this->speakerCode == 0x6b || (this->speakerCode == 0x6c && pWav == NULL))
    {
        if (msgCode < 0x6b)
        {
            if (msgCode == 0x6a) pWav = (var == 0) ? "HPCA005L" : "HPCA008L";
            else if (msgCode == 0)
            {
                if (var == 0)
                {
                    pWav = "HPCA001";
                    if (this->bAutoAdvance == 0)
                    { this->speechDelay = 1.0f; this->bAutoAdvance = 1; }
                    else
                    { this->speechDelay = 7.0f; this->bAutoAdvance = 1; }
                }
                else { pWav = "HPCA002L"; this->bAutoAdvance = 1; }
            }
        }
        else if (msgCode < 0x1789)
        {
            if (msgCode == 0x1788) pWav = "HPCA034";
            else if (msgCode == 0x96) pWav = "HPCA004";
        }
        else if (msgCode < 0x7531)
        {
            if (msgCode == 30000)
            {
                // Note: binary dispatches a lost widget message here.
            }
            else switch (msgCode) {
                case 0x1f41: pWav = "HPCA016L"; break;
                case 0x1f42: pWav = "HPCA010"; break;
                case 0x1f43: pWav = "HPCA012"; break;
                case 0x1f45: pWav = "HPCA020"; break;
                case 0x1f46: pWav = "HPCA021L"; break;
                case 0x1f47: pWav = "HPCA024"; break;
                case 0x1f48: pWav = "HPCA025"; break;
            }
        }
        else if (0x7919 < msgCode)
        {
            if (msgCode < 0x791c) pWav = "HPCA033";
            else if (msgCode == 0x7924) pWav = "HPCA013";
        }
    }

    if (pWav == NULL)
        return 0;
    if (*pWav == '\0')
        return 0;

    this->StopSpeech();
    _sprintf(aWavName, "%s.wav", pWav);
    stdPlatform_Printf("Help: %s\n", aWavName); // binary: jk_logtofile

    if (this->speakerCode == 0x6b)
    {
        if (dwGuiInGame_pActive != NULL)
        {
            dwGuiInGame_pActive->PlayVoiceLineEx(0, aWavName, 0, 1);
            local_25 = 1;
        }
    }
    else
    {
        dwSoundSample* pSample = dwSound_Play(aWavName);
        if (pSample != NULL)
        {
            pSample->pFinishMsg = (void*)0x2329; // finish message CODE
            this->dwAnim::Play((uint8_t)0);      // start the mouth flap
            uint32_t frame = (uint32_t)this->savedAnimFrame;
            this->curFrame = frame;              // resume the idle frame
            this->accumTimeSec = (float)frame / this->fps;
            local_25 = 1;
        }
    }

    if (local_25 != '\0')
        this->currentWav.AssignCStr(aWavName);
    return local_25;
}

// =====================================================================
// dwGuiIndicator
// =====================================================================

// @4197b0 (dwGuiIndicator_Ctor)
dwGuiIndicator::dwGuiIndicator(dwRect* pRect, char* pImage1Name, char* pImage2Name,
                               int code, float progress0)
    : dwWidget(pRect)
{
    this->pImage1 = NULL;
    // imageName1 default-constructed by its member ctor.
    this->pImage2 = NULL;
    // imageName2 default-constructed by its member ctor.
    // Note: the binary ctor's clip-init writes are botched EH temps overwritten
    // by SetProgress; the reveal rect at full progress is the whole widget rect.
    this->clipLeft = this->left;
    this->clipTop = this->top;
    this->clipRight = this->right;
    this->clipBottom = this->bottom;
    this->progress = 1.0f;
    this->code = code;
    this->bActive = 0;
    this->bBlinkPhase = 0;
    this->blinkTimer = 0.0f;
    this->SetProgress(progress0);
    this->imageName1.AssignCStr(pImage1Name);
    this->imageName2.AssignCStr(pImage2Name);
    this->EnsureImages();
}

// @4198a0 (dwGuiIndicator_Dtor; scalar-deleting wrapper @419880)
dwGuiIndicator::~dwGuiIndicator()
{
    this->FreeImages();
    // imageName1/imageName2 dtors free their buffers; dwWidget base dtor last.
}

// @419910 (dwGuiIndicator_SetProgress)
void dwGuiIndicator::SetProgress(float progress)
{
    if (progress < 0.0f)
        progress = 0.0f;
    else if (progress > 1.0f)
        progress = 1.0f;

    if (this->progress != progress)
    {
        this->clipLeft = this->left;
        this->clipTop = this->top;
        this->clipRight = this->right;
        this->clipBottom = this->bottom;
        this->progress = progress;
        if ((int16_t)(this->right - this->left) < (int16_t)(this->bottom - this->top))
        {
            // taller than wide: reveal upward from the bottom
            int16_t h = (int16_t)(progress * (float)(this->bottom - this->top));
            this->clipTop = (int16_t)(this->clipBottom - h);
        }
        else
        {
            // reveal rightward from the left
            int16_t w = (int16_t)(progress * (float)(this->right - this->left));
            this->clipRight = (int16_t)(this->clipLeft + w);
        }
        this->Invalidate();
    }
}

// vtbl +0x18 @419a00 (dwGuiIndicator_OnHover — shared COMDAT; the twin body
// in dwWorkshopCtrl.cpp confirms it reads the +0x3c field as the pSender).
int dwGuiIndicator::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    // hover-notify: dispatch { 0x7531, code } and return 1.
    return this->OnHoverNotify((void*)(intptr_t)this->code);
}

// @419a30 (dwGuiIndicator_Show)
void dwGuiIndicator::Show()
{
    if (this->bActive == 0)
    {
        this->bActive = 1;
        this->bBlinkPhase = 1;
        this->blinkTimer = 0.5f;
        this->Invalidate();
    }
}

// @419a50 (dwGuiIndicator_Hide)
void dwGuiIndicator::Hide()
{
    if (this->bActive != 0)
    {
        this->bActive = 0;
        this->bBlinkPhase = 0;
        this->Invalidate();
    }
}

// vtbl +0x14 @419a70 (dwGuiIndicator_Update)
void dwGuiIndicator::Update(float dt)
{
    if (this->bActive != 0)
    {
        uint8_t oldPhase = this->bBlinkPhase;
        this->blinkTimer -= dt;
        while (this->blinkTimer <= 0.0f)
        {
            this->bBlinkPhase = (this->bBlinkPhase == 0);
            this->blinkTimer += 0.5f;
        }
        if (this->bBlinkPhase != oldPhase)
            this->Invalidate();
    }
}

// vtbl +0x44 @419ad0 (dwGuiIndicator_Draw)
void dwGuiIndicator::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->EnsureImages();
    if (this->bBlinkPhase != 0 && this->bActive != 0 && this->pImage2 != NULL)
        this->pImage2->Blit(pDestBits, this->left, this->top, pClipRect);
    if (this->pImage1 != NULL)
    {
        dwRect reveal;
        reveal.left = this->clipLeft;
        reveal.top = this->clipTop;
        reveal.right = this->clipRight;
        reveal.bottom = this->clipBottom;
        dwRect_Clip(&reveal, pClipRect);
        this->pImage1->Blit(pDestBits, this->left, this->top, &reveal);
    }
}

// vtbl +0x3c @419b50 (dwGuiIndicator_EnsureImages)
void dwGuiIndicator::EnsureImages()
{
    if (this->pImage1 == NULL && this->imageName1.length != 0)
        this->pImage1 = dwImage_LoadFile(this->imageName1.pBuffer);
    if (this->pImage2 == NULL && this->imageName2.length != 0)
        this->pImage2 = dwImage_LoadFile(this->imageName2.pBuffer);
}

// vtbl +0x40 @419ba0 (dwGuiIndicator_FreeImages)
void dwGuiIndicator::FreeImages()
{
    if (this->pImage1 != NULL)
    {
        delete this->pImage1;
        this->pImage1 = NULL;
    }
    if (this->pImage2 != NULL)
    {
        delete this->pImage2;
        this->pImage2 = NULL;
    }
}

// =====================================================================
// C-linkage shims (own the ex-dwMain.c placeholders)
// =====================================================================

// @418af0 — placement-ctor over a caller-allocated 0x5c block.
extern "C" dwHelp* dwHelp_Ctor(dwHelp* pThis, dwRect* pRect, char* pAnimName, int speakerCode)
{
    return new (pThis) dwHelp(pRect, pAnimName, speakerCode);
}

// @4197b0 — placement-ctor over a caller-allocated 0x48 block.
extern "C" dwGuiIndicator* dwGuiIndicator_Ctor(dwGuiIndicator* pThis, dwRect* pRect,
                                               char* pImage1Name, char* pImage2Name,
                                               int code, float progress0)
{
    return new (pThis) dwGuiIndicator(pRect, pImage1Name, pImage2Name, code, progress0);
}

extern "C" void dwGuiIndicator_SetProgress(dwGuiIndicator* pInd, float progress)
{
    pInd->SetProgress(progress);
}

extern "C" void dwGuiIndicator_Show(dwGuiIndicator* pInd)
{
    pInd->Show();
}

extern "C" void dwGuiIndicator_Hide(dwGuiIndicator* pInd)
{
    pInd->Hide();
}
