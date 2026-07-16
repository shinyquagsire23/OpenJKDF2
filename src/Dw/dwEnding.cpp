// dwEnding — end-game graduation "certificate" sequence (dwMovie subclass).
// DroidWorks.exe 0x410a30-0x410d5f, vtbl dwEnding_vtbl @0x51eaf8. See
// Dw/dwEnding.h for the class notes.
//
// Rank tables (.rdata @0x51ead8 / @0x51eae8, Ghidra binned them into the
// neighboring dwGuiStatsDroid_vtbl label): the VO names ENJB018/019/010.wav
// and the localizable rank keys APPRENTICE/DESIGNER/MASTER, both indexed by
// the 0-based averaged rank.

#include "Dw/dwEnding.h"

#include "Dw/dwMovie.h"
#include "Dw/dwColormap.h"    // dwColormap_Load
#include "Dw/dwConfFile.h"    // certificate.ifc parsing
#include "Dw/dwStringTable.h" // certificate.txt (screen-local table)
#include "Dw/dwString.h"      // dwString_Equals
#include "Dw/dwSound.h"       // dwSound_pManager->GetOrLoadSample / dwSound_Play
#include "Dw/dwList.h"        // overlay children append
#include "Dw/dwGuiScreen.h"   // dwGuiScreen_CreateControl / _LocalizeString
#include "Dw/dwGuiHypText.h"  // the TEXT control the RANK/PLAYER lines target
#include "Dw/dwMission.h"     // dwMission record + dwCore_pMissionList
#include "Dw/dwPlayer.h"      // dwPlayer_name

#include "stdPlatform.h"

// TODO(dw-decomp): placeholder for the lecSmush SMUSH frame counter (binary
// DAT_0068b1c4) — owner is the untranslated lecSmush/SmushPlay unit (P8),
// which must adopt this definition (it stays 0 while SMUSH is stubbed, so
// the frame-gated VO/draw paths below stay dormant).
uint32_t lecSmush_frameNum = 0; // @0x68b1c4 (declared extern "C" in dwEnding.h)

// @0x51ead8 (dwEnding_aVoiceNames): rank congratulation VO, indexed by the
// 0-based rank.
static const char* dwEnding_aVoiceNames[3] = {
    "ENJB018.wav",
    "ENJB019.wav",
    "ENJB010.wav",
};

// @0x51eae8 (dwEnding_aRankNames): localizable rank-name keys for the
// certificate's RANK_NAME line.
static const char* dwEnding_aRankNames[3] = {
    "APPRENTICE",
    "DESIGNER",
    "MASTER",
};

// Note: no binary counterpart — soft-reset seam for the placeholder global.
extern "C" void dwEnding_Startup(void)
{
    lecSmush_frameNum = 0;
}

// Added: C-callable factory (see dwEnding.h). Upcasts through dwMovie ->
// dwSegment to the dwSegment subobject for dwSegment_Push.
extern "C" dwSegment* dwEnding_New(void)
{
    return static_cast<dwSegment*>(new dwEnding());
}

// @410a30 (dwEnding_Ctor)
dwEnding::dwEnding()
    : dwMovie("ending.san")
{
    this->rankIndex = 0; // Note: uninitialized until Activate in the binary
    this->bVoicePlayed = 0;
}

// @410a70 (dwEnding_Dtor; scalar-deleting wrapper @410a50)
dwEnding::~dwEnding()
{
}

// vtbl +0x00 @410a80 (dwEnding_OnActivate)
int dwEnding::Activate()
{
    dwColormap_Load((char*)"ending.cmp");

    // Average the NORMAL missions' earned ranks (missionType == 0) with a
    // +count/4 rounding bias; clamp to at least rank 1, then make 0-based.
    this->rankIndex = 0;
    uint32_t count = 0;
    // Note: NULL-guard added — dwCore_pMissionList is a dwMain.c placeholder
    // (NULL) until the P7 boot flow lands; the binary list always exists.
    if (dwCore_pMissionList != NULL)
    {
        for (dwListNode* pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
        {
            dwMission* pMission = (dwMission*)pNode->pData;
            if (pMission->missionType == 0)
            {
                count++;
                this->rankIndex += pMission->rank;
            }
        }
    }
    // Note: guard added for the placeholder world — the binary divides
    // unconditionally (retail data always has normal missions).
    if (count != 0)
        this->rankIndex = ((count >> 2) + this->rankIndex) / count;
    else
        this->rankIndex = 0;
    if (this->rankIndex == 0)
        this->rankIndex = 1;

    int rank1 = this->rankIndex; // 1-based
    this->rankIndex = rank1 - 1; // 0-based from here on
    dwSound_pManager->GetOrLoadSample(dwEnding_aVoiceNames[rank1 - 1]);

    // Build the certificate overlay from certificate.ifc (+ its string table).
    dwStringTable table("certificate.txt");
    dwConfFile conf;
    dwConfFile_Open(&conf, "certificate.ifc");
    while (conf.bEof == 0)
    {
        dwConfFile_ReadLine(&conf);
        char* pTok = dwConfFile_NextToken(&conf);
        dwWidget* pCtl;
        char* pText = NULL;
        if (dwString_Equals(pTok, "RANK_NAME"))
        {
            pTok = dwConfFile_NextToken(&conf);
            pCtl = dwGuiScreen_CreateControl(pTok, &conf, NULL);
            if (pCtl != NULL)
                pText = dwGuiScreen_LocalizeString((char*)dwEnding_aRankNames[this->rankIndex], NULL);
        }
        else if (dwString_Equals(pTok, "PLAYER_NAME"))
        {
            pTok = dwConfFile_NextToken(&conf);
            pCtl = dwGuiScreen_CreateControl(pTok, &conf, NULL);
            pText = dwPlayer_name.pBuffer;
        }
        else
        {
            pCtl = dwGuiScreen_CreateControl(pTok, &conf, &table);
        }

        if (pText != NULL && pCtl != NULL)
        {
            // The RANK_NAME/PLAYER_NAME keywords name a TEXT control — the
            // binary blindly treats the result as a dwGuiHypText and injects
            // the text via the +0x48 SetText virtual (which APPENDS, so the
            // existing text is freed first).
            dwGuiHypText* pHyp = (dwGuiHypText*)pCtl;
            pHyp->text.Free();
            pHyp->SetText(pText);
        }
        if (pCtl != NULL)
        {
            // Append to the movie overlay's child list (drawn by dwMovie's
            // +0x18 Draw over each presented frame).
            this->overlay.children.InsertAfter(this->overlay.children.pSentinel->pPrev, pCtl);
        }
    }
    int ret = dwMovie::Activate();
    dwConfFile_Close(&conf);
    return ret;
}

// vtbl +0x10 @410cb0 (dwEnding_Update)
void dwEnding::Update()
{
    if (lecSmush_frameNum > 0x168 && this->bVoicePlayed == 0)
    {
        dwSound_Play(dwEnding_aVoiceNames[this->rankIndex]);
        this->bVoicePlayed = 1;
    }
    dwMovie::Update();
}

// vtbl +0x18 @410cf0 (dwEnding_Draw)
void dwEnding::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (lecSmush_frameNum > 0x185 && lecSmush_frameNum < 0x1e9)
        dwMovie::Draw(pDestBits, pClipRect);
}
