#include "jkGUIForce.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdString.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "World/jkPlayer.h"
#include "Gameplay/sithInventory.h"
#include "Gameplay/sithPlayer.h"
#include "Win95/stdDisplay.h"
#include "Win95/Windows.h"
#include "Main/jkStrings.h"
#include "World/jkPlayer.h"

static const char* jkGuiForce_bitmaps[17] = {
    "foAbsorb.bm",
    "foBlinding.bm",
    "foDeadlySight.bm",
    "foDestruction.bm",
    "foGrip.bm",
    "foHealth.bm",
    "foJump.bm",
    "foPersuasion.bm",
    "foProtection.bm",
    "foPull.bm",
    "foSeeing.bm",
    "foSpeed.bm",
    "foThrow.bm",
    "foThunderBolt.bm",
    "foStars.bm",
    "forceMeter.bm",
    "forceMeterBack.bm"
};

static const char* jkGuiForce_bitmapsMots[19] = {
    "foAbsorb.bm",
    "foBlinding.bm",
    "foChainLight.bm",
    "foDeadlySight.bm",
    "foDefense.bm",
    "foDestruct.bm",
    "foFarSight.bm",
    "foGrip.bm",
    "foHealth.bm",
    "foJump.bm",
    "foPersuasion.bm",
    "foProjection.bm",
    "foProtection.bm",
    "foPull.bm",
    "foPush.bm",
    "foSaberThrow.bm",
    "foSeeing.bm",
    "foSpeed.bm",
    "foStars.bm",
};

#define IDX_FOSTARS (Main_bMotsCompat ? 18 : 14)

#define EIDX_NAMETEXT (1)
#define EIDX_FLAVORTEXT (2)
#define EIDX_START_FP (3)
#define EIDX_END_FP_CLICKABLE (Main_bMotsCompat ? 20 : 15)
#define EIDX_END_FP (Main_bMotsCompat ? 20+1 : 16+1)
#define EIDX_MOTS_DEFENSE (20)
#define EIDX_RESET (Main_bMotsCompat ? 26 : 18)
#define EIDX_QUIT (Main_bMotsCompat ? 27 : 19)
#define EIDX_ALIGN_SLIDER (Main_bMotsCompat ? 30 : 23)

#define EIDX_OK_BUTTON (Main_bMotsCompat ? EIDX_END_FP +  4 : EIDX_END_FP)
#define EIDX_RESET_BUTTON (EIDX_OK_BUTTON + 1)
#define EIDX_QUIT_BUTTON (EIDX_RESET_BUTTON + 1)

static int jkGuiForce_alignment;
static float jkGuiForce_flt_556674;
static int jkGuiForce_numSpendStars;
static int jkGuiForce_bCanSpendStars;
static float jkGuiForce_isMulti;
static stdBitmap* jkGuiForce_aBitmaps[19];

static int jkGuiForce_sliderBitmapIndices[2] = {16, 15};

static wchar_t jkGuiForce_waTmp[400];

jkGuiElement jkGuiForce_buttonsMots[31] = { 
/*0*/        { ELEMENT_TEXT, 0, 2, NULL, 
                3, { 160, 350, 320, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*1*/        { ELEMENT_TEXT, 0, 2, NULL, 
                3, { 10, 15, 620, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*2*/        { ELEMENT_TEXT, 0, 2, NULL, 
                3, { 10, 46, 620, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 

/*3*/        { ELEMENT_PICBUTTON, SITHBIN_F_JUMP, 0, NULL, 
                9, { 146, 120, -1, -1 }, 1, 0, "GUI_HINT_JUMP", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*4*/        { ELEMENT_PICBUTTON, SITHBIN_F_PROJECT, 0, NULL, 
                11, { 146, 150, -1, -1 }, 1, 0, "GUI_HINT_PROJECTION", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*5*/        { ELEMENT_PICBUTTON, SITHBIN_F_SEEING, 0, NULL, 
                16, { 146, 180, -1, -1 }, 1, 0, "GUI_HINT_SEEING", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*6*/        { ELEMENT_PICBUTTON, SITHBIN_F_SPEED, 0, NULL, 
                17, { 146, 210, -1, -1 }, 1, 0, "GUI_HINT_SPEED", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*7*/        { ELEMENT_PICBUTTON, SITHBIN_F_PUSH, 0, NULL, 
                14, { 146, 240, -1, -1 }, 1, 0, "GUI_HINT_PUSH", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*8*/        { ELEMENT_PICBUTTON, SITHBIN_F_PULL, 0, NULL, 
                13, { 296, 120, -1, -1 }, 1, 0, "GUI_HINT_PULL", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*9*/        { ELEMENT_PICBUTTON, SITHBIN_F_SABERTHROW, 0, NULL, 
                15, { 296, 150, -1, -1 }, 1, 0, "GUI_HINT_SABERTHROW", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*10*/        { ELEMENT_PICBUTTON, SITHBIN_F_GRIP, 0, NULL, 
                7, { 296, 180, -1, -1 }, 1, 0, "GUI_HINT_GRIP", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*11*/        { ELEMENT_PICBUTTON, SITHBIN_F_FARSIGHT, 0, NULL, 
                6, { 296, 210, -1, -1 }, 1, 0, "GUI_HINT_FARSIGHT", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*12*/        { ELEMENT_PICBUTTON, SITHBIN_F_PERSUASION, 0, NULL, 
                10, { 446, 120, -1, -1 }, 1, 0, "GUI_HINT_PERSUASION", NULL, &jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*13*/        { ELEMENT_PICBUTTON, SITHBIN_F_HEALING, 0, NULL, 
                8, { 446, 150, -1, -1 }, 1, 0, "GUI_HINT_HEALING", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*14*/        { ELEMENT_PICBUTTON, SITHBIN_F_BLINDING, 0, NULL, 
                1, { 446, 180, -1, -1 }, 1, 0, "GUI_HINT_BLINDING", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*15*/        { ELEMENT_PICBUTTON, SITHBIN_F_CHAINLIGHT, 0, NULL, 
                2, { 446, 210, -1, -1 }, 1, 0, "GUI_HINT_CHAINLIGHT", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*16*/        { ELEMENT_PICBUTTON, SITHBIN_F_ABSORB, 0, NULL, 
                0, { 596, 120, -1, -1 }, 1, 0, "GUI_HINT_ABSORB", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*17*/        { ELEMENT_PICBUTTON, SITHBIN_F_DESTRUCTION, 0, NULL, 
                5, { 596, 150, -1, -1 }, 1, 0, "GUI_HINT_DESTRUCTION", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*18*/        { ELEMENT_PICBUTTON, SITHBIN_F_PROTECTION, 0, NULL, 
                12, { 596, 180, -1, -1 }, 1, 0, "GUI_HINT_PROTECTION", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*19*/        { ELEMENT_PICBUTTON, SITHBIN_F_DEADLYSIGHT, 0, NULL, 
                3, { 596, 210, -1, -1 }, 1, 0, "GUI_HINT_DEADLYSIGHT", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 
/*20*/        { ELEMENT_PICBUTTON, SITHBIN_F_DEFENSE, 0, NULL, 
                4, { 308, 300, -1, -1 }, 1, 0, "GUI_HINT_DEFENSE", NULL, jkGuiForce_ButtonClick, NULL, {0}, 0 }, 

              // `Choose <num>:` text
/*21*/        { ELEMENT_TEXT, 0, 2, &jkGuiForce_waTmp[0], 
                3, { 20, 90, 150, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*22*/        { ELEMENT_TEXT, 0, 2, &jkGuiForce_waTmp[100], 
                3, { 170, 90, 150, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*23*/        { ELEMENT_TEXT, 0, 2, &jkGuiForce_waTmp[200], 
                3, { 320, 90, 150, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*24*/        { ELEMENT_TEXT, 0, 2, &jkGuiForce_waTmp[300], 
                3, { 470, 90, 150, 30 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 

/*25*/        { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 
                3, { 550, 440, 80, 40 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*26*/        { ELEMENT_TEXTBUTTON, 0, 2, "GUI_RESET", 
                3, { 270, 440, 100, 30 }, 1, 0, NULL, NULL, &jkGuiForce_ResetClick, NULL, {0}, 0 }, 
/*27*/        { ELEMENT_TEXTBUTTON, /*12345*/-1, 2, "GUI_QUIT", 
                3, { 0, 440, 100, 40 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0 }, 
/*28*/        { ELEMENT_CUSTOM, 0, 0, NULL, 
                0, { 0, 390, 640, 30 }, 1, 0, NULL, &jkGuiForce_ForceStarsDraw, NULL, NULL, {0}, 0 }, 
/*29*/        { ELEMENT_END, 0, 0, NULL, 
                0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, {0}, 0 },

// HACK: Just make an unused slider
/*30*/  { ELEMENT_SLIDER,      0, 0, .origExtraInt = 200,  
        100, {150, 418, 340, 40}, 1, 0,  NULL,           0,  0,          &jkGuiForce_sliderBitmapIndices, {0},  0}, 
};  


static jkGuiElement jkGuiForce_buttons[25] = {
/*0*/   { ELEMENT_TEXT,       0,  2, NULL,               
         3, {160, 320, 320, 30}, 1, 0, NULL,                   0,  0,                      0, {0},  0},
/*1*/   { ELEMENT_TEXT,       0,  2, NULL,               
         3, {10, 15, 620, 30},   1, 0, NULL,                   0,  0,                      0, {0},  0},
/*2*/   { ELEMENT_TEXT,       0,  2, NULL,               
         3, {10, 46, 620, 30},   1, 0, NULL,                   0,  0,                      0, {0},  0},

/*3*/   { ELEMENT_PICBUTTON,  SITHBIN_F_ABSORB, 0, NULL,               
          0, {-1, -1, -1, -1},    1, 0, "GUI_HINT_ABSORB",      0, jkGuiForce_ButtonClick,  0, {0},  0},
/*4*/   { ELEMENT_PICBUTTON,  SITHBIN_F_BLINDING, 0, NULL,               
          1, {-1, -1, -1, -1},    1, 0, "GUI_HINT_BLINDING",    0, jkGuiForce_ButtonClick,  0, {0},  0},
/*5*/   { ELEMENT_PICBUTTON,  SITHBIN_F_DESTRUCTION, 0, NULL,               
          3, {-1, -1, -1, -1},    1, 0, "GUI_HINT_DESTRUCTION", 0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*6*/   { ELEMENT_PICBUTTON,  SITHBIN_F_GRIP, 0, NULL,               
          4, {-1, -1, -1, -1},    1, 0, "GUI_HINT_GRIP",        0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*7*/   { ELEMENT_PICBUTTON,  SITHBIN_F_HEALING, 0, NULL,               
          5, {-1, -1, -1, -1},    1, 0, "GUI_HINT_HEALING",     0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*8*/   { ELEMENT_PICBUTTON,  SITHBIN_F_JUMP, 0, NULL,               
          6, {-1, -1, -1, -1},    1, 0, "GUI_HINT_JUMP",        0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*9*/   { ELEMENT_PICBUTTON,  SITHBIN_F_PERSUASION, 0, NULL,               
          7, {-1, -1, -1, -1},    1, 0, "GUI_HINT_PERSUASION",  0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*10*/  { ELEMENT_PICBUTTON,  SITHBIN_F_PULL, 0, NULL,               
          9, {-1, -1, -1, -1},    1, 0, "GUI_HINT_PULL",        0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*11*/  { ELEMENT_PICBUTTON,  SITHBIN_F_SEEING, 0, NULL,              
         10, {-1, -1, -1, -1},    1, 0, "GUI_HINT_SEEING",      0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*12*/  { ELEMENT_PICBUTTON,  SITHBIN_F_SPEED, 0, NULL,              
         11, {-1, -1, -1, -1},    1, 0, "GUI_HINT_SPEED",       0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*13*/  { ELEMENT_PICBUTTON,  SITHBIN_F_THROW,       0, NULL,              
         12, {-1, -1, -1, -1},    1, 0, "GUI_HINT_THROW",       0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*14*/  { ELEMENT_PICBUTTON,  SITHBIN_F_LIGHTNING,   0, NULL,              
         13, {-1, -1, -1, -1},    1, 0, "GUI_HINT_LIGHTNING",   0, jkGuiForce_ButtonClick,  0, {0},  0}, 
/*15*/  { ELEMENT_PICBUTTON,  SITHBIN_F_PROTECTION,  0, NULL,               
          8, {-1, -1, -1, -1},    1, 0, "GUI_HINT_PROTECTION",  0, jkGuiForce_ExtraClick,   0, {0},  0}, 
/*16*/  { ELEMENT_PICBUTTON,  SITHBIN_F_DEADLYSIGHT, 0, NULL,               
          2, {-1, -1, -1, -1},    1, 0, "GUI_HINT_DEADLYSIGHT", 0, jkGuiForce_ExtraClick,   0, {0},  0}, 

/*17*/  { ELEMENT_TEXTBUTTON,  1, 2, "GUI_OK",    
          3, {550, 420, 80, 40},  1, 0, NULL,                   0, 0,                       0, {0},  0}, 
/*18*/  { ELEMENT_TEXTBUTTON,  0, 2, "GUI_RESET", 
          3, {270, 350, 100, 30}, 1, 0, NULL,                   0, jkGuiForce_ResetClick,   0, {0},  0}, 
/*19*/  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_QUIT",  
          3, { 0, 420, 100, 40},  1, 0, NULL,                   0,  0,                      0, {0},  0}, 

/*20*/  { ELEMENT_CUSTOM,      0, 0, NULL,               
          0, { 0, 390, 640, 30},  1, 0, NULL,            jkGuiForce_ForceStarsDraw,     0,  0, {0},  0}, 
/*21*/  { ELEMENT_CUSTOM,      0, 0, NULL,               
          0, {320, 418, 170, 40}, 1, 0, "GUI_DARKSIDE",  jkGuiForce_DarkLightHoverDraw, 0,  0, {0},  0}, 
/*22*/  { ELEMENT_CUSTOM,      0, 0, NULL,               
          0, {150, 418, 170, 40}, 1, 0, "GUI_LIGHTSIDE", jkGuiForce_DarkLightHoverDraw, 0,  0, {0},  0}, 

/*23*/  { ELEMENT_SLIDER,      0, 0, .origExtraInt = 200,  
        100, {150, 418, 340, 40}, 1, 0,  NULL,           0,  0,          &jkGuiForce_sliderBitmapIndices, {0},  0}, 
/*24*/  { ELEMENT_END,         0, 0, NULL,               
          0, {0},                 0, 0,  NULL,           0,  0,                             0, {0},  0}
};

static jkGuiMenu jkGuiForce_menu =
{ jkGuiForce_buttons, 0, 0xe1, 0xff, 0x0f, 0, 0, jkGuiForce_aBitmaps, jkGui_stdFonts, 0, jkGuiForce_ChoiceRemoveStars, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

static jkGuiMenu jkGuiForce_menuMots =
{ jkGuiForce_buttonsMots, 0, 0xe1, 0xff, 0x0f, 0, 0, jkGuiForce_aBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};


static jkGuiElement* jkGuiForce_pElements = jkGuiForce_buttons;
static jkGuiMenu* jkGuiForce_pMenu = &jkGuiForce_menu;

void jkGuiForce_ChoiceRemoveStar(jkGuiMenu *menu, int fpIdx, int amount)
{
    sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (float)((int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS) + 1));
    sithPlayer_SetBinAmt(fpIdx, (float)(amount - 1));
    if ( fpIdx >= SITHBIN_F_THROW && fpIdx <= SITHBIN_F_DESTRUCTION )
    {
        jkGuiRend_PlayWav("ForcePersuas01.wav");
    }
    else if ( fpIdx >= SITHBIN_F_HEALING && fpIdx <= SITHBIN_F_ABSORB )
    {
        jkGuiRend_PlayWav("ForceBlind01.wav");
    }
    jkGuiForce_pElements[EIDX_ALIGN_SLIDER].selectedTextEntry = 100 - (int)jkPlayer_CalcAlignment(jkGuiForce_isMulti);

    for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
    {
        int id = jkGuiForce_pElements[i].hoverId;
        jkGuiForce_pElements[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
    }

    jkGuiRend_Paint(menu);
}

void jkGuiForce_ChoiceRemoveStars(jkGuiMenu *menu)
{
    if ( jkGuiForce_alignment && (double)(unsigned int)stdPlatform_GetTimeMsec() > jkGuiForce_flt_556674 )
    {
        jkGuiForce_flt_556674 = (double)(unsigned int)stdPlatform_GetTimeMsec() - -1000.0;
        int beginIdx = SITHBIN_F_THROW;
        int endIdx = SITHBIN_F_DEADLYSIGHT;
        
        if ( jkGuiForce_alignment == 2 )
        {
            beginIdx = SITHBIN_F_HEALING;
            endIdx = SITHBIN_F_PROTECTION;
        }

        for (int i = beginIdx; i < endIdx; i++)
        {
            sithPlayer_SetBinCarries(i, 0);
            int curAmt = (int)sithPlayer_GetBinAmt(i);
            if (curAmt > 0)
            {
                jkGuiForce_ChoiceRemoveStar(menu, i, curAmt);
                return;
            }
        }

        if ( jkGuiForce_alignment == 2 )
        {
            jkPlayer_SetChoice(jkGuiForce_alignment);
        }
        else if ( jkGuiForce_alignment == 1 )
        {
            jkPlayer_SetChoice(jkGuiForce_alignment);
        }

        jkGuiForce_alignment = 0;
        jkGuiForce_pElements[EIDX_ALIGN_SLIDER].selectedTextEntry = 100 - (int)jkPlayer_CalcAlignment(0.0);
        for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
        {
            int id = jkGuiForce_pElements[i].hoverId;
            jkGuiForce_pElements[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
        }
        jkGuiRend_Paint(menu);
    }
}

void jkGuiForce_ForceStarsDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    int spendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    if ( spendStars <= 0 )
    {
        stdFont_Draw4(vbuf, jkGui_stdFonts[2], element->rect.x, element->rect.y, element->rect.width, element->rect.height, 3, jkStrings_GetUniStringWithFallback("GUI_NO_STARS"), 1);
    }
    else
    {
        stdVBuffer* bitmap = jkGuiForce_aBitmaps[IDX_FOSTARS]->mipSurfaces[Main_bMotsCompat ? 10 : 0];

        // MOTS added
        int spendStarsVisualMax = element->rect.width / bitmap->format.width;
        if (spendStarsVisualMax <= spendStars) {
            spendStars = spendStarsVisualMax;
        }

        for (int i = 0; i < spendStars; i++)
        {
            stdDisplay_VBufferCopy(vbuf, bitmap, element->rect.x + bitmap->format.width * i + ((element->rect.width - bitmap->format.width * spendStars) >> 1), element->rect.y, 0, 1);
        }
    }
    
    for (int i = EIDX_START_FP; i < (Main_bMotsCompat ? EIDX_END_FP : EIDX_END_FP_CLICKABLE); i++)
    {
        // MOTS added: different rendering
        if (Main_bMotsCompat) {
            jkGuiElement* pFpElement = &jkGuiForce_pElements[i];

            int id = pFpElement->hoverId;
            int numStars = (int)sithPlayer_GetBinAmt(id);
            if (!jkGuiForce_isMulti && i == EIDX_MOTS_DEFENSE)
                continue;

            stdBitmap* psVar1 = !pFpElement->bIsVisible ? menu->ui_structs[pFpElement->selectedTextEntry] : NULL;
            if (psVar1) 
            {
                rdRect local_10;

                local_10.x = 0;
                local_10.y = 0;
                local_10.width = pFpElement->rect.width;
                if (psVar1->mipSurfaces[3]->format.width <= local_10.width) {
                    local_10.width = (psVar1->mipSurfaces[3]->format).width;
                }
                local_10.height = pFpElement->rect.height;
                if (psVar1->mipSurfaces[3]->format.height <= local_10.height) {
                    local_10.height = psVar1->mipSurfaces[3]->format.height;
                }
                stdDisplay_VBufferCopy(vbuf, psVar1->mipSurfaces[3], pFpElement->rect.x, pFpElement->rect.y, &local_10, 1);
            }

            int x_left = pFpElement->rect.x - jkGuiForce_aBitmaps[IDX_FOSTARS]->mipSurfaces[numStars]->format.width - 19;
            int x_right =  pFpElement->rect.x + pFpElement->rect.width + 19;
            int y = pFpElement->rect.y + 3;
            stdDisplay_VBufferCopy(vbuf, jkGuiForce_aBitmaps[IDX_FOSTARS]->mipSurfaces[numStars + 5], x_left, y, NULL,1);

            if (i == EIDX_MOTS_DEFENSE) 
            {
                stdDisplay_VBufferCopy(vbuf, jkGuiForce_aBitmaps[IDX_FOSTARS]->mipSurfaces[numStars], x_right, y, NULL, 1);
            }
        }
        else {
            int id = jkGuiForce_pElements[i].hoverId;
            int numStars = (int)sithPlayer_GetBinAmt(id) - 1;
            if ( numStars >= 0 )
            {
                if (id >= SITHBIN_F_HEALING && id <= SITHBIN_F_ABSORB)
                {
                    numStars += 4; // Light side
                }
                else if (id >= SITHBIN_F_THROW && id <= SITHBIN_F_DESTRUCTION)
                {
                    numStars += 8; // Dark side
                }

                // Show the number of force stars next to each button
                int x;
                if (jkGuiForce_pElements[i].rect.x >= 320 )
                    x = jkGuiForce_pElements[i].rect.width + jkGuiForce_pElements[i].rect.x + 19;
                else
                    x = jkGuiForce_pElements[i].rect.x - jkGuiForce_aBitmaps[IDX_FOSTARS]->mipSurfaces[numStars]->format.width - 19;

                stdDisplay_VBufferCopy(vbuf, jkGuiForce_aBitmaps[IDX_FOSTARS]->mipSurfaces[numStars], x, jkGuiForce_pElements[i].rect.y + 3, NULL, 1);
            }
        }
    }
}

int jkGuiForce_ExtraClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c)
{
    return 0;
}

int jkGuiForce_ButtonClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c)
{
    if ( !jkGuiForce_bCanSpendStars )
        return 0;

    int binIdx = element->hoverId;
    int spendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    int curLevel = (int)sithPlayer_GetBinAmt(binIdx);

    int bIsDefense = Main_bMotsCompat ? (!!(element == &jkGuiForce_pElements[EIDX_MOTS_DEFENSE]) + 1) : 0;

    if (Main_bMotsCompat) {
        int pvVar1;
        if ((element == &jkGuiForce_pElements[EIDX_MOTS_DEFENSE]) && (-1 < jkPlayer_aMotsFpBins[curLevel + 0x44])) {
            int iVar3 = 0;
            float fVar5;
            int* piVar2 = jkPlayer_aMotsFpBins + jkPlayer_aMotsFpBins[curLevel + 0x44] * 8;
            do {
                if ((*piVar2 != 0) &&
                   (fVar5 = sithPlayer_GetBinAmt(*piVar2), 0.0 < fVar5)) break;
                iVar3 = iVar3 + 1;
                piVar2 = piVar2 + 1;
            } while (iVar3 < 8);
            if (iVar3 != 8) {
                return 0;
            }
        }
        if ((curLevel < 4) && (bIsDefense <= spendStars)) {
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,(float)(spendStars - bIsDefense));
            sithPlayer_SetBinAmt(binIdx,(float)(curLevel + 1));
        }
        if (jkGuiForce_isMulti == 0) {
            if ((curLevel == element->oldForcePoints) ||
               ((curLevel != 4 && (bIsDefense <= spendStars)))) goto LAB_00418eb2;
            sithPlayer_SetBinAmt
                      (SITHBIN_SPEND_STARS,
                       (float)((curLevel - element->oldForcePoints) * bIsDefense + spendStars));
            pvVar1 = element->oldForcePoints;
        }
        else {
            

            if ((curLevel != 4) && (bIsDefense <= spendStars)) goto LAB_00418eb2;
            if (element == &jkGuiForce_pElements[EIDX_MOTS_DEFENSE]) {
                pvVar1 = (int)jkPlayer_aMultiParams[119];
            }
            else {
                pvVar1 = 0;
            }
            sithPlayer_SetBinAmt
                      (SITHBIN_SPEND_STARS,(float)((curLevel - pvVar1) * bIsDefense + spendStars));
        }
        sithPlayer_SetBinAmt(binIdx,(float)pvVar1);

LAB_00418eb2:
        jkGuiForce_UpdateViewForRank();
        jkGuiRend_Paint(menu);
        return 0;
    }
    else {
        if ( curLevel < 4 && spendStars > 0 )
        {
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (float)(spendStars - 1));
            sithPlayer_SetBinAmt(binIdx, (float)(curLevel + 1));
            jkGuiForce_pElements[EIDX_ALIGN_SLIDER].selectedTextEntry = 100 - (int)jkPlayer_CalcAlignment(jkGuiForce_isMulti);
            jkGuiRend_Paint(menu);
        }

        if (jkGuiForce_isMulti)
        {
            if ( curLevel == 4 || !spendStars )
            {
                sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (float)(spendStars + curLevel));
                sithPlayer_SetBinAmt(binIdx, 0.0);
                jkGuiForce_pElements[EIDX_ALIGN_SLIDER].selectedTextEntry = 100 - (int)jkPlayer_CalcAlignment(jkGuiForce_isMulti);
            }

            jkGuiForce_UpdateViewForRank();
            jkGuiRend_Paint(menu);
        }
    }

    return 0;
}

// MOTS altered
int jkGuiForce_ResetClick(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw)
{
    if ( !jkGuiForce_bCanSpendStars )
        return 0;

    sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (double)jkGuiForce_numSpendStars);
    for (int i = EIDX_START_FP; i < (Main_bMotsCompat ? EIDX_END_FP : EIDX_END_FP_CLICKABLE); i++)
    {
        float initialForcePoints = (float)jkGuiForce_pElements[i].oldForcePoints;
        sithPlayer_SetBinAmt(jkGuiForce_pElements[i].hoverId, initialForcePoints);
    }

    // MOTS added: no condition
    if (Main_bMotsCompat || jkGuiForce_isMulti)
    {
        jkGuiForce_UpdateViewForRank();
    }

    if (!Main_bMotsCompat)
        jkGuiForce_pElements[EIDX_ALIGN_SLIDER].selectedTextEntry = 100 - (uint64_t)(int)jkPlayer_CalcAlignment(jkGuiForce_isMulti);
    jkGuiRend_Paint(menu);
    return 0;
}

// MOTS altered
int jkGuiForce_Show(int bCanSpendStars, int isMulti, int a4, wchar_t* a5, int *pbIsLight, int bEnableIdk)
{
    int newStars;
    int spendStars;

    int isLight = 1;
    jkGuiForce_bCanSpendStars = bCanSpendStars;
    jkGuiForce_isMulti = isMulti;

    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_FORCE]->palette);
    
    jkGuiForce_pElements[EIDX_NAMETEXT].wstr = jkPlayer_playerShortName;
    jkGuiForce_pElements[EIDX_RESET].bIsVisible = bCanSpendStars;
    jkGuiForce_pElements[EIDX_QUIT].bIsVisible = bEnableIdk != 0;

    float darklight_float = jkPlayer_CalcAlignment(jkGuiForce_isMulti);
    if (Main_bMotsCompat) {
        if (!isMulti || jkPlayer_personality == 1) {
            stdString_snprintf(std_genBuffer, 1024, "RANK_%d_%c",jkPlayer_GetJediRank(),'L');
        }
        else {
            stdString_snprintf(std_genBuffer, 1024, "GUI_PERSONALITY%d",jkPlayer_personality);
        }
    }
    else {
        stdString_snprintf(std_genBuffer, 1024, "RANK_%d_%c", jkPlayer_GetJediRank(), (darklight_float >= 0.0) ? 'L' : 'D');
    }

    jkGuiForce_pElements[EIDX_FLAVORTEXT].wstr = jkStrings_GetUniStringWithFallback(std_genBuffer);
    if ( Main_bMotsCompat || (!Main_bMotsCompat && a4 == 0) )
    {
        newStars = (int)sithPlayer_GetBinAmt(SITHBIN_NEW_STARS);
        spendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
        sithPlayer_SetBinAmt(SITHBIN_NEW_STARS, 0.0);
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (float)(newStars + spendStars));
    }

    if (!Main_bMotsCompat)
    {
        jkGuiForce_numSpendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
        jkGuiForce_pElements[EIDX_ALIGN_SLIDER].bIsVisible = 1;
        jkGuiForce_pElements[EIDX_ALIGN_SLIDER].enableHover = 1;
        jkGuiForce_pElements[EIDX_ALIGN_SLIDER].selectedTextEntry = 100 - (uint32_t)darklight_float;
        if (isMulti)
        {
            jkPlayer_SetAccessiblePowers(jkPlayer_GetJediRank());
            jkGuiForce_UpdateViewForRank();
            jkGuiForce_pElements[EIDX_NAMETEXT].wstr = (wchar_t *)a5;
        }

        for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
        {
            int id = jkGuiForce_pElements[i].hoverId;

            jkGuiForce_pElements[i].oldForcePoints = (int)sithPlayer_GetBinAmt(id);

            jkGuiForce_pElements[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
        }

        if ( a4 != 0 )
        {
            if ( darklight_float >= 0.0 )
            {
                jkGuiForce_pElements[EIDX_FLAVORTEXT].wstr = jkStrings_GetUniStringWithFallback("GUI_PATH_LIGHT");
                if ( jkPlayer_GetAlignment() == 1 )
                {
                    sithPlayer_SetBinCarries(SITHBIN_F_PROTECTION, 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_PROTECTION, 4.0);
                }
                jkGuiForce_alignment = 1;
                isLight = 1;
            }
            else
            {
                jkGuiForce_pElements[EIDX_FLAVORTEXT].wstr = jkStrings_GetUniStringWithFallback("GUI_PATH_DARK");
                if ( jkPlayer_GetAlignment() == 2 )
                {
                    sithPlayer_SetBinCarries(SITHBIN_F_DEADLYSIGHT, 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_DEADLYSIGHT, 4.0);
                }
                jkGuiForce_alignment = 2;
                isLight = 0;
            }
        }
    }
    else 
    {
        // MOTS added: no slider
        if (isMulti)
        {
            jkGuiForce_pElements[EIDX_NAMETEXT].wstr = a5;
        }
        jkGuiForce_UpdateViewForRank();
        jkGuiForce_numSpendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);

        for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
        {
            int id = jkGuiForce_pElements[i].hoverId;

            // Added?
            if (i == EIDX_MOTS_DEFENSE) {
                jkGuiForce_pElements[i].bIsVisible = !!jkGuiForce_isMulti;
            }
            jkGuiForce_pElements[i].oldForcePoints = (int)sithPlayer_GetBinAmt(id);
        }
    }
    
    
    jkGuiRend_MenuSetReturnKeyShortcutElement(jkGuiForce_pMenu, &jkGuiForce_pElements[EIDX_OK_BUTTON]);

    int clicked;
    while (1)
    {
        clicked = jkGuiRend_DisplayAndReturnClicked(jkGuiForce_pMenu);
        if ( clicked == -1 )
        {
            if ( !jkGuiDialog_YesNoDialog(jkStrings_GetUniStringWithFallback("GUI_ABORT_GAME"), jkStrings_GetUniStringWithFallback("GUI_CONFIRM_ABORTCD")) )
                continue;
        }
        else if ( clicked != 1 )
        {
            continue;
        }
        
        break;
    }
    
    if (isMulti)
    {
        sithPlayer_SetBinAmt(SITHBIN_NEW_STARS, 0.0);
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, 0.0);
    }
    jkGui_SetModeGame();
    if ( pbIsLight )
        *pbIsLight = isLight;

    return clicked;
}

void jkGuiForce_Startup()
{
    char tmp[128];

    if (Main_bMotsCompat) {
        jkGuiForce_pMenu = &jkGuiForce_menuMots;
        jkGuiForce_pElements = jkGuiForce_buttonsMots;
    }
    else {
        jkGuiForce_pMenu = &jkGuiForce_menu;
        jkGuiForce_pElements = jkGuiForce_buttons;
    }

    jkGui_InitMenu(jkGuiForce_pMenu, jkGui_stdBitmaps[JKGUI_BM_BK_FORCE]);
    if (Main_bMotsCompat) {
        for (int i = 0; i < 19; i++)
        {
            stdString_snprintf(tmp, sizeof(tmp), "ui\\bm\\%s", jkGuiForce_bitmapsMots[i]);
            jkGuiForce_aBitmaps[i] = stdBitmap_Load(tmp, 1, 0);
            if (jkGuiForce_aBitmaps[i] == NULL)
                Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
        }
    }
    else {
        for (int i = 0; i < 17; i++)
        {
            stdString_snprintf(tmp, sizeof(tmp), "ui\\bm\\%s", jkGuiForce_bitmaps[i]);
            jkGuiForce_aBitmaps[i] = stdBitmap_Load(tmp, 1, 0);
            if (jkGuiForce_aBitmaps[i] == NULL)
                Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
        }
    }
}

void jkGuiForce_Shutdown()
{
    for (int i = 0; i < (Main_bMotsCompat ? 19 : 17); i++)
    {
        if ( jkGuiForce_aBitmaps[i] )
        {
            stdBitmap_Free(jkGuiForce_aBitmaps[i]);
            jkGuiForce_aBitmaps[i] = NULL;
        }
    }

    // Added: Clean restart
    jkGuiForce_alignment = 0;
    jkGuiForce_flt_556674 = 0;
    jkGuiForce_numSpendStars = 0;
    jkGuiForce_bCanSpendStars = 0;
    jkGuiForce_isMulti = 0;
    memset(jkGuiForce_aBitmaps, 0, sizeof(jkGuiForce_aBitmaps));
    memset(jkGuiForce_waTmp, 0, sizeof(jkGuiForce_waTmp));
}


void jkGuiForce_UpdateViewForRankMots(void)
{
    int jediRank;
    int jediRank_;
    int *piVar2;
    wchar_t *pwVar5;
    int bIsMulti;
    
    jediRank = jkPlayer_GetJediRank();
    bIsMulti = jkGuiForce_isMulti;
    jediRank_ = jkPlayer_GetJediRank(); // ?
    bIsMulti = jkPlayer_SyncForcePowers(jediRank_,bIsMulti);
    if (bIsMulti) 
    {
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS) + (float)bIsMulti);
    }

    for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
    {
        int id = jkGuiForce_pElements[i].hoverId;
        jkGuiForce_pElements[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
    }

    pwVar5 = jkGuiForce_waTmp;
    for (int categoryIdx = 0; categoryIdx < 4; categoryIdx++)
    {
        jediRank_ = 0;
        for(int fpIdx = 0; fpIdx < 8; fpIdx++) 
        {
            int amt = jkPlayer_aMotsFpBins[(categoryIdx*8) + fpIdx];
            if (amt && !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[amt].state & ITEMSTATE_CARRIES)) {
                jediRank_ = jediRank_ + 1;
            }
        }

        *pwVar5 = 0;
        if (jkPlayer_aMotsFpBins[0x20 + (jediRank * 4) + categoryIdx] <= jediRank_) {
            jediRank_ = jkPlayer_aMotsFpBins[0x20 + (jediRank * 4) + categoryIdx];
        }

        if (jediRank_ != 0) {
            jk_snwprintf(pwVar5,100,jkStrings_GetUniStringWithFallback("GUI_CHOOSE_N"),jediRank_);
        }
        pwVar5 = pwVar5 + 100;
    }

    if (jkGuiForce_isMulti) 
    {
        if (jkPlayer_personality != 1) 
        {
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,0.0);
            for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
            {
                int id = jkGuiForce_pElements[i].hoverId;
                jkGuiForce_pElements[i].bIsVisible = (sithPlayer_GetBinAmt(id) > 0.0);

                // Added?
                if (i == EIDX_MOTS_DEFENSE) {
                    jkGuiForce_pElements[i].bIsVisible = !!jkGuiForce_isMulti;
                }
            }

            for (int i = 0; i < 4; i++) {
                jkGuiForce_waTmp[100 * i] = 0;
            }
        }
        if (jkGuiForce_isMulti) {
            return;
        }
    }
    jkGuiForce_pElements[EIDX_MOTS_DEFENSE].bIsVisible = 0;
}

void jkGuiForce_UpdateViewForRank()
{
    if (Main_bMotsCompat) {
        jkGuiForce_UpdateViewForRankMots();
        return;
    }

    jkPlayer_SetProtectionDeadlysight();
    if ( jkPlayer_GetJediRank() >= 7 )
        jkPlayer_DisallowOtherSide(jkPlayer_GetJediRank());
    for (int i = EIDX_START_FP; i < EIDX_END_FP; i++)
    {
        int id = jkGuiForce_pElements[i].hoverId;
        jkGuiForce_pElements[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
    }
}

void jkGuiForce_DarkLightHoverDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
}
