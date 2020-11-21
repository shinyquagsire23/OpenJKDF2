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
#include "World/sithInventory.h"
#include "World/sithPlayer.h"
#include "Win95/stdDisplay.h"
#include "Win95/Windows.h"

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

static int jkGuiForce_alignment;
static float jkGuiForce_flt_556674;
static int jkGuiForce_numSpendStars;
static int jkGuiForce_bCanSpendStars;
static float jkGuiForce_darkLightBalance;
static stdBitmap* jkGuiForce_aBitmaps[17];

static rdVector2i jkGuiForce_idkExtra = {16, 15};

static jkGuiElement jkGuiForce_buttons[25] = {
{ ELEMENT_TEXT,       0,  2, NULL,               3, {160, 320, 320, 30}, 1, 0, NULL,                   0,  0,                      0, {0},  0},
{ ELEMENT_TEXT,       0,  2, NULL,               3, {10, 15, 620, 30},   1, 0, NULL,                   0,  0,                      0, {0},  0},
{ ELEMENT_TEXT,       0,  2, NULL,               3, {10, 46, 620, 30},   1, 0, NULL,                   0,  0,                      0, {0},  0},
{ ELEMENT_PICBUTTON,  28, 0, NULL,               0, {-1, -1, -1, -1},    1, 0, "GUI_HINT_ABSORB",      0, jkGuiForce_ButtonClick,  0, {0},  0},
{ ELEMENT_PICBUTTON,  27, 0, NULL,               1, {-1, -1, -1, -1},    1, 0, "GUI_HINT_BLINDING",    0, jkGuiForce_ButtonClick,  0, {0},  0},
{ ELEMENT_PICBUTTON,  33, 0, NULL,               3, {-1, -1, -1, -1},    1, 0, "GUI_HINT_DESTRUCTION", 0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  31, 0, NULL,               4, {-1, -1, -1, -1},    1, 0, "GUI_HINT_GRIP",        0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  25, 0, NULL,               5, {-1, -1, -1, -1},    1, 0, "GUI_HINT_HEALING",     0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  21, 0, NULL,               6, {-1, -1, -1, -1},    1, 0, "GUI_HINT_JUMP",        0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  26, 0, NULL,               7, {-1, -1, -1, -1},    1, 0, "GUI_HINT_PERSUASION",  0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  24, 0, NULL,               9, {-1, -1, -1, -1},    1, 0, "GUI_HINT_PULL",        0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  23, 0, NULL,              10, {-1, -1, -1, -1},    1, 0, "GUI_HINT_SEEING",      0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  22, 0, NULL,              11, {-1, -1, -1, -1},    1, 0, "GUI_HINT_SPEED",       0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  30, 0, NULL,              12, {-1, -1, -1, -1},    1, 0, "GUI_HINT_THROW",       0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  32, 0, NULL,              13, {-1, -1, -1, -1},    1, 0, "GUI_HINT_LIGHTNING",   0, jkGuiForce_ButtonClick,  0, {0},  0}, 
{ ELEMENT_PICBUTTON,  29, 0, NULL,               8, {-1, -1, -1, -1},    1, 0, "GUI_HINT_PROTECTION",  0, jkGuiForce_ExtraClick,   0, {0},  0}, 
{ ELEMENT_PICBUTTON,  34, 0, NULL,               2, {-1, -1, -1, -1},    1, 0, "GUI_HINT_DEADLYSIGHT", 0, jkGuiForce_ExtraClick,   0, {0},  0}, 
{ ELEMENT_TEXTBUTTON,  1, 2, .str = "GUI_OK",    3, {550, 420, 80, 40},  1, 0, NULL,                   0, 0,                       0, {0},  0}, 
{ ELEMENT_TEXTBUTTON,  0, 2, .str = "GUI_RESET", 3, {270, 350, 100, 30}, 1, 0, NULL,                   0, jkGuiForce_ResetClick,   0, {0},  0}, 
{ ELEMENT_TEXTBUTTON, -1, 2, .str = "GUI_QUIT",  3, { 0, 420, 100, 40},  1, 0, NULL,                   0,  0,                      0, {0},  0}, 
{ ELEMENT_CUSTOM,      0, 0, NULL,               0, { 0, 390, 640, 30},  1, 0, NULL,            jkGuiForce_ForceStarsDraw,     0,  0, {0},  0}, 
{ ELEMENT_CUSTOM,      0, 0, NULL,               0, {320, 418, 170, 40}, 1, 0, "GUI_DARKSIDE",  jkGuiForce_DarkLightHoverDraw, 0,  0, {0},  0}, 
{ ELEMENT_CUSTOM,      0, 0, NULL,               0, {150, 418, 170, 40}, 1, 0, "GUI_LIGHTSIDE", jkGuiForce_DarkLightHoverDraw, 0,  0, {0},  0}, 
{ ELEMENT_SLIDER,      0, 0, .extraInt = 200,  100, {150, 418, 340, 40}, 1, 0,  NULL,           0,  0,          &jkGuiForce_idkExtra, {0},  0}, 
{ ELEMENT_END,         0, 0, NULL,               0, {0},                 0, 0,  NULL,           0,  0,                             0, {0},  0}
};

static jkGuiMenu jkGuiForce_menu =
{ jkGuiForce_buttons, 0, 0xe1, 0xff, 0x0f, 0, 0, jkGuiForce_aBitmaps, jkGui_stdFonts, 0, jkGuiForce_ChoiceRemoveStars, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

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
    jkGuiForce_buttons[23].selectedTextEntry = 100 - (unsigned __int64)(int)jkPlayer_CalcDarkLightBalance(jkGuiForce_darkLightBalance);

    for (int i = 3; i < 17; i++)
    {
        int id = jkGuiForce_buttons[i].hoverId;
        jkGuiForce_buttons[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
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
            int v2 = (int)sithPlayer_GetBinAmt(i);
            if (v2 > 0)
            {
                jkGuiForce_ChoiceRemoveStar(menu, i, v2);
                return;
            }
        }

        if ( jkGuiForce_alignment == 2 )
        {
            jkPlayer_sub_405CC0(jkGuiForce_alignment);
        }
        else if ( jkGuiForce_alignment == 1 )
        {
            jkPlayer_sub_405CC0(1);
        }

        jkGuiForce_alignment = 0;
        jkGuiForce_buttons[23].selectedTextEntry = 100 - (unsigned __int64)(int)jkPlayer_CalcDarkLightBalance(0.0);
        for (int i = 3; i < 17; i++)
        {
            int id = jkGuiForce_buttons[i].hoverId;
            jkGuiForce_buttons[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
        }
        jkGuiRend_Paint(menu);
    }
}

void jkGuiForce_ForceStarsDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    int spendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    if ( spendStars <= 0 )
    {
        stdFont_Draw4(vbuf, jkGui_stdFonts[2], element->rect.x, element->rect.y, element->rect.width, element->rect.height, 3, jkStrings_GetText("GUI_NO_STARS"), 1);
    }
    else
    {
        for (int i = 0; i < spendStars; i++)
        {
            stdVBuffer* bitmap = jkGuiForce_aBitmaps[14]->mipSurfaces[0];
            stdDisplay_VBufferCopy(vbuf, bitmap, element->rect.x + bitmap->format.width * i + ((element->rect.width - bitmap->format.width * spendStars) >> 1), element->rect.y, 0, 1);
            
        }
    }
    
    for (int i = 3; i < 15; i++)
    {
        int id = jkGuiForce_buttons[i].hoverId;
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
            if ( jkGuiForce_buttons[i].rect.x >= 320 )
                x = jkGuiForce_buttons[i].rect.width + jkGuiForce_buttons[i].rect.x + 19;
            else
                x = jkGuiForce_buttons[i].rect.x - jkGuiForce_aBitmaps[14]->mipSurfaces[numStars]->format.width - 19;

            stdDisplay_VBufferCopy(vbuf, jkGuiForce_aBitmaps[14]->mipSurfaces[numStars], x, jkGuiForce_buttons[i].rect.y + 3, 0, 1);
        }
    }
}

int jkGuiForce_ExtraClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c)
{
    return 0;
}

int jkGuiForce_ButtonClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c)
{
    float v8; // ST04_4
    signed int v9; // eax
    int v12; // ecx

    int binIdx = element->hoverId;
    if ( !jkGuiForce_bCanSpendStars )
        return 0;
    int spendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    int curLevel = (int)sithPlayer_GetBinAmt(binIdx);
    if ( curLevel < 4 && spendStars > 0 )
    {
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (float)(spendStars - 1));
        sithPlayer_SetBinAmt(binIdx, (float)(curLevel + 1));
        jkGuiForce_buttons[23].selectedTextEntry = 100 - (int)jkPlayer_CalcDarkLightBalance(jkGuiForce_darkLightBalance);
        jkGuiRend_Paint(menu);
    }

    if (jkGuiForce_darkLightBalance != 0.0)
    {
        if ( curLevel == 4 || !spendStars )
        {
            v8 = (double)(spendStars + curLevel);
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, v8);
            sithPlayer_SetBinAmt(binIdx, 0.0);
            jkGuiForce_buttons[23].selectedTextEntry = 100 - (int)jkPlayer_CalcDarkLightBalance(jkGuiForce_darkLightBalance);
        }
        jkPlayer_SetProtectionDeadlysight();
        v9 = jkPlayer_GetJediRank();
        if ( v9 >= 7 )
            jkPlayer_sub_407210(v9);
        for (int i = 3; i < 17; i++)
        {
            int id = jkGuiForce_buttons[i].hoverId;
            jkGuiForce_buttons[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
        }
        jkGuiRend_Paint(menu);
    }
    return 0;
}

int jkGuiForce_ResetClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c)
{
    if ( !jkGuiForce_bCanSpendStars )
        return 0;
    sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (double)jkGuiForce_numSpendStars);
    for (int i = 3; i < 15; i++)
    {
        float v5 = (double)(*(int*)&jkGuiForce_buttons[i].anonymous_13);
        sithPlayer_SetBinAmt(jkGuiForce_buttons[i].hoverId, v5);
    }

    if (jkGuiForce_darkLightBalance != 0.0)
    {
        jkPlayer_SetProtectionDeadlysight();
        if ( jkPlayer_GetJediRank() >= 7 )
            jkPlayer_sub_407210(jkPlayer_GetJediRank());
        for (int i = 3; i < 17; i++)
        {
            int id = jkGuiForce_buttons[i].hoverId;
            jkGuiForce_buttons[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
        }
    }
    jkGuiForce_buttons[23].selectedTextEntry = 100 - (unsigned __int64)(int)jkPlayer_CalcDarkLightBalance(jkGuiForce_darkLightBalance);
    jkGuiRend_Paint(menu);
    return 0;
}

int jkGuiForce_Show(int bCanSpendStars, float darkLightBalance, float a4, int a5, int *pbIsLight, int bEnableIdk)
{
    int jediRank; // ebx
    int newStars; // esi
    int spendStars; // edi
    float totalStars; // ST10_4
    int v21; // eax
    int isLight; // [esp+14h] [ebp-4h]
    float darklight_float; // [esp+1Ch] [ebp+4h]

    //bCanSpendStars = 1;
    //bEnableIdk = 1;

    isLight = 1;
    jkGuiForce_bCanSpendStars = bCanSpendStars;
    jkGuiForce_buttons[18].bIsVisible = bCanSpendStars;    
    jkGuiForce_darkLightBalance = darkLightBalance;
    jkGui_SetModeMenu(jkGui_stdBitmaps[9]->palette);
    jkGuiForce_buttons[1].unistr = jkPlayer_playerShortName;
    darklight_float = jkPlayer_CalcDarkLightBalance(jkGuiForce_darkLightBalance);
    jkGuiForce_buttons[19].bIsVisible = bEnableIdk != 0;

    stdString_snprintf(std_genBuffer, 1024, "RANK_%d_%c", jkPlayer_GetJediRank(), (darklight_float >= 0.0) ? 'L' : 'D');
    jkGuiForce_buttons[2].unistr = jkStrings_GetText(std_genBuffer);
    if ( a4 == 0.0 )
    {
        newStars = (int)sithPlayer_GetBinAmt(SITHBIN_NEW_STARS);
        spendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
        sithPlayer_SetBinAmt(SITHBIN_NEW_STARS, 0.0);
        totalStars = (double)(newStars + spendStars);
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, totalStars);
    }
    jkGuiForce_numSpendStars = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    jkGuiForce_buttons[23].bIsVisible = 1;
    jkGuiForce_buttons[23].anonymous_9 = 1;
    jkGuiForce_buttons[23].selectedTextEntry = 100 - (uint32_t)darklight_float;
    if ( darkLightBalance != 0.0 )
    {
        jkPlayer_SetAccessiblePowers(jkPlayer_GetJediRank());
        jkGuiForce_UpdateViewForRank();
        jkGuiForce_buttons[1].unistr = (wchar_t *)a5;
    }
    
    for (int i = 3; i < 17; i++)
    {
        int id = jkGuiForce_buttons[i].hoverId;

        *(int*)&jkGuiForce_buttons[i].anonymous_13 = (int)sithPlayer_GetBinAmt(id);

        jkGuiForce_buttons[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
    }

    if ( a4 != 0.0 )
    {
        if ( darklight_float >= 0.0 )
        {
            jkGuiForce_buttons[2].unistr = jkStrings_GetText("GUI_PATH_LIGHT");
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
            jkGuiForce_buttons[2].unistr = jkStrings_GetText("GUI_PATH_DARK");
            if ( jkPlayer_GetAlignment() == 2 )
            {
                sithPlayer_SetBinCarries(SITHBIN_F_DEADLYSIGHT, 1);
                sithPlayer_SetBinAmt(SITHBIN_F_DEADLYSIGHT, 4.0);
            }
            jkGuiForce_alignment = 2;
            isLight = 0;
        }
    }
    jkGuiRend_MenuSetLastElement(&jkGuiForce_menu, &jkGuiForce_buttons[17]);

    while (1)
    {
        v21 = jkGuiRend_DisplayAndReturnClicked(&jkGuiForce_menu);
        if ( v21 == -1 )
        {
            if ( !jkGuiDialog_YesNoDialog(jkStrings_GetText("GUI_ABORT_GAME"), jkStrings_GetText("GUI_CONFIRM_ABORTCD")) )
                continue;
        }
        else if ( v21 != 1 )
        {
            continue;
        }
        
        break;
    }
    
    if ( darkLightBalance != 0.0 )
    {
        sithPlayer_SetBinAmt(SITHBIN_NEW_STARS, 0.0);
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, 0.0);
    }
    jkGui_SetModeGame();
    if ( pbIsLight )
        *pbIsLight = isLight;

    return v21;
}

void jkGuiForce_Initialize()
{
    char tmp[128];

    jkGui_InitMenu(&jkGuiForce_menu, jkGui_stdBitmaps[9]);
    for (int i = 0; i < 17; i++)
    {
        stdString_snprintf(tmp, sizeof(tmp), "ui\\bm\\%s", jkGuiForce_bitmaps[i]);
        jkGuiForce_aBitmaps[i] = stdBitmap_Load(tmp, 1, 0);
        if (jkGuiForce_aBitmaps[i] == NULL)
            Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
    }
}

void jkGuiForce_Shutdown()
{
    for (int i = 0; i < 17; i++)
    {
        if ( jkGuiForce_aBitmaps[i] )
        {
            stdBitmap_Free(jkGuiForce_aBitmaps[i]);
            jkGuiForce_aBitmaps[i] = NULL;
        }
    }
}

void jkGuiForce_UpdateViewForRank()
{
    jkPlayer_SetProtectionDeadlysight();
    if ( jkPlayer_GetJediRank() >= 7 )
        jkPlayer_sub_407210(jkPlayer_GetJediRank());
    for (int i = 3; i < 17; i++)
    {
        int id = jkGuiForce_buttons[i].hoverId;
        jkGuiForce_buttons[i].bIsVisible = !!(jkPlayer_playerInfos[playerThingIdx].iteminfo[id].state & ITEMSTATE_CARRIES);
    }
}

void jkGuiForce_DarkLightHoverDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
}
