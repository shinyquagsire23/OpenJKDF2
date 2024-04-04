#include "jkQuakeConsole.h"

#include "General/stdHashTable.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdString.h"
#include "General/stdLinklist.h"
#include "Win95/stdDisplay.h"
#include "Devices/sithConsole.h"
#include "Win95/WinIdk.h"
#include "World/sithThing.h"
#include "Gameplay/sithInventory.h"
#include "Gameplay/jkSaber.h"
#include "World/jkPlayer.h"
#include "World/sithActor.h"
#include "World/sithTemplate.h"
#include "Main/sithCommand.h"
#include "Dss/sithMulti.h"
#include "Main/Main.h"
#include "Main/jkMain.h"
#include "Main/jkStrings.h"
#include "Main/jkDev.h"
#include "stdPlatform.h"
#include "wprintf.h"
#include "Dss/jkDSS.h"
#include "Platform/std3D.h"
#include "Win95/Window.h"
#include "Platform/stdControl.h"
#include "Platform/Common/stdUpdater.h"
#include "Gameplay/sithPlayerActions.h"
#include "Main/sithCvar.h"
#include "../jk.h"

#define JKQUAKECONSOLE_COMMAND_HISTORY_DEPTH (64)
#define JKQUAKECONSOLE_NUM_LINES (1024)
#define JKQUAKECONSOLE_CHAT_LEN (256)
#define JKQUAKECONSOLE_SORTED_LIMIT (256)

int jkQuakeConsole_bOnce = 0;

int jkQuakeConsole_bInitted = 0;
stdFont* jkQuakeConsole_pFont = NULL;

int jkQuakeConsole_bOpen = 0;
uint64_t jkQuakeConsole_lastTimeUs = 0;
uint64_t jkQuakeConsole_blinkCounter = 0;
float jkQuakeConsole_shadeY = 0.0;

char jkQuakeConsole_chatStrSaved[JKQUAKECONSOLE_CHAT_LEN+16];

char jkQuakeConsole_chatStr[JKQUAKECONSOLE_CHAT_LEN+16];
int32_t jkQuakeConsole_chatStrPos = 0;
int32_t jkQuakeConsole_scrollPos = 0;
uint32_t jkQuakeConsole_realLines = 0;
uint32_t jkQuakeConsole_tabIdx = 0;
int jkQuakeConsole_bHasTabbed = 0;
int jkQuakeConsole_realHistoryLines = 0;
int jkQuakeConsole_selectedHistory = 0;
int jkQuakeConsole_bShiftHeld = 0;
int jkQuakeConsole_bShowUpdateText = 0;
int jkQuakeConsole_updateTextCooldown = 0;
int jkQuakeConsole_updateTextWidth = 0;
int jkQuakeConsole_updateTextHeight = 0;
int jkQuakeConsole_bClickedUpdate = 0;

char* jkQuakeConsole_pTabPos = NULL;
char* jkQuakeConsole_aLines[JKQUAKECONSOLE_NUM_LINES];
char* jkQuakeConsole_aLastCommands[JKQUAKECONSOLE_COMMAND_HISTORY_DEPTH];

int jkQuakeConsole_sortTmpIdx = 0;
const char* jkQuakeConsole_aSortTmp[JKQUAKECONSOLE_SORTED_LIMIT];

void jkQuakeConsole_ResetShade();

static int jkQuakeConsole_cmpstr(const void* a, const void* b) 
{
    const char* aa = *(const char**)a;
    const char* bb = *(const char**)b;
    return strcmp(aa, bb);
}

void jkQuakeConsole_Startup()
{
    jkQuakeConsole_pFont = stdFont_Load("ui\\sft\\msgFont16.sft", 0, 0);

    int num = jkQuakeConsole_pFont->charsetHead.charLast - jkQuakeConsole_pFont->charsetHead.charFirst;
    int averageW = 0;
    int largestW = 0;
    for (int i = 0; i < num; i++)
    {
        int w = jkQuakeConsole_pFont->charsetHead.pEntries[i].field_4;
        char theChar = i + jkQuakeConsole_pFont->charsetHead.charFirst;
        averageW += w;
        if (w > largestW && theChar != ' ' && theChar != '\t') {
            largestW = w;
        }
    }
    averageW /= num;

    jkQuakeConsole_pFont->monospaceW = (averageW + averageW + largestW) / 3;
    for (int i = 0; i < num; i++)
    {
        //jkQuakeConsole_pFont->charsetHead.pEntries[i].field_4 = largestW;
    }

    Window_AddMsgHandler(jkQuakeConsole_WmHandler);

    jkQuakeConsole_ResetShade();

    if (!jkQuakeConsole_bOnce)
    {
        memset(jkQuakeConsole_aLines, 0, sizeof(jkQuakeConsole_aLines));

        memset(jkQuakeConsole_chatStr, 0, sizeof(jkQuakeConsole_chatStr));
        jkQuakeConsole_chatStrPos = 0;

        jkQuakeConsole_tabIdx = 0;
        jkQuakeConsole_bHasTabbed = 0;
        jkQuakeConsole_selectedHistory = 0;
        memset(jkQuakeConsole_chatStrSaved, 0, sizeof(jkQuakeConsole_chatStrSaved));

        jkQuakeConsole_bShiftHeld = 0;

        jkQuakeConsole_bShowUpdateText = stdUpdater_CheckForUpdates();
        if (jkQuakeConsole_bShowUpdateText) {
            jkQuakeConsole_updateTextCooldown = 10*1000*1000;
        }

        jkQuakeConsole_bOnce = 1;
    }
    
    jkQuakeConsole_bOpen = 0;
    jkQuakeConsole_bInitted = 1;
}

void jkQuakeConsole_Shutdown()
{
    stdFont_Free(jkQuakeConsole_pFont);
    jkQuakeConsole_pFont = NULL;

    Window_RemoveMsgHandler(jkQuakeConsole_WmHandler);

    jkQuakeConsole_ResetShade();

    //memset(jkQuakeConsole_aLines, 0, sizeof(jkQuakeConsole_aLines));
    //jkQuakeConsole_realLines = 0;

    jkQuakeConsole_bOpen = 0;
    jkQuakeConsole_bInitted = 0;
}

void jkQuakeConsole_ResetShade()
{
    jkQuakeConsole_lastTimeUs = Linux_TimeUs();
    jkQuakeConsole_shadeY = 0.0f;
    jkQuakeConsole_blinkCounter = 0;
    
    jkQuakeConsole_scrollPos = 0;

    jkQuakeConsole_pTabPos = NULL;
    jkQuakeConsole_sortTmpIdx = 0;
    memset(jkQuakeConsole_aSortTmp, 0, sizeof(jkQuakeConsole_aSortTmp));
}

void jkQuakeConsole_Render()
{
    if (!jkQuakeConsole_bInitted) return;

    int64_t deltaUs = Linux_TimeUs() - jkQuakeConsole_lastTimeUs;
    jkQuakeConsole_lastTimeUs = Linux_TimeUs();
    if (deltaUs < 0) {
        deltaUs = 0;
    }

    float screenW = Video_menuBuffer.format.width;
    float screenH = Video_menuBuffer.format.height;
    float fontHeight = ((*jkQuakeConsole_pFont->bitmap->mipSurfaces)->format.height + jkQuakeConsole_pFont->marginY) * jkPlayer_hudScale;
    if (fontHeight <= 0.0) {
        fontHeight = 1.0;
    }
    int maxVisibleLines = (int)((screenH / 2) / fontHeight)-2;

    // Show update text over everything
    if (jkQuakeConsole_bShowUpdateText || jkQuakeConsole_bClickedUpdate) {
        wchar_t tmp[128];

        jkQuakeConsole_updateTextCooldown -= deltaUs;
        if (jkQuakeConsole_updateTextCooldown <= 0) {
            jkQuakeConsole_updateTextCooldown = 0;
            jkQuakeConsole_bShowUpdateText = 0;
        }

        // TODO: i8n
        stdUpdater_GetUpdateText(tmp, sizeof(tmp));
        jkQuakeConsole_updateTextWidth = stdFont_Draw1GPU(jkQuakeConsole_pFont, 0, 0, screenW, tmp, 1, jkPlayer_hudScale);
        
#if !defined(PLATFORM_LINUX)
        if (!jkQuakeConsole_bClickedUpdate) {
            stdFont_Draw1GPU(jkQuakeConsole_pFont, 0, fontHeight, screenW, jkStrings_GetUniStringWithFallback("GUIEXT_UPDATE_CLICK_TO_DL"), 1, jkPlayer_hudScale);
        }
#endif
        jkQuakeConsole_updateTextHeight = (int)(fontHeight * 2);
    }

    if (jkQuakeConsole_bOpen)
    {
        jkQuakeConsole_shadeY += (float)deltaUs * 0.005;
        if (jkQuakeConsole_shadeY > screenH / 2) {
            jkQuakeConsole_shadeY = screenH / 2;
        }
    }
    else {
        jkQuakeConsole_shadeY -= (float)deltaUs * 0.005;
        if (jkQuakeConsole_shadeY <= 0.0) {
            jkQuakeConsole_shadeY = 0.0f;
            return;
        }
    }

    if (jkQuakeConsole_bOpen)
    {
        jkQuakeConsole_scrollPos += Window_mouseWheelY;
        if (jkQuakeConsole_scrollPos < 0) {
            jkQuakeConsole_scrollPos = 0;
        }
        if (jkQuakeConsole_realLines < maxVisibleLines) {
            jkQuakeConsole_scrollPos = 0;
        }
        if (jkQuakeConsole_scrollPos > jkQuakeConsole_realLines - maxVisibleLines) {
            jkQuakeConsole_scrollPos = jkQuakeConsole_realLines - maxVisibleLines;
        }
        Window_mouseWheelX = 0;
        Window_mouseWheelY = 0;
    }
    else {
        jkQuakeConsole_scrollPos = 0;
    }
    
    int realScrollY = jkQuakeConsole_scrollPos;

    float realShadeY = -(screenH / 2) + jkQuakeConsole_shadeY;
    float realShadeBottom = realShadeY + (screenH / 2);

    if (jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]) {
        float scaleX = screenW / jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->mipSurfaces[0]->format.width;
        float scaleY = screenH / jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->mipSurfaces[0]->format.height;
        rdRect srcRect = {0,20,jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->mipSurfaces[0]->format.width, jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->mipSurfaces[0]->format.height*0.5};
        std3D_DrawUIBitmapRGBA(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN], 0, 0.0, realShadeY, &srcRect, scaleX, scaleY, 0, 80, 80, 80, 192);

        rdRect srcRect2 = {0,jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->mipSurfaces[0]->format.height-4, 1, 2};
        std3D_DrawUIBitmapRGBA(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN], 0, 0.0, realShadeBottom, &srcRect2, (float)screenW, scaleY, 0, 255, 255, 255, 255);
    }
    else {
        rdRect rect = {0, realShadeY, screenW, screenH / 2};
        std3D_DrawUIClearedRectRGBA(0, 0, 0, 128, &rect);
    }

    jkQuakeConsole_blinkCounter += deltaUs;
    jkQuakeConsole_blinkCounter %= (1000*1000);
    int isBlink = jkQuakeConsole_blinkCounter > ((1000*1000)/2);
    
    char tmpBlinkCut = jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos];
    if (!jkQuakeConsole_bHasTabbed)
        jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos] = 0;

    char tmpBlink[JKQUAKECONSOLE_CHAT_LEN*2];
    stdString_snprintf(tmpBlink, sizeof(tmpBlink), "]%s", jkQuakeConsole_chatStr);

    //stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, 0, realShadeY, 640, tmpBlink, 1, jkPlayer_hudScale);
    uint32_t blink_pos_x = stdFont_DrawAsciiWidth(jkQuakeConsole_pFont, 0, realShadeBottom - fontHeight*2, screenW, tmpBlink, 1, jkPlayer_hudScale);
    jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos] = tmpBlinkCut;

    stdString_snprintf(tmpBlink, sizeof(tmpBlink), "]%s", jkQuakeConsole_chatStr);
    stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, 0, realShadeBottom - fontHeight*2, screenW, tmpBlink, 1, jkPlayer_hudScale);
    stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, blink_pos_x, realShadeBottom - fontHeight*2 + (fontHeight / 4), screenW, isBlink ? " " : "_", 1, jkPlayer_hudScale);

    stdString_snprintf(tmpBlink, sizeof(tmpBlink), "OpenJKDF2 %s (%s)", openjkdf2_aReleaseVersion, openjkdf2_aReleaseCommitShort);
    uint32_t strW = stdFont_DrawAsciiWidth(jkQuakeConsole_pFont, 0, realShadeBottom - fontHeight, screenW, tmpBlink, 1, jkPlayer_hudScale);
    stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, screenW - strW, realShadeBottom - fontHeight, screenW, tmpBlink, 1, jkPlayer_hudScale);
    
    for (int i = 0; i < JKQUAKECONSOLE_NUM_LINES; i++)
    {
        char* pLine = jkQuakeConsole_aLines[i];
        if (!pLine) continue;

        float outY = realShadeY + (screenH / 2) - fontHeight * (i+3-realScrollY);
        if (outY + fontHeight < 0.0) {
            continue;
        }
        if (outY > realShadeBottom - fontHeight*(realScrollY ? 4 : 3)) {
            continue;
        }

        stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, 0, outY, screenW, pLine, 1, jkPlayer_hudScale);
    }
    if (realScrollY) {
        stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, 0, realShadeBottom - fontHeight*3, screenW, "^   ^   ^   ^   ^   ^   ^", 1, jkPlayer_hudScale);
    }
}

int jkQuakeConsole_AutocompleteCvarsCallback_bPrintOnce = 0;

void jkQuakeConsole_AutocompleteCvarsCallback(tSithCvar* pCvar)
{
    if (!*jkQuakeConsole_pTabPos || !__strnicmp(jkQuakeConsole_pTabPos, pCvar->pName, strlen(jkQuakeConsole_pTabPos))) {
        jkQuakeConsole_AutocompleteCvarsCallback_bPrintOnce = 1;

        if (jkQuakeConsole_sortTmpIdx < JKQUAKECONSOLE_SORTED_LIMIT) {
            jkQuakeConsole_aSortTmp[jkQuakeConsole_sortTmpIdx++] = pCvar->pName;
        }
    }
}

int jkQuakeConsole_AutocompleteCvars()
{
    if (!jkQuakeConsole_pTabPos) return 0;

    jkQuakeConsole_AutocompleteCvarsCallback_bPrintOnce = 0;
    sithCvar_Enumerate(jkQuakeConsole_AutocompleteCvarsCallback);

    return jkQuakeConsole_AutocompleteCvarsCallback_bPrintOnce;
}

int jkQuakeConsole_AutocompleteCheats()
{
    if (!jkQuakeConsole_pTabPos) return 0;

    int bPrintOnce = 0;
    for (int i = 0; i < jkDev_cheatHashtable->numBuckets; i++)
    {
        stdLinklist* pIter = &jkDev_cheatHashtable->buckets[i];
        while (pIter)
        {
            if (pIter->key) {
                if (!*jkQuakeConsole_pTabPos || !__strnicmp(jkQuakeConsole_pTabPos, pIter->key, strlen(jkQuakeConsole_pTabPos))) {
                    bPrintOnce = 1;

                    if (jkQuakeConsole_sortTmpIdx < JKQUAKECONSOLE_SORTED_LIMIT) {
                        jkQuakeConsole_aSortTmp[jkQuakeConsole_sortTmpIdx++] = pIter->key;
                    }
                }
            }
            pIter = pIter->next;
        }
    }
    return bPrintOnce;
}

int jkQuakeConsole_AutocompleteConsoleCmds()
{
    if (!jkQuakeConsole_pTabPos) return 0;

    int bPrintOnce = 0;
    for (int i = 0; i < sithConsole_pCmdHashtable->numBuckets; i++)
    {
        stdLinklist* pIter = &sithConsole_pCmdHashtable->buckets[i];
        while (pIter)
        {
            if (pIter->key) {
                if (!*jkQuakeConsole_pTabPos || !__strnicmp(jkQuakeConsole_pTabPos, pIter->key, strlen(jkQuakeConsole_pTabPos))) {
                    bPrintOnce = 1;

                    if (jkQuakeConsole_sortTmpIdx < JKQUAKECONSOLE_SORTED_LIMIT) {
                        jkQuakeConsole_aSortTmp[jkQuakeConsole_sortTmpIdx++] = pIter->key;
                    }
                }
            }
            pIter = pIter->next;
        }
    }
    return bPrintOnce;
}

int jkQuakeConsole_AutocompleteTemplates()
{
    if (!jkQuakeConsole_pTabPos) return 0;

    int bPrintOnce = 0;

    if (sithWorld_pStatic && sithWorld_pStatic->templates) 
    {
        for (int i = 0; i < sithWorld_pStatic->numTemplatesLoaded; i++)
        {
            char* pName = sithWorld_pStatic->templates[i].template_name;
            if (!strncmp(jkQuakeConsole_pTabPos, pName, strlen(jkQuakeConsole_pTabPos))) {
                bPrintOnce = 1;

                if (jkQuakeConsole_sortTmpIdx < JKQUAKECONSOLE_SORTED_LIMIT) {
                    jkQuakeConsole_aSortTmp[jkQuakeConsole_sortTmpIdx++] = pName;
                }
            }
        }
    }
    
    if (!sithWorld_pCurrentWorld || !sithWorld_pCurrentWorld->templates) return bPrintOnce;
    
    for (int i = 0; i < sithWorld_pCurrentWorld->numTemplatesLoaded; i++)
    {
        char* pName = sithWorld_pCurrentWorld->templates[i].template_name;
        if (!strncmp(jkQuakeConsole_pTabPos, pName, strlen(jkQuakeConsole_pTabPos))) {
            bPrintOnce = 1;

            if (jkQuakeConsole_sortTmpIdx < JKQUAKECONSOLE_SORTED_LIMIT) {
                jkQuakeConsole_aSortTmp[jkQuakeConsole_sortTmpIdx++] = pName;
            }
        }
    }
    return bPrintOnce;
}

void jkQuakeConsole_ExecuteCommand(const char* pCmd)
{
    if ( jkHud_dword_552D10 == -1 && sithNet_isMulti )
    {
        _sprintf(std_genBuffer, "You say, '%s'", pCmd);
        jkDev_DebugLog(std_genBuffer);
        sithMulti_SendChat(pCmd, -1, playerThingIdx);
    }
    else if ( !jkDev_TryCommand(pCmd) )
    {
        sithConsole_TryCommand(pCmd);
    }
}

void jkQuakeConsole_SendInput(char wParam, int bIsChar)
{
    wchar_t tmp[256]; // [esp+4h] [ebp-100h] BYREF
    char tmp_cvar[SITHCVAR_MAX_STRLEN];

    if ( wParam == VK_ESCAPE || wParam == VK_OEM_3 || wParam == 0xffffffc0 || wParam == '`' || wParam == '~')
    {
        return;
    }

    if ( wParam == VK_RETURN )
    {
        char tmp2[JKQUAKECONSOLE_CHAT_LEN*2];
        stdString_snprintf(tmp2, sizeof(tmp2), "]%s", jkQuakeConsole_chatStr);
        jkQuakeConsole_PrintLine(tmp2);
        jkQuakeConsole_tabIdx = 0;
        jkQuakeConsole_selectedHistory = 0;

        if ( jkQuakeConsole_chatStrPos )
        {
            jkQuakeConsole_RecordHistory(jkQuakeConsole_chatStr);

            jkQuakeConsole_ExecuteCommand(jkQuakeConsole_chatStr);
        }
        jkQuakeConsole_chatStrPos = 0;
        memset(jkQuakeConsole_chatStr, 0, sizeof(jkQuakeConsole_chatStr));
        //jkHud_bChatOpen = 0;
        jkDev_sub_41FC90(103);
    }
    else
    {
        if (wParam == VK_UP && !bIsChar)
        {
            if (!jkQuakeConsole_selectedHistory) {
                strcpy(jkQuakeConsole_chatStrSaved, jkQuakeConsole_chatStr);
            }

            jkQuakeConsole_selectedHistory++;
            if (jkQuakeConsole_selectedHistory >= jkQuakeConsole_realHistoryLines) {
                jkQuakeConsole_selectedHistory = jkQuakeConsole_realHistoryLines;
            }

            if (jkQuakeConsole_selectedHistory)
            {
                strncpy(jkQuakeConsole_chatStr, jkQuakeConsole_aLastCommands[jkQuakeConsole_selectedHistory-1], JKQUAKECONSOLE_CHAT_LEN-1);
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
            }
        }
        else if (wParam == VK_DOWN && !bIsChar)
        {
            if (!jkQuakeConsole_selectedHistory) {
                strcpy(jkQuakeConsole_chatStrSaved, jkQuakeConsole_chatStr);
            }

            jkQuakeConsole_selectedHistory--;
            if (jkQuakeConsole_selectedHistory < 0) {
                jkQuakeConsole_selectedHistory = 0;
            }

            if (!jkQuakeConsole_selectedHistory) {
                strcpy(jkQuakeConsole_chatStr, jkQuakeConsole_chatStrSaved);
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
            }
            else {
                strncpy(jkQuakeConsole_chatStr, jkQuakeConsole_aLastCommands[jkQuakeConsole_selectedHistory-1], JKQUAKECONSOLE_CHAT_LEN-1);
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
            }
        }
        else if (wParam == VK_LEFT && !bIsChar)
        {
            jkQuakeConsole_chatStrPos--;
            if (jkQuakeConsole_chatStrPos < 0) {
                jkQuakeConsole_chatStrPos = 0;
            }
            if (jkQuakeConsole_chatStrPos > strlen(jkQuakeConsole_chatStr)) {
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
            }
            if (jkQuakeConsole_chatStrPos > JKQUAKECONSOLE_CHAT_LEN-1) {
                jkQuakeConsole_chatStrPos = JKQUAKECONSOLE_CHAT_LEN-1;
            }

            jkQuakeConsole_tabIdx = 0;
            jkQuakeConsole_selectedHistory = 0;
            jkQuakeConsole_bHasTabbed = 0;
        }
        else if (wParam == VK_RIGHT && !bIsChar)
        {
            jkQuakeConsole_chatStrPos++;

            // User has chosen to continue the completion
            if (jkQuakeConsole_bHasTabbed) {
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
            }

            if (jkQuakeConsole_chatStrPos < 0) {
                jkQuakeConsole_chatStrPos = 0;
            }
            if (jkQuakeConsole_chatStrPos > strlen(jkQuakeConsole_chatStr)) {
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
            }
            if (jkQuakeConsole_chatStrPos > JKQUAKECONSOLE_CHAT_LEN-1) {
                jkQuakeConsole_chatStrPos = JKQUAKECONSOLE_CHAT_LEN-1;
            }

            jkQuakeConsole_tabIdx = 0;
            jkQuakeConsole_selectedHistory = 0;
            jkQuakeConsole_bHasTabbed = 0;
        }
        else if ( wParam == VK_BACK && bIsChar)
        {
            if (jkQuakeConsole_bHasTabbed && jkQuakeConsole_chatStrPos) {
                jkQuakeConsole_chatStr[--jkQuakeConsole_chatStrPos] = 0;
            }
            else if ( jkQuakeConsole_chatStrPos ) {
                memmove(&jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos-1], &jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos], JKQUAKECONSOLE_CHAT_LEN-jkQuakeConsole_chatStrPos-1);
                //jkQuakeConsole_chatStr[--jkQuakeConsole_chatStrPos] = 0;
                jkQuakeConsole_chatStrPos--;
            }
            jkQuakeConsole_tabIdx = 0;
            jkQuakeConsole_selectedHistory = 0;
            jkQuakeConsole_bHasTabbed = 0;
        }
        else if ( wParam == VK_DELETE && !bIsChar)
        {
            if ( jkQuakeConsole_chatStrPos < JKQUAKECONSOLE_CHAT_LEN-1) {
                memmove(&jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos], &jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos+1], JKQUAKECONSOLE_CHAT_LEN-jkQuakeConsole_chatStrPos-1);
            }
            jkQuakeConsole_tabIdx = 0;
            jkQuakeConsole_selectedHistory = 0;
            jkQuakeConsole_bHasTabbed = 0;
        }
        else if ( wParam == VK_TAB )
        {
            if (!jkDev_cheatHashtable) return;

            if (jkQuakeConsole_bHasTabbed) {
                if (jkQuakeConsole_chatStrPos) {
                    jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos-1] = 0;
                }
                else {
                    jkQuakeConsole_chatStr[0] = 0;
                }
            }

            char tmp2[JKQUAKECONSOLE_CHAT_LEN*2];
            stdString_snprintf(tmp2, sizeof(tmp2), "]%s", jkQuakeConsole_chatStr);
            
            int shouldPrint = !jkQuakeConsole_bHasTabbed;
            int bPrintOnce = 0;
            char* tabbedStr = NULL;

            char* baseCmd = (char*)malloc(strlen(jkQuakeConsole_chatStr)+1);
            strcpy(baseCmd, jkQuakeConsole_chatStr);

            int bCanAutocompleteCheats = 1;
            jkQuakeConsole_pTabPos = _strrchr(jkQuakeConsole_chatStr, ' ');
            if (!jkQuakeConsole_pTabPos) {
                jkQuakeConsole_pTabPos = jkQuakeConsole_chatStr;
            }
            else {
                bCanAutocompleteCheats = 0;
                memset(baseCmd, 0, strlen(jkQuakeConsole_chatStr)+1);

                jkQuakeConsole_pTabPos++;
                strncpy(baseCmd, jkQuakeConsole_chatStr, (jkQuakeConsole_pTabPos-jkQuakeConsole_chatStr));
            }

            jkQuakeConsole_sortTmpIdx = 0;

            if (bCanAutocompleteCheats) {
                bPrintOnce |= jkQuakeConsole_AutocompleteCvars();
                bPrintOnce |= jkQuakeConsole_AutocompleteCheats();
                bPrintOnce |= jkQuakeConsole_AutocompleteConsoleCmds();
            }
            
            // TODO proper command db
            if (!__strcmpi(baseCmd, "thing spawn ") || !__strcmpi(baseCmd, "npc spawn ")) {
                bPrintOnce |= jkQuakeConsole_AutocompleteTemplates();
            }

            if (!jkQuakeConsole_bHasTabbed && bPrintOnce) {
                jkQuakeConsole_PrintLine(tmp2);
            }

            _qsort(jkQuakeConsole_aSortTmp, jkQuakeConsole_sortTmpIdx, sizeof(char*), jkQuakeConsole_cmpstr);
            for (int i = 0; i < jkQuakeConsole_sortTmpIdx; i++) {
                if (i == jkQuakeConsole_tabIdx) {
                    // Keep track of where we were, so if backspace is pressed 
                    // then it reverts the completion.
                    if (!jkQuakeConsole_bHasTabbed) {
                        jkQuakeConsole_chatStrPos++;
                    }

                    tabbedStr = jkQuakeConsole_aSortTmp[i];

                    jkQuakeConsole_bHasTabbed = 1;
                }
                if (shouldPrint) {

                    tSithCvar* pCvar = sithCvar_Find(jkQuakeConsole_aSortTmp[i]);
                    if (pCvar) {
                        sithCvar_ToString(jkQuakeConsole_aSortTmp[i], tmp_cvar, SITHCVAR_MAX_STRLEN);
                        stdPlatform_Printf("  %s = \"%s\"\n", jkQuakeConsole_aSortTmp[i], tmp_cvar);
                    }
                    else {
                        stdPlatform_Printf("  %s\n", jkQuakeConsole_aSortTmp[i]);
                    }
                }
            }

            if (tabbedStr) {
                strncpy(jkQuakeConsole_pTabPos, tabbedStr, JKQUAKECONSOLE_CHAT_LEN-1);
                strncat(jkQuakeConsole_pTabPos, " ", JKQUAKECONSOLE_CHAT_LEN-1);
            }
            free(baseCmd);

            jkQuakeConsole_tabIdx++;
            if (jkQuakeConsole_sortTmpIdx) {
                jkQuakeConsole_tabIdx %= jkQuakeConsole_sortTmpIdx;
            }
            else {
                jkQuakeConsole_tabIdx = 0;
            }
            
            //if ( sithNet_isMulti )
            //    jkHud_dword_552D10 = (jkHud_dword_552D10 == -2) - 2;
        }
        else
        {
            // User has chosen to continue the completion
            if (jkQuakeConsole_bHasTabbed) {
                jkQuakeConsole_chatStrPos = strlen(jkQuakeConsole_chatStr);
                if (jkQuakeConsole_chatStrPos > JKQUAKECONSOLE_CHAT_LEN-1) {
                    jkQuakeConsole_chatStrPos = JKQUAKECONSOLE_CHAT_LEN-1;
                }
            }
            jkQuakeConsole_tabIdx = 0;
            jkQuakeConsole_selectedHistory = 0;
            jkQuakeConsole_bHasTabbed = 0;
            if ( jkQuakeConsole_chatStrPos < JKQUAKECONSOLE_CHAT_LEN-2 )
            {
                memmove(&jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos+1], &jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos], JKQUAKECONSOLE_CHAT_LEN-jkQuakeConsole_chatStrPos-1);
                jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos] = wParam;
                //jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos + 1] = 0;
                jkQuakeConsole_chatStrPos++;
            }
        }
        if ( jkHud_dword_552D10 == -2 )
        {
            //stdString_SafeWStrCopy(tmp, jkStrings_GetUniStringWithFallback("HUD_COMMAND"), 0x80u);
        }
        else if ( jkHud_dword_552D10 == -1 )
        {
            //stdString_SafeWStrCopy(tmp, jkStrings_GetUniStringWithFallback("HUD_SENDTOALL"), 0x80u);
        }
        //int v2 = _wcslen(tmp);
        //stdString_CharToWchar(&tmp[v2], jkQuakeConsole_chatStr, 127 - v2);
        //tmp[127] = 0;
        //jkDev_sub_41FB80(103, tmp);
    }
}

int jkQuakeConsole_WmHandler(HWND a1, UINT msg, WPARAM wParam, HWND a4, LRESULT *a5)
{
    LPARAM lParam = (LPARAM)a4;
    uint16_t repeats = lParam & 0xFFFF;
    uint16_t mouseX = lParam & 0xFFFF;
    uint16_t mouseY = (lParam >> 16) & 0xFFFF;

    switch ( msg )
    {
        case WM_KEYFIRST:
            if (wParam == VK_SHIFT || wParam == VK_LSHIFT || wParam == VK_RSHIFT) {
                jkQuakeConsole_bShiftHeld = 1;
            }
            else if (wParam == VK_OEM_3 && !repeats && (!sithNet_isMulti || jkQuakeConsole_bShiftHeld)) // `/~ key
            {
                jkQuakeConsole_bOpen = !jkQuakeConsole_bOpen;
                if (jkQuakeConsole_bOpen) {
                    jkQuakeConsole_ResetShade();
                }
                stdControl_ToggleCursor(!jkQuakeConsole_bOpen);
                *a5 = 1;
                return 1;
            }
            else if (wParam == VK_UP || wParam == VK_DOWN || wParam == VK_LEFT || wParam == VK_RIGHT || wParam == VK_DELETE) { // 
                jkQuakeConsole_SendInput(wParam, 0);
            }
            else if (!jkHud_bChatOpen && !jkQuakeConsole_bOpen) {
                sithCommand_HandleBinds(wParam);
            }

            // Hijack all input to the console if the shade is down.
            if (jkQuakeConsole_bOpen) {
                *a5 = 1;
                return 1;
            }
            break;

        case WM_KEYUP:
            if (wParam == VK_SHIFT || wParam == VK_LSHIFT || wParam == VK_RSHIFT) {
                jkQuakeConsole_bShiftHeld = 0;
            }
            break;
            
        case WM_CHAR:
            if ( jkQuakeConsole_bOpen ) // Added: Quake console
            {
                jkQuakeConsole_SendInput(wParam, 1);
                *a5 = 1;
                return 1;
            }
            else if (!jkHud_bChatOpen && !jkQuakeConsole_bOpen) {
                sithCommand_HandleBinds(wParam);
            }
            break;
        case WM_LBUTTONDOWN:
            if (jkQuakeConsole_bShowUpdateText && mouseX < jkQuakeConsole_updateTextWidth && mouseY < jkQuakeConsole_updateTextHeight)
            {
                jkQuakeConsole_bClickedUpdate = 1;
                stdUpdater_DoUpdate();
            }
            break;
        default:
            break;
    }
    
    return 0;
}

void jkQuakeConsole_PrintLine(const char* pLine)
{
    if (!pLine) return;

    char* pLastLine = jkQuakeConsole_aLines[JKQUAKECONSOLE_NUM_LINES-1];
    if (pLastLine) {
        free(pLastLine);
    }

    for (int i = JKQUAKECONSOLE_NUM_LINES-1; i > 0; i--)
    {
        jkQuakeConsole_aLines[i] = jkQuakeConsole_aLines[i-1];
    }

    char* pNewLine = malloc(strlen(pLine)+2);
    strcpy(pNewLine, pLine);

    jkQuakeConsole_aLines[0] = pNewLine;

    jkQuakeConsole_realLines++;
    if (jkQuakeConsole_realLines > JKQUAKECONSOLE_NUM_LINES) {
        jkQuakeConsole_realLines = JKQUAKECONSOLE_NUM_LINES;
    }

    if (jkQuakeConsole_bOpen && jkQuakeConsole_scrollPos) {
        jkQuakeConsole_scrollPos++;
    }
}

void jkQuakeConsole_RecordHistory(const char* pLine)
{
    if (!pLine) return;

    char* pLastLine = jkQuakeConsole_aLastCommands[JKQUAKECONSOLE_COMMAND_HISTORY_DEPTH-1];
    if (pLastLine) {
        free(pLastLine);
    }

    for (int i = JKQUAKECONSOLE_COMMAND_HISTORY_DEPTH-1; i > 0; i--)
    {
        jkQuakeConsole_aLastCommands[i] = jkQuakeConsole_aLastCommands[i-1];
    }

    char* pNewLine = malloc(strlen(pLine)+2);
    strcpy(pNewLine, pLine);

    jkQuakeConsole_aLastCommands[0] = pNewLine;

    jkQuakeConsole_realHistoryLines++;
    if (jkQuakeConsole_realHistoryLines > JKQUAKECONSOLE_COMMAND_HISTORY_DEPTH) {
        jkQuakeConsole_realHistoryLines = JKQUAKECONSOLE_COMMAND_HISTORY_DEPTH;
    }
}