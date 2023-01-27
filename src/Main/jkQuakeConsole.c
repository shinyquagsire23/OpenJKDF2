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
#include "../jk.h"

#define JKQUAKECONSOLE_NUM_LINES (1024)
#define JKQUAKECONSOLE_CHAT_LEN (256)

int jkQuakeConsole_bOnce = 0;

int jkQuakeConsole_bInitted = 0;
stdFont* jkQuakeConsole_pFont = NULL;

int jkQuakeConsole_bOpen = 0;
uint64_t jkQuakeConsole_lastTimeUs = 0;
uint64_t jkQuakeConsole_blinkCounter = 0;
float jkQuakeConsole_shadeY = 0.0;

char jkQuakeConsole_chatStr[JKQUAKECONSOLE_CHAT_LEN];
uint32_t jkQuakeConsole_chatStrPos = 0;
int32_t jkQuakeConsole_scrollPos = 0;
uint32_t jkQuakeConsole_realLines = 0;
uint32_t jkQuakeConsole_tabIdx = 0;
int jkQuakeConsole_bHasTabbed = 0;

char* jkQuakeConsole_aLines[JKQUAKECONSOLE_NUM_LINES];

void jkQuakeConsole_ResetShade();

void jkQuakeConsole_Startup()
{
    // Added
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
        jkQuakeConsole_bOnce = 1;
    }
    
    jkQuakeConsole_bOpen = 0;
    jkQuakeConsole_bInitted = 1;
}

void jkQuakeConsole_Shutdown()
{
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
    jkQuakeConsole_chatStrPos = 0;
    jkQuakeConsole_scrollPos = 0;
    jkQuakeConsole_tabIdx = 0;
    jkQuakeConsole_bHasTabbed = 0;
    memset(jkQuakeConsole_chatStr, 0, sizeof(jkQuakeConsole_chatStr));
}

void jkQuakeConsole_Render()
{
    if (!jkQuakeConsole_bInitted) return;

    int64_t deltaUs = Linux_TimeUs() - jkQuakeConsole_lastTimeUs;
    jkQuakeConsole_lastTimeUs = Linux_TimeUs();

    float screenW = Video_menuBuffer.format.width;
    float screenH = Video_menuBuffer.format.height;
    float fontHeight = ((*jkQuakeConsole_pFont->bitmap->mipSurfaces)->format.height + jkQuakeConsole_pFont->marginY) * jkPlayer_hudScale;
    int maxVisibleLines = (int)((screenH / 2) / fontHeight)-2;

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
    int realScrollY = jkQuakeConsole_scrollPos;

    float realShadeY = -(screenH / 2) + jkQuakeConsole_shadeY;
    float realShadeBottom = realShadeY + (screenH / 2);

    if (jkGui_stdBitmaps[0]) {
        float scaleX = screenW / jkGui_stdBitmaps[0]->mipSurfaces[0]->format.width;
        float scaleY = screenH / jkGui_stdBitmaps[0]->mipSurfaces[0]->format.height;
        rdRect srcRect = {0,20,jkGui_stdBitmaps[0]->mipSurfaces[0]->format.width, jkGui_stdBitmaps[0]->mipSurfaces[0]->format.height*0.5};
        std3D_DrawUIBitmapRGBA(jkGui_stdBitmaps[0], 0, 0.0, realShadeY, &srcRect, scaleX, scaleY, 0, 80, 80, 80, 192);

        rdRect srcRect2 = {0,jkGui_stdBitmaps[0]->mipSurfaces[0]->format.height-4, 1, 2};
        std3D_DrawUIBitmapRGBA(jkGui_stdBitmaps[0], 0, 0.0, realShadeBottom, &srcRect2, (float)screenW, scaleY, 0, 255, 255, 255, 255);
    }
    else {
        rdRect rect = {0, realShadeY, screenW, screenH / 2};
        std3D_DrawUIClearedRectRGBA(0, 0, 0, 128, &rect);
    }

    jkQuakeConsole_blinkCounter += deltaUs;
    jkQuakeConsole_blinkCounter %= (1000*1000);
    int isBlink = jkQuakeConsole_blinkCounter > ((1000*1000)/2);
    
    char tmpBlink[JKQUAKECONSOLE_CHAT_LEN*2];
    stdString_snprintf(tmpBlink, sizeof(tmpBlink), "]%s%c", jkQuakeConsole_chatStr, isBlink ? ' ' : '_');

    //stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, 0, realShadeY, 640, tmpBlink, 1, jkPlayer_hudScale);
    stdFont_DrawAsciiGPU(jkQuakeConsole_pFont, 0, realShadeBottom - fontHeight*2, screenW, tmpBlink, 1, jkPlayer_hudScale);

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

void jkQuakeConsole_SendInput(char wParam)
{
    wchar_t tmp[256]; // [esp+4h] [ebp-100h] BYREF

    if ( wParam == VK_ESCAPE || wParam == VK_OEM_3 || wParam == 0xffffffc0 || wParam == '`')
    {
        return;
    }

    if ( wParam == VK_RETURN )
    {
        char tmp2[JKQUAKECONSOLE_CHAT_LEN*2];
        stdString_snprintf(tmp2, sizeof(tmp2), "]%s", jkQuakeConsole_chatStr);
        jkQuakeConsole_PrintLine(tmp2);
        jkQuakeConsole_tabIdx = 0;

        if ( jkQuakeConsole_chatStrPos )
        {
            if ( jkHud_dword_552D10 == -1 && sithNet_isMulti )
            {
                _sprintf(std_genBuffer, "You say, '%s'", jkQuakeConsole_chatStr);
                jkDev_DebugLog(std_genBuffer);
                sithMulti_SendChat(jkQuakeConsole_chatStr, -1, playerThingIdx);
            }
            else if ( !jkDev_TryCommand(jkQuakeConsole_chatStr) )
            {
                sithConsole_TryCommand(jkQuakeConsole_chatStr);
            }
        }
        jkQuakeConsole_chatStrPos = 0;
        memset(jkQuakeConsole_chatStr, 0, sizeof(jkQuakeConsole_chatStr));
        //jkHud_bChatOpen = 0;
        jkDev_sub_41FC90(103);
    }
    else
    {
        if ( wParam == VK_BACK )
        {
            if ( jkQuakeConsole_chatStrPos )
                jkQuakeConsole_chatStr[--jkQuakeConsole_chatStrPos] = 0;
            jkQuakeConsole_tabIdx = 0;
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
            int bPrintOnce = jkQuakeConsole_bHasTabbed;
            int idx = 0;

            char* tabbedStr = NULL;
            for (int i = 0; i < jkDev_cheatHashtable->numBuckets; i++)
            {
                stdLinklist* pIter = &jkDev_cheatHashtable->buckets[i];
                while (pIter)
                {
                    if (pIter->key) {
                        if (!strncmp(jkQuakeConsole_chatStr, pIter->key, strlen(jkQuakeConsole_chatStr))) {
                            if (!bPrintOnce)
                            {
                                jkQuakeConsole_PrintLine(tmp2);
                                bPrintOnce = 1;
                            }

                            if (idx == jkQuakeConsole_tabIdx) {
                                // Keep track of where we were, so if backspace is pressed 
                                // then it reverts the completion.
                                if (!jkQuakeConsole_bHasTabbed) {
                                    jkQuakeConsole_chatStrPos++;
                                }

                                tabbedStr = pIter->key;

                                jkQuakeConsole_bHasTabbed = 1;
                            }
                            idx++;

                            if (shouldPrint) {
                                stdPlatform_Printf("  %s\n", pIter->key);
                            }
                        }
                    }
                    pIter = pIter->next;
                }
            }

            if (tabbedStr) {
                strncpy(jkQuakeConsole_chatStr, tabbedStr, JKQUAKECONSOLE_CHAT_LEN-1);
            }

            jkQuakeConsole_tabIdx++;
            jkQuakeConsole_tabIdx %= idx;
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
            jkQuakeConsole_bHasTabbed = 0;
            if ( jkQuakeConsole_chatStrPos < JKQUAKECONSOLE_CHAT_LEN-2 )
            {
                jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos] = wParam;
                jkQuakeConsole_chatStr[jkQuakeConsole_chatStrPos + 1] = 0;
                jkQuakeConsole_chatStrPos++;
            }
        }
        if ( jkHud_dword_552D10 == -2 )
        {
            //stdString_SafeWStrCopy(tmp, jkStrings_GetText("HUD_COMMAND"), 0x80u);
        }
        else if ( jkHud_dword_552D10 == -1 )
        {
            //stdString_SafeWStrCopy(tmp, jkStrings_GetText("HUD_SENDTOALL"), 0x80u);
        }
        //int v2 = _wcslen(tmp);
        //stdString_CharToWchar(&tmp[v2], jkQuakeConsole_chatStr, 127 - v2);
        //tmp[127] = 0;
        //jkDev_sub_41FB80(103, tmp);
    }
}

int jkQuakeConsole_WmHandler(HWND a1, UINT msg, WPARAM wParam, HWND a4, LRESULT *a5)
{
    switch ( msg )
    {
        case WM_KEYFIRST:
            if (wParam == VK_OEM_3) // `/~ key
            {
                jkQuakeConsole_bOpen = !jkQuakeConsole_bOpen;
                if (jkQuakeConsole_bOpen) {
                    jkQuakeConsole_ResetShade();
                }
                stdControl_ToggleCursor(!jkQuakeConsole_bOpen);
                *a5 = 1;
                return 1;
            }

            // Hijack all input to the console if the shade is down.
            if (jkQuakeConsole_bOpen) {
                *a5 = 1;
                return 1;
            }
            break;
            
        case WM_CHAR:
            if ( jkQuakeConsole_bOpen ) // Added: Quake console
            {
                jkQuakeConsole_SendInput(wParam);
                *a5 = 1;
                return 1;
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
}