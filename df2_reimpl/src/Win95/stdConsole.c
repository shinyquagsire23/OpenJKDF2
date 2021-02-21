#include "stdConsole.h"

#include "jk.h"
#include <windows.h>

int stdConsole_Startup(LPCSTR lpConsoleTitle, uint32_t dwWriteCoord, int a3)
{
    const CHAR *v3; // ebx
    void *v5; // eax
    int v7; // eax
    HWND v8; // eax
    DWORD tmp;
    COORD nopCoord = {0};

    jk_AllocConsole();
    v3 = lpConsoleTitle;
    jk_SetConsoleTitleA(lpConsoleTitle);
    stdConsole_hConsoleInput = jk_GetStdHandle(0xFFFFFFF6);
    v5 = (void *)jk_GetStdHandle(0xFFFFFFF5);
    stdConsole_wAttributes = dwWriteCoord;
    stdConsole_hConsoleOutput = v5;
    stdConsole_ConsoleCursorInfo.dwSize = 8;
    stdConsole_ConsoleCursorInfo.bVisible = 1;
    stdConsole_cursorHidden = 0;
    stdConsole_foregroundAttr = dwWriteCoord & 0xF0;
    jk_SetConsoleTextAttribute(v5, dwWriteCoord & 0xF0);
    dwWriteCoord = 0;
    jk_FillConsoleOutputCharacterA(stdConsole_hConsoleOutput, ' ', 0x7D0u, nopCoord, (LPDWORD)&tmp);
    v7 = (v7 & 0xFFFF0000) | stdConsole_wAttributes;
    stdConsole_foregroundAttr = stdConsole_wAttributes;
    jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v7);
    if ( a3 )
    {
        v8 = jk_FindWindowA(0, v3);
        jk_ShowWindow(v8, 6);
    }
    return 1;
}

BOOL stdConsole_Shutdown()
{
    return jk_FreeConsole();
}

stdConsole* stdConsole_New(int a1, int a2, int a3, int a4, char *a5, char a6, char a7, char a8, char a9, __int16 a10, unsigned __int8 a11, unsigned __int8 a12, char a13)
{
    stdConsole *v13; // esi
    int v15; // eax
    int v16; // edi
    int v17; // ecx
    int v18; // ebx
    int v19; // edi
    void *v20; // eax
    unsigned int v21; // edx

    v13 = (stdConsole *)_malloc(0x90u);
    if ( !v13 )
        return 0;
    v15 = a1;
    v16 = a3;
    if ( a1 < 0 )
    {
        v16 = a1 + a3;
        v15 = 0;
    }
    v17 = a2;
    v18 = a4;
    if ( a2 < 0 )
    {
        v18 = v15 + a4;
        v17 = 0;
    }
    if ( v16 + v15 - 1 > 79 )
        v16 = 80 - v15;
    if ( v18 + v17 - 1 > 24 )
        v18 = 25 - v17;
    v13->dword4 = v15;
    v13->dword8 = v17;
    v13->dwordC = v16 + v15 - 1;
    v13->dword14 = v16;
    v13->dword18 = v18;
    v13->dword10 = v18 + v17 - 1;
    _strncpy(&v13->char1C, a5, 0x50u);
    v13->byte6E = a8;
    v13->word72 = a11;
    v13->dword84 = v16 * v18;
    v19 = v16 - 2;
    v13->byte6C = a6;
    v13->byte6D = a7;
    v13->byte6F = a9;
    v13->word70 = a10;
    v13->word74 = a12;
    v13->byte76 = a13;
    v13->bufferLen = v19 * (v18 - 2);
    v13->dword88 = 0;
    v13->dword8C = 0;
    v21 = v13->bufferLen;
    v13->buffer = _malloc(v19 * (v18 - 2));
    _memset(v13->buffer, 0x20u, v21);
    v13->dword88 = 0;
    v13->dword8C = 0;
    v13->dword0 = 0;
    return v13;
}

void stdConsole_Free(stdConsole *a1)
{
    _free(a1->buffer);
    _free(a1);
}

BOOL stdConsole_SetCursorPos(COORD dwCursorPosition, SHORT a2)
{
    dwCursorPosition.Y = a2;
    return jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
}

void stdConsole_GetCursorPos(COORD *a1)
{
    SHORT v1; // cx
    struct _CONSOLE_SCREEN_BUFFER_INFO consoleScreenBufferInfo; // [esp+0h] [ebp-18h]

    jk_GetConsoleScreenBufferInfo(stdConsole_hConsoleOutput, &consoleScreenBufferInfo);
    v1 = consoleScreenBufferInfo.dwCursorPosition.Y;
    a1->X = consoleScreenBufferInfo.dwCursorPosition.X;
    a1->Y = v1;
}

void stdConsole_ToggleCursor(int a1)
{
    if ( a1 )
    {
        if ( stdConsole_cursorHidden > 0 && !--stdConsole_cursorHidden )
        {
            stdConsole_ConsoleCursorInfo.bVisible = 1;
            jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
        }
    }
    else
    {
        if ( !stdConsole_cursorHidden )
        {
            stdConsole_ConsoleCursorInfo.bVisible = 0;
            jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
        }
        ++stdConsole_cursorHidden;
    }
}

int stdConsole_GetTextAttribute(WORD a1)
{
    stdConsole_wAttributes = a1;
    return 1;
}

void stdConsole_SetTextAttribute(__int16 wAttributes)
{
    stdConsole_foregroundAttr = wAttributes;
    jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, wAttributes);
}

void stdConsole_Flush()
{
    jk_FlushConsoleInputBuffer(stdConsole_hConsoleInput);
}

void stdConsole_Clear()
{
    DWORD NumberOfCharsWritten;
    COORD nopCoord = {0};

    stdConsole_foregroundAttr = stdConsole_wAttributes & 0xF0;
    jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, stdConsole_wAttributes & 0xF0);
    jk_FillConsoleOutputCharacterA(stdConsole_hConsoleOutput, ' ', 0x7D0u, nopCoord, &NumberOfCharsWritten);
    stdConsole_foregroundAttr = stdConsole_wAttributes;
    jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, stdConsole_wAttributes);
}

void stdConsole_Reset(SHORT a1)
{
    COORD ST14_4_1; // ST14_4
    DWORD NumberOfCharsWritten; // [esp+4h] [ebp-4h]

    stdConsole_foregroundAttr = stdConsole_wAttributes & 0xF0;
    jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, stdConsole_wAttributes & 0xF0);
    ST14_4_1.X = 0;
    ST14_4_1.Y = a1;
    jk_FillConsoleOutputCharacterA(stdConsole_hConsoleOutput, ' ', 0x50u, ST14_4_1, &NumberOfCharsWritten);
}

void stdConsole_Putc(char Buffer, __int16 wAttributes)
{
    if ( stdConsole_foregroundAttr != wAttributes )
    {
        stdConsole_foregroundAttr = wAttributes;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, wAttributes);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, &Buffer, 1u, (LPDWORD)&wAttributes, 0);
}

void stdConsole_Puts(char *lpBuffer, WORD wAttributes)
{
    if ( stdConsole_foregroundAttr != wAttributes )
    {
        stdConsole_foregroundAttr = wAttributes;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, wAttributes);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, lpBuffer, _strlen(lpBuffer), (LPDWORD)&wAttributes, 0);
}

int stdConsole_ClearBuf(stdConsole *a1)
{
    _memset(a1->buffer, 0x20u, a1->bufferLen);
    a1->dword88 = 0;
    a1->dword8C = 0;
    return 0;
}

void stdConsole_ClearBuf2(stdConsole *a1, int a2)
{
    _memset((char *)a1->buffer + (a1->dword14 - 2) * a2, ' ', a1->dword14 - 2);
}

void stdConsole_WriteBorderMaybe(stdConsole *console)
{
    stdConsole *v1; // esi
    int v2; // ecx
    int v3; // ecx
    int v4; // edx
    WORD v6; // ax
    int v8; // eax
    WORD v9; // ax
    int v10; // eax
    int v11; // edi
    WORD v12; // ax
    int v13; // ecx
    int v14; // edx
    WORD v15; // ax
    int v16; // eax
    WORD v17; // ax
    int v18; // eax
    int v19; // ecx
    WORD v20; // ax
    int v21; // eax
    int v22; // edi
    WORD v23; // ax
    WORD v24; // ax
    int v25; // ecx
    unsigned int v26; // kr04_4
    int v27; // edi
    int v28; // eax
    int v29; // eax
    WORD v30; // ax
    WORD v31; // ax
    int v32; // eax
    WORD v33; // ax
    char v34; // [esp+119h] [ebp-19h]
    char v35; // [esp+11Ah] [ebp-18h]
    char v36; // [esp+11Bh] [ebp-17h]
    char v37; // [esp+11Ch] [ebp-16h]
    char v38; // [esp+11Dh] [ebp-15h]
    char v39; // [esp+11Eh] [ebp-14h]
    char v40; // [esp+11Fh] [ebp-13h]
    char v41; // [esp+120h] [ebp-12h]
    char v42; // [esp+121h] [ebp-11h]
    COORD dwCursorPosition; // [esp+122h] [ebp-10h]
    DWORD NumberOfCharsWritten; // [esp+126h] [ebp-Ch]
    DWORD v45; // [esp+12Ah] [ebp-8h]
    DWORD v46; // [esp+12Eh] [ebp-4h]
    char writeChr;

    v1 = console;
    if ( console->byte6C )
    {
        if ( console->byte6C == 1 )
        {
            v37 = -51;
            v2 = (unsigned __int8)console->byte6F;
            v42 = -58;
            v41 = -75;
            if ( console->byte6F )
            {
                if ( v2 == 1 )
                    writeChr = -55;
            }
            else
            {
                writeChr = -43;
            }
            if ( v2 )
            {
                if ( v2 == 1 )
                    v35 = -69;
            }
            else
            {
                v35 = -72;
            }
        }
    }
    else
    {
        v37 = -60;
        v42 = -61;
        v41 = -76;
        if ( console->byte6E )
        {
            if ( console->byte6E == 1 )
                writeChr = -42;
        }
        else
        {
            writeChr = -38;
        }
        if ( v1->byte6F )
        {
            if ( v1->byte6F == 1 )
                v35 = -73;
        }
        else
        {
            v35 = -65;
        }
    }
    v3 = (unsigned __int8)v1->byte6E;
    if ( v1->byte6E )
    {
        if ( v1->byte6E == 1 )
            v39 = -70;
    }
    else
    {
        v39 = -77;
    }
    v4 = (unsigned __int8)v1->byte6F;
    if ( v1->byte6F )
    {
        if ( v1->byte6F == 1 )
            v40 = -70;
    }
    else
    {
        v40 = -77;
    }
    if ( v1->byte6D )
    {
        if ( v1->byte6D == 1 )
        {
            v38 = -51;
            if ( v1->byte6E )
            {
                if ( v3 == 1 )
                    v34 = -56;
            }
            else
            {
                v34 = -44;
            }
            if ( v1->byte6F )
            {
                if ( v4 == 1 )
                    v36 = -68;
            }
            else
            {
                v36 = -66;
            }
        }
    }
    else
    {
        v38 = -60;
        if ( v1->byte6E )
        {
            if ( v3 == 1 )
                v34 = -45;
        }
        else
        {
            v34 = -64;
        }
        if ( v1->byte6F )
        {
            if ( v4 == 1 )
                v36 = -67;
        }
        else
        {
            v36 = -39;
        }
    }
    if ( !stdConsole_cursorHidden )
    {
        stdConsole_ConsoleCursorInfo.bVisible = 0;
        jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
    }
    dwCursorPosition.X = v1->dword4;
    dwCursorPosition.Y = v1->dword8;
    ++stdConsole_cursorHidden;
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
    v6 = v1->word72;
    if ( stdConsole_foregroundAttr != v6 )
    {
        stdConsole_foregroundAttr = v1->word72;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v6);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1u, &NumberOfCharsWritten, 0);
    v8 = v1->dword18 + v1->dword8 - 1;
    dwCursorPosition.X = v1->dword4;
    dwCursorPosition.Y = v8;
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
    v9 = v1->word72;
    writeChr = v34;
    if ( stdConsole_foregroundAttr != v9 )
    {
        stdConsole_foregroundAttr = v9;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v9);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &NumberOfCharsWritten, 0);
    v10 = v1->dword4;
    v11 = v10 + 1;
    if ( v10 + 1 < v1->dword14 + v10 - 1 )
    {
        do
        {
            dwCursorPosition.X = v11;
            dwCursorPosition.Y = v1->dword8;
            jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
            v12 = v1->word72;
            writeChr = v37;
            if ( stdConsole_foregroundAttr != v12 )
            {
                stdConsole_foregroundAttr = v12;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v12);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v45, 0);
            v13 = v1->dword18;
            v14 = v1->dword8;
            dwCursorPosition.X = v11;
            dwCursorPosition.Y = v13 + v14 - 1;
            jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
            v15 = v1->word72;
            writeChr = v38;
            if ( stdConsole_foregroundAttr != v15 )
            {
                stdConsole_foregroundAttr = v15;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v15);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v46, 0);
            ++v11;
        }
        while ( v11 < v1->dword14 + v1->dword4 - 1 );
    }
    v16 = v1->dword8;
    dwCursorPosition.X = v11;
    dwCursorPosition.Y = v16;
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
    v17 = v1->word72;
    writeChr = v35;
    if ( stdConsole_foregroundAttr != v17 )
    {
        stdConsole_foregroundAttr = v17;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v17);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v46, 0);
    v18 = v1->dword18;
    v19 = v1->dword8;
    dwCursorPosition.X = v11;
    dwCursorPosition.Y = (v18 + v19 - 1);
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
    v20 = v1->word72;
    writeChr = v36;
    if ( stdConsole_foregroundAttr != v20 )
    {
        stdConsole_foregroundAttr = v20;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v20);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v46, 0);
    v21 = v1->dword8;
    v22 = v21 + 1;
    if ( v21 + 1 < v1->dword18 + v21 - 1 )
    {
        do
        {
            dwCursorPosition.X = v1->dword4;
            dwCursorPosition.Y = v22;
            jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
            v23 = v1->word72;
            writeChr = v39;
            if ( stdConsole_foregroundAttr != v23 )
            {
                stdConsole_foregroundAttr = v23;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v23);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v46, 0);
            dwCursorPosition.Y = v22;
            dwCursorPosition.X = (v1->dword14 & 0xFFFF) + v1->dword4 - 1;
            jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
            v24 = v1->word72;
            writeChr = v40;
            if ( stdConsole_foregroundAttr != v24 )
            {
                stdConsole_foregroundAttr = v24;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v24);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v45, 0);
            ++v22;
        }
        while ( v22 < v1->dword18 + v1->dword8 - 1 );
    }
    v26 = _strlen(&v1->char1C) + 1;
    v25 = v26 - 1;
    NumberOfCharsWritten = v26 - 1;
    if ( v26 != 1 )
    {
        if ( v1->byte76 )
        {
            if ( v1->byte76 != 1 )
            {
                if ( v1->byte76 == 2 )
                {
                    v27 = v1->dwordC - v25 - 3;
LABEL_76:
                    v29 = v1->dword8;
                    dwCursorPosition.X = v27;
                    dwCursorPosition.Y = v29;
                    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
                    v30 = v1->word72;
                    writeChr = v41;
                    if ( stdConsole_foregroundAttr != v30 )
                    {
                        stdConsole_foregroundAttr = v30;
                        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v30);
                    }
                    jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v46, 0);
                    dwCursorPosition.X = (v27 + 1);
                    dwCursorPosition.Y = v1->dword8;
                    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
                    v31 = v1->word74;
                    if ( stdConsole_foregroundAttr != v31 )
                    {
                        stdConsole_foregroundAttr = v1->word74;
                        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v31);
                    }
                    jk_WriteConsoleA(stdConsole_hConsoleOutput, &v1->char1C, _strlen(&v1->char1C), &v46, 0);
                    v32 = v1->dword8;
                    dwCursorPosition.X = (NumberOfCharsWritten + dwCursorPosition.X + 1);
                    dwCursorPosition.Y = v32;
                    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, dwCursorPosition);
                    v33 = v1->word72;
                    writeChr = v42;
                    if ( stdConsole_foregroundAttr != v33 )
                    {
                        stdConsole_foregroundAttr = v33;
                        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v33);
                    }
                    jk_WriteConsoleA(stdConsole_hConsoleOutput, &writeChr, 1, &v46, 0);
                    goto LABEL_83;
                }
LABEL_75:
                v27 = dwCursorPosition.X;
                goto LABEL_76;
            }
            v28 = v1->dword4 + 3;
        }
        else
        {
            v28 = v1->dword14 / 2 - (signed int)(v26 - 1) / 2 + v1->dword4 - 1;
        }
        dwCursorPosition.X = v28;
        goto LABEL_75;
    }
LABEL_83:
    _memset(v1->buffer, 0x20u, v1->bufferLen);
    v1->dword88 = 0;
    v1->dword8C = 0;
    stdConsole_WriteBorderMaybe3((int)v1);
    if ( stdConsole_cursorHidden > 0 && !--stdConsole_cursorHidden )
    {
        stdConsole_ConsoleCursorInfo.bVisible = 1;
        jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
    }
    v1->dword0 = 1;
}

void stdConsole_WriteBorderMaybe2(stdConsole *console, char *a2, signed int a3)
{
    stdConsole *console_; // ebp
    signed int v4; // eax
    char *v5; // ebx
    char *v6; // edx
    int v7; // eax
    int v8; // ecx
    int v9; // eax
    int v10; // edi
    int v11; // eax
    int v12; // edx
    COORD coord; // [esp+14h] [ebp+4h]

    console_ = console;
    v4 = console->dword14;
    if ( v4 > 2 && console->dword18 > 2 )
    {
        v5 = a2;
        v6 = (char *)console->buffer + console->dword8C * (v4 - 2) + console->dword88;
        while ( *v5 )
        {
            v7 = console->dword14;
            if ( console->dword88 >= v7 - 2 )
            {
                v8 = console->dword8C;
                console->dword88 = 0;
                console->dword8C = v8 + 1;
            }
            if ( console->dword8C >= console->dword18 - 2 )
            {
                _memcpy(console->buffer, (char *)console->buffer + v7 - 2, console->bufferLen - v7 + 2);
                v9 = console->dword14;
                v10 = console->dword8C - 1;
                console->dword8C = v10;
                v6 += 2 - v9;
                _memset((char *)console->buffer + (v9 - 2) * v10, 0x20u, v9 - 2);
            }
            v11 = (char)*v5++;
            if ( v11 == 10 )
            {
                v12 = console->dword8C;
                console->dword88 = 0;
                console->dword8C = ++v12;
                v6 = (char *)console->buffer + v12 * (console->dword14 - 2);
            }
            else
            {
                *v6++ = v11;
                ++console->dword88;
            }
        }
        stdConsole_WriteBorderMaybe3((int)console);
        if ( a3 )
        {
            coord.Y = LOWORD(console->dword8) + LOWORD(console->dword8C) + 1;
            coord.X = console_->dword4 + console_->dword88 + 1;
            jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, coord);
        }
    }
}

void stdConsole_WriteBorderMaybe3(stdConsole *a1)
{
    WORD v1; // ax
    unsigned int v2; // ebx
    int v3; // eax
    int v4; // edx
    COORD ST2C_4_8; // ST2C_4
    WORD v6; // ax
    char *v7; // [esp+10h] [ebp-80h]
    int v8; // [esp+14h] [ebp-7Ch]
    COORD v9; // [esp+1Ch] [ebp-74h]
    DWORD NumberOfCharsWritten; // [esp+20h] [ebp-70h]
    struct _CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo; // [esp+24h] [ebp-6Ch]
    char Buffer[84]; // [esp+3Ch] [ebp-54h]

    jk_GetConsoleScreenBufferInfo(stdConsole_hConsoleOutput, &ConsoleScreenBufferInfo);
    if ( !stdConsole_cursorHidden )
    {
        stdConsole_ConsoleCursorInfo.bVisible = 0;
        jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
    }
    v1 = a1->word70;
    ++stdConsole_cursorHidden;
    if ( stdConsole_foregroundAttr != v1 )
    {
        stdConsole_foregroundAttr = v1;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v1);
    }
    v2 = a1->dword14 - 2;
    v3 = a1->dword18 - 2;
    v4 = a1->dword8 + 1;
    v7 = (char *)a1->buffer;
    v8 = a1->dword8 + 1;
    Buffer[v2] = 0;
    v9.X = 0;
    if ( v3 > 0 )
    {
        while ( 1 )
        {
            _memcpy(Buffer, v7, v2);
            ST2C_4_8.X = a1->dword4 + 1;
            ST2C_4_8.Y = v4;
            jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, ST2C_4_8);
            v6 = a1->word70;
            if ( stdConsole_foregroundAttr != v6 )
            {
                stdConsole_foregroundAttr = a1->word70;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v6);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, Buffer, _strlen(Buffer), &NumberOfCharsWritten, 0);
            v7 += v2;
            v8++;
            if ( ++v9.X >= a1->dword18 - 2 )
                break;
            v4 = v8;
        }
    }
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, ConsoleScreenBufferInfo.dwCursorPosition);
    if ( stdConsole_cursorHidden > 0 && !--stdConsole_cursorHidden )
    {
        stdConsole_ConsoleCursorInfo.bVisible = 1;
        jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
    }
}

void stdConsole_WriteBorderMaybe4(COORD Buffer, const char *lpBuffer, __int16 a3, WORD wAttributes)
{
    int v4; // ebx
    SHORT v5; // di
    unsigned int v6; // kr08_4
    COORD ST24_4_3; // ST24_4
    int v8; // esi
    __int16 v9; // bp
    int v11; // ebx
    int v12; // edi
    int result; // eax

    v4 = 0;
    if ( !stdConsole_cursorHidden )
    {
        stdConsole_ConsoleCursorInfo.bVisible = 0;
        jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
    }
    ++stdConsole_cursorHidden;
    v6 = _strlen(lpBuffer) + 1;
    v5 = Buffer.X;
    ST24_4_3.X = 0;
    ST24_4_3.Y = Buffer.X;
    v8 = 40 - (signed int)(v6 - 1) / 2;
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, ST24_4_3);
    v9 = wAttributes;
    if ( v8 > 0 )
    {
        v4 = 40 - (signed int)(v6 - 1) / 2;
        do
        {
            char tmp = ' ';
            if ( stdConsole_foregroundAttr != v9 )
            {
                stdConsole_foregroundAttr = v9;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v9);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, &tmp, 1u, (LPDWORD)&wAttributes, 0);
            --v8;
        }
        while ( v8 );
    }
    Buffer.X = v4;
    Buffer.Y = v5;
    jk_SetConsoleCursorPosition(stdConsole_hConsoleOutput, Buffer);
    if ( stdConsole_foregroundAttr != a3 )
    {
        stdConsole_foregroundAttr = a3;
        jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, a3);
    }
    jk_WriteConsoleA(stdConsole_hConsoleOutput, lpBuffer, _strlen(lpBuffer), &Buffer, 0);
    v11 = v6 - 1 + v4;
    if ( v11 < 80 )
    {
        v12 = 80 - v11;
        do
        {
            char tmp = ' ';
            if ( stdConsole_foregroundAttr != v9 )
            {
                stdConsole_foregroundAttr = v9;
                jk_SetConsoleTextAttribute(stdConsole_hConsoleOutput, v9);
            }
            jk_WriteConsoleA(stdConsole_hConsoleOutput, &tmp, 1, &Buffer, 0);
            --v12;
        }
        while ( v12 );
    }
    result = stdConsole_cursorHidden;
    if ( stdConsole_cursorHidden > 0 )
    {
        result = stdConsole_cursorHidden - 1;
        stdConsole_cursorHidden = result;
        if ( !result )
        {
            stdConsole_ConsoleCursorInfo.bVisible = 1;
            jk_SetConsoleCursorInfo(stdConsole_hConsoleOutput, &stdConsole_ConsoleCursorInfo);
        }
    }
}
