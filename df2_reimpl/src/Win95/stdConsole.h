#ifndef _STDCONSOLE_H
#define _STDCONSOLE_H

#include <windows.h>
#include <stdint.h>

#define stdConsole_Startup_ADDR (0x004277B0)
#define stdConsole_Shutdown_ADDR (0x00427880)
#define stdConsole_New_ADDR (0x00427890)
#define stdConsole_Free_ADDR (0x004279C0)
#define stdConsole_SetCursorPos_ADDR (0x004279E0)
#define stdConsole_GetCursorPos_ADDR (0x00427A10)
#define stdConsole_ToggleCursor_ADDR (0x00427A40)
#define stdConsole_GetTextAttribute_ADDR (0x00427AA0)
#define stdConsole_SetTextAttribute_ADDR (0x00427AC0)
#define stdConsole_Flush_ADDR (0x00427AE0)
#define stdConsole_Clear_ADDR (0x00427AF0)
#define stdConsole_Reset_ADDR (0x00427B60)
#define stdConsole_Putc_ADDR (0x00427BB0)
#define stdConsole_Puts_ADDR (0x00427BF0)
#define stdConsole_ClearBuf_ADDR (0x00427C40)
#define stdConsole_ClearBuf2_ADDR (0x00427C80)
#define stdConsole_WriteBorderMaybe_ADDR (0x00427CB0)
#define stdConsole_WriteBorderMaybe2_ADDR (0x00428360)
#define stdConsole_WriteBorderMaybe3_ADDR (0x004284D0)
#define stdConsole_WriteBorderMaybe4_ADDR (0x00428680)

#define stdConsole_foregroundAttr (*(uint16_t*)0x0055BB68)
#define stdConsole_wAttributes (*(uint16_t*)0x0055BB6C)
#define stdConsole_cursorHidden (*(int*)0x0055BB70)
#define stdConsole_ConsoleCursorInfo (*(CONSOLE_CURSOR_INFO*)0x0055BB78)

#define stdConsole_hConsoleOutput (*(HANDLE*)0x00866860)
#define stdConsole_hConsoleInput (*(HANDLE*)0x00866864)

typedef struct stdConsole
{
    uint32_t dword0;
    uint32_t dword4;
    uint32_t dword8;
    uint32_t dwordC;
    uint32_t dword10;
    uint32_t dword14;
    uint32_t dword18;
    char char1C;
    char gap1D;
    char field_1E;
    char field_1F;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint8_t byte6C;
    uint8_t byte6D;
    uint8_t byte6E;
    uint8_t byte6F;
    uint16_t word70;
    uint16_t word72;
    uint16_t word74;
    uint8_t byte76;
    uint8_t field_77;
    void* buffer;
    uint32_t field_7C;
    uint32_t bufferLen;
    uint32_t dword84;
    uint32_t dword88;
    uint32_t dword8C;
} stdConsole;

int stdConsole_Startup(LPCSTR lpConsoleTitle, uint32_t dwWriteCoord, int a3);
BOOL stdConsole_Shutdown();
stdConsole* stdConsole_New(int a1, int a2, int a3, int a4, char *a5, char a6, char a7, char a8, char a9, __int16 a10, unsigned __int8 a11, unsigned __int8 a12, char a13);
void stdConsole_Free(stdConsole *a1);
BOOL stdConsole_SetCursorPos(COORD dwCursorPosition, SHORT a2);
void stdConsole_GetCursorPos(COORD *a1);
void stdConsole_ToggleCursor(int a1);
int stdConsole_GetTextAttribute(WORD a1);
void stdConsole_SetTextAttribute(__int16 wAttributes);
void stdConsole_Flush();
void stdConsole_Clear();
void stdConsole_Reset(SHORT a1);
void stdConsole_Putc(char Buffer, __int16 wAttributes);
void stdConsole_Puts(char *lpBuffer, WORD wAttributes);
int stdConsole_ClearBuf(stdConsole *a1);
void stdConsole_ClearBuf2(stdConsole *a1, int a2);
void stdConsole_WriteBorderMaybe(stdConsole *console);
void stdConsole_WriteBorderMaybe2(stdConsole *console, char *a2, signed int a3);
void stdConsole_WriteBorderMaybe3(stdConsole *a1);
void stdConsole_WriteBorderMaybe4(COORD Buffer, const char *lpBuffer, __int16 a3, WORD wAttributes);

#endif // _STDCONSOLE_H
