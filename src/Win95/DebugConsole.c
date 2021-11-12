#include "DebugConsole.h"

#include "Engine/sithDebugConsole.h"
#include "Win95/stdSound.h"
#include "Engine/sithSound.h"
#include "General/stdHashTable.h"
#include "stdPlatform.h"
#include "jk.h"

int DebugConsole_Initialize(int maxCmds)
{
    stdHashTable *v1; // eax
    IDirectSoundBuffer *v2; // eax
    signed int result; // eax

    DebugConsole_aCmds = (stdDebugConsoleCmd *)pSithHS->alloc(sizeof(stdDebugConsoleCmd) * maxCmds);
    v1 = stdHashTable_New(2 * maxCmds);
    DebugConsole_pCmdHashtable = v1;
    if ( DebugConsole_aCmds )
    {
        if ( v1 )
        {
            DebugConsole_maxCmds = maxCmds;
            _memset(DebugConsole_aCmds, 0, 4 * ((sizeof(stdDebugConsoleCmd) * maxCmds) >> 2));
            DebugGui_fnPrint = 0;
            DebugGui_fnPrintUniStr = 0;
            sithDebugConsole_Initialize();
            v2 = sithSound_InitFromPath("set_vlo2.wav");
            DebugConsole_alertSound = v2;
            if ( v2 )
                stdSound_BufferSetVolume(v2, 0.80000001);
            result = 1;
            DebugConsole_bInitted = 1;
            return result;
        }
        if ( DebugConsole_aCmds )
        {
            pSithHS->free(DebugConsole_aCmds);
            v1 = DebugConsole_pCmdHashtable;
            DebugConsole_aCmds = 0;
        }
    }
    if ( v1 )
    {
        stdHashTable_Free(v1);
        DebugConsole_pCmdHashtable = 0;
    }
    return 0;
}

void DebugConsole_Shutdown()
{
    if ( DebugConsole_aCmds )
    {
        pSithHS->free((void *)DebugConsole_aCmds);
        DebugConsole_aCmds = 0;
    }
    if ( DebugConsole_pCmdHashtable )
    {
        stdHashTable_Free(DebugConsole_pCmdHashtable);
        DebugConsole_pCmdHashtable = 0;
    }
    if ( DebugConsole_alertSound )
        stdSound_BufferRelease(DebugConsole_alertSound);
    DebugConsole_bInitted = 0;
}

int DebugConsole_Open(int maxLines)
{
    signed int result; // eax

    DebugGui_maxLines = maxLines;
    _memset(DebugLog_buffer, 0, 4 * ((unsigned int)(maxLines << 7) >> 2));
    DebugGui_some_line_amt = 0;
    DebugGui_some_num_lines = 0;
    DebugGui_idk = 0;
    DebugConsole_bOpened = 1;
    
    // Added: Prevent arithmetic exception on modulus
    if (DebugGui_maxLines <= 0)
        DebugGui_maxLines = 1;
    
    return 1;
}

void DebugConsole_Close()
{
    DebugConsole_bOpened = 0;
}

void DebugConsole_Print(char *str)
{
#ifdef PLATFORM_POSIX
    printf("%s\n", str);
    return;
#endif
    if ( DebugGui_fnPrint )
    {
        // TODO TODO regression
        //DebugGui_fnPrint(str);
        jk_printf("%s\n", str);
    }
    else
    {
        // Added
        if (!DebugConsole_bOpened) return;

        DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
        if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
            DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;
        _strncpy(&DebugLog_buffer[128 * DebugGui_some_num_lines], str, 0x7Fu);
        DebugLog_buffer[128 * DebugGui_some_num_lines + 127] = 0;
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
    }
}

void DebugConsole_PrintUniStr(wchar_t *a1)
{
#ifdef LINUX_TMP
    printf("STUB: DebugConsole_PrintUniStr\n");
    return;
#endif
    if ( DebugGui_fnPrintUniStr )
        DebugGui_fnPrintUniStr(a1);
}

int DebugConsole_TryCommand(char *cmd)
{
    char *v1; // esi
    stdDebugConsoleCmd *v2; // edi
    char *v3; // eax

    _strtolower(cmd);
    v1 = _strtok(cmd, ", \t\n\r");
    if ( v1 )
    {
        v2 = (stdDebugConsoleCmd *)stdHashTable_GetKeyVal(DebugConsole_pCmdHashtable, v1);
        if ( v2 )
        {
            v3 = _strtok(0, "\n\r");
            ((void (__cdecl *)(stdDebugConsoleCmd *, char *))v2->cmdFunc)(v2, v3);
            return 1;
        }
        _sprintf(std_genBuffer, "Console command %s not recognized.", v1);
        if ( DebugGui_fnPrint )
        {
            DebugGui_fnPrint(std_genBuffer);
            return 0;
        }
        DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
        if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
            DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;
        _strncpy(&DebugLog_buffer[128 * DebugGui_some_num_lines], std_genBuffer, 0x7Fu);
        DebugLog_buffer[128 * DebugGui_some_num_lines + 127] = 0;
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
    }
    return 0;
}

int DebugConsole_sub_4DA100()
{
    return 1;
}

void DebugConsole_AdvanceLogBuf()
{
    uint32_t v0; // edx

    v0 = DebugGui_idk;
    if ( DebugGui_idk != DebugGui_some_num_lines )
    {
        do
            v0 = (v0 + 1) % DebugGui_maxLines;
        while ( v0 != DebugGui_some_num_lines );
        DebugGui_idk = v0;
    }
}

int DebugConsole_RegisterDevCmd(void *fn, char *cmd, int extra)
{
    stdDebugConsoleCmd *v4; // [esp-4h] [ebp-4h]

    if ( DebugConsole_numRegisteredCmds == DebugConsole_maxCmds )
        return 0;
    _strncpy(DebugConsole_aCmds[DebugConsole_numRegisteredCmds].cmdStr, cmd, 0x1Fu);
    v4 = &DebugConsole_aCmds[DebugConsole_numRegisteredCmds];
    v4->cmdStr[31] = 0;
    v4->cmdFunc = fn;
    v4->extra = extra;
    stdHashTable_SetKeyVal(DebugConsole_pCmdHashtable, v4->cmdStr, v4);
    ++DebugConsole_numRegisteredCmds;
    return 1;
}

int DebugConsole_SetPrintFuncs(void *a1, void *a2)
{
    DebugGui_fnPrint = a1;
    DebugGui_fnPrintUniStr = a2;
    return 1;
}

int DebugConsole_PrintHelp()
{
    uint32_t v0; // esi
    unsigned int v1; // ebp
    int v2; // edi
    signed int result; // eax
    char v4[80]; // [esp+10h] [ebp-50h] BYREF

    *(int16_t*)v4 = DebugConsole_idk2;
    _memset(&v4[2], 0, 0x4Cu);
    *(int16_t*)&v4[78] = 0;
    v0 = 0;
    if ( DebugGui_fnPrint )
    {
        DebugGui_fnPrint("The following commands are available:");
    }
    else
    {
        DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
        if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
            DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;
        _strncpy(&DebugLog_buffer[128 * DebugGui_some_num_lines], "The following commands are available:", 0x7Fu);
        DebugLog_buffer[128 * DebugGui_some_num_lines + 127] = 0;
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
    }
    v1 = 0;
    if ( DebugConsole_numRegisteredCmds )
    {
        v2 = 0;
        do
        {
            if ( v0 + 0x10 >= 0x50 )
            {
                if ( DebugGui_fnPrint )
                {
                    DebugGui_fnPrint(v4);
                }
                else
                {
                    DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
                    if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
                        DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;
                    _strncpy(&DebugLog_buffer[128 * DebugGui_some_num_lines], v4, 0x7Fu);
                    DebugLog_buffer[128 * DebugGui_some_num_lines + 127] = 0;
                    DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
                }
                v0 = 0;
            }
            _sprintf(&v4[v0], "%-15s", DebugConsole_aCmds[v2].cmdStr);
            v0 += 15;
            ++v1;
            ++v2;
        }
        while ( v1 < DebugConsole_numRegisteredCmds );
    }
    if ( DebugGui_fnPrint )
    {
        DebugGui_fnPrint(v4);
        result = 1;
    }
    else
    {
        DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
        if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
            DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;
        _strncpy(&DebugLog_buffer[128 * DebugGui_some_num_lines], v4, 0x7Fu);
        DebugLog_buffer[128 * DebugGui_some_num_lines + 127] = 0;
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
        result = 1;
    }
    return result;
}

void DebugConsole_AlertSound()
{
    if ( DebugConsole_alertSound )
    {
        stdSound_BufferReset(DebugConsole_alertSound);
        stdSound_BufferPlay(DebugConsole_alertSound, 0);
    }
}
