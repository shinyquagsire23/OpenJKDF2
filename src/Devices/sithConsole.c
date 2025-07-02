#include "sithConsole.h"

#include "Main/sithCommand.h"
#include "Win95/stdSound.h"
#include "Devices/sithSound.h"
#include "General/stdHashTable.h"
#include "General/stdString.h"
#include "Main/sithCvar.h"
#include "stdPlatform.h"
#include "jk.h"

int sithConsole_Startup(int maxCmds)
{
    stdHashTable *v1; // eax
    signed int result; // eax

    sithConsole_aCmds = (stdDebugConsoleCmd *)pSithHS->alloc(sizeof(stdDebugConsoleCmd) * maxCmds);
    v1 = stdHashTable_New(2 * maxCmds);
    sithConsole_pCmdHashtable = v1;
    if ( sithConsole_aCmds )
    {
        if ( v1 )
        {
            sithConsole_maxCmds = maxCmds;
            _memset(sithConsole_aCmds, 0, sizeof(stdDebugConsoleCmd) * maxCmds);
            DebugGui_fnPrint = 0;
            DebugGui_fnPrintUniStr = 0;
            sithCommand_Startup();
            sithConsole_alertSound = sithSound_InitFromPath("set_vlo2.wav");
            if ( sithConsole_alertSound )
                stdSound_BufferSetVolume(sithConsole_alertSound, 0.8);
            result = 1;
            sithConsole_bInitted = 1;
            return result;
        }
        if ( sithConsole_aCmds )
        {
            pSithHS->free(sithConsole_aCmds);
            v1 = sithConsole_pCmdHashtable;
            sithConsole_aCmds = 0;
        }
    }
    if ( v1 )
    {
        stdHashTable_Free(v1);
        sithConsole_pCmdHashtable = 0;
    }

    return 0;
}

void sithConsole_Shutdown()
{
    if ( sithConsole_aCmds )
    {
        pSithHS->free((void *)sithConsole_aCmds);
        sithConsole_aCmds = 0;
    }
    if ( sithConsole_pCmdHashtable )
    {
        stdHashTable_Free(sithConsole_pCmdHashtable);
        sithConsole_pCmdHashtable = 0;
    }
    if ( sithConsole_alertSound )
        stdSound_BufferRelease(sithConsole_alertSound);

    // Added
    sithCommand_ShutdownBinds();

    sithConsole_bInitted = 0;
}

int sithConsole_Open(int maxLines)
{
    signed int result; // eax

    DebugGui_maxLines = maxLines;
    _memset(DebugLog_buffer, 0, 0x80 * maxLines);
    DebugGui_some_line_amt = 0;
    DebugGui_some_num_lines = 0;
    DebugGui_idk = 0;
    sithConsole_bOpened = 1;
    
    // Added: Prevent arithmetic exception on modulus
    if (DebugGui_maxLines <= 0)
        DebugGui_maxLines = 1;
    
    return 1;
}

void sithConsole_Close()
{
    sithConsole_bOpened = 0;
}

void sithConsole_Print(const char *str)
{
    if ( DebugGui_fnPrint )
    {
        // TODO TODO regression
        DebugGui_fnPrint(str);
        //jk_printf("%s\n", str);
    }
    else
    {
        // Added
        if (!sithConsole_bOpened) return;

        DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
        if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
            DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;

        stdString_SafeStrCopy(&DebugLog_buffer[128 * DebugGui_some_num_lines], str, 0x80);
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
    }
}

void sithConsole_PrintUniStr(const wchar_t *a1)
{
    if ( DebugGui_fnPrintUniStr )
        DebugGui_fnPrintUniStr(a1);
}

int sithConsole_TryCommand(const char *cmd)
{
    char *v1; // esi
    stdDebugConsoleCmd *v2; // edi
    char *v3; // eax
    char tmp_cvar[SITHCVAR_MAX_STRLEN];

    // Added: mutable copy of cmd
    char* pCmdMutable = (char*)malloc(strlen(cmd)+1);
    strcpy(pCmdMutable, cmd);

    _strtolower(pCmdMutable); // Added: mutable copy of cmd
    v1 = _strtok(pCmdMutable, ", \t\n\r"); // Added: mutable copy of cmd
    if ( v1 )
    {
        // Added: cvars
        tSithCvar* pCvar = sithCvar_Find(v1);
        if (pCvar) {
            v3 = _strtok(0, "\n\r");

            if (pCvar->flags & CVARFLAG_READONLY) {
                if (!_strtok(v3, ", \t\n\r")) {
                    sithCvar_ToString(pCvar->pName, tmp_cvar, SITHCVAR_MAX_STRLEN);
                    _sprintf(std_genBuffer, "%s = \"%s\"", pCvar->pName, tmp_cvar);
                    if ( DebugGui_fnPrint )
                    {
                        DebugGui_fnPrint(std_genBuffer);
                    }
                    free((void*)pCmdMutable); // Added: mutable copy of cmd
                    return 0;
                }

                _sprintf(std_genBuffer, "Cvar %s is read-only.", pCvar->pName);
                if ( DebugGui_fnPrint )
                {
                    DebugGui_fnPrint(std_genBuffer);
                }
                free((void*)pCmdMutable); // Added: mutable copy of cmd
                return 0;
            }

            
            if (!sithCvar_SetFromString(pCvar->pName, v3))
            {
                sithCvar_ToString(pCvar->pName, tmp_cvar, SITHCVAR_MAX_STRLEN);
                _sprintf(std_genBuffer, "%s = \"%s\"", pCvar->pName, tmp_cvar);
                if ( DebugGui_fnPrint )
                {
                    DebugGui_fnPrint(std_genBuffer);
                }
                free((void*)pCmdMutable); // Added: mutable copy of cmd
                return 0;
            }
            free((void*)pCmdMutable); // Added: mutable copy of cmd
            return 1;
        }

        v2 = (stdDebugConsoleCmd *)stdHashTable_GetKeyVal(sithConsole_pCmdHashtable, v1);
        if ( v2 )
        {
            v3 = _strtok(0, "\n\r");
            v2->cmdFunc(v2, (const char*)v3);
            free((void*)pCmdMutable);
            return 1;
        }
        _sprintf(std_genBuffer, "Console command %s not recognized.", v1);
        if ( DebugGui_fnPrint )
        {
            DebugGui_fnPrint(std_genBuffer);
            free((void*)pCmdMutable); // Added: mutable copy of cmd
            return 0;
        }
        DebugGui_some_num_lines = (DebugGui_some_num_lines + 1) % DebugGui_maxLines;
        if ( DebugGui_some_num_lines == DebugGui_some_line_amt )
            DebugGui_some_line_amt = (DebugGui_some_line_amt + 1) % DebugGui_maxLines;

        stdString_SafeStrCopy(&DebugLog_buffer[128 * DebugGui_some_num_lines], std_genBuffer, 0x80);
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
    }
    free((void*)pCmdMutable); // Added: mutable copy of cmd
    return 0;
}

int sithConsole_sub_4DA100()
{
    return 1;
}

void sithConsole_AdvanceLogBuf()
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

int sithConsole_RegisterDevCmd(DebugConsoleCmd_t fn, const char *cmd, int extra)
{
    stdDebugConsoleCmd *v4; // [esp-4h] [ebp-4h]

    if ( sithConsole_numRegisteredCmds == sithConsole_maxCmds )
        return 0;
    stdString_SafeStrCopy(sithConsole_aCmds[sithConsole_numRegisteredCmds].cmdStr, cmd, 0x20);
    v4 = &sithConsole_aCmds[sithConsole_numRegisteredCmds];
    v4->cmdFunc = fn;
    v4->extra = extra;
    stdHashTable_SetKeyVal(sithConsole_pCmdHashtable, v4->cmdStr, v4);
    ++sithConsole_numRegisteredCmds;
    return 1;
}

int sithConsole_SetPrintFuncs(DebugConsolePrintFunc_t a1, DebugConsolePrintUniStrFunc_t a2)
{
    DebugGui_fnPrint = a1;
    DebugGui_fnPrintUniStr = a2;
    return 1;
}

int sithConsole_PrintHelp(stdDebugConsoleCmd* a, const char* b)
{
    uint32_t v0; // esi
    unsigned int v1; // ebp
    int v2; // edi
    signed int result; // eax
    char v4[80]; // [esp+10h] [ebp-50h] BYREF

    *(int16_t*)v4 = sithConsole_idk2;
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
        
        stdString_SafeStrCopy(&DebugLog_buffer[128 * DebugGui_some_num_lines], "The following commands are available:", 0x80);
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
    }
    v2 = 0;
    for (v1 = 0; v1 < sithConsole_numRegisteredCmds; v1++ )
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
                stdString_SafeStrCopy(&DebugLog_buffer[128 * DebugGui_some_num_lines], v4, 0x80);
                DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
            }
            v0 = 0;
        }
        _sprintf(&v4[v0], "%-15s", sithConsole_aCmds[v2].cmdStr);
        v0 += 15;
        ++v2;
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
        stdString_SafeStrCopy(&DebugLog_buffer[128 * DebugGui_some_num_lines], v4, 0x80);
        DebugGui_aIdk[DebugGui_some_num_lines] = stdPlatform_GetTimeMsec();
        result = 1;
    }
    return result;
}

void sithConsole_AlertSound()
{
    if ( sithConsole_alertSound )
    {
#ifdef QOL_IMPROVEMENTS
        // Original game did not respect SFX volume for this
        stdSound_BufferSetVolume(sithConsole_alertSound, jkGuiSound_sfxVolume);
#endif
        stdSound_BufferReset(sithConsole_alertSound);
        stdSound_BufferPlay(sithConsole_alertSound, 0);
    }
}