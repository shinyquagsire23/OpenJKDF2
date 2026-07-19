// dwConfFile — token/keyword config-file reader used by the DW GUI factories.
// DroidWorks.exe unit range: 0x4477c0-0x447f1x (13 functions).
//
// Wraps a file handle obtained through the DW HostServices. In the original
// binary this is dw_hostServices @0x53d988, whose file ops get hooked by the
// dwGob/inits units so "files" can come from GOB archives; here that role is
// filled by dwMain_pHS. Reads one logical line at a time into aLine, skips
// blank/comment lines (leading ';' or '#'), then hands out whitespace- or
// quote-delimited tokens from pCursor.
//
// HostServices member mapping (repo src/types.h names == DW Ghidra names):
//   fileOpen(path, mode) / fileClose(fd) / fileGets(fd, buf, n) / ftell(fd).
//
// Note: the binary's whitespace test FUN_00507d80 is CRT isspace(int) called
// with a sign-extended char; we cast to unsigned char to avoid UB on
// high-bit chars (no behavior change for the ASCII config files DW ships).
//
// No module statics — no _Startup/_Shutdown needed.
//
// Compiled as C++ (the unit is __thiscall C++ in the binary and ParseString/
// ParseQuotedString manipulate dwString objects via dwString::Assign), in
// procedural style; the entire API keeps C linkage via dwConfFile.h's
// extern "C" guards.

#include "Dw/dwConfFile.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "stdPlatform.h"

// TODO(dw-decomp): defined by dwMain (original global: dwHS / dw_hostServices
// @0x53d988). dwMain is (and stays) C — declare with C linkage.
extern "C" HostServices* dwMain_pHS;

// @4477c0
void dwConfFile_Open(dwConfFile* pThis, const char* pPath)
{
    pThis->pFile = NULL;
    pThis->pCursor = pThis->aLine;
    pThis->bEof = 1;
    pThis->aLine[0] = '\0';
    pThis->pFile = (void*)dwMain_pHS->fileOpen(pPath, "r");
    if (pThis->pFile)
    {
        // Note: original stores the ftell result taken right after open as
        // nFileLen (under DW's hooked HostServices this reads as the file
        // length); the field is write-only within this unit.
        pThis->nFileLen = dwMain_pHS->ftell((stdFile_t)pThis->pFile);
        pThis->bEof = 0;
        return;
    }
    // Note: original calls JK.EXE-style jk_logtofile(); no direct analog here.
    stdPlatform_Printf("WARNING: File %s not found!\n", pPath);
}

// @447830
void dwConfFile_Close(dwConfFile* pThis)
{
    if (pThis->pFile)
    {
        dwMain_pHS->fileClose((stdFile_t)pThis->pFile);
    }
}

// @447850
int dwConfFile_ReadLine(dwConfFile* pThis)
{
    if (pThis->pFile)
    {
        const char* pRead;
        pThis->pCursor = pThis->aLine;
        pThis->aLine[0] = '\0';
        do
        {
            pRead = dwMain_pHS->fileGets((stdFile_t)pThis->pFile, pThis->aLine, 0x400);
            if (!pRead)
            {
                pThis->bEof = 1;
            }
            else
            {
                char c;

                pThis->pCursor = pThis->aLine;
                while (*pThis->pCursor && isspace((unsigned char)*pThis->pCursor))
                    pThis->pCursor++;
                c = *pThis->pCursor;
                if (c == '\0' || c == ';' || c == '#')
                {
                    // Blank or comment line: discard and read another.
                    pRead = NULL;
                    pThis->aLine[0] = '\0';
                }
                else
                {
                    size_t len = strlen(pRead);
                    if (pThis->aLine[len - 1] == '\n')
                        pThis->aLine[len - 1] = '\0';
                }
            }
        } while (!pRead && !pThis->bEof);
    }
    return pThis->bEof == 0;
}

// @447910
char* dwConfFile_NextToken(dwConfFile* pThis)
{
    char* pToken = pThis->pCursor;
    if (*pToken == '\"')
    {
        return dwConfFile_NextQuotedToken(pThis);
    }
    // Skip over the token itself...
    while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
        pThis->pCursor++;
    if (*pThis->pCursor)
    {
        // ...terminate it and skip the trailing whitespace.
        *pThis->pCursor = '\0';
        pThis->pCursor++;
        while (*pThis->pCursor && isspace((unsigned char)*pThis->pCursor))
            pThis->pCursor++;
    }
    return pToken;
}

// @447990
void dwConfFile_ParseString(dwConfFile* pThis, dwString* pOut)
{
    char* pSrc = dwConfFile_NextToken(pThis);
    pOut->Assign(pSrc, 0);
}

// @4479b0
// The delimiter is whatever character the cursor currently points at (the
// callers guarantee it's a '"' via NextToken's check); the returned token
// starts just past it.
char* dwConfFile_NextQuotedToken(dwConfFile* pThis)
{
    char* pToken = pThis->pCursor;
    char quoteChar = *pToken;
    if (quoteChar != '\0')
    {
        pToken = pToken + 1;
        pThis->pCursor = pToken;
        while (*pThis->pCursor && *pThis->pCursor != quoteChar)
            pThis->pCursor++;
        // Terminate at the closing quote (or the NUL itself) and skip
        // trailing whitespace.
        *pThis->pCursor = '\0';
        pThis->pCursor++;
        while (*pThis->pCursor && isspace((unsigned char)*pThis->pCursor))
            pThis->pCursor++;
    }
    return pToken;
}

// @447a20
void dwConfFile_ParseQuotedString(dwConfFile* pThis, dwString* pOut)
{
    char* pSrc = dwConfFile_NextQuotedToken(pThis);
    pOut->Assign(pSrc, 0);
}

// @447a40
void dwConfFile_ParseULong(dwConfFile* pThis, uint32_t* pOut)
{
    // Note: original sscanf's "%lu" straight into the caller's 32-bit slot
    // (long == 32-bit on the original x86 target); scan into a temp and
    // narrow so 64-bit hosts don't overwrite 8 bytes.
    unsigned long val;
    if (sscanf(pThis->pCursor, "%lu", &val) == 1)
    {
        *pOut = (uint32_t)val;
        while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
            pThis->pCursor++;
        if (*pThis->pCursor)
        {
            while (isspace((unsigned char)*pThis->pCursor))
            {
                pThis->pCursor++;
                if (!*pThis->pCursor)
                    return;
            }
        }
    }
    else
    {
        *pOut = 0;
    }
}

// @447ad0
void dwConfFile_ParseLong(dwConfFile* pThis, int32_t* pOut)
{
    // Note: 32-bit "%ld" in the original; temp + narrow (see ParseULong).
    long val;
    if (sscanf(pThis->pCursor, "%ld", &val) == 1)
    {
        *pOut = (int32_t)val;
        while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
            pThis->pCursor++;
        if (*pThis->pCursor)
        {
            while (isspace((unsigned char)*pThis->pCursor))
            {
                pThis->pCursor++;
                if (!*pThis->pCursor)
                    return;
            }
        }
    }
    else
    {
        *pOut = 0;
    }
}

// @447b60
void dwConfFile_ParseFloat(dwConfFile* pThis, float* pOut)
{
    if (sscanf(pThis->pCursor, "%f", pOut) == 1)
    {
        while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
            pThis->pCursor++;
        if (*pThis->pCursor)
        {
            while (isspace((unsigned char)*pThis->pCursor))
            {
                pThis->pCursor++;
                if (!*pThis->pCursor)
                    return;
            }
        }
    }
    else
    {
        *pOut = 0.0f;
    }
}

// @447bf0
// Quirk (original): unlike the scalar parsers, on scan failure the output
// rect is left untouched and the cursor is not advanced.
void dwConfFile_ParseRect(dwConfFile* pThis, dwRect* pOut)
{
    int16_t left, top, right, bottom;
    if (sscanf(pThis->pCursor, "%hd %hd %hd %hd", &left, &top, &right, &bottom) == 4)
    {
        // Advance past the four consumed tokens (unrolled in the binary).
        for (int i = 0; i < 4; ++i)
        {
            while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
                pThis->pCursor++;
            while (*pThis->pCursor && isspace((unsigned char)*pThis->pCursor))
                pThis->pCursor++;
        }
        pOut->left = left;
        pOut->top = top;
        pOut->right = right;
        pOut->bottom = bottom;
    }
}

// @447da0
// Quirk (original): output untouched / cursor not advanced on scan failure
// (same as ParseRect).
void dwConfFile_ParsePoint(dwConfFile* pThis, dwPoint* pOut)
{
    int16_t x, y;
    if (sscanf(pThis->pCursor, "%hd %hd", &x, &y) == 2)
    {
        // Advance past the two consumed tokens (unrolled in the binary).
        for (int i = 0; i < 2; ++i)
        {
            while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
                pThis->pCursor++;
            while (*pThis->pCursor && isspace((unsigned char)*pThis->pCursor))
                pThis->pCursor++;
        }
        pOut->x = x;
        pOut->y = y;
    }
}

// @447e90
void dwConfFile_ParseHex(dwConfFile* pThis, uint32_t* pOut)
{
    // Note: 32-bit "%lx" in the original; temp + narrow (see ParseULong).
    unsigned long val;
    if (sscanf(pThis->pCursor, "%lx", &val) == 1)
    {
        *pOut = (uint32_t)val;
        while (*pThis->pCursor && !isspace((unsigned char)*pThis->pCursor))
            pThis->pCursor++;
        if (*pThis->pCursor)
        {
            while (isspace((unsigned char)*pThis->pCursor))
            {
                pThis->pCursor++;
                if (!*pThis->pCursor)
                    return;
            }
        }
    }
    else
    {
        *pOut = 0;
    }
}
