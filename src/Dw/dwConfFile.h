#ifndef _DWCONFFILE_H
#define _DWCONFFILE_H

// dwConfFile — token/keyword config-file reader used by the DW GUI factories.
// DroidWorks.exe unit range: 0x4477c0-0x447f1x (13 functions).
//
// Implemented in dwConfFile.cpp (compiled as C++: the parse-out functions
// call dwString::Assign, and the binary's unit is __thiscall C++), but the
// whole surface keeps C linkage so C units can still drive it — dwString
// crosses the boundary as an opaque pointer (see dwString.h's C view).

#include "Dw/dwTypes.h"
#include "Dw/dwString.h"
#include "Dw/dwRect.h" // dwRect / dwPoint (short-LTRB rect + short point)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dwConfFile
{
    void* pFile;       // 0x000: stdFile_t from dwMain_pHS->fileOpen (NULL when closed/failed)
    int nFileLen;      // 0x004: ftell result right after open
    char* pCursor;     // 0x008: parse cursor into aLine
    char aLine[0x400]; // 0x00c: current logical line
    uint8_t bEof;      // 0x40c: set when fileGets returns NULL (also 1 before a successful Open)
} dwConfFile; // sizeof 0x40d in the binary (0x410 with padding)

void dwConfFile_Open(dwConfFile* pThis, const char* pPath);                // @4477c0
void dwConfFile_Close(dwConfFile* pThis);                                  // @447830
int dwConfFile_ReadLine(dwConfFile* pThis);                                // @447850: fetch next non-blank/comment line; returns !bEof
char* dwConfFile_NextToken(dwConfFile* pThis);                             // @447910: next whitespace- or quote-delimited token
void dwConfFile_ParseString(dwConfFile* pThis, dwString* pOut);            // @447990: NextToken -> dwString
char* dwConfFile_NextQuotedToken(dwConfFile* pThis);                       // @4479b0: quote-delimited token (delimiter = current char)
void dwConfFile_ParseQuotedString(dwConfFile* pThis, dwString* pOut);      // @447a20: NextQuotedToken -> dwString
void dwConfFile_ParseULong(dwConfFile* pThis, uint32_t* pOut);             // @447a40: "%lu"; 0 on scan failure
void dwConfFile_ParseLong(dwConfFile* pThis, int32_t* pOut);               // @447ad0: "%ld"; 0 on scan failure
void dwConfFile_ParseFloat(dwConfFile* pThis, float* pOut);                // @447b60: "%f"; 0 on scan failure
void dwConfFile_ParseRect(dwConfFile* pThis, dwRect* pOut);                // @447bf0: "%hd %hd %hd %hd" -> LTRB; untouched on failure
void dwConfFile_ParsePoint(dwConfFile* pThis, dwPoint* pOut);              // @447da0: "%hd %hd" -> x,y; untouched on failure
void dwConfFile_ParseHex(dwConfFile* pThis, uint32_t* pOut);               // @447e90: "%lx"; 0 on scan failure

#ifdef __cplusplus
}
#endif

#endif // _DWCONFFILE_H
