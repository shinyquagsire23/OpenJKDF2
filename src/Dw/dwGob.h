#ifndef _DWGOB_H
#define _DWGOB_H

// dwGob (DroidWorks.exe 0x414e70-0x4155a0): transparent GOB-archive vs OS-file
// I/O shim. dwGob_Startup saves the HostServices OS file ops and installs the
// dwGob_* wrappers in their place, so ALL HostServices file I/O transparently
// resolves into mounted GOB archives ("...\foo.GOB\member" paths) or plain OS
// files. See DW/DECOMP_PROGRESS.md (P1) and the unit plate in Ghidra.

#include "Dw/dwTypes.h"

// C view of the C++ dwList class (Dw/dwList.h): opaque forward decl only —
// dwGob.cpp includes the real header.
typedef struct dwList dwList;
typedef struct Gob Gob; // Win95/stdGob.h

// Implemented in dwGob.cpp (compiled as C++: the unit has MSVC EH frames
// around dwString locals in the binary), but the whole surface keeps C
// linkage — dwInits.cpp and future C callers both consume these.
#ifdef __cplusplus
extern "C" {
#endif

// Per-open-file handle, one of 256 slots in dwGob_aHandles.
// /DW struct dwGobFile (0xc): {int type; byte bTextMode; void* pBacking}.
// Note: pBacking is pointer-sized; on 64-bit it holds a GobFileHandle*
// (type 2) or the base HostServices stdFile_t (type 1) unmodified.
typedef struct dwGobFile
{
    int32_t type;       // DWGOB_TYPE_*; 0 = free slot
    uint8_t bTextMode;  // mode string had no 'b' (GOB opens only): Gets converts trailing CRLF -> LF
    void* pBacking;     // type 1: stdFile_t from the saved OS fileOpen; type 2: GobFileHandle*
} dwGobFile;

enum
{
    DWGOB_TYPE_FREE   = 0,
    DWGOB_TYPE_OSFILE = 1,
    DWGOB_TYPE_GOB    = 2,
};

int  dwGob_IsGobPath(const char *pPath);
int  dwGob_Startup(HostServices *pHS);
void dwGob_Shutdown(void);
void dwGob_ListFilesByExt(char *pGobPath, char *pExt, dwList *pList);

// HostServices wrapper entry points (installed by dwGob_Startup). The
// stdFile_t values they exchange are really dwGobFile* handles.
stdFile_t dwGob_Open(const char *pPath, const char *pMode);          // -> HostServices.fileOpen
int dwGob_Close(stdFile_t fhand);                                    // -> HostServices.fileClose
size_t dwGob_Read(stdFile_t fhand, void *pDst, size_t size);         // -> HostServices.fileRead
const char* dwGob_Gets(stdFile_t fhand, char *pStr, size_t size);    // -> HostServices.fileGets
size_t dwGob_Write(stdFile_t fhand, void *pSrc, size_t size);        // -> HostServices.fileWrite
int dwGob_Eof(stdFile_t fhand);                                      // -> HostServices.fileEof
int dwGob_Tell(stdFile_t fhand);                                     // -> HostServices.ftell
int dwGob_Seek(stdFile_t fhand, int offset, int origin);             // -> HostServices.fseek
int dwGob_Printf(stdFile_t fhand, const char *pFmt, ...);            // -> HostServices.filePrintf

// Internals (unit-local in the binary, exposed for cross-unit use/debugging).
dwGobFile* dwGob_OpenFromGob(const char *pPath, const char *pMode);
dwGobFile* dwGob_OpenOsFile(const char *pPath, const char *pMode);
Gob* dwGob_LoadArchive(char *pPath);
dwGobFile* dwGob_AllocHandle(void);

#ifdef __cplusplus
}
#endif

#endif // _DWGOB_H
