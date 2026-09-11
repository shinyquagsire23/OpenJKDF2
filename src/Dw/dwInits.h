#ifndef _DWINITS_H
#define _DWINITS_H

// DroidWorks "inits" unit (0x411560-0x41237f): the DW VFS / file-resolution
// layer. Installs a hooked HostServices fileOpen that maps bare filenames to
// their real location via a 27-entry extension->searchpath table, searching
// installPath/workingDir/sourcePath base dirs x {plain dirs, GOB archives}.
// Extensions not in the table resolve into the player profile directory.
// See DW/DECOMP_PROGRESS.md.
//
// Implemented in dwInits.cpp (compiled as C++: the unit has MSVC EH frames
// around dwString locals in the binary), but the whole surface keeps C
// linkage — the HostServices fileOpen pointer install and future C callers
// (dwMain) depend on it. dwString/dwList cross the C boundary as opaque
// pointers only.

#include "Dw/dwTypes.h"
#include "Dw/dwString.h" // dual-language: class for C++, opaque typedef for C

#ifdef __cplusplus
#include "Dw/dwList.h"
#else
typedef struct dwList dwList; // C view: opaque forward decl (dwList.h is C++-only)
#endif

#ifdef __cplusplus
extern "C" {
#endif

int  inits_Startup(HostServices* pHS);              // hooks pHS->fileOpen (after dwGob_Startup)
void inits_Shutdown(void);

stdFile_t inits_HookedFileOpen(const char* pPath, const char* pMode);
stdFile_t inits_ResolveAndOpen(const char* pFilename, const char* pMode, dwString* pResolvedOut);
int  inits_LookupExtIndex(const char* pExt);        // 27 (DWINITS_NUM_EXTS) = not found
stdFile_t inits_TryOpenInPaths(const char* pFilename, const dwString* pBasePath, const char* pMode, int extIdx, dwString* pTmp);

void inits_EnumFilesByPattern(const char* pPattern, dwList* pOutList); // pattern "*.EXT"
void inits_EnumFilesByExt(const char* pExt, dwList* pOutList);
void inits_FindFilesInDir(const dwString* pDir, const char* pPattern, dwList* pOutList);
void inits_EnumSubdirs(const char* pExt, dwList* pOutList);

int  inits_DeleteFile(const char* pPath);
int  inits_MakeDir(const char* pExt, const char* pSubdir);
int  inits_RemoveDirTree(const char* pExt, const char* pSubdir);
int  inits_FileExists(const char* pPath);

#define DWINITS_NUM_EXTS (27)

// Unit-owned globals (base search paths; dwString values — opaque to C)
extern dwString dwCore_workingDir;
extern dwString dwCore_installPath;
extern dwString dwCore_sourcePath;

#ifdef __cplusplus
}
#endif

#endif // _DWINITS_H
