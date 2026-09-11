#include "Dw/dwInits.h"

// DroidWorks "inits" unit (0x411560-0x41237f): VFS / file-resolution layer.
//
// Compiled as C++ (the binary unit carries MSVC EH unwind frames around its
// dwString locals) in procedural style; the entire API keeps C linkage via
// dwInits.h's extern "C" guards.
//
// Boot order (inits_Startup): dwGob_Startup(pHS) installs the GOB-aware file
// ops FIRST; inits then saves those as its "original" fileOpen/fileClose and
// installs inits_HookedFileOpen on top. So the resolution chain for a bare
// filename is:
//   pHS->fileOpen == inits_HookedFileOpen
//     -> ext lookup -> candidate path "base\component\file"
//     -> dwGob_Open (saved pointer): GOB-embedded path? open inside archive
//        : real OS open.
// Paths use '\\' separators like the original binary; the platform layer
// (Linux_stdFileOpen) converts to '/' at the bottom.

#include "Dw/dwGob.h"
#include "Dw/dwPlayer.h" // dwPlayer_name/basePath/profileDir (owner unit)
#include "General/stdFileUtil.h"
#include "stdPlatform.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h> // Note: getcwd replaces GetCurrentDirectoryA

// ------------------------------------------------------------------
// Unit-owned globals
// ------------------------------------------------------------------

// C linkage (declared extern "C" in dwInits.h / used by future C units).
dwString dwCore_workingDir;  // @0x53d8xx: cwd at startup, trailing '\'
dwString dwCore_installPath; // registry InstallPath (empty if == workingDir)
dwString dwCore_sourcePath;  // registry SourcePath (CD), read-only fallback

static stdFile_t (*dwCore_pfnOrigFileOpen)(const char*, const char*);
static int (*dwCore_pfnOrigFileClose)(stdFile_t);

// dwPlayer_name/basePath/profileDir now live in their owner unit (dwPlayer.h,
// P5); this unit reads them for profile-dir resolution like the binary.

// TODO(dw-decomp): temporary cross-unit placeholders — dwString objects need a
// C++ TU, so they park here (precedent: the dwPlayer globals above) instead of
// dwMain.c's placeholder block. Owner: dw core P7 (binary static ctors
// dwCore_RefFileInit etc.); move there when it lands.
extern "C" {
dwString dwCore_workspaceName;   // @0x53d978: workspace droid display name
dwString dwCore_currentRefFile;  // @0x53d968: current reference-room topic file (.plr TOPIC)
}

// The 27-entry extension -> search-path-list table (binary: interleaved
// dwCore_aFileExtNames/aFileExtPaths @0x527ad0/4). MUST stay sorted by
// extension name (inits_LookupExtIndex binary-searches it, case-insensitive).
// Path lists are whitespace-separated components appended to a base path;
// components ending in .GOB resolve inside that archive via dwGob.
typedef struct dwCoreFileExtEntry
{
    const char* pExtName;
    const char* pPathList;
} dwCoreFileExtEntry;

static const dwCoreFileExtEntry dwCore_aFileExtTable[DWINITS_NUM_EXTS] = {
    { "3DO", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "AI",  ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "BBL", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "BMP", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "BRF", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "CMP", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "COG", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "FLC", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "IFC", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "INV", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "JKL", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "KEY", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "LAF", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "LOG", "." },
    { "MAT", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "MIS", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "PLS", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "PUP", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "REC", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "RLE", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "SAN", ". MOVIE" },
    { "SND", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "SPR", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "SUB", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "TPC", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "TXT", ". dwCD.GOB dwHD.GOB dwMin.GOB" },
    { "WAV", ". dwCD.GOB dwHD.GOB dwMin.GOB dwStream.GOB" },
};

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// Append a '\' if the string is nonempty and doesn't already end in a
// separator. Note: also accepts '/' as "already terminated" (POSIX cwd),
// unlike the original which only checked '\\'.
static void inits_EnsureTrailingSlash(dwString* pStr)
{
    if (pStr->length != 0
        && pStr->pBuffer[pStr->length - 1] != '\\'
        && pStr->pBuffer[pStr->length - 1] != '/')
    {
        pStr->Append("\\", 1);
    }
}

// Push-back a freshly heap-allocated dwString(pName) onto pList.
// (The binary inlines this list-append COMDAT at each site.)
static void inits_ListAppendName(dwList* pList, const char* pName)
{
    pList->InsertAfter(pList->pSentinel->pPrev, new dwString(pName, 0));
}

// ------------------------------------------------------------------
// Startup / shutdown
// ------------------------------------------------------------------

int inits_Startup(HostServices* pHS)
{
    // Statics reset (soft-reset rule). Free() is idempotent, so this is a
    // no-op after a clean Shutdown; it replaces the old memset reset (and,
    // unlike it, releases any stale buffer instead of leaking on a
    // double-Startup).
    dwCore_workingDir.Free();
    dwCore_installPath.Free();
    dwCore_sourcePath.Free();
    dwCore_pfnOrigFileOpen = NULL;
    dwCore_pfnOrigFileClose = NULL;

    dwGob_Startup(pHS);

    // The "originals" ARE dwGob's GOB-aware wrappers (see boot-order note).
    dwCore_pfnOrigFileOpen = pHS->fileOpen;
    dwCore_pfnOrigFileClose = pHS->fileClose;
    pHS->fileOpen = inits_HookedFileOpen;

    // Working dir = cwd, trailing '\'s trimmed.
    // Note: original used GetCurrentDirectoryA.
    {
        char aCwd[512];
        if (getcwd(aCwd, sizeof(aCwd))) {
            size_t len = strlen(aCwd);
            while (len != 0 && (aCwd[len - 1] == '\\' || aCwd[len - 1] == '/')) {
                len--;
            }
            dwCore_workingDir.Assign(aCwd, (uint32_t)len);
        }
    }

    // Note: the original read HKLM\Software\Lucas Learning Ltd\
    // Star Wars DroidWorks\1.0 values SourcePath/InstallPath. Adapted to env
    // vars so a repo checkout can point at an extracted install (DW_res/):
    //   OPENJKDF2_DW_INSTALL_PATH  (skipped if == working dir, like the binary)
    //   OPENJKDF2_DW_SOURCE_PATH   (CD image path; read-only fallback)
    {
        const char* pInstall = getenv("OPENJKDF2_DW_INSTALL_PATH");
        const char* pSource = getenv("OPENJKDF2_DW_SOURCE_PATH");
        if (pSource && *pSource) {
            dwCore_sourcePath.AssignCStr(pSource);
        }
        if (pInstall && *pInstall && !dwString_Equals(pInstall, dwCore_workingDir.pBuffer)) {
            dwCore_installPath.AssignCStr(pInstall);
        }
    }

    inits_EnsureTrailingSlash(&dwCore_sourcePath);
    inits_EnsureTrailingSlash(&dwCore_installPath);
    inits_EnsureTrailingSlash(&dwCore_workingDir);

    stdPlatform_Printf("dwInits: Working Directory: %s\n", dwCore_workingDir.pBuffer ? dwCore_workingDir.pBuffer : "");
    stdPlatform_Printf("dwInits: Install Path: %s\n", dwCore_installPath.pBuffer ? dwCore_installPath.pBuffer : "");
    stdPlatform_Printf("dwInits: Source Path: %s\n", dwCore_sourcePath.pBuffer ? dwCore_sourcePath.pBuffer : "");
    return 1;
}

void inits_Shutdown(void)
{
    dwCore_workingDir.Free();
    dwCore_installPath.Free();
    dwCore_sourcePath.Free();
    dwPlayer_basePath.Free();  // binary: inits_Shutdown frees these two dwPlayer globals
    dwPlayer_profileDir.Free();
    dwGob_Shutdown();
}

// ------------------------------------------------------------------
// Resolution + hooked open
// ------------------------------------------------------------------

// HostServices fileOpen replacement. Bare filenames (no directory part) get
// resolved through the ext table; anything with a path passes straight
// through to the GOB-aware open.
stdFile_t inits_HookedFileOpen(const char* pPath, const char* pMode)
{
    char* pFilenamePart = (char*)pPath;
    dwString_FindFilename(&pFilenamePart);
    if (pFilenamePart != pPath) {
        stdFile_t f = dwCore_pfnOrigFileOpen(pPath, pMode);
        if (f) {
            return f;
        }
        // Added: GOB-only fallback. A directory-prefixed path (e.g. the engine's
        // "jkl\static.jkl", or "parts\parts.pls") that is neither a loose disk
        // file nor an explicit "<archive>.GOB\member" path still resolves by its
        // BASENAME through the ext-table search paths — the DW GOB basename index
        // keys "static.jkl" -> its real member "mission\static.jkl" regardless of
        // the caller's directory prefix. The DroidWorks binary relied on such
        // files existing loose on disk; OpenJKDF2 users typically have GOB-only
        // assets, so try the basename before giving up. Read paths only (a write
        // to a prefixed path must stay literal). No recursion: inits_ResolveAndOpen
        // routes to dwCore_pfnOrigFileOpen (dwGob_Open), not back through here.
        if (pMode && (*pMode == 'r')) {
            dwString resolvedAlt;
            f = inits_ResolveAndOpen(pFilenamePart, pMode, &resolvedAlt);
            if (f) {
                return f;
            }
        }
        return 0;
    }

    dwString resolved; // freed by the dtor (explicit Free removed)
    return inits_ResolveAndOpen(pPath, pMode, &resolved);
}

stdFile_t inits_ResolveAndOpen(const char* pFilename, const char* pMode, dwString* pResolvedOut)
{
    stdFile_t ret = 0;
    pResolvedOut->AssignCStr("");
    if (!pFilename || !*pFilename) {
        return 0;
    }

    // Note (faithful quirk): FindExtension leaves the pointer at the string
    // START when there is no dot, and the binary increments unconditionally
    // (its NULL-check is vestigial). So a dotless filename looks up
    // filename+1 as its "extension" — do NOT sanitize this.
    char* pExt = (char*)pFilename;
    dwString_FindExtension(&pExt);
    pExt++;

    int extIdx = inits_LookupExtIndex(pExt);
    if (extIdx < DWINITS_NUM_EXTS) {
        if (dwCore_installPath.length != 0) {
            ret = inits_TryOpenInPaths(pFilename, &dwCore_installPath, pMode, extIdx, pResolvedOut);
        }
        if (ret == 0) {
            if (dwCore_workingDir.length != 0) {
                ret = inits_TryOpenInPaths(pFilename, &dwCore_workingDir, pMode, extIdx, pResolvedOut);
            }
            if (ret == 0 && dwCore_sourcePath.length != 0 && *pMode == 'r') {
                ret = inits_TryOpenInPaths(pFilename, &dwCore_sourcePath, pMode, extIdx, pResolvedOut);
            }
        }
    }
    else {
        // Unknown extension -> player profile directory
        pResolvedOut->AssignString(&dwPlayer_profileDir);
        pResolvedOut->Append(pFilename, 0);
        ret = dwCore_pfnOrigFileOpen(pResolvedOut->pBuffer, pMode);
    }
    return ret;
}

// Binary-search the ext table (case-insensitive). Returns DWINITS_NUM_EXTS
// when pExt is NULL or not present.
int inits_LookupExtIndex(const char* pExt)
{
    if (!pExt) {
        return DWINITS_NUM_EXTS;
    }
    int lo = 0;
    int hi = DWINITS_NUM_EXTS;
    do {
        int mid = (hi + lo) / 2;
        int cmp = dwString_CompareI(pExt, dwCore_aFileExtTable[mid].pExtName);
        if (cmp < 0) {
            hi = mid - 1;
        } else if (cmp > 0) {
            lo = mid + 1;
        } else {
            return mid;
        }
    } while (lo <= hi);
    return DWINITS_NUM_EXTS;
}

// Try "base + component + '\' + filename" for each whitespace-separated
// component in the ext's path list. Returns the first successful open (via
// the GOB-aware saved fileOpen); pTmp holds the winning path.
stdFile_t inits_TryOpenInPaths(const char* pFilename, const dwString* pBasePath, const char* pMode, int extIdx, dwString* pTmp)
{
    stdFile_t ret = 0;
    const char* pSrc = dwCore_aFileExtTable[extIdx].pPathList;

    while (*pSrc != '\0' && ret == 0) {
        while (*pSrc != '\0' && isspace((unsigned char)*pSrc)) {
            pSrc++;
        }
        const char* pEnd = pSrc;
        while (*pEnd != '\0' && !isspace((unsigned char)*pEnd)) {
            pEnd++;
        }
        if (pEnd == pSrc) {
            break;
        }
        pTmp->AssignString(pBasePath);
        pTmp->Append(pSrc, (uint32_t)(pEnd - pSrc));
        pTmp->Append("\\", 1);
        pTmp->Append(pFilename, 0);
        ret = dwCore_pfnOrigFileOpen(pTmp->pBuffer, pMode);
        pSrc = pEnd;
    }
    return ret;
}

int inits_FileExists(const char* pPath)
{
    stdFile_t f = inits_HookedFileOpen(pPath, "r");
    if (f) {
        dwCore_pfnOrigFileClose(f);
    }
    return f != 0;
}

// ------------------------------------------------------------------
// Enumeration
// ------------------------------------------------------------------

// Enumerate all files matching pPattern ("*.EXT") across every search
// location for that extension; results are appended to pOutList as
// heap-allocated dwString* payloads, deduped by name (dir hits only).
void inits_EnumFilesByPattern(const char* pPattern, dwList* pOutList)
{
    char* pExt = (char*)pPattern;
    dwString_FindExtension(&pExt);
    if (*pExt == '.') {
        pExt++;
    }

    int extIdx = inits_LookupExtIndex(pExt);
    if (extIdx >= DWINITS_NUM_EXTS) {
        if (dwPlayer_name.length != 0) {
            inits_FindFilesInDir(&dwPlayer_profileDir, pPattern, pOutList);
        }
        return;
    }

    dwString full;      // freed by the dtors at return (explicit Frees removed)
    dwString component;

    const char* pSrc = dwCore_aFileExtTable[extIdx].pPathList;
    while (*pSrc != '\0') {
        while (*pSrc != '\0' && isspace((unsigned char)*pSrc)) {
            pSrc++;
        }
        const char* pEnd = pSrc;
        while (*pEnd != '\0' && !isspace((unsigned char)*pEnd)) {
            pEnd++;
        }
        if (pEnd == pSrc) {
            break;
        }
        component.Assign(pSrc, (uint32_t)(pEnd - pSrc));

        if (!dwGob_IsGobPath(component.pBuffer)) {
            component.Append("\\", 1);
            if (dwCore_installPath.length != 0) {
                full.AssignString(&dwCore_installPath);
                full.Append(component.pBuffer, component.length);
                inits_FindFilesInDir(&full, pPattern, pOutList);
            }
            if (dwCore_workingDir.length != 0) {
                full.AssignString(&dwCore_workingDir);
                full.Append(component.pBuffer, component.length);
                inits_FindFilesInDir(&full, pPattern, pOutList);
            }
            if (dwCore_sourcePath.length != 0) {
                full.AssignString(&dwCore_sourcePath);
                full.Append(component.pBuffer, component.length);
                inits_FindFilesInDir(&full, pPattern, pOutList);
            }
        } else {
            if (dwCore_installPath.length != 0) {
                full.AssignString(&dwCore_installPath);
                full.Append(component.pBuffer, component.length);
                dwGob_ListFilesByExt(full.pBuffer, pExt, pOutList);
            }
            if (dwCore_workingDir.length != 0) {
                full.AssignString(&dwCore_workingDir);
                full.Append(component.pBuffer, component.length);
                dwGob_ListFilesByExt(full.pBuffer, pExt, pOutList);
            }
            if (dwCore_sourcePath.length != 0) {
                full.AssignString(&dwCore_sourcePath);
                full.Append(component.pBuffer, component.length);
                dwGob_ListFilesByExt(full.pBuffer, pExt, pOutList);
            }
        }
        pSrc = pEnd;
    }
}

void inits_EnumFilesByExt(const char* pExt, dwList* pOutList)
{
    char aPattern[12];
    // Note: the original sprintf'd into a 12-byte stack buffer too; snprintf
    // only differs where sprintf was already UB (ext > 9 chars — never).
    snprintf(aPattern, sizeof(aPattern), "*.%s", pExt);
    inits_EnumFilesByPattern(aPattern, pOutList);
}

// Scan one OS directory with stdFileUtil, appending each nonempty filename
// not already present in pOutList (dedupe via dwString_Equals).
void inits_FindFilesInDir(const dwString* pDir, const char* pPattern, dwList* pOutList)
{
    // Note: the repo stdFileUtil_NewFind supports modes 0-3 only (the binary's
    // DW file enumerator used its own mode 4). Mode 3 = "filter by extension",
    // and it builds the "*.<ext>" glob itself — so pass the bare extension, not
    // the full "*.<ext>" pattern (mode 4 left search->path empty -> FindNext
    // crashed on strrchr(path,'*')).
    if (!pDir || !pDir->pBuffer) {
        return;
    }
    const char* pExt = pPattern;
    const char* pDot = _strrchr((char*)pPattern, '.');
    if (pDot) {
        pExt = pDot + 1;
    }
    stdFileSearch* pSearch = stdFileUtil_NewFind(pDir->pBuffer, 3, pExt);
    if (!pSearch) {
        return;
    }

    stdFileSearchResult result;
    while (stdFileUtil_FindNext(pSearch, &result)) {
        if (result.fpath[0] == '\0') {
            continue;
        }
        dwListNode* pNode = pOutList->pSentinel->pNext;
        while (pNode != pOutList->pSentinel) {
            if (dwString_Equals(((dwString*)pNode->pData)->pBuffer, result.fpath)) {
                break;
            }
            pNode = pNode->pNext;
        }
        if (pNode == pOutList->pSentinel) {
            inits_ListAppendName(pOutList, result.fpath);
        }
    }
    stdFileUtil_DisposeFind(pSearch);
}

// Enumerate subdirectories of the ext's first search location (or the player
// base path for non-table exts). Used for profile enumeration.
// Note (faithful quirk): for table exts the binary appends the ENTIRE
// whitespace-separated path list string to the base, not one component.
void inits_EnumSubdirs(const char* pExt, dwList* pOutList)
{
    dwString base; // freed by the dtor at return (explicit Free removed)

    if (*pExt == '.') {
        pExt++;
    }
    int extIdx = inits_LookupExtIndex(pExt);
    if (extIdx < DWINITS_NUM_EXTS) {
        base.AssignString(&dwCore_installPath);
        if (base.length == 0) {
            base.AssignString(&dwCore_workingDir);
        }
        base.Append(dwCore_aFileExtTable[extIdx].pPathList, 0);
    } else {
        base.AssignString(&dwPlayer_basePath);
    }

    stdFileSearch* pSearch = stdFileUtil_NewFind(base.pBuffer, 2, NULL);
    if (pSearch) {
        stdFileSearchResult result;
        while (stdFileUtil_FindNext(pSearch, &result)) {
            if (result.is_subdirectory
                && !dwString_Equals(result.fpath, ".")
                && !dwString_Equals(result.fpath, "..")
                && result.fpath[0] != '\0')
            {
                inits_ListAppendName(pOutList, result.fpath);
            }
        }
        stdFileUtil_DisposeFind(pSearch);
    }
}

// ------------------------------------------------------------------
// Filesystem mutation (profiles etc.)
// ------------------------------------------------------------------

int inits_DeleteFile(const char* pPath)
{
    return stdFileUtil_DelFile((char*)pPath) != 0;
}

int inits_MakeDir(const char* pExt, const char* pSubdir)
{
    dwString path; // freed by the dtor at return (explicit Free removed)

    int extIdx = inits_LookupExtIndex(pExt);
    if (extIdx < DWINITS_NUM_EXTS) {
        path.AssignString(&dwCore_installPath);
        if (path.length == 0) {
            path.AssignString(&dwCore_workingDir);
        }
        path.Append(dwCore_aFileExtTable[extIdx].pPathList, 0);
    } else {
        path.AssignString(&dwPlayer_basePath);
    }
    path.Append(pSubdir, 0);

    return stdFileUtil_MkDir(path.pBuffer) != 0;
}

// Note (faithful quirk): unlike MakeDir, the table-ext branch does NOT
// prepend installPath/workingDir — the binary builds a relative path.
int inits_RemoveDirTree(const char* pExt, const char* pSubdir)
{
    dwString path; // freed by the dtor at return (explicit Free removed)

    int extIdx = inits_LookupExtIndex(pExt);
    if (extIdx < DWINITS_NUM_EXTS) {
        path.Append(dwCore_aFileExtTable[extIdx].pPathList, 0);
    } else {
        path.AssignString(&dwPlayer_basePath);
    }
    path.Append(pSubdir, 0);

    return stdFileUtil_Deltree(path.pBuffer) != 0;
}
