// dwGob — DroidWorks' transparent GOB-vs-OS-file stdio shim.
//
// Decompiled from DroidWorks.exe, unit range 0x414e70-0x4155a0 (the
// 0x414e70-0x414e9x dwCore_RefFile* static ctors and the 0x4155e0+ dwRef
// control are mis-binned neighbors and are NOT part of this unit).
//
// dwGob_Startup(pHS) first hands the *original* pHS to stdGob_Startup (so the
// stdGob layer keeps using real OS file ops), saves a full copy of *pHS into
// dwGob_baseServices, then overwrites the live HostServices file-op pointers
// with the dwGob_* wrappers below. Every subsequent HostServices file open
// checks the path: if it contains ".GOB" the path is split at its last
// separator into <archive path>\<member name>, the archive is find-or-loaded
// into a 12-slot cache, and the member is opened through stdGob; otherwise the
// saved OS fileOpen is used. Open handles are dwGobFile slots from a 256-entry
// table; each wrapper dispatches on dwGobFile.type (1 = OS file via the saved
// base services, 2 = GOB member via stdGob_File*).
//
// All open/close/list operations were serialized by a Win32 CRITICAL_SECTION
// (dwGob_critSec@0x6b6240); translated here as an SDL mutex (see dwGob_Lock).
//
// Compiled as C++ (the binary unit carries MSVC EH frames around dwString
// locals) in procedural style; the entire API keeps C linkage via dwGob.h's
// extern "C" guards.

#include "Dw/dwGob.h"
#include "Dw/dwString.h"
#include "Dw/dwList.h"

#include <stdlib.h>
#include <stdarg.h>

#include "jk.h"
#include <ctype.h>
// Win95/stdGob.h + General/stdHashtbl.h have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/stdGob.h"
#include "General/stdHashtbl.h"
}

#include <SDL3/SDL.h> // Note: SDL_Mutex replaces the original Win32 CRITICAL_SECTION (desktop-only unit)

#ifdef STDGOB_COMPACT_ENTRIES
// dwGob_ListFilesByExt enumerates resident GOB entry names; the compact-entry
// option (retro targets) strips them. src/Dw is desktop-only, so this should
// never trip.
#error "dwGob requires resident GOB entry names (STDGOB_COMPACT_ENTRIES unsupported)"
#endif

#define DWGOB_MAX_HANDLES     (256)  // dwGob_aHandles@0x53db10: 0x300 dwords = 256 * sizeof(dwGobFile)
#define DWGOB_MAX_GOBS        (12)   // dwGob_apLoadedGobs@0x53e710
#define DWGOB_GOB_NUM_HANDLES (0x40) // per-archive stdGob handle count passed to stdGob_Load
#define DWGOB_SCRATCH_LEN     (0x104)

// Module statics (all reset in dwGob_Startup; soft-reset rule).
static HostServices dwGob_baseServices;              // @0x53da70: copy of the pre-patch HostServices
static HostServices* dwGob_pBaseServices = NULL;     // @0x53da00
static dwGobFile dwGob_aHandles[DWGOB_MAX_HANDLES];  // @0x53db10
static Gob* dwGob_apLoadedGobs[DWGOB_MAX_GOBS];      // @0x53e710
static tHashTable* dwGob_apBasenameHash[DWGOB_MAX_GOBS]; // Note: added — see dwGob_BuildBasenameIndex
static char dwGob_scratchBuf[DWGOB_SCRATCH_LEN];     // shared path/printf staging buffer
static HostServices* dwGob_pInstalledHS = NULL;      // Note: added — which HostServices we patched (for Shutdown restore)
static int dwGob_bInstalled = 0;                     // Note: added — guards double-install on soft reset
static SDL_Mutex* dwGob_mtx = NULL;                  // Note: replaces dwGob_critSec@0x6b6240; lazily created, kept across soft resets

static tHashTable* dwGob_BuildBasenameIndex(Gob* pGob);
static const char* dwGob_FindMemberPath(Gob* pGob, const char* pMember);

// Note: the original never enters its wrappers before InitializeCriticalSection;
// guard on NULL so pre-Startup calls stay harmless.
static void dwGob_Lock(void)
{
    if (dwGob_mtx)
        SDL_LockMutex(dwGob_mtx);
}

static void dwGob_Unlock(void)
{
    if (dwGob_mtx)
        SDL_UnlockMutex(dwGob_mtx);
}

// Note: the binary installs a CRT `return 0` stub (FUN_0050dc80) into
// HostServices.fileGetws — DroidWorks deliberately disables wide-char gets.
static const char16_t* dwGob_GetwsStub(stdFile_t fhand, char16_t *pStr, size_t size)
{
    return NULL;
}

// @0x414ea0. Note: case-sensitive ".GOB" substring test, as in the binary
// (string @0x527ecc); lowercase ".gob" paths fall through to the OS branch.
int dwGob_IsGobPath(const char *pPath)
{
    return _strstr(pPath, ".GOB") != NULL;
}

// @0x414ec0
int dwGob_Startup(HostServices *pHS)
{
    // Note: added — a re-Startup without Shutdown (soft-reset loop) would
    // otherwise snapshot our own wrappers into dwGob_baseServices and recurse.
    if (dwGob_bInstalled)
        dwGob_Shutdown();

    // Statics reset (the binary also zeroes the handle table + archive cache here)
    _memset(dwGob_aHandles, 0, sizeof(dwGob_aHandles));
    _memset(dwGob_apLoadedGobs, 0, sizeof(dwGob_apLoadedGobs));
    _memset(dwGob_apBasenameHash, 0, sizeof(dwGob_apBasenameHash));
    _memset(&dwGob_baseServices, 0, sizeof(dwGob_baseServices));
    _memset(dwGob_scratchBuf, 0, sizeof(dwGob_scratchBuf));
    dwGob_pBaseServices = NULL;
    dwGob_pInstalledHS = NULL;

    if (!dwGob_mtx)
        dwGob_mtx = SDL_CreateMutex(); // Note: replaces InitializeCriticalSection (done outside this fn in the binary)

    // stdGob snapshots *pHS BEFORE we patch it, so the GOB layer itself
    // always uses the real OS file ops (same ordering as the binary).
    stdGob_Startup(pHS);

    _memcpy(&dwGob_baseServices, pHS, sizeof(HostServices)); // binary copies 0x1c dwords = the whole struct
    dwGob_pBaseServices = &dwGob_baseServices;
    dwGob_pInstalledHS = pHS;

    // Install the wrappers. Signatures match src/types.h HostServices members
    // exactly (stdFile_t handles are pointer-sized; a dwGobFile* is passed
    // through them). Mapping (original -> repo member):
    //   dwGob_Open   -> fileOpen    stdFile_t (*)(const char*, const char*)
    //   dwGob_Close  -> fileClose   int (*)(stdFile_t)
    //   dwGob_Read   -> fileRead    size_t (*)(stdFile_t, void*, size_t)
    //   dwGob_Write  -> fileWrite   size_t (*)(stdFile_t, void*, size_t)
    //   dwGob_Eof    -> fileEof     int (*)(stdFile_t)
    //   dwGob_Tell   -> ftell       int (*)(stdFile_t)
    //   dwGob_Seek   -> fseek       int (*)(stdFile_t, int, int)
    //   dwGob_Printf -> filePrintf  int (*)(stdFile_t, const char*, ...)
    //   dwGob_Gets   -> fileGets    const char* (*)(stdFile_t, char*, size_t)
    //   (stub)       -> fileGetws   const char16_t* (*)(stdFile_t, char16_t*, size_t)
    // Note: like the binary, fileSize is NOT wrapped — it keeps pointing at the
    // OS implementation and would misbehave on a GOB-backed handle (DW never
    // calls it on one).
    pHS->fileOpen = dwGob_Open;
    pHS->fileClose = dwGob_Close;
    pHS->fileRead = dwGob_Read;
    pHS->fileWrite = dwGob_Write;
    pHS->fileEof = dwGob_Eof;
    pHS->ftell = dwGob_Tell;
    pHS->fseek = dwGob_Seek;
    pHS->filePrintf = dwGob_Printf;
    pHS->fileGets = dwGob_Gets;
    pHS->fileGetws = dwGob_GetwsStub;

    dwGob_bInstalled = 1;
    return 1;
}

// @0x414f50
void dwGob_Shutdown(void)
{
    if (!dwGob_bInstalled)
        return;

    dwGob_Lock();
    for (int i = 0; i < DWGOB_MAX_GOBS; i++)
    {
        if (dwGob_apLoadedGobs[i])
        {
            stdGob_Free(dwGob_apLoadedGobs[i]);
            dwGob_apLoadedGobs[i] = NULL; // Note: binary leaves the slots stale; cleared for soft-reset hygiene
        }
        if (dwGob_apBasenameHash[i])
        {
            stdHashtbl_Free(dwGob_apBasenameHash[i]);
            dwGob_apBasenameHash[i] = NULL;
        }
    }
    stdGob_Shutdown();

    // Note: added — the binary never restores the patched HostServices (the
    // process exits); we restore the saved ops so a soft reset gets a clean
    // table back.
    if (dwGob_pInstalledHS)
    {
        dwGob_pInstalledHS->fileOpen = dwGob_baseServices.fileOpen;
        dwGob_pInstalledHS->fileClose = dwGob_baseServices.fileClose;
        dwGob_pInstalledHS->fileRead = dwGob_baseServices.fileRead;
        dwGob_pInstalledHS->fileWrite = dwGob_baseServices.fileWrite;
        dwGob_pInstalledHS->fileEof = dwGob_baseServices.fileEof;
        dwGob_pInstalledHS->ftell = dwGob_baseServices.ftell;
        dwGob_pInstalledHS->fseek = dwGob_baseServices.fseek;
        dwGob_pInstalledHS->filePrintf = dwGob_baseServices.filePrintf;
        dwGob_pInstalledHS->fileGets = dwGob_baseServices.fileGets;
        dwGob_pInstalledHS->fileGetws = dwGob_baseServices.fileGetws;
        dwGob_pInstalledHS = NULL;
    }
    dwGob_bInstalled = 0;
    dwGob_Unlock();
}

// @0x414f90 — append a dwString for every member of archive pGobPath whose
// extension case-insensitively equals pExt (no dot), skipping names already
// in the list (inits_EnumFilesByPattern calls this once per search path, all
// appending into one list). Takes the dwList handle directly now — the old
// dwList** parameter reflected the previous node-is-list C view.
void dwGob_ListFilesByExt(char *pGobPath, char *pExt, dwList *pList)
{
    dwGob_Lock();
    Gob* pGob = dwGob_LoadArchive(pGobPath);
    if (pGob && pGob->entries)
    {
        // Note: the binary walks the gob's directory hashtable (Gob+0x8c,
        // {name -> entry} chains); we enumerate the same name set from the
        // resident entry array instead of depending on stdHashTable internals.
        for (uint32_t i = 0; i < pGob->numFiles; i++)
        {
            char* pName = pGob->entries[i].fname;
            char* pDot = _strrchr(pName, '.');
            if (!pDot || __strcmpi(pDot + 1, pExt) != 0)
                continue;

            // Return the BASENAME, matching the binary. The binary's
            // dwGob_ListFilesByExt walks the DW basename-index hashtable
            // (Gob+0x8c, keyed by lowercased entry basename), so it yields
            // "parts.pls" — NOT the full member path "parts\parts.pls". Callers
            // reopen the bare name, which inits_HookedFileOpen then resolves
            // through the ext-table (". dwCD.GOB dwHD.GOB ..."), i.e. it tries
            // "<base>\dwHD.GOB\parts.pls" -> dwGob basename index -> the member.
            // Our repo stdGob keys FULL paths (pGob->entries[i].fname carries the
            // "parts\" prefix), so we must strip to the basename here or the
            // directory prefix makes inits_HookedFileOpen bail past the ext-table
            // (that was the "parts\parts.pls not found" / empty-build-menu bug).
            char* pBase = pName;
            dwString_FindFilename(&pBase); // basename (drop the member subdir)

            // Skip if an equal (case-insensitive) name is already listed
            dwListNode* pSentinel = pList->pSentinel;
            dwListNode* pNode = pSentinel->pNext;
            while (pNode != pSentinel)
            {
                if (dwString_Equals(((dwString*)pNode->pData)->pBuffer, pBase))
                    break;
                pNode = pNode->pNext;
            }
            if (pNode != pSentinel)
                continue;

            // binary: operator new(0xc) + ctor, then the tail insert (before
            // the sentinel) that dwList::InsertAfter implements.
            dwString* pStr = new dwString(pBase, 0);
            pList->InsertAfter(pSentinel->pPrev, pStr);
        }
    }
    dwGob_Unlock();
}

// @0x415130 — the installed HostServices.fileOpen
stdFile_t dwGob_Open(const char *pPath, const char *pMode)
{
    dwGobFile* pFile;

    dwGob_Lock();
    //stdPlatform_Printf("DEBUG: dwGob_Open %s %s\n", pPath, pMode);
    if (dwGob_IsGobPath(pPath))
        pFile = dwGob_OpenFromGob(pPath, pMode);
    else
        pFile = dwGob_OpenOsFile(pPath, pMode);
    dwGob_Unlock();
    return (stdFile_t)pFile;
}

// @0x415190 — split "<...>\foo.GOB\member" at the LAST separator, mount the
// archive, open the member through stdGob. Caller holds the lock.
dwGobFile* dwGob_OpenFromGob(const char *pPath, const char *pMode)
{
    _strncpy(dwGob_scratchBuf, pPath, DWGOB_SCRATCH_LEN - 1); // binary: plain strcpy into the scratch buffer
    dwGob_scratchBuf[DWGOB_SCRATCH_LEN - 1] = 0;

    char* pSlash = _strrchr(dwGob_scratchBuf, '\\');
    if (!pSlash)
        pSlash = _strrchr(dwGob_scratchBuf, '/'); // Note: added — host paths use '/' on POSIX; binary only splits on '\\'
    if (!pSlash)
        return NULL;
    *pSlash = 0; // scratch = archive path, pSlash+1 = member name

    Gob* pGob = dwGob_LoadArchive(dwGob_scratchBuf);
    if (!pGob)
        return NULL;

    // Bare member names resolve through the DW basename index (see
    // dwGob_BuildBasenameIndex); fall back to the literal name so
    // full in-archive paths keep working too.
    const char* pFullName = dwGob_FindMemberPath(pGob, pSlash + 1);
    GobFileHandle* pHandle = stdGob_FileOpen(pGob, pFullName ? pFullName : pSlash + 1);
    if (!pHandle)
        return NULL;

    dwGobFile* pFile = dwGob_AllocHandle();
    if (!pFile)
        return NULL; // Note: like the binary, the stdGob handle is leaked when the slot table is full

    // Text mode iff the mode string has no 'b' (binary: strchr(pMode, 'b'))
    pFile->bTextMode = (_strchr((char*)pMode, 'b') == NULL) ? 1 : 0;
    pFile->type = DWGOB_TYPE_GOB;
    pFile->pBacking = pHandle;
    return pFile;
}

// @0x415240 — plain OS file through the saved base services. Caller holds the lock.
dwGobFile* dwGob_OpenOsFile(const char *pPath, const char *pMode)
{
    stdFile_t fhand = dwGob_pBaseServices->fileOpen(pPath, pMode);
    if (!fhand)
        return NULL;

    dwGobFile* pFile = dwGob_AllocHandle();
    if (!pFile)
    {
        dwGob_pBaseServices->fileClose(fhand);
        return NULL;
    }
    pFile->pBacking = (void*)fhand;
    pFile->type = DWGOB_TYPE_OSFILE;
    // Note: like the binary, bTextMode is not set on the OS path (it is only
    // ever read for DWGOB_TYPE_GOB handles, in dwGob_Gets).
    return pFile;
}

// @0x415290 — find-or-load an archive in the 12-slot cache. Case-SENSITIVE
// strcmp against the loaded gob's fpath, as in the binary. Caller holds the lock.
// DW's stdGob fork keys each archive's directory hashtable by entry BASENAME
// (stdGob_LoadEntry@502740: name after the last '\', first entry wins) and
// lowercases lookups (stdGob_FileOpen@502af0 via the tolower helper @506770).
// That's how bare filenames like "items.inv" resolve to "misc\items.inv"
// inside a GOB. The repo's stdGob hashes FULL paths instead, so dwGob layers
// the basename index here rather than touching shared engine code:
// basename -> full entry fname, then stdGob_FileOpen with the full path.
static tHashTable* dwGob_BuildBasenameIndex(Gob* pGob)
{
    tHashTable* pHash = stdHashtbl_New(0x400); // DW: fixed 0x400 buckets per archive
    if (!pHash)
        return NULL;
    for (uint32_t i = 0; i < pGob->numFiles; i++)
    {
        char* pName = pGob->entries[i].fname;
        char* pBase = pName;
        for (char* p = pName; *p; p++) {
            if (*p == '\\' || *p == '/')
                pBase = p + 1;
        }
        if (!stdHashtbl_Find(pHash, pBase))
            stdHashtbl_Add(pHash, pBase, pGob->entries[i].fname);
    }
    return pHash;
}

// Resolve a bare member name to the archive's full entry path (or NULL).
// Query lowercased like DW's stdGob_FileOpen; GOB entry names are lowercase
// on disk.
static const char* dwGob_FindMemberPath(Gob* pGob, const char* pMember)
{
    tHashTable* pHash = NULL;
    for (int i = 0; i < DWGOB_MAX_GOBS; i++)
    {
        if (dwGob_apLoadedGobs[i] == pGob) {
            pHash = dwGob_apBasenameHash[i];
            break;
        }
    }
    if (!pHash)
        return NULL;

    char aLower[128];
    int n = 0;
    for (; pMember[n] && n < 127; n++)
        aLower[n] = (char)tolower((unsigned char)pMember[n]);
    aLower[n] = 0;
    return (const char*)stdHashtbl_Find(pHash, aLower);
}

Gob* dwGob_LoadArchive(char *pPath)
{
    for (int i = 0; i < DWGOB_MAX_GOBS; i++)
    {
        if (!dwGob_apLoadedGobs[i])
        {
            Gob* pGob = stdGob_Load(pPath, DWGOB_GOB_NUM_HANDLES, 0);
            if (!pGob)
                return NULL;
            dwGob_apLoadedGobs[i] = pGob;
            dwGob_apBasenameHash[i] = dwGob_BuildBasenameIndex(pGob);
            return pGob;
        }
        if (_strcmp(pPath, dwGob_apLoadedGobs[i]->fpath) == 0)
            return dwGob_apLoadedGobs[i];
    }
    return NULL; // cache full
}

// @0x415320 — first free slot (type == 0); the caller stamps type/pBacking.
// Only called with the lock held (dwGob_Open paths), as in the binary.
dwGobFile* dwGob_AllocHandle(void)
{
    for (int i = 0; i < DWGOB_MAX_HANDLES; i++)
    {
        if (dwGob_aHandles[i].type == DWGOB_TYPE_FREE)
            return &dwGob_aHandles[i];
    }
    return NULL;
}

// @0x415350 — the installed HostServices.fileClose
int dwGob_Close(stdFile_t fhand)
{
    dwGobFile* pFile = (dwGobFile*)fhand;
    int result = -1;

    dwGob_Lock();
    if (pFile->type == DWGOB_TYPE_OSFILE)
    {
        pFile->type = DWGOB_TYPE_FREE;
        result = dwGob_pBaseServices->fileClose((stdFile_t)pFile->pBacking);
    }
    else if (pFile->type == DWGOB_TYPE_GOB)
    {
        pFile->type = DWGOB_TYPE_FREE;
        stdGob_FileClose((GobFileHandle*)pFile->pBacking); // Note: repo stdGob_FileClose returns void; binary also forced result 0 here
        result = 0;
    }
    dwGob_Unlock();
    return result;
}

// @0x4153c0 — the installed HostServices.fileEof
int dwGob_Eof(stdFile_t fhand)
{
    dwGobFile* pFile = (dwGobFile*)fhand;

    if (pFile->type == DWGOB_TYPE_OSFILE)
        return dwGob_pBaseServices->fileEof((stdFile_t)pFile->pBacking);
    if (pFile->type == DWGOB_TYPE_GOB)
        return (int)stdGob_FileEOF((GobFileHandle*)pFile->pBacking);
    return 0; // Note: return value is undefined in the binary for a stale handle
}

// @0x415400 — the installed HostServices.ftell
int dwGob_Tell(stdFile_t fhand)
{
    dwGobFile* pFile = (dwGobFile*)fhand;

    if (pFile->type == DWGOB_TYPE_OSFILE)
        return dwGob_pBaseServices->ftell((stdFile_t)pFile->pBacking);
    if (pFile->type == DWGOB_TYPE_GOB)
        return (int)stdGob_FileTell((GobFileHandle*)pFile->pBacking);
    return 0;
}

// @0x415430 — the installed HostServices.fseek. stdio convention: 0 on
// success, -1 on failure (stdGob_FileSeek returns nonzero on success).
int dwGob_Seek(stdFile_t fhand, int offset, int origin)
{
    dwGobFile* pFile = (dwGobFile*)fhand;

    if (pFile->type == DWGOB_TYPE_OSFILE)
        return dwGob_pBaseServices->fseek((stdFile_t)pFile->pBacking, offset, origin);
    if (pFile->type == DWGOB_TYPE_GOB)
    {
        if (stdGob_FileSeek((GobFileHandle*)pFile->pBacking, offset, origin))
            return 0;
    }
    return -1;
}

// @0x415490 — the installed HostServices.fileRead
size_t dwGob_Read(stdFile_t fhand, void *pDst, size_t size)
{
    dwGobFile* pFile = (dwGobFile*)fhand;

    if (pFile->type == DWGOB_TYPE_OSFILE)
        return dwGob_pBaseServices->fileRead((stdFile_t)pFile->pBacking, pDst, size);
    if (pFile->type == DWGOB_TYPE_GOB)
        return stdGob_FileRead((GobFileHandle*)pFile->pBacking, pDst, (uint32_t)size); // Note: repo stdGob_FileRead takes uint32_t sizes
    return 0;
}

// @0x4154e0 — the installed HostServices.fileGets. For text-mode GOB opens,
// a trailing "\r\n" is rewritten to "\n" (CRT text-translation emulation;
// stdGob reads raw bytes).
const char* dwGob_Gets(stdFile_t fhand, char *pStr, size_t size)
{
    dwGobFile* pFile = (dwGobFile*)fhand;

    if (pFile->type == DWGOB_TYPE_OSFILE)
        return dwGob_pBaseServices->fileGets((stdFile_t)pFile->pBacking, pStr, size);
    if (pFile->type != DWGOB_TYPE_GOB)
        return NULL;

    char* pRet = (char*)stdGob_FileGets((GobFileHandle*)pFile->pBacking, pStr, (unsigned int)size);
    if (pRet && pFile->bTextMode)
    {
        size_t len = _strlen(pRet);
        // Note: added len >= 2 guard; the binary indexes pRet[len-2] unchecked
        if (len >= 2 && pRet[len - 2] == '\r' && pRet[len - 1] == '\n')
        {
            pRet[len - 2] = '\n';
            pRet[len - 1] = 0;
        }
    }
    return pRet;
}

// @0x415570 — the installed HostServices.fileWrite. GOB members are
// read-only: writes only go through for OS-file handles, else 0.
size_t dwGob_Write(stdFile_t fhand, void *pSrc, size_t size)
{
    dwGobFile* pFile = (dwGobFile*)fhand;

    if (pFile->type == DWGOB_TYPE_OSFILE)
        return dwGob_pBaseServices->fileWrite((stdFile_t)pFile->pBacking, pSrc, size);
    return 0;
}

// @0x4155a0 — the installed HostServices.filePrintf: format into the shared
// scratch buffer, then dwGob_Write. Always returns 0, as in the binary.
int dwGob_Printf(stdFile_t fhand, const char *pFmt, ...)
{
    va_list args;

    va_start(args, pFmt);
    int len = __vsnprintf(dwGob_scratchBuf, DWGOB_SCRATCH_LEN, pFmt, args);
    va_end(args);

    // Note: added — MSVC _vsnprintf returns -1 on truncation and the binary
    // passed that straight to write as a huge size_t; clamp to the buffer.
    if (len < 0 || len > DWGOB_SCRATCH_LEN - 1)
        len = DWGOB_SCRATCH_LEN - 1;

    dwGob_Write(fhand, dwGob_scratchBuf, (size_t)len);
    return 0;
}
