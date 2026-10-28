#include "stdFileUtil.h"

#include "stdPlatform.h"
#include "General/stdFnames.h"
#include "General/stdString.h"
#ifdef TARGET_DREAMCAST
#include "Platform/Dreamcast/dcStorage.h" // Added: asset-dir listing routes to /cd
#endif
#include "jk.h"

#ifdef PLATFORM_POSIX
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <dirent.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#ifndef _WIN32
#ifndef TARGET_RETRO_HOMEBREW
#include <ftw.h>
#endif
#endif

#include "external/fcaseopen/fcaseopen.h"
#endif

#ifdef TARGET_RETRO_HOMEBREW
#include <errno.h>
#endif

#if defined(PLATFORM_POSIX) && !defined(WIN32)
// Added: build a complete search pattern or fail, rather than storing a
// truncated directory/filter in the fixed-size legacy search structure.
static int stdFileUtil_PrepareSearchPath(char* pOut, size_t outSize,
    const char* pPath, int mode, const char* pFilter)
{
    char aDirectory[sizeof(((stdFileSearch*)0)->path)];
    const char* pExtension = "*";
    size_t pathLen;
    int written;

    if (!pOut || !outSize) return 0;
    pOut[0] = 0;
    if (!pPath || mode < 0 || mode > 3) return 0;
    if (mode == 3) {
        if (!pFilter) return 0;
        pExtension = *pFilter == '.' ? pFilter + 1 : pFilter;
        if (strpbrk(pExtension, "/\\")
            || (strchr(pExtension, '*') && strcmp(pExtension, "*"))) return 0;
    }
    if (strlen(pExtension) >= outSize) return 0;
    pathLen = strlen(pPath);
    if (pathLen >= sizeof(aDirectory)) return 0;

    // Added: an empty directory means the current directory. Normalize the
    // separators before case correction, and keep an absolute root intact.
    if (!pathLen) {
        strcpy(aDirectory, ".");
        pathLen = 1;
    }
    else {
        memcpy(aDirectory, pPath, pathLen + 1);
    }
    for (size_t i = 0; i < pathLen; ++i) {
        if (aDirectory[i] == '\\') aDirectory[i] = '/';
    }
    while (pathLen > 1 && aDirectory[pathLen - 1] == '/') {
        aDirectory[--pathLen] = 0;
    }

#ifdef FS_POSIX
    // Added: preserve stdFnames_MakePath's existing case correction without
    // letting its path concatenation truncate the search pattern.
    char aCasedDirectory[sizeof(aDirectory) + 16];
    if (casepath(aDirectory, aCasedDirectory)) {
        const char* pCased = aCasedDirectory;
        if (pCased[0] == '.' && pCased[1] == '/') pCased += 2;
        pathLen = strlen(pCased);
        if (!pathLen || pathLen >= sizeof(aDirectory)) return 0;
        memcpy(aDirectory, pCased, pathLen + 1);
    }
#endif

    written = snprintf(pOut, outSize, "%s%s*.%s", aDirectory,
        aDirectory[pathLen - 1] == '/' ? "" : "/", pExtension);
    if (written < 0 || (size_t)written >= outSize) {
        pOut[0] = 0;
        return 0;
    }
    return 1;
}

// Added: inspect the final pattern component before removing it. A missing
// separator means the current directory; '/' must never become an empty path.
static int stdFileUtil_PrepareSearchDirectory(const char* pPath, size_t pathSize,
    char* pOut, size_t outSize, const char** ppExtension)
{
    const char* pEnd;
    const char* pPattern;
    size_t directoryLen;

    if (!pPath || !pOut || !outSize || !ppExtension) return 0;
    pOut[0] = 0;
    *ppExtension = NULL;
    pEnd = memchr(pPath, 0, pathSize);
    if (!pEnd) return 0;
    pPattern = pPath;
    for (const char* p = pPath; p < pEnd; ++p) {
        if (*p == '/' || *p == '\\') pPattern = p + 1;
    }
    if (pEnd - pPattern < 2 || pPattern[0] != '*' || pPattern[1] != '.') return 0;
    if (strchr(pPattern + 2, '*') && strcmp(pPattern, "*.*")) return 0;

    directoryLen = (size_t)(pPattern - pPath);
    if (!directoryLen) {
        if (outSize < 2) return 0;
        strcpy(pOut, ".");
    }
    else {
        // Altered: only remove actual trailing separators, keeping the root.
        while (directoryLen > 1
            && (pPath[directoryLen - 1] == '/' || pPath[directoryLen - 1] == '\\')) {
            --directoryLen;
        }
        if (directoryLen >= outSize) return 0;
        memcpy(pOut, pPath, directoryLen);
        pOut[directoryLen] = 0;
        for (size_t i = 0; i < directoryLen; ++i) {
            if (pOut[i] == '\\') pOut[i] = '/';
        }
    }
    if (strcmp(pPattern, "*.*")) *ppExtension = strrchr(pPattern, '.');
    return 1;
}
#endif

stdFileSearch* stdFileUtil_NewFind(const char *path, int mode, const char *pFilter)
{
    stdFileSearch* search = (stdFileSearch *)STD_ALLOC(sizeof(stdFileSearch));
    if ( !search ) {
        return search;
    }
    _memset(search, 0, sizeof(stdFileSearch));

#if defined(PLATFORM_POSIX) && !defined(WIN32)
    // Added: reject unsupported/incomplete patterns before any enumeration.
    if (!stdFileUtil_PrepareSearchPath(search->path, sizeof(search->path), path, mode, pFilter)) {
        STD_FREE(search);
        return NULL;
    }
    if (mode <= 2) return search;
#else
    if ( mode < 0 )
        return search;
    if ( mode <= 2 )
    {
        stdFnames_MakePath(search->path, 128, path, "*.*");
        return search;
    }
    if ( mode != 3 )
        return search;
    if ( *pFilter == '.' )
        pFilter = pFilter + 1;
    stdString_snprintf(std_g_genBuffer, 1024, "*.%s", pFilter);
    stdFnames_MakePath(search->path, 128, path, std_g_genBuffer);
    
#ifdef FS_POSIX
    for (int i = 0; i < strlen(search->path); i++)
    {
        if (search->path[i] == '\\')
            search->path[i] = '/';
    }
#endif
#endif

    stdPlatform_Printf("OpenJKDF2: %s %s\n", __func__, search->path);
    
    return search;
}

#ifdef WIN64_STANDALONE
#define __findnext _findnext
#define __findfirst _findfirst
#define __findclose _findclose
#endif

#ifdef WIN32
int stdFileUtil_FindNext(stdFileSearch *ffData, stdFileSearchResult *pFileInfo)
{
    intptr_t v4; // eax
    struct _finddata_t v6; // [esp+8h] [ebp-118h] BYREF

    if ( !ffData )
        return 0;

    if (ffData->isNotFirst++)
    {
        v4 = __findnext(ffData->field_88, &v6);
    }
    else
    {
        v4 = __findfirst(ffData->path, &v6);
        ffData->field_88 = v4;
    }
    if ( v4 == -1 )
        return 0;

    // Added: strcpy -> strncpy
    _strncpy(pFileInfo->fpath, v6.name, sizeof(pFileInfo->fpath)-1);

    pFileInfo->time_write = v6.time_write;
    pFileInfo->is_subdirectory = v6.attrib & 0x10;
    return 1;
}

void stdFileUtil_DisposeFind(stdFileSearch *ffData)
{
    if ( ffData )
    {
        if ( ffData->isNotFirst )
            __findclose(ffData->field_88);
        STD_FREE(ffData);
    }
}

void stdFileUtil_FindReset(stdFileSearch *search)
{
    if ( search && search->isNotFirst )
    {
        __findclose(search->field_88);
    }
    if ( search )
    {
        search->isNotFirst = 0;
    }
}

int stdFileUtil_FindQuick(const char *pPath, int mode, const char *pFilter, stdFileSearchResult *pFileInfo)
{
    stdFileSearch *search = stdFileUtil_NewFind(pPath, mode, pFilter);
    if ( !search )
        return 0;

    int found = stdFileUtil_FindNext(search, pFileInfo);
    stdFileUtil_DisposeFind(search);
    return found;
}

int stdFileUtil_CountMatches(const char *pPath, int mode, const char *pFilter)
{
    stdFileSearchResult result;
    stdFileSearch *search = stdFileUtil_NewFind(pPath, mode, pFilter);
    if ( !search )
        return 0;

    int count = 0;
    while ( stdFileUtil_FindNext(search, &result) )
    {
        count++;
    }
    stdFileUtil_DisposeFind(search);
    return count;
}

int stdFileUtil_FileExists(const char *pFilename)
{
    struct _WIN32_FIND_DATAA findData;
    HANDLE h = FindFirstFileA(pFilename, (LPWIN32_FIND_DATAA)&findData);
    if ( h != INVALID_HANDLE_VALUE )
    {
        FindClose(h);
        return 1;
    }
    return 0;
}

void stdFileUtil_RmDir(const char *pDir)
{
    RemoveDirectoryA(pDir);
}

// https://stackoverflow.com/questions/1517685/recursive-createdirectory
int TryCreateDirectory(LPCSTR lpPathName)
{
    char *p;
    int b;

    if( !(b = CreateDirectoryA(lpPathName, 0))
        && !(b = NULL ==(p = strrchr(lpPathName, '\\')))
        )
    {
        size_t i;

        (p=strncpy((char *)STD_ALLOC(1+i), lpPathName, i=p-lpPathName))[i] = '\0';
        b = TryCreateDirectory(p);
        free(p);
        b = b ? CreateDirectoryA(lpPathName, 0) : 0;
    }

    return b;
}

BOOL stdFileUtil_MkDir(LPCSTR lpPathName)
{
    // Added
    TryCreateDirectory(lpPathName);

    return CreateDirectoryA(lpPathName, 0);
}

int stdFileUtil_DelFile(char* pFilename)
{
    return DeleteFileA(pFilename);
}

int stdFileUtil_Deltree(LPCSTR lpPathName)
{
    int v2; // ebx
    char* v3; // edi
    int v4; // eax
    HANDLE hFindFile; // [esp+10h] [ebp-248h]
    char FileName[260]; // [esp+14h] [ebp-244h] BYREF
    struct _WIN32_FIND_DATAA FindFileData; // [esp+118h] [ebp-140h] BYREF

    strcpy(FileName, lpPathName);
    v2 = 1;
    v3 = &FileName[strlen(FileName)];
    strcpy(v3, "\\*.*");
    hFindFile = FindFirstFileA(FileName, &FindFileData);
    if (hFindFile == (HANDLE)-1)
        return 0;
    do
    {
        if (FindFileData.dwFileAttributes != 16)
        {
            strcpy(FileName, lpPathName);
            strcpy(&FileName[strlen(FileName)], "\\");
            strcat(FileName, FindFileData.cFileName);
            v4 = DeleteFileA(FileName);
            goto LABEL_7;
        }
        if (strcmp(FindFileData.cFileName, ".") && strcmp(FindFileData.cFileName, ".."))
        {
            strcpy(FileName, lpPathName);
            strcpy(&FileName[strlen(FileName)], "\\");
            strcat(FileName, FindFileData.cFileName);
            v4 = stdFileUtil_Deltree(FileName);
LABEL_7:
            v2 = v4;
        }
    } while (FindNextFileA(hFindFile, &FindFileData) && v2 == 1);
    FindClose(hFindFile);
    if (v2)
        return RemoveDirectoryA(lpPathName);
    return v2;
}
#endif // WIN32

#ifdef PLATFORM_POSIX

// Stolen from https://stackoverflow.com/questions/2256945/removing-a-non-empty-directory-programmatically-in-c-or-c
static int rmFiles(const char *pathname, const struct stat *sbuf, int type, struct FTW *ftwb)
{
    if(remove(pathname) < 0)
    {
        perror("ERROR: remove");
        return -1;
    }
    return 0;
}

#ifndef _WIN32
int stdFileUtil_Deltree(const char* lpPathName)
{
    char tmp[512];
    size_t len = _strlen(lpPathName);

    if (len > 512) {
        len = 512;
    }
    stdString_SafeStrCopy(tmp, lpPathName, sizeof(tmp));

#ifndef WIN64_STANDALONE
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif

#ifndef TARGET_RETRO_HOMEBREW
    nftw(tmp, rmFiles, 10, FTW_DEPTH|FTW_MOUNT|FTW_PHYS);
#else
    DIR *dir;
    struct dirent *entry;
    char filepath[256];
    struct stat statbuf;
    int result = 1;

    dir = opendir(tmp);
    if (!dir)
        return 0;

    while ((entry = readdir(dir)) != NULL && result == 1) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", tmp, entry->d_name);

        if (stat(filepath, &statbuf) == -1) { // use lstat on non-DSi
            result = 0;
            break;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            result = stdFileUtil_Deltree(filepath);
        } else {
            if (unlink(filepath) != 0) {
                result = 0;
                break;
            }
        }
    }

    closedir(dir);

    if (result) {
        if (rmdir(tmp) != 0)
            result = 0;
    }

    return result;
#endif

    //rmdir(tmp);
    return 0;
}
#endif // _WIN32
#endif // PLATFORM_POSIX

#if defined(PLATFORM_POSIX) && !defined(WIN32)

static const char* search_ext = "";

/* when return 1, scandir will put this dirent to the list */
static int parse_ext(const struct dirent *dir)
{
    if(!dir)
        return 0;

    if(dir->d_type == DT_REG) 
    {
        const char *ext = strrchr(dir->d_name,'.');
        if((!ext) || (ext == dir->d_name)) {
            return 0;
        }
        else 
        {
            if(__strnicmp(ext, search_ext, 3) == 0)
                return 1;
        }
    }
    else
    {
        if (!strncmp(dir->d_name, ".", 1)) return 1;
        if (!strncmp(dir->d_name, "..", 1)) return 1;
    }

    return 0;
}

int stdFileUtil_FindNext(stdFileSearch *a1, stdFileSearchResult *a2)
{
    struct dirent *iter;
    char tmp[sizeof(a1->path)];

    if ( !a1 )
        return 0;

    // Added: isNotFirst is 1 + the index of the next namelist entry to return.
    if (!a1->isNotFirst)
    {
        // Added: a failed preparation is an empty search until FindReset.
        a1->isNotFirst = 1;
        if (!stdFileUtil_PrepareSearchDirectory(a1->path, sizeof(a1->path),
            tmp, sizeof(tmp), &search_ext)) return 0;

        const char* pDirectory = tmp;

#ifdef TARGET_RETRO_HOMEBREW
        // Added: the Dreamcast asset root and the search path each fit 128
        // bytes. Reserve room for both instead of truncating the resolved path.
        char aResolvedDirectory[sizeof(a1->path) * 2];
#ifdef TARGET_DREAMCAST
        // Added: retain GD-ROM asset routing and writable-CWD fallback. An
        // explicit current directory or absolute root keeps its own meaning.
        if (strcmp(tmp, ".")
            && dcStorage_ResolveAssetPath(tmp, aResolvedDirectory, sizeof(aResolvedDirectory))) {
            pDirectory = aResolvedDirectory;
        }
        else
#endif
        if (tmp[0] != '/') {
            char aCwd[sizeof(aResolvedDirectory)];
            if (!getcwd(aCwd, sizeof(aCwd))) return 0;
            size_t cwdLen = strlen(aCwd);
            int written = snprintf(aResolvedDirectory, sizeof(aResolvedDirectory), "%s%s%s",
                aCwd, cwdLen && aCwd[cwdLen - 1] == '/' ? "" : "/", tmp);
            if (written < 0 || (size_t)written >= sizeof(aResolvedDirectory)) return 0;
            pDirectory = aResolvedDirectory;
        }
        errno = 0;
#endif
        a1->nFoundFiles = scandir(pDirectory, &a1->namelist, search_ext ? parse_ext : NULL, alphasort);

        if (!a1->namelist || a1->nFoundFiles <= 0) return 0;
    }

    // Added: skip "." and ".." by name. This used to skip the first two
    // entries, but alphasort puts names like "!dm.gob" before ".", so a real
    // file was dropped and "." or ".." was returned in its place.
    iter = NULL;
    while (a1->isNotFirst - 1 < a1->nFoundFiles)
    {
        struct dirent* pEntry = a1->namelist[a1->isNotFirst - 1];
        a1->isNotFirst++;
        if (!strcmp(pEntry->d_name, ".") || !strcmp(pEntry->d_name, ".."))
            continue;
        iter = pEntry;
        break;
    }

    if (!iter)
        return 0;

    strncpy(a2->fpath, iter->d_name, sizeof(a2->fpath));

    a2->time_write = 0;
    a2->is_subdirectory = iter->d_type == DT_DIR ? 0x10 : 0;

    return 1;
}

void stdFileUtil_DisposeFind(stdFileSearch *search)
{
    if ( search )
    {
        for (int i = 0; i < search->nFoundFiles; i++)
        {
           free(search->namelist[i]);
        }
        free(search->namelist);

        STD_FREE(search);
    }
}

void stdFileUtil_FindReset(stdFileSearch *search)
{
    if ( search )
    {
        for (int i = 0; i < search->nFoundFiles; i++)
        {
            free(search->namelist[i]);
        }
        free(search->namelist);
        search->namelist = NULL;
        search->isNotFirst = 0;
        search->nFoundFiles = 0;
    }
}

int stdFileUtil_FindQuick(const char *path, int type, const char *extension, stdFileSearchResult *result)
{
    stdFileSearch *search = stdFileUtil_NewFind(path, type, extension);
    if ( !search )
        return 0;

    int found = stdFileUtil_FindNext(search, result);
    stdFileUtil_DisposeFind(search);
    return found;
}

int stdFileUtil_CountMatches(const char *path, int type, const char *extension)
{
    stdFileSearchResult result;
    stdFileSearch *search = stdFileUtil_NewFind(path, type, extension);
    if ( !search )
        return 0;

    int count = 0;
    while ( stdFileUtil_FindNext(search, &result) )
    {
        count++;
    }
    stdFileUtil_DisposeFind(search);
    return count;
}

int stdFileUtil_FileExists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

void stdFileUtil_RmDir(const char *path)
{
    rmdir(path);
}

// https://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix
static void _mkdir(const char *dir, int perms) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, perms);
            *p = '/';
        }
    mkdir(tmp, perms);
}

int stdFileUtil_MkDir(char* path)
{
    char tmp[512];
    size_t len = _strlen(path);

    if (len > 512) {
        len = 512;
    }
    _strncpy(tmp, path, sizeof(tmp));

#ifndef WIN64_STANDALONE
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif

    _mkdir(tmp, 0777);

    return 1;
}

int stdFileUtil_DelFile(char* lpFileName)
{
    char tmp[512];
    size_t len = _strlen(lpFileName);

    if (len > 512) {
        len = 512;
    }
    _strncpy(tmp, lpFileName, sizeof(tmp));

#ifndef WIN64_STANDALONE
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif

    unlink(tmp);

    return 1;
}
#endif // PLATFORM_POSIX
