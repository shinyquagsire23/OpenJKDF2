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

stdFileSearch* stdFileUtil_NewFind(const char *path, int mode, const char *pFilter)
{
    stdFileSearch* search = (stdFileSearch *)STD_ALLOC(sizeof(stdFileSearch));
    if ( !search ) {
        return search;
    }
    _memset(search, 0, sizeof(stdFileSearch));

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

static char* search_ext = "";

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
    char tmp[128];

    if ( !a1 )
        return 0;

    if (a1->isNotFirst++)
    {
        if (a1->isNotFirst >= a1->nFoundFiles)
            iter = NULL;
        else
            iter = a1->namelist[a1->isNotFirst];
    }
    else
    {
#ifdef TARGET_DREAMCAST
        // Added: asset directories (resource/, episode/, ...) live on the GD-ROM;
        // route their listing to the asset root. Writable dirs (player/) fall
        // through to the getcwd() path below, i.e. the writable CWD.
        if (dcStorage_ResolveAssetPath(a1->path, tmp, 128)) {
        }
        else {
            getcwd(tmp, 128-1);
            strncat(tmp, "/", 128-1);
            strncat(tmp, a1->path, 128-1);
        }
#elif defined(TARGET_RETRO_HOMEBREW)
        getcwd(tmp, 128-1);
        //strncpy(tmp, pcwd, 128-1);
        strncat(tmp, "/", 128-1);
        strncat(tmp, a1->path, 128-1);
#else
        strncpy(tmp, a1->path, 128);
#endif

        // Clear out extension
        // TODO: ehhhh
        if (!strcmp(strrchr(tmp,'*'), "*")) {
            *strrchr(tmp,'.') = 0;
            *strrchr(tmp,'*') = 0;
            search_ext = strrchr(a1->path,'.');
            search_ext = NULL;
        }
        else
        {
            *strrchr(tmp,'.') = 0;
            *strrchr(tmp,'*') = 0;
            search_ext = strrchr(a1->path,'.');
        }
        
        for (int i = 0; i < strlen(tmp); i++)
        {
            if (tmp[i] == '\\') {
                tmp[i] = '/';
            }
        }
        if (tmp[strlen(tmp)-1] = '/') {
            tmp[strlen(tmp)-1] = 0;
        }

#ifdef TARGET_RETRO_HOMEBREW
        errno = 0;
#endif
        a1->nFoundFiles = scandir(tmp, &a1->namelist, search_ext ? parse_ext : NULL, alphasort);
        
        if (!a1->namelist || a1->nFoundFiles <= 0) return 0;
        
        iter = a1->namelist[2];
        a1->isNotFirst = 2;
    }

    if (a1->nFoundFiles <= 2 || !iter)
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
