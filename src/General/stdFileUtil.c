#include "stdFileUtil.h"

#include "stdPlatform.h"
#include "General/stdFnames.h"
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
#ifndef TARGET_TWL
#include <ftw.h>
#endif
#endif

#include "external/fcaseopen/fcaseopen.h"
#endif

stdFileSearch* stdFileUtil_NewFind(const char *path, int a2, const char *extension)
{
    stdFileSearch* search = (stdFileSearch *)std_pHS->alloc(sizeof(stdFileSearch));
    if ( !search ) {
        return search;
    }
    _memset(search, 0, sizeof(stdFileSearch));

    if ( a2 < 0 )
        return search;
    if ( a2 <= 2 )
    {
        stdFnames_MakePath(search->path, 128, path, "*.*");
        return search;
    }
    if ( a2 != 3 )
        return search;
    if ( *extension == '.' )
        extension = extension + 1;
    _sprintf(std_genBuffer, "*.%s", extension);
    stdFnames_MakePath(search->path, 128, path, std_genBuffer);
    
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
int stdFileUtil_FindNext(stdFileSearch *a1, stdFileSearchResult *a2)
{
    intptr_t v4; // eax
    struct _finddata_t v6; // [esp+8h] [ebp-118h] BYREF

    if ( !a1 )
        return 0;

    if (a1->isNotFirst++)
    {
        v4 = __findnext(a1->field_88, &v6);
    }
    else
    {
        v4 = __findfirst(a1->path, &v6);
        a1->field_88 = v4;
    }
    if ( v4 == -1 )
        return 0;

    // Added: strcpy -> strncpy
    _strncpy(a2->fpath, v6.name, sizeof(a2->fpath)-1);

    a2->time_write = v6.time_write;
    a2->is_subdirectory = v6.attrib & 0x10;
    return 1;
}

void stdFileUtil_DisposeFind(stdFileSearch *search)
{
    if ( search )
    {
        if ( search->isNotFirst )
            __findclose(search->field_88);
        std_pHS->free(search);
    }
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

        (p=strncpy((char *)std_pHS->alloc(1+i), lpPathName, i=p-lpPathName))[i] = '\0';
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

int stdFileUtil_DelFile(char* lpFileName)
{
    return DeleteFileA(lpFileName);
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
    _strncpy(tmp, lpPathName, sizeof(tmp));

#ifndef WIN64_STANDALONE
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif

#ifndef TARGET_TWL
    nftw(tmp, rmFiles, 10, FTW_DEPTH|FTW_MOUNT|FTW_PHYS);
#else
    assert(0);
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
        if (a1->isNotFirst >= a1->num_found)
            iter = NULL;
        else
            iter = a1->namelist[a1->isNotFirst];
    }
    else
    {
#ifdef TARGET_TWL
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

        errno = 0;
        a1->num_found = scandir(tmp, &a1->namelist, search_ext ? parse_ext : NULL, alphasort);
        
        if (!a1->namelist || a1->num_found <= 0) return 0;
        
        iter = a1->namelist[2];
        a1->isNotFirst = 2;
    }

    if (a1->num_found <= 2 || !iter)
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
        for (int i = 0; i < search->num_found; i++)
        {
           free(search->namelist[i]);
        }
        free(search->namelist);

        std_pHS->free(search);
    }
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
