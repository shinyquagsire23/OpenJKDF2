#include "stdFileUtil.h"

#include "stdPlatform.h"
#include "General/stdFnames.h"
#include "jk.h"

#ifdef LINUX
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#endif

stdFileSearch* stdFileUtil_NewFind(char *path, int a2, char *extension)
{
    stdFileSearch* search = (stdFileSearch *)std_pHS->alloc(sizeof(stdFileSearch));
    if ( !search )
        return search;
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
    
#ifdef LINUX
    for (int i = 0; i < strlen(search->path); i++)
    {
        if (search->path[i] == '\\')
            search->path[i] = '/';
    }
#endif
    
    return search;
}

#ifdef WIN32
int stdFileUtil_FindNext(stdFileSearch *a1, stdFileSearchResult *a2)
{
    int v4; // eax
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
    _strcpy(a2->fpath, v6.name);

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

BOOL stdFileUtil_MkDir(LPCSTR lpPathName)
{
    return CreateDirectoryA(lpPathName, 0);
}

int stdFileUtil_DelFile(char* lpFileName)
{
    return DeleteFileA(lpFileName);
}
#endif

#ifdef LINUX

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
        strncpy(tmp, a1->path, 128);

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

        a1->num_found = scandir(tmp, &a1->namelist, search_ext ? parse_ext : NULL, alphasort);
        
        if (!a1->namelist) return 0;
        
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

int stdFileUtil_Deltree(char* lpPathName)
{
    return 0;
}

int stdFileUtil_MkDir(char* path)
{
    return 0;
}

int stdFileUtil_DelFile(char* lpFileName)
{
    return 0;
}
#endif
