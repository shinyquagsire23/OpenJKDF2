#ifndef _STDFILEUTIL_H
#define _STDFILEUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

#define stdFileUtil_NewFind_ADDR (0x00431740)
#define stdFileUtil_DisposeFind_ADDR (0x004317E0)
#define stdFileUtil_FindReset_ADDR (0x00431820)
#define stdFileUtil_FindNext_ADDR (0x00431850)
#define stdFileUtil_FindQuick_ADDR (0x00431910)
#define stdFileUtil_CountMatches_ADDR (0x00431A70)
#define stdFileUtil_MkDir_ADDR (0x00431BC0)
#define stdFileUtil_DirExists_ADDR (0x00431BD0)
#define stdFileUtil_RmDir_ADDR (0x00431C00)
#define stdFileUtil_DelFile_ADDR (0x00431C10)
#define stdFileUtil_Deltree_ADDR (0x00431C20)

typedef struct stdFileSearch
{
    int field_0;
    int isNotFirst;
    char path[128];
    union
    {
        intptr_t field_88;
        struct dirent **namelist;
    };
    int num_found;
} stdFileSearch;

typedef struct stdFileSearchResult
{
    char fpath[256];
    int field_100;
    int is_subdirectory;
    int time_write;
} stdFileSearchResult;

stdFileSearch* stdFileUtil_NewFind(char *path, int a2, char *extension);
int stdFileUtil_FindNext(stdFileSearch *a1, stdFileSearchResult *a2);
void stdFileUtil_DisposeFind(stdFileSearch *search);

int stdFileUtil_DelFile(char* lpFileName);
int stdFileUtil_Deltree(const char* lpPathName);

#ifdef LINUX
int stdFileUtil_MkDir(char* path);
#else
//static int (*stdFileUtil_MkDir)(char* lpPathName) = (void*)stdFileUtil_MkDir_ADDR;
BOOL stdFileUtil_MkDir(LPCSTR lpPathName);
#endif

//static stdFileSearch* (*stdFileUtil_NewFind)(char *path, int a2, char *extension) = (void*)stdFileUtil_NewFind_ADDR;
//static int (*stdFileUtil_FindNext)(stdFileSearch *a1, stdFileSearchResult *a2) = (void*)stdFileUtil_FindNext_ADDR;
//static void (*stdFileUtil_DisposeFind)(stdFileSearch *a1) = (void*)stdFileUtil_DisposeFind_ADDR;

#ifdef __cplusplus
}
#endif

#endif // _STDFILEUTIL_H
