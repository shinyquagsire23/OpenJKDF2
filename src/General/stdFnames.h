#ifndef _STDFNAMES_H
#define _STDFNAMES_H

#define stdFnames_FindMedName_ADDR (0x00430A10)
#define stdFnames_FindExt_ADDR (0x00430A40)
#define stdFnames_AddDefaultExt_ADDR (0x00430A80)
#define stdFnames_StripExt_ADDR (0x00430B10)
#define stdFnames_StripExtAndDot_ADDR (0x00430B50)
#define stdFnames_ChangeExt_ADDR (0x00430B90)
#define stdFnames_StripDirAndExt_ADDR (0x00430C10)
#define stdFnames_CopyExt_ADDR (0x00430C70)
#define stdFnames_CopyMedName_ADDR (0x00430CE0)
#define stdFnames_CopyDir_ADDR (0x00430D30)
#define stdFnames_CopyShortName_ADDR (0x00430D70)
#define stdFnames_Concat_ADDR (0x00430DF0)
#define stdFnames_MakePath_ADDR (0x00430E40)
#define stdFnames_MakePath3_ADDR (0x00430EB0)

#ifdef WIN32
#define LEC_PATH_SEPARATOR_CHR ('\\')
#define LEC_PATH_SEPARATOR "\\"
#else
#define LEC_PATH_SEPARATOR_CHR ('/')
#define LEC_PATH_SEPARATOR "/"
#endif

#ifdef __cplusplus
extern "C" {
#endif


char* stdFnames_FindMedName(char *path);
char* stdFnames_FindExt(char *path);
int stdFnames_AddDefaultExt(char *str, const char *ext);
char* stdFnames_StripExt(char *str);
char* stdFnames_StripExtAndDot(char *str);
int stdFnames_ChangeExt(char *str, char* ext);
int stdFnames_StripDirAndExt(char *str);
int stdFnames_CopyExt(char *out, int out_size, char *path);
int stdFnames_CopyMedName(char *out, int out_size, char *path);
char* stdFnames_CopyDir(char *out, int out_size, char *path);
char* stdFnames_CopyShortName(char *a1, int a2, char *a3);
char* stdFnames_Concat(char *a1, char *a2, int a3);
char* stdFnames_MakePath(char *a1, int a2, const char *pBasePath, const char *pAppendedPath);
char* stdFnames_MakePath3(char *a1, int a2, char *a3, char *a4, char *a5);

#ifdef __cplusplus
}
#endif

#endif // _STDFNAMES_H
