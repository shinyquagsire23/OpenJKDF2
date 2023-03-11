#include "stdFnames.h"

#include "jk.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

char* stdFnames_FindMedName(char *path)
{
    char *result; // eax
    char v2; // cl

    result = _strrchr(path, LEC_PATH_SEPARATOR_CHR);
    if (!result)
        return path;

    if ( *result == LEC_PATH_SEPARATOR_CHR )
    {
        while ( (result++)[1] == LEC_PATH_SEPARATOR_CHR );
    }
    return result;
}

char* stdFnames_FindExt(char *path)
{
    char *result;

    result = _strrchr(stdFnames_FindMedName(path), '.');
    if (result)
        ++result;
    return result;
}

int stdFnames_AddDefaultExt(char *str, const char *ext)
{
    if (stdFnames_FindExt(str))
        return 0;

    _strcat(str, ".");
    _strcat(str, ext);
    return 1;
}

char* stdFnames_StripExt(char *str)
{
    char* result;

    result = stdFnames_FindExt(str);
    if (result)
        *result = 0;

    return result;
}

char* stdFnames_StripExtAndDot(char *str)
{
    char* result;

    result = stdFnames_FindExt(str);
    if (result)
        *(result-1) = 0;

    return result;
}

int stdFnames_ChangeExt(char *str, char* ext)
{
    stdFnames_StripExtAndDot(str);
    return stdFnames_AddDefaultExt(str, ext);
}

int stdFnames_StripDirAndExt(char *str)
{
    char *strip;
    char *find_drive;
    char *find_lastfolder;
    char *find_ext;
    int result;

    strip = str;

    find_drive = _strrchr(str, ':');
    if (find_drive)
        strip = find_drive + 1;

    find_lastfolder = _strrchr(strip, LEC_PATH_SEPARATOR_CHR);
    if ( find_lastfolder )
        strip = find_lastfolder + 1;

    find_ext = _strrchr(strip, '.');
    if ( find_ext )
        *find_ext = 0;

    result = _strlen(strip) + 1;
    _memcpy(str, strip, result);
    return result;
}

int stdFnames_CopyExt(char *out, int out_size, char *path)
{
  char *ext; // eax
  int result; // eax

  ext = stdFnames_FindExt(path);
  if ( ext )
  {
    _strncpy(out, ext, out_size - 1);
    out[out_size - 1] = 0;
    result = 1;
  }
  else
  {
    *out = 0;
    result = 0;
  }
  return result;
}

int stdFnames_CopyMedName(char *out, int out_size, char *path)
{
  char *mname; // eax
  int result; // eax

  mname = stdFnames_FindMedName(path);
  if ( mname )
  {
    _strncpy(out, mname, out_size - 1);
    out[out_size - 1] = 0;
    result = 1;
  }
  else
  {
    *out = 0;
    result = 0;
  }
  return result;
}

char* stdFnames_CopyDir(char *out, int out_size, char *path)
{
    char *result; // eax

    _strncpy(out, path, out_size - 1);
    out[out_size - 1] = 0;

    result = _strrchr(out, LEC_PATH_SEPARATOR_CHR);
    if (result)
        *result = 0;

    return result;
}

char* stdFnames_CopyShortName(char *a1, int a2, char *a3)
{
  char *v3; // eax
  char v4; // cl
  char *v5; // eax
  char v6; // cl
  char *result; // eax

  v3 = _strrchr(a3, LEC_PATH_SEPARATOR_CHR);
  if ( v3 )
  {
    if ( *v3 == LEC_PATH_SEPARATOR_CHR )
    {
      do
        v4 = (v3++)[1];
      while ( v4 == LEC_PATH_SEPARATOR_CHR );
    }
  }
  else
  {
    v3 = a3;
  }
  _strncpy(a1, v3, a2 - 1);
  a1[a2 - 1] = 0;
  v5 = _strrchr(a1, LEC_PATH_SEPARATOR_CHR);
  if ( v5 )
  {
    if ( *v5 == LEC_PATH_SEPARATOR_CHR )
    {
      do
        v6 = (v5++)[1];
      while ( v6 == LEC_PATH_SEPARATOR_CHR );
    }
  }
  else
  {
    v5 = a1;
  }
  result = _strrchr(v5, '.');
  if ( result )
    ++result;
  if ( result )
    *(result - 1) = 0;
  return result;
}

char* stdFnames_Concat(char *a1, char *a2, int a3)
{
  int v3; // ecx
  unsigned int v4; // kr04_4

  v4 = _strlen(a1) + 1;
  v3 = v4 - 1;
  if ( a1[v4 - 2] != LEC_PATH_SEPARATOR_CHR && v3 < a3 - 1 && *a1 )
  {
    a1[v3] = LEC_PATH_SEPARATOR_CHR;
    v3 = v4;
    a1[v4] = 0;
  }
  _strncat(a1, a2, a3 - v3 - 1);
  return a1;
}

char* stdFnames_MakePath(char *a1, int a2, const char *a3, const char *a4)
{
    int v4; // ecx
    unsigned int v5; // kr04_4

    _strncpy(a1, a3, a2 - 1);
    a1[a2 - 1] = 0;
    v5 = _strlen(a1) + 1;
    v4 = v5 - 1;
    if ( a1[v5 - 2] != LEC_PATH_SEPARATOR_CHR && v4 < a2 - 1 && *a1 )
    {
      a1[v4] = LEC_PATH_SEPARATOR_CHR;
      v4 = v5;
      a1[v5] = 0;
    }

#ifdef LINUX
    char *r = malloc(strlen(a1) + 16);
    if (casepath(a1, r))
    {
        strcpy(a1, r);
    }
    free(r);
#endif

    _strncat(a1, a4, a2 - v4 - 1);
    return a1;
}

char* stdFnames_MakePath3(char *a1, int a2, char *a3, char *a4, char *a5)
{
  int v5; // ebx
  int v6; // ecx
  unsigned int v7; // kr04_4
  int v8; // ecx
  unsigned int v9; // kr08_4

  v5 = a2 - 1;
  _strncpy(a1, a3, a2 - 1);
  a1[a2 - 1] = 0;
  v7 = _strlen(a1) + 1;
  v6 = v7 - 1;
  if ( a1[v7 - 2] != LEC_PATH_SEPARATOR_CHR && v6 < v5 && *a1 )
  {
    a1[v6] = LEC_PATH_SEPARATOR_CHR;
    v6 = v7;
    a1[v7] = 0;
  }
  _strncat(a1, a4, a2 - v6 - 1);
  v9 = _strlen(a1) + 1;
  v8 = v9 - 1;
  if ( a1[v9 - 2] != LEC_PATH_SEPARATOR_CHR && v8 < v5 && *a1 )
  {
    a1[v8] = LEC_PATH_SEPARATOR_CHR;
    v8 = v9;
    a1[v9] = 0;
  }
  _strncat(a1, a5, a2 - v8 - 1);
  return a1;
}
