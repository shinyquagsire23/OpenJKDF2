#ifndef _STDCONFFILE_H
#define _STDCONFFILE_H

#include <stdio.h>
#include "types.h"
#include "globals.h"

#define stdConffile_OpenRead_ADDR (0x00430F50)
#define stdConffile_OpenWrite_ADDR (0x00431100)
#define stdConffile_OpenMode_ADDR (0x00431160)
#define stdConffile_Close_ADDR (0x00431310)
#define stdConffile_CloseWrite_ADDR (0x004313E0)
#define stdConffile_WriteLine_ADDR (0x00431420)
#define stdConffile_Write_ADDR (0x00431470)
#define stdConffile_Printf_ADDR (0x004314B0)
#define stdConffile_Read_ADDR (0x00431510)
#define stdConffile_ReadArgsFromStr_ADDR (0x00431550)
#define stdConffile_ReadArgs_ADDR (0x004315C0)
#define stdConffile_ReadLine_ADDR (0x00431650)
#define stdConffile_GetFileHandle_ADDR (0x00431730)


int stdConffile_OpenRead(char *jkl_fname);
int stdConffile_OpenWrite(char *a1);
int stdConffile_OpenMode(char *fpath, char* mode);
void stdConffile_Close();
void stdConffile_CloseWrite();
int stdConffile_WriteLine(const char *line);
int stdConffile_Write(const char* line, int amt);
int stdConffile_Printf(char *fmt, ...);
int stdConffile_Read(void* out, int len);
int stdConffile_ReadArgsFromStr(char *str);
int stdConffile_ReadArgs();
int stdConffile_ReadLine();
int stdConffile_GetFileHandle();

#endif // _STDCONFFILE_H
