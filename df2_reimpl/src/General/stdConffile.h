#ifndef _STDCONFFILE_H
#define _STDCONFFILE_H

#include <stdio.h>
#include "types.h"

typedef struct stdConffileArg
{
    char* key;
    char* value;
} stdConffileArg;

typedef struct stdConffileEntry
{
    int numArgs;
    stdConffileArg args[128];
} stdConffileEntry;

#define aFilenameStack  ((char*)0x0055D620)
#define apBufferStack ((char**)0x55E020)
#define linenumStack  ((int*)0x55E070)
#define aEntryStack   ((char*)0x0055E0C0)
#define openFileStack ((int*)0x563110)
#define printfBuffer  ((char*)0x00563160)
#define stdConffile_linenum (*(int*)0x00563560)
#define stdConffile_bOpen (*(int*)0x00563564)
#define openFile (*(int*)0x00563568)
#define writeFile      (*(int*)0x0056356C)
#define stackLevel	  (*(unsigned int*)0x00563570)

#define stdConffile_aWriteFilename ((char*)0x860820)
#define stdConffile_entry (*(stdConffileEntry*)0x8608A0)
#define stdConffile_pFilename ((char*)0x860CC0)
#define stdConffile_aLine (*(char**)0x860D40)


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
