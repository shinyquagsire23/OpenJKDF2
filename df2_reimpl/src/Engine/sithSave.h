#ifndef _SITHSAVE_H
#define _SITHSAVE_H

#include <stdint.h>

#define sithSave_GetProfilePath_ADDR (0x004DA400)
#define sithSave_Setidk_ADDR (0x004DA450)
#define sithSave_Write_ADDR (0x004DA490)
#define sithSave_Load_ADDR (0x004DA6A0)
#define sithSave_SerializeAllThings_ADDR (0x004DA770)
#define sithSave_WriteEntry_ADDR (0x004DA9C0)
#define sithSave_LoadEntry_ADDR (0x004DAB70)

static int (*sithSave_Load)(char *a1, int a2, int a3) = (void*)sithSave_Load_ADDR;
static int (*sithSave_Write)(char *a1, int a2, int a3, wchar_t *a4) = (void*)sithSave_Write_ADDR;

#endif // _SITHSAVE_H
