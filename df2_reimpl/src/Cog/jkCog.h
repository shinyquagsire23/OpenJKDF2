#ifndef _JKCOG_H
#define _JKCOG_H

#include "types.h"

#include "sithCog.h"

#define jkCog_bInitted (*(int*)0x00553FB0)

void jkCog_RegisterVerbs();
int jkCog_Initialize();
void jkCog_Shutdown();
int jkCog_StringsInit();

#define jkCog_strings (*(stdStrTable*)0x0553FA0)

#endif // _JKCOG_H
