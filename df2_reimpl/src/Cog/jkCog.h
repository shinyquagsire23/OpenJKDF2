#ifndef _JKCOG_H
#define _JKCOG_H

#include "types.h"

#include "sithCog.h"

void jkCog_RegisterVerbs();
int jkCog_Initialize();

#define jkCog_strings (*(stdStrTable*)0x0553FA0)

#endif // _JKCOG_H
