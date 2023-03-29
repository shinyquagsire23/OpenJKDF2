#ifndef _SITHSTRTABLE_H
#define _SITHSTRTABLE_H

#include "types.h"

#define sithStrTable_Startup_ADDR (0x004F2970)
#define sithStrTable_Shutdown_ADDR (0x004F2990)
#define sithStrTable_GetUniString_ADDR (0x004F29B0)
#define sithStrTable_GetUniStringWithFallback_ADDR (0x004F29D0)

int sithStrTable_Startup();
void sithStrTable_Shutdown();
wchar_t* sithStrTable_GetUniString(const char *key);
wchar_t* sithStrTable_GetUniStringWithFallback(char *key);

#endif // _SITHSTRTABLE_H
