#ifndef _JKSTRINGS_H
#define _JKSTRINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

#define jkStrings_Startup_ADDR (0x0040B3F0)
#define jkStrings_Shutdown_ADDR (0x0040B410)
#define jkStrings_GetUniString_ADDR (0x0040B430)
#define jkStrings_GetUniStringWithFallback_ADDR (0x0040B460)
#define jkStrings_unused_sub_40B490_ADDR (0x0040B490)

int jkStrings_Startup();
void jkStrings_Shutdown();
wchar_t* jkStrings_GetUniString(const char *key);
wchar_t* jkStrings_GetUniStringWithFallback(const char *key);
int jkStrings_unused_sub_40B490();

#ifdef QOL_IMPROVEMENTS
extern stdStrTable jkStrings_tableExtOver;
#endif


#ifdef __cplusplus
}
#endif

#endif // _JKSTRINGS_H
