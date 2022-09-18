#ifndef _JKSTRINGS_H
#define _JKSTRINGS_H

#include "types.h"

#define jkStrings_Startup_ADDR (0x0040B3F0)
#define jkStrings_Shutdown_ADDR (0x0040B410)
#define jkStrings_GetText2_ADDR (0x0040B430)
#define jkStrings_GetText_ADDR (0x0040B460)
#define jkStrings_unused_sub_40B490_ADDR (0x0040B490)

int jkStrings_Startup();
void jkStrings_Shutdown();
wchar_t* jkStrings_GetText2(const char *key);
wchar_t* jkStrings_GetText(const char *key);
int jkStrings_unused_sub_40B490();

#endif // _JKSTRINGS_H
