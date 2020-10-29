#ifndef _STDPLATFORM_H
#define _STDPLATFORM_H

#include "jk.h"

#define std_genBuffer ((char*)0x866880)
#define std_pHS (*((struct common_functions **)0x866C80))

#define stdPlatform_GetTimeMsec_ADDR (0x0042C2B0)

static int (*stdPrintf)(int a1, char *a2, int line, char *fmt, ...) = (void*)0x426D80;
static int (__cdecl *stdPlatform_GetTimeMsec)(void) = (void*)stdPlatform_GetTimeMsec_ADDR;

#endif // _STDPLATFORM_H
