#ifndef _MAIN_JKHUDSCOPE_H
#define _MAIN_JKHUDSCOPE_H

#include "types.h"

void jkHudScope_Startup(void);
void jkHudScope_Shutdown(void);
int jkHudScope_Open(void);
void jkHudScope_Close(void);
void jkHudScope_Draw(void);

#endif // _MAIN_JKHUDSCOPE_H