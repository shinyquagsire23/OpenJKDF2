#ifndef _JKSMACK_H
#define _JKSMACK_H

#include "types.h"
#include "globals.h"

#define jkSmack_Initialize_ADDR (0x00402BB0)
#define jkSmack_Shutdown_ADDR (0x00402BD0)
#define jkSmack_GetCurrentGuiState_ADDR (0x00402C00)
#define jkSmack_SmackPlay_ADDR (0x00402C10)

void jkSmack_Initialize();
void jkSmack_Shutdown();
int jkSmack_GetCurrentGuiState();
int jkSmack_SmackPlay(const char *fname);

#endif // _JKSMACK_H
