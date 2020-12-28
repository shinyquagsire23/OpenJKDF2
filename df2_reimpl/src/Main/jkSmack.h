#ifndef _JKSMACK_H
#define _JKSMACK_H

#define jkSmack_Initialize_ADDR (0x00402BB0)
#define jkSmack_Shutdown_ADDR (0x00402BD0)
#define jkSmack_GetCurrentGuiState_ADDR (0x00402C00)
#define jkSmack_SmackPlay_ADDR (0x00402C10)

#define jkSmack_gameMode (*(int*)0x00552B78)
#define jkSmack_bInit (*(int*)0x00552B7C)
#define jkSmack_stopTick (*(int*)0x00552B84)
#define jkSmack_currentGuiState (*(int*)0x00552B88)
#define jkSmack_nextGuiState (*(int*)0x00552B8C)
#define jkSmack_alloc (*(void**)0x00552B74)

void jkSmack_Initialize();
void jkSmack_Shutdown();
int jkSmack_GetCurrentGuiState();
int jkSmack_SmackPlay(const char *fname);

#endif // _JKSMACK_H
