#ifndef _JKMAIN_H
#define _JKMAIN_H

#define jkSmack_GetCurrentGuiState_ADDR (0x00402C00)
#define jkMain_SetVideoMode_ADDR (0x00402D00)
#define jkMain_SetVideoModeGdi_ADDR (0x00402E40)

static int (*jkSmack_GetCurrentGuiState)() = (void*)jkSmack_GetCurrentGuiState_ADDR;

#endif // _JKMAIN_H
