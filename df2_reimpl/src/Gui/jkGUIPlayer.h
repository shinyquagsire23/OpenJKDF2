#ifndef _JKGUIPLAYER_H
#define _JKGUIPLAYER_H

#define jkGuiPlayer_Initialize_ADDR (0x004105F0)
#define jkGuiPlayer_Shutdown_ADDR (0x00410630)
#define jkGuiPlayer_sub_410640_ADDR (0x00410640)
#define jkGuiPlayer_ShowNewPlayer_ADDR (0x00410870)
#define jkGuiPlayer_NewPlayerIdk_ADDR (0x00410D10)

static int (*jkGuiPlayer_Initialize)() = (void*)jkGuiPlayer_Initialize_ADDR;
static void (*jkGuiPlayer_ShowNewPlayer)(int) = (void*)jkGuiPlayer_ShowNewPlayer_ADDR;

#endif // _JKGUIPLAYER_H
