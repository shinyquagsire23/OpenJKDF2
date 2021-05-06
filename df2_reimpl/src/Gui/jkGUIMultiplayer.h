#ifndef _JKGUIMULTIPLAYER_H
#define _JKGUIMULTIPLAYER_H

#define jkGuiMultiplayer_Initialize_ADDR (0x00413180)
#define jkGuiMultiplayer_Shutdown_ADDR (0x004131E0)
#define jkGuiMultiplayer_Show_ADDR (0x004131F0)

static int (*jkGuiMultiplayer_Initialize)() = (void*)jkGuiMultiplayer_Initialize_ADDR;
static int (*jkGuiMultiplayer_Show)() = (void*)jkGuiMultiplayer_Show_ADDR;

#endif // _JKGUIMULTIPLAYER_H
