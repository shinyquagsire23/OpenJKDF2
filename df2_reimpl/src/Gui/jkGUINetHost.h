#ifndef _JKGUINETHOST_H
#define _JKGUINETHOST_H

#include "types.h"
#include "globals.h"

#define jkGuiNetHost_Initialize_ADDR (0x00411000)
#define jkGuiNetHost_Shutdown_ADDR (0x00411110)
#define jkGuiNetHost_Show_ADDR (0x004111C0)
#define jkGuiNetHost_sub_4118C0_ADDR (0x004118C0)
#define jkGuiNetHost_sub_4119D0_ADDR (0x004119D0)
#define jkGuiNetHost_sub_411AE0_ADDR (0x00411AE0)

static int (*jkGuiNetHost_Initialize)() = (void*)jkGuiNetHost_Initialize_ADDR;
static void (*jkGuiNetHost_Shutdown)() = (void*)jkGuiNetHost_Shutdown_ADDR;
static int (*jkGuiNetHost_Show)(jkMultiEntry3* a) = (void*)jkGuiNetHost_Show_ADDR;

#endif // _JKGUINETHOST_H
