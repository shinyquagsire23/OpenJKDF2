#ifndef _JKGUISETUP_H
#define _JKGUISETUP_H

#define jkGuiSetup_sub_412EF0_ADDR (0x00412EF0)
#define jkGuiSetup_Show_ADDR (0x00412F40)
#define jkGuiSetup_Initialize_0_ADDR (0x00413140)
#define jkGuiSetup_Shutdown_0_ADDR (0x00413170)

static void (*jkGuiSetup_Show)() = (void*)jkGuiSetup_Show_ADDR;

#endif // _JKGUISETUP_H
