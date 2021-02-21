#ifndef _JKGUIMAIN_H
#define _JKGUIMAIN_H

#define jkGuiMain_Show_ADDR (0x004100F0)
#define jkGuiMain_ShowCutscenes_ADDR (0x00410210)
#define jkGuiMain_Initialize_ADDR (0x004104A0)
#define jkGuiMain_Shutdown_ADDR (0x004104C0)
#define jkGuiMain_sub_4104D0_ADDR (0x004104D0)
#define jkGuiMain_sub_4105B0_ADDR (0x004105B0)

static int (*jkGuiMain_Initialize)() = (void*)jkGuiMain_Initialize_ADDR;

#endif // _JKGUIMAIN_H
