#ifndef _JKGUINET_H
#define _JKGUINET_H

#define jkGuiNet_Show_ADDR (0x00413960)
#define jkGuiNet_ShowSynchronizing_ADDR (0x00413BA0)
#define jkGuiNet_ShowWaitHostSettings_ADDR (0x00413C10)
#define jkGuiNet_sub_413C80_ADDR (0x00413C80)
#define jkGuiNet_CogMsgHandleJoining_ADDR (0x00413CF0)
#define jkGuiNet_sub_413E00_ADDR (0x00413E00)
#define jkGuiNet_sub_413E50_ADDR (0x00413E50)
#define jkGuiNet_sub_4140B0_ADDR (0x004140B0)
#define jkGuiNet_idk_ADDR (0x00414230)
#define jkGuiNet_sub_4142C0_ADDR (0x004142C0)

static void (*jkGuiNet_sub_413E00)() = (void*)jkGuiNet_sub_413E00_ADDR;
static int (*jkGuiNet_CogMsgHandleJoining)(int a1) = (void*)jkGuiNet_CogMsgHandleJoining_ADDR;
static int (*jkGuiNet_ShowSynchronizing)() = (void*)jkGuiNet_ShowSynchronizing_ADDR;
static int (*jkGuiNet_Show)() = (void*)jkGuiNet_Show_ADDR;

#endif // _JKGUINET_H
