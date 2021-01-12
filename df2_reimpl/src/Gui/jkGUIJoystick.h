#ifndef _JKGUI_JOYSTICK_H
#define _JKGUI_JOYSTICK_H

#define jkGuiJoystick_nullsub_51_ADDR (0x0041AD50)
#define jkGuiJoystick_sub_41AD60_ADDR (0x0041AD60)
#define jkGuiJoystick_sub_41ADD0_ADDR (0x0041ADD0)
#define jkGuiJoystick_sub_41B220_ADDR (0x0041B220)
#define jkGuiJoystick_sub_41B2A0_ADDR (0x0041B2A0)
#define jkGuiJoystick_sub_41B390_ADDR (0x0041B390)
#define jkGuiJoystick_sub_41B570_ADDR (0x0041B570)
#define jkGuiJoystick_sub_41B740_ADDR (0x0041B740)
#define jkGuiJoystick_sub_41B870_ADDR (0x0041B870)
#define jkGuiJoystick_sub_41B8B0_ADDR (0x0041B8B0)
#define jkGuiJoystick_sub_41B920_ADDR (0x0041B920)
#define jkGuiJoystick_sub_41BA70_ADDR (0x0041BA70)
#define jkGuiJoystick_sub_41BAF0_ADDR (0x0041BAF0)
#define jkGuiJoystick_sub_41BB30_ADDR (0x0041BB30)
#define jkGuiJoystick_sub_41BB60_ADDR (0x0041BB60)
#define jkGuiJoystick_Show_ADDR (0x0041BF00)
#define jkGuiJoystick_sub_41C170_ADDR (0x0041C170)
#define jkGuiJoystick_Initialize_ADDR (0x0041C1C0)
#define jkGuiJoystick_Shutdown_ADDR (0x0041C1E0)

static int (*jkGuiJoystick_Show)() = (void*)jkGuiJoystick_Show_ADDR;

#endif // _JKGUI_JOYSTICK_H
