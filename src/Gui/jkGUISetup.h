#ifndef _JKGUISETUP_H
#define _JKGUISETUP_H

#define jkGuiSetup_sub_412EF0_ADDR (0x00412EF0)
#define jkGuiSetup_Show_ADDR (0x00412F40)
#define jkGuiSetup_Initialize_ADDR (0x00413140)
#define jkGuiSetup_Shutdown_ADDR (0x00413170)

typedef struct jkGuiMenu jkGuiMenu;

void jkGuiSetup_sub_412EF0(jkGuiMenu *menu, int a2);
void jkGuiSetup_Show();
void jkGuiSetup_Initialize();
void jkGuiSetup_Shutdown();

#endif // _JKGUISETUP_H
