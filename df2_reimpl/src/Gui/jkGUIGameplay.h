#ifndef _JKGUI_GAMEPLAY_H
#define _JKGUI_GAMEPLAY_H

#define jkGuiGameplay_Initialize_ADDR (0x0041C1F0)
#define jkGuiGameplay_Shutdown_ADDR (0x0041C210)
#define jkGuiGameplay_Show_ADDR (0x0041C220)

void jkGuiGameplay_Initialize();
void jkGuiGameplay_Shutdown();
int jkGuiGameplay_Show();

#endif // _JKGUI_GAMEPLAY_H
