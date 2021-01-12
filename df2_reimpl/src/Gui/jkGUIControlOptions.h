#ifndef _JKGUI_CONTROLOPTIONS_H
#define _JKGUI_CONTROLOPTIONS_H

#define jkGuiControlOptions_Initialize_ADDR (0x0041C4C0)
#define jkGuiControlOptions_Shutdown_ADDR (0x0041C4E0)
#define jkGuiControlOptions_Show_ADDR (0x0041C4F0)

void jkGuiControlOptions_Initialize();
void jkGuiControlOptions_Shutdown();
int jkGuiControlOptions_Show();

#endif // _JKGUI_CONTROLOPTIONS_H
