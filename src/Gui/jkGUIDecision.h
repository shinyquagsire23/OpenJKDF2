#ifndef _JKGUIDECISION_H 
#define _JKGUIDECISION_H

#define jkGuiDecision_Initialize_ADDR (0x0041A3E0)
#define jkGuiDecision_Shutdown_ADDR (0x0041A400)
#define jkGuiDecision_Show_ADDR (0x0041A410)

void jkGuiDecision_Initialize();
void jkGuiDecision_Shutdown();
int jkGuiDecision_Show();

#endif // _JKGUIDECISION_H
