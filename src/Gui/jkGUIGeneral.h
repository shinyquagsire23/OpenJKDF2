#ifndef _JKGUIGENERAL_H
#define _JKGUIGENERAL_H

#define jkGuiGeneral_Startup_ADDR (0x0041A300)
#define jkGuiGeneral_Shutdown_ADDR (0x0041A320)
#define jkGuiGeneral_Show_ADDR (0x0041A330)

void jkGuiGeneral_Startup();
void jkGuiGeneral_Shutdown();
int jkGuiGeneral_Show();

#endif // _JKGUIGENERAL_H
