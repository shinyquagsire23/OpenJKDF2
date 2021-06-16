#ifndef _JKGUINETHOST_H
#define _JKGUINETHOST_H

#define jkGuiNetHost_Initialize_ADDR (0x00411000)
#define jkGuiNetHost_Shutdown_ADDR (0x00411110)
#define jkGuiNetHost_Show_ADDR (0x004111C0)
#define jkGuiNetHost_sub_4118C0_ADDR (0x004118C0)
#define jkGuiNetHost_sub_4119D0_ADDR (0x004119D0)
#define jkGuiNetHost_sub_411AE0_ADDR (0x00411AE0)

#define jkGuiNetHost_maxRank (*(int*)0x00860460)
#define jkGuiNetHost_timeLimit (*(int*)0x00860464)
#define jkGuiNetHost_scoreLimit (*(int*)0x00860468)
#define jkGuiNetHost_maxPlayers (*(int*)0x0086046C)
#define jkGuiNetHost_sessionFlags (*(int*)0x00860470)
#define jkGuiNetHost_gameFlags (*(int*)0x00860474)
#define jkGuiNetHost_tickRate (*(int*)0x00860478)
#define jkGuiNetHost_gameName ((wchar_t*)0x0086047C)

static int (*jkGuiNetHost_Initialize)() = (void*)jkGuiNetHost_Initialize_ADDR;
static void (*jkGuiNetHost_Shutdown)() = (void*)jkGuiNetHost_Shutdown_ADDR;

#endif // _JKGUINETHOST_H
