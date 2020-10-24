#ifndef _SITHTIME_H
#define _SITHTIME_H

#include <stdint.h>

#define sithTime_Tick_ADDR (0x004DD640)
#define sithTime_Pause_ADDR (0x004DD710)
#define sithTime_Resume_ADDR (0x004DD730)
#define sithTime_SetDelta_ADDR (0x004DD760)
#define sithTime_Startup_ADDR (0x004DD800)
#define sithTime_SetMs_ADDR (0x004DD830)

#define sithTime_deltaMs (*(uint32_t*)0x00836C08)
#define sithTime_deltaSeconds (*(float*)0x00836C0C)
#define sithTime_TickHz (*(float*)0x00836C10)
#define sithTime_curMs (*(uint32_t*)0x00836C14)
#define sithTime_curSeconds (*(float*)0x00836C18)
#define sithTime_curMsAbsolute (*(uint32_t*)0x00836C1C)
#define sithTime_pauseTimeMs (*(uint32_t*)0x00836C20)
#define sithTime_bRunning (*(int*)0x00836C24)

void sithTime_Tick();
void sithTime_Pause();
void sithTime_Resume();
void sithTime_SetDelta(int deltaMs);
void sithTime_Startup();
void sithTime_SetMs(uint32_t curMs);

#endif // _SITHTIME_H
