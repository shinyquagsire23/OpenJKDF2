#ifndef _SITHTIME_H
#define _SITHTIME_H

#include <stdint.h>
#include "types.h"

#define sithTime_Tick_ADDR (0x004DD640)
#define sithTime_Pause_ADDR (0x004DD710)
#define sithTime_Resume_ADDR (0x004DD730)
#define sithTime_SetDelta_ADDR (0x004DD760)
#define sithTime_Startup_ADDR (0x004DD800)
#define sithTime_SetMs_ADDR (0x004DD830)

void sithTime_Tick();
void sithTime_Pause();
void sithTime_Resume();
void sithTime_SetDelta(int deltaMs);
void sithTime_Startup();
void sithTime_SetMs(uint32_t curMs);

extern flex_d_t sithTime_physicsRolloverFrames;

#endif // _SITHTIME_H
